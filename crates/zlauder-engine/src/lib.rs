//! zlauder-engine — reversible PII masking for LLM traffic.
//!
//! Detection is delegated to `presidio-rs` (offline regex recognizers); tokens are
//! minted deterministically (blake3, session salt) and stored reversibly
//! (AES-256-GCM, per-session key). The four-arrow [`Surface`] model decides mask
//! vs unmask. This crate is runtime-free (synchronous); the proxy calls it from
//! async handlers.

mod config;
mod detect;
mod error;
mod manifest;
mod store;
mod surface;
mod token;

pub use config::{AllowList, Category, CustomReplacement, EngineConfig, Operator, Profile};
pub use error::EngineError;
pub use manifest::{ManifestEntry, MaskOutcome, UnmaskManifest};
pub use surface::{Direction, Surface};
pub use token::{MAX_TOKEN_LEN, TOKEN_HASH_HEX_LEN, make_token, token_regex};

use std::sync::Mutex;

use detect::{CompiledCustom, compile_customs, run_detection};
use store::SessionStore;
use token::hash_value;

/// The masking engine. Cheap to share behind an `Arc`; interior mutability via a
/// `Mutex` on the session store.
pub struct MaskEngine {
    analyzer: presidio_analyzer::AnalyzerEngine,
    config: EngineConfig,
    customs: Vec<CompiledCustom>,
    store: Mutex<SessionStore>,
}

impl MaskEngine {
    /// Build the analyzer (offline regex recognizers) and a fresh random session.
    pub fn new(config: EngineConfig) -> Result<Self, EngineError> {
        let analyzer = presidio_analyzer::default_analyzer(&config.language);
        let customs = compile_customs(&config.custom_replacements)?;
        Ok(Self {
            analyzer,
            config,
            customs,
            store: Mutex::new(SessionStore::new()),
        })
    }

    /// Build with an explicit session key + salt (proxy passes the SessionStart
    /// session bytes so token minting is stable for the whole session).
    pub fn with_session(
        config: EngineConfig,
        key: [u8; 32],
        salt: [u8; 16],
    ) -> Result<Self, EngineError> {
        let analyzer = presidio_analyzer::default_analyzer(&config.language);
        let customs = compile_customs(&config.custom_replacements)?;
        Ok(Self {
            analyzer,
            config,
            customs,
            store: Mutex::new(SessionStore::with_key_and_salt(key, salt)),
        })
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Number of distinct tokens minted so far this session.
    pub fn token_count(&self) -> usize {
        self.store.lock().expect("store mutex poisoned").len()
    }

    /// Mask `text` (request path). Detect -> filter -> mint tokens -> splice.
    ///
    /// `surface` is a policy/audit label, not a direction gate: under
    /// unmask-on-the-wire the proxy masks every outbound field (including
    /// assistant-authored history, which the local transcript stores as
    /// plaintext) and unmasks every inbound field. Determinism makes the
    /// round-trip reproduce the original token form exactly.
    pub fn mask(&self, text: &str, surface: Surface) -> Result<MaskOutcome, EngineError> {
        if !self.config.surface_enabled(surface) {
            return Ok(MaskOutcome {
                masked_text: text.to_string(),
                manifest: UnmaskManifest::new(),
            });
        }

        let dets = match run_detection(&self.analyzer, &self.config, &self.customs, text, surface) {
            Ok(d) => d,
            Err(e) => {
                if self.config.fail_closed {
                    return Err(e);
                }
                tracing::warn!("detection failed, passing text through unmasked: {e}");
                return Ok(MaskOutcome {
                    masked_text: text.to_string(),
                    manifest: UnmaskManifest::new(),
                });
            }
        };

        let mut manifest = UnmaskManifest::new();
        let mut out = text.to_string();
        // Splice back-to-front so original byte offsets stay valid.
        for d in dets.iter().rev() {
            let slice = &text[d.start..d.end];
            let replacement = match d.operator {
                Operator::Keep => continue,
                Operator::Redact => "[REDACTED]".to_string(),
                Operator::Mask { char, from_end } => mask_value(slice, char, from_end),
                Operator::Hash => hash_value(&d.entity_type, slice),
                Operator::Token => {
                    let token = {
                        let mut store = self.store.lock().expect("store mutex poisoned");
                        if let Some(fixed) = &d.fixed_token {
                            store.intern_fixed(fixed.clone(), slice)?;
                            fixed.clone()
                        } else {
                            store.intern(&d.entity_type, slice)?
                        }
                    };
                    manifest.push(ManifestEntry {
                        canonical_form: slice.to_string(),
                        token_handle: token.clone(),
                        entity_kind: d.entity_type.clone(),
                        arrow_origin: surface,
                        exposed_at: None,
                    });
                    token
                }
            };
            out.replace_range(d.start..d.end, &replacement);
        }

        Ok(MaskOutcome {
            masked_text: out,
            manifest,
        })
    }

    /// Unmask an UNMASK-direction surface (Arrow 2 / Arrow 3). Replaces every known
    /// token with its plaintext (manifest first, then session-store fallback for
    /// tokens minted in earlier turns). Never re-masks; unknown tokens are left
    /// verbatim.
    pub fn unmask(&self, text: &str, manifest: &UnmaskManifest) -> Result<String, EngineError> {
        let store = self.store.lock().expect("store mutex poisoned");
        let re = token_regex();
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for m in re.find_iter(text) {
            out.push_str(&text[last..m.start()]);
            let tok = m.as_str();
            if let Some(p) = manifest.lookup(tok) {
                out.push_str(p);
            } else if let Some(p) = store.reveal(tok) {
                out.push_str(&p);
            } else {
                out.push_str(tok);
            }
            last = m.end();
        }
        out.push_str(&text[last..]);
        drop(store);

        // Custom literal tokens that don't match the standard token grammar.
        for e in &manifest.entries {
            if !re.is_match(&e.token_handle) {
                out = out.replace(&e.token_handle, &e.canonical_form);
            }
        }
        Ok(out)
    }

    /// Reveal a single token to its plaintext (audit). `None` if unknown.
    pub fn reveal(&self, token: &str) -> Option<String> {
        self.store.lock().expect("store mutex poisoned").reveal(token)
    }

    /// Export the session key + salt so a sibling process can decrypt for audit.
    pub fn session_handle(&self) -> ([u8; 32], [u8; 16]) {
        let store = self.store.lock().expect("store mutex poisoned");
        (*store.key(), *store.salt())
    }
}

/// `Mask` operator: keep the last `from_end` chars, replace the rest with `ch`.
fn mask_value(slice: &str, ch: char, from_end: usize) -> String {
    let chars: Vec<char> = slice.chars().collect();
    let n = chars.len();
    let keep = from_end.min(n);
    let mut s = String::with_capacity(slice.len());
    for _ in 0..(n - keep) {
        s.push(ch);
    }
    for c in &chars[n - keep..] {
        s.push(*c);
    }
    s
}

// Engine must be shareable across async tasks in the proxy.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MaskEngine>();
};

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> MaskEngine {
        MaskEngine::new(EngineConfig::default()).unwrap()
    }

    // T1 — mask -> unmask round-trip.
    #[test]
    fn round_trip_email() {
        let e = engine();
        let original = "contact me at alice@example.com please";
        let outcome = e.mask(original, Surface::UserMessage).unwrap();
        assert!(!outcome.masked_text.contains("alice@example.com"));
        assert!(outcome.masked_text.contains("[EMAIL_ADDRESS_"));
        let back = e.unmask(&outcome.masked_text, &outcome.manifest).unwrap();
        assert_eq!(back, original);
    }

    // T2 — determinism / cache stability.
    #[test]
    fn determinism_same_engine() {
        let e = engine();
        let a = e.mask("write to carol@example.com", Surface::UserMessage).unwrap();
        let b = e.mask("write to carol@example.com", Surface::ToolResult).unwrap();
        assert!(a.masked_text.contains("[EMAIL_ADDRESS_"), "got: {}", a.masked_text);
        assert_eq!(a.masked_text, b.masked_text, "same plaintext => identical token");
    }

    #[test]
    fn determinism_shared_salt_vs_isolation() {
        let key = [7u8; 32];
        let salt = [9u8; 16];
        let e1 = MaskEngine::with_session(EngineConfig::default(), key, salt).unwrap();
        let e2 = MaskEngine::with_session(EngineConfig::default(), key, salt).unwrap();
        let t1 = e1.mask("alice@example.com", Surface::UserMessage).unwrap();
        let t2 = e2.mask("alice@example.com", Surface::UserMessage).unwrap();
        assert_eq!(t1.masked_text, t2.masked_text, "same (key,salt) => same token");

        let e3 = MaskEngine::with_session(EngineConfig::default(), key, [1u8; 16]).unwrap();
        let t3 = e3.mask("alice@example.com", Surface::UserMessage).unwrap();
        assert_ne!(t1.masked_text, t3.masked_text, "different salt => different token");
    }

    // T3 — reveal.
    #[test]
    fn reveal_token() {
        let e = engine();
        let outcome = e.mask("alice@example.com", Surface::UserMessage).unwrap();
        let token = outcome.manifest.entries[0].token_handle.clone();
        assert_eq!(e.reveal(&token).as_deref(), Some("alice@example.com"));
        assert_eq!(e.reveal("[EMAIL_ADDRESS_deadbeef0000]"), None);
    }

    // T4 — operator coverage.
    #[test]
    fn operators() {
        let mut cfg = EngineConfig::default();
        cfg.entity_operators
            .insert("CREDIT_CARD".into(), Operator::Mask { char: '*', from_end: 4 });
        cfg.entity_operators
            .insert("EMAIL_ADDRESS".into(), Operator::Redact);
        let e = MaskEngine::new(cfg).unwrap();

        let out = e.mask("card 4111111111111111 here", Surface::UserMessage).unwrap();
        assert!(out.masked_text.contains("************1111"));
        assert!(out.manifest.is_empty(), "Mask produces no reversible entry");

        let out2 = e.mask("mail bob@example.com", Surface::UserMessage).unwrap();
        assert!(out2.masked_text.contains("[REDACTED]"));
        assert!(!out2.masked_text.contains("bob@example.com"));
        // Unmasking redacted text is a no-op.
        let back = e.unmask(&out2.masked_text, &out2.manifest).unwrap();
        assert_eq!(back, out2.masked_text);
    }

    // T5 — allow-list + custom rules.
    #[test]
    fn allow_list_and_custom() {
        let mut cfg = EngineConfig::default();
        cfg.allow_list.add_exact("admin@example.com");
        cfg.custom_replacements.push(CustomReplacement {
            pattern: "ACME-CODENAME".into(),
            entity_type: "CODENAME".into(),
            is_regex: false,
            case_sensitive: true,
            priority: 0,
            literal_token: true,
            token: Some("[CODENAME_acme]".into()),
            apply_to_surfaces: None,
        });
        let e = MaskEngine::new(cfg).unwrap();

        let out = e
            .mask(
                "ping admin@example.com about ACME-CODENAME",
                Surface::UserMessage,
            )
            .unwrap();
        assert!(out.masked_text.contains("admin@example.com"), "allow-listed not masked");
        assert!(out.masked_text.contains("[CODENAME_acme]"));
        let back = e.unmask(&out.masked_text, &out.manifest).unwrap();
        assert_eq!(back, "ping admin@example.com about ACME-CODENAME");
    }

    // presidio's strict UrlRecognizer (default) drops scheme-less filenames/code
    // (`CLAUDE.md`, `opts.la`) while still masking real URLs.
    #[test]
    fn strict_url_skips_filenames_keeps_real_urls() {
        let e = engine();
        let text =
            "edit CLAUDE.md and opts.la then open https://corp.example.com/secret and mail bob@example.com";
        let out = e.mask(text, Surface::UserMessage).unwrap();
        assert!(out.masked_text.contains("CLAUDE.md"), "filename masked: {}", out.masked_text);
        assert!(out.masked_text.contains("opts.la"), "code ident masked: {}", out.masked_text);
        assert!(
            !out.masked_text.contains("https://corp.example.com/secret"),
            "real URL not masked: {}",
            out.masked_text
        );
        assert!(!out.masked_text.contains("bob@example.com"));
        assert!(out.masked_text.contains("[URL_"));
        assert!(out.masked_text.contains("[EMAIL_ADDRESS_"));
    }

    // Any surface label can be masked (no direction gate); unmask round-trips.
    #[test]
    fn assistant_surface_masks_and_round_trips() {
        let e = engine();
        let original = "I emailed dave@example.com for you";
        let out = e.mask(original, Surface::AssistantText).unwrap();
        assert!(out.masked_text.contains("[EMAIL_ADDRESS_"));
        assert_eq!(e.unmask(&out.masked_text, &out.manifest).unwrap(), original);
    }
}
