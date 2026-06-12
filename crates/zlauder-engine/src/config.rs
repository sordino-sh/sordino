//! Engine configuration: profiles, entity categories, operators, allow-list, and
//! custom rules. Ported (trimmed) from orchestr8-privacy `config.rs`.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::surface::Surface;

// --- Custom entity-string contract (shared recognizer ↔ config gate) ---------
//
// These zlauder-local `Custom` entity types are NOT canonical `presidio_core::EntityType`
// Display names — they are labels emitted by the hard-context regex recognizers (DOB /
// card-expiry / CVV / URL-credential) and by the ML `private_date` remap. The
// category gate (`entity_enabled`) matches on the EXACT emitted string, so the
// recognizer's emitted label and the `Category::entity_types()` entry MUST be the
// SAME string — a desync silently no-ops the gate (every detection of that type is
// dropped). Defining them as `pub const`s here is the single source of truth both
// sides reference, so a rename is a compile-wide change, never a silent drift.
//
// Later stages (recognizers.rs, ml.rs) import these instead of repeating literals.

/// Date of birth (hard-context regex recognizer) → [`Category::Identity`].
pub const ENTITY_DATE_OF_BIRTH: &str = "DATE_OF_BIRTH";
/// Credit-card expiration date (hard-context regex recognizer) →
/// [`Category::Financial`]. Emitted ONLY when the expiry match carries STRONG
/// payment evidence (a plausible Luhn-valid PAN or an unambiguous payment term in
/// window). See [`ENTITY_EXPIRATION_DATE`] for the neutral, weak-evidence sibling.
pub const ENTITY_CREDIT_CARD_EXPIRATION: &str = "CREDIT_CARD_EXPIRATION";
/// Neutral expiration date (hard-context regex recognizer) → BOTH
/// [`Category::Financial`] AND [`Category::Identity`]. The weak-evidence sibling of
/// [`ENTITY_CREDIT_CARD_EXPIRATION`]: the same EMIT gate fires, but when only an
/// AMBIGUOUS keyword (`card`/`visa`/`discover`/`valid thru`) is present — i.e. no
/// PAN and no unambiguous payment term — the value is labeled neutrally so a travel
/// visa / gift-card / subscription expiry is NOT mislabeled as a credit-card expiry.
/// Masked tokens are visible to the upstream LLM, so a wrong CREDIT_CARD label would
/// corrupt the model's reasoning. NEVER suppresses the mask — only relabels it.
///
/// Dual category membership (FIX 1a): the neutral trigger case spans identity
/// documents (travel visas) AND financial cards (gift / credit cards), so it masks
/// when EITHER Financial OR Identity is enabled. `entity_enabled` ORs across the
/// enabled categories, so membership in both is the lever for that OR semantics.
pub const ENTITY_EXPIRATION_DATE: &str = "EXPIRATION_DATE";
/// Card verification value (hard-context regex recognizer) →
/// [`Category::Financial`]. PCI Sensitive Authentication Data — defaults to the
/// irreversible [`Operator::Redact`] (see [`EngineConfig::operator_for`]).
pub const ENTITY_CVV: &str = "CVV";
/// ML `private_date` remap target → [`Category::Identity`]. Deliberately NOT
/// `DATE_OF_BIRTH`: the model's `private_date` label covers ALL private dates, so
/// relabeling generic dates as births would be an audit-trail lie in every
/// `entity_kind`-displaying surface. `DATE_OF_BIRTH` stays reserved for the
/// hard-context regex recognizer.
pub const ENTITY_PRIVATE_DATE: &str = "PRIVATE_DATE";
/// Credential embedded in a URL / config string — a sensitive-named query param
/// value (`?token=…`, `password=…`) or URL userinfo (`scheme://user:pass@host`)
/// → [`Category::Secrets`]. Lives in the always-on Secrets category (NOT Network)
/// so that turning `Network` off — which stops masking the URL itself — never stops
/// masking a credential *inside* a URL. Caught by the context-based
/// `UrlCredentialRecognizer` (matches by param-name / userinfo position, not by
/// value shape), so it covers opaque/low-entropy secrets that the entropy-gated
/// generic API_KEY catch-all misses. Reserved system entity name. See [`Category::Network`].
///
/// Operator: inherits the profile `default_operator` (reversible `Token`), matching the
/// other detected secret entities (`API_KEY`, …) and the project's reversible-on-wire
/// model — the value never reaches the upstream LLM, but stays revealable for local
/// audit. Deployments wanting it irreversible can set `entity_operators.URL_CREDENTIAL`
/// to `Hash`/`Redact`.
pub const ENTITY_URL_CREDENTIAL: &str = "URL_CREDENTIAL";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Strict,
    #[default]
    Balanced,
    Minimal,
    /// Secrets-only profile. Renamed from the former `DevelopmentSafe`; the
    /// `development_safe` serde alias keeps OLD configs/control-plane clients
    /// loading after the rename.
    #[serde(rename = "secrets_only", alias = "development_safe")]
    SecretsOnly,
}

impl Profile {
    /// Every profile variant, in lineup order. Single source of truth for any
    /// caller that needs to enumerate the profiles (tests, validation).
    pub const ALL: [Profile; 4] = [
        Profile::Strict,
        Profile::Balanced,
        Profile::Minimal,
        Profile::SecretsOnly,
    ];

    pub fn default_threshold(self) -> f32 {
        match self {
            Profile::Strict => 0.4,
            Profile::Balanced => 0.5,
            Profile::SecretsOnly => 0.6,
            Profile::Minimal => 0.6,
        }
    }

    pub fn default_categories(self) -> HashSet<Category> {
        use Category::*;
        let v: &[Category] = match self {
            Profile::Strict => &[Secrets, Financial, Identity, Contact, Network, Personal],
            // Balanced (default) deliberately OMITS Network: URL/IP/MAC are
            // load-bearing infra context, not PII, and a real secret inside a URL
            // is still caught via `URL_CREDENTIAL` (Secrets) regardless.
            Profile::Balanced => &[Secrets, Financial, Identity, Contact],
            Profile::Minimal => &[Secrets, Financial],
            Profile::SecretsOnly => &[Secrets],
        };
        v.iter().copied().collect()
    }

    pub fn default_operator(self) -> Operator {
        // Every profile now masks with a REVERSIBLE deterministic token (so the
        // operator can always reveal/audit). Strict was changed from the previous
        // irreversible `Redact` to `Token` (approved owner change).
        let _ = self;
        Operator::Token
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Secrets,
    Financial,
    Identity,
    Contact,
    /// Network / infrastructure identifiers (URL, IP, MAC). Split out of `Contact`
    /// because — unlike email/phone — these are load-bearing context in a coding
    /// tool's traffic (API endpoints, docs links, the monitor's own URL, loopback /
    /// private IPs that are never PII), and masking them to one opaque token degrades
    /// the model's reasoning for little privacy gain. OFF in the default `Balanced`
    /// profile; ON in `Strict`. A genuine secret embedded in a URL is still masked
    /// regardless of this category — see `URL_CREDENTIAL` in `Secrets`.
    Network,
    Personal,
}

impl Category {
    /// Every category, for callers that need to enumerate the whole set.
    pub const ALL: [Category; 6] = [
        Category::Secrets,
        Category::Financial,
        Category::Identity,
        Category::Contact,
        Category::Network,
        Category::Personal,
    ];

    /// The canonical, deduplicated set of every `EntityType` Display string the
    /// categories cover. This is the SAME source `entity_types` returns, so a
    /// config validator can reject an `entity_operators` key / `custom_replacement`
    /// `entity_type` that names an alias or typo (which would otherwise be a silent
    /// no-op against the category gate).
    pub fn canonical_entity_types() -> HashSet<&'static str> {
        Category::ALL
            .iter()
            .flat_map(|c| c.entity_types().iter().copied())
            .collect()
    }

    /// Entity-type strings (matching `presidio_core::EntityType`'s `Display`) that
    /// belong to this category.
    pub fn entity_types(self) -> &'static [&'static str] {
        match self {
            Category::Secrets => &[
                "API_KEY",
                "AWS_ACCESS_KEY",
                "AWS_SECRET_KEY",
                "AZURE_KEY",
                "GCP_API_KEY",
                "PRIVATE_KEY",
                "JWT",
                // zlauder-local Custom entity (context-based recognizer). Kept in the
                // always-on Secrets category so an in-URL credential stays masked even
                // when `Network` (the URL/IP/MAC category) is off — design §3.
                ENTITY_URL_CREDENTIAL,
            ],
            Category::Financial => &[
                "CREDIT_CARD",
                // These MUST be the canonical `EntityType` Display strings, NOT the
                // parse aliases — the category gate matches on `Display`, so an alias
                // here silently drops every detection of that entity. The aliases are
                // `IBAN` (→ `IBAN_CODE`), `CRYPTO_WALLET`/`CRYPTO_ADDRESS` (→ `CRYPTO`),
                // `US_ROUTING_NUMBER` (→ `ABA_ROUTING_NUMBER`), and `US_BANK_ACCOUNT`
                // (→ `US_BANK_NUMBER`). The IbanRecognizer / CryptoRecognizer are in
                // the default `en` set, so the alias bug was masking nothing for them.
                "IBAN_CODE",
                "CRYPTO",
                "US_BANK_NUMBER",
                "ABA_ROUTING_NUMBER",
                // zlauder-local Custom entities (hard-context regex recognizers).
                // Referenced via the shared consts so the gate string can never drift
                // from the recognizer's emitted label. `EXPIRATION_DATE` is the
                // neutral, weak-evidence sibling of `CREDIT_CARD_EXPIRATION` (emitted
                // when only an ambiguous card keyword fired — travel visa / gift card /
                // subscription expiry), so the upstream LLM never sees a generic expiry
                // mislabeled as a credit-card one.
                ENTITY_CREDIT_CARD_EXPIRATION,
                ENTITY_EXPIRATION_DATE,
                ENTITY_CVV,
            ],
            Category::Identity => &[
                "US_SSN",
                "US_ITIN",
                "NATIONAL_ID",
                "PASSPORT",
                "US_PASSPORT",
                "UK_PASSPORT",
                "DRIVER_LICENSE",
                "US_DRIVER_LICENSE",
                "UK_DRIVING_LICENCE",
                // Canonical Display is `MEDICAL_LICENSE` (`US_MEDICAL_LICENSE` is a
                // parse alias). The UsMedicalLicenseRecognizer IS in the default set,
                // so the alias was silently dropping every hit.
                "MEDICAL_LICENSE",
                "US_NPI",
                "US_MBI",
                "UK_NHS",
                "UK_NINO",
                // zlauder-local Custom entities. `DATE_OF_BIRTH` is the hard-context
                // regex recognizer; `PRIVATE_DATE` is the ML `private_date` remap
                // target (kept distinct so generic private dates are not mislabeled as
                // births). Referenced via the shared consts to prevent gate drift.
                ENTITY_DATE_OF_BIRTH,
                ENTITY_PRIVATE_DATE,
                // `EXPIRATION_DATE` lives in BOTH Financial AND Identity (FIX 1a):
                // its trigger case spans identity docs (travel visas) and financial
                // cards (gift / credit cards). Because `entity_enabled` ORs across the
                // enabled categories (`.any()`), dual membership means a neutral expiry
                // masks when EITHER Financial OR Identity is on — the intended behavior.
                // Dual membership is safe: `canonical_entity_types()` is a HashSet
                // (dedups) and `entity_enabled` uses `.any()` (idempotent).
                ENTITY_EXPIRATION_DATE,
            ],
            // Contact = ways to reach a *person* (genuine PII). Infra identifiers
            // (URL / IP / MAC) moved to `Network` so the default can keep them
            // unmasked without giving up email/phone masking.
            Category::Contact => &["EMAIL_ADDRESS", "PHONE_NUMBER"],
            // Network / infrastructure identifiers — OFF by default (see `Category::Network`).
            // URL relies on presidio's strict `UrlRecognizer` (the default since
            // its strict-mode change), which drops scheme-less `file.ext`/`opts.la`
            // false positives while keeping real URLs (scheme / www. / path).
            // DOMAIN stays OFF: its recognizer is still aggressive on filenames;
            // re-enable per-deployment via `entity_operators` if wanted.
            Category::Network => &["IP_ADDRESS", "URL", "MAC_ADDRESS"],
            Category::Personal => &["PERSON", "LOCATION", "ORGANIZATION"],
        }
    }
    // NOTE: `DATE_TIME` (the ML model's `private_date` label) is deliberately not in
    // any category — dates are noisy (the regex `DateTimeRecognizer` is off by
    // default for the same reason), so the ML recognizer's date spans are dropped by
    // the category gate. It stays opt-in per deployment via an explicit
    // `entity_operators` entry (which `entity_enabled` honors). Locked by
    // `date_time_unmapped_by_default_but_opt_in` in lib.rs.
}

/// Scope of the deterministic token salt (DEFERRED behavior; the flag is parsed
/// but inert — see Component 3 of `glittery-bubbling-locket.md`).
/// - `Project` (today): one persisted per-project salt → cross-conversation token
///   determinism (stable Anthropic prompt-cache prefix on resume).
/// - `Conversation`: a per-conversation salt, keyed by a similarity-based content
///   fingerprint, so tokens do not correlate across conversations. NOT YET WIRED.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaltScope {
    #[default]
    Project,
    Conversation,
}

/// How widely a *burned* (pre-mask-exposed) value is redacted (DEFERRED behavior;
/// parsed but inert). `Leaf` redacts only the pre-ML occurrence; `Value` redacts
/// every occurrence (fully severs the token↔plaintext bridge at the cost of model
/// coherence). NOT YET WIRED.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureRedactionScope {
    #[default]
    Leaf,
    Value,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Operator {
    /// Reversible deterministic blake3 token (default).
    #[default]
    Token,
    /// Irreversible: replace with `[REDACTED]`.
    Redact,
    /// Irreversible: keep the last `from_end` chars, replace the rest with `char`.
    Mask { char: char, from_end: usize },
    /// Irreversible: `[ENTITY:hash]`.
    Hash,
    /// Reversible, but ONLY at the tool-input boundary (broker). The model never
    /// sees the value and it is never display-revealable; the real value is spliced
    /// in only at local tool execution (gated by `BrokerPolicy`). Reachable ONLY via
    /// a registered secret — rejected in `default_operator`/`entity_operators`
    /// (it is meaningless without a registered secret name + a broker rule).
    Broker,
    /// Reversible "owner-reveal" (local) token: masked on the wire (the provider sees a
    /// token), REVEALED on the display path (Arrow 2 → the user) so the model can relay
    /// it, but REFUSED into tool inputs (Arrow 3) unless the operator promotes the handle
    /// for the session. For the user's OWN credential (the proxy admin key) — fine to show
    /// *them*, never to a tool/provider. Reachable ONLY via a registered secret (rejected
    /// in `default_operator`/`entity_operators`, like `Broker`); `#[serde(skip)]` so it can
    /// never be set through serialized config or appear in a config snapshot.
    #[serde(skip)]
    Local,
    /// Detected but left verbatim (e.g. an allow-list-by-policy passthrough).
    Keep,
}

#[derive(Clone, Debug, Default)]
pub struct AllowList {
    pub exact: HashSet<String>,
    pub exact_ci: HashSet<String>,
    pub patterns: Vec<regex::Regex>,
}

impl AllowList {
    /// A small set of common safe words/hosts unlikely to be PII.
    pub fn with_common_words() -> Self {
        let mut al = Self::default();
        for w in ["Anthropic", "Claude", "127.0.0.1"] {
            al.add_exact(w);
        }
        al.add_exact_ci("localhost");
        al
    }

    pub fn is_allowed(&self, value: &str) -> bool {
        if self.exact.contains(value) {
            return true;
        }
        let lower = value.to_lowercase();
        if self.exact_ci.contains(&lower) {
            return true;
        }
        self.patterns.iter().any(|p| p.is_match(value))
    }

    pub fn add_exact(&mut self, v: impl Into<String>) {
        self.exact.insert(v.into());
    }

    pub fn add_exact_ci(&mut self, v: impl Into<String>) {
        self.exact_ci.insert(v.into().to_lowercase());
    }

    pub fn add_pattern(&mut self, p: regex::Regex) {
        self.patterns.push(p);
    }

    /// Build an allow-list from raw config strings (compiling pattern strings),
    /// seeded with the common-words defaults. Lets callers avoid a `regex` dep.
    pub fn from_specs(
        exact: Vec<String>,
        exact_ci: Vec<String>,
        patterns: Vec<String>,
    ) -> Result<Self, regex::Error> {
        let mut al = Self::with_common_words();
        for e in exact {
            al.add_exact(e);
        }
        for e in exact_ci {
            al.add_exact_ci(e);
        }
        for p in patterns {
            al.add_pattern(regex::Regex::new(&p)?);
        }
        Ok(al)
    }
}

/// Display-time decoration for *unmasked assistant text* (Arrow 2 only). When a
/// token is restored to plaintext on its way to the terminal, the plaintext is
/// wrapped with `prefix`/`suffix` so the operator can SEE, at a glance, exactly
/// which spans of the assistant's reply were un-masked. This is purely a local
/// rendering aid:
///
/// - It is applied ONLY to `Surface::AssistantText` (the model's prose), never to
///   tool inputs, tool results, citations, or compaction — wrapping those could
///   corrupt a value the model is writing into a file or passing to a tool.
/// - On the next turn the wrapped reply is re-sent as assistant history; the mask
///   path strips the marker literals *before* detection (see `MaskEngine::mask`),
///   so upstream receives the bare token — byte-identical to a no-marker
///   round-trip, with zero added noise and a stable prompt-cache prefix.
///
/// The default `prefix`/`suffix` are the printable brackets `⟦`/`⟧` (U+27E6/U+27E7):
/// they render everywhere — terminal, file, and the Claude Code web UI alike — unlike
/// raw ANSI escapes, which show as literal `␛[…m` bytes anywhere that doesn't interpret
/// them. Any prefix/suffix pair works; pick markers that do NOT occur in ordinary prose
/// or code, since the strip removes the exact literals from re-sent assistant history
/// (the `⟦`/`⟧` brackets are chosen precisely because they don't appear in code/prose;
/// a backtick would over-strip code spans, and ANSI renders as junk out-of-terminal).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevealMarker {
    /// Master switch for the decoration. On by default — the printable `⟦`/`⟧` markers
    /// (see the type doc) make un-masked spans visible locally with no out-of-band junk.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Inserted immediately before each un-masked value.
    #[serde(default = "default_marker_prefix")]
    pub prefix: String,
    /// Inserted immediately after each un-masked value.
    #[serde(default = "default_marker_suffix")]
    pub suffix: String,
}

/// `⟦` (U+27E6) — a printable left bracket that renders in every sink (terminal, file,
/// web UI) and never occurs in ordinary code or prose, so the strip can't over-remove.
fn default_marker_prefix() -> String {
    "\u{27e6}".to_string()
}
/// `⟧` (U+27E7) — the matching right bracket.
fn default_marker_suffix() -> String {
    "\u{27e7}".to_string()
}

impl Default for RevealMarker {
    fn default() -> Self {
        Self {
            enabled: true,
            prefix: default_marker_prefix(),
            suffix: default_marker_suffix(),
        }
    }
}

impl RevealMarker {
    /// On (and has at least one non-empty delimiter to add/strip).
    pub fn is_active(&self) -> bool {
        self.enabled && (!self.prefix.is_empty() || !self.suffix.is_empty())
    }

    /// Wrap one un-masked value for display: `prefix || value || suffix`.
    pub fn wrap(&self, value: &str) -> String {
        let mut s = String::with_capacity(self.prefix.len() + value.len() + self.suffix.len());
        s.push_str(&self.prefix);
        s.push_str(value);
        s.push_str(&self.suffix);
        s
    }

    /// Could `text` contain either delimiter? Cheap guard so the common
    /// (marker-free) leaf skips the allocation in [`Self::strip`].
    pub fn contained_in(&self, text: &str) -> bool {
        (!self.prefix.is_empty() && text.contains(&self.prefix))
            || (!self.suffix.is_empty() && text.contains(&self.suffix))
    }

    /// Remove every exact `prefix`/`suffix` literal — used on the mask path to peel
    /// a prior turn's display decoration off re-sent assistant history *before*
    /// detection runs, so detection sees the original value (no marker char fused to
    /// the PII) and upstream gets the bare token.
    pub fn strip(&self, text: &str) -> String {
        let mut out = if self.prefix.is_empty() {
            text.to_string()
        } else {
            text.replace(&self.prefix, "")
        };
        if !self.suffix.is_empty() && self.suffix != self.prefix {
            out = out.replace(&self.suffix, "");
        }
        out
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustomReplacement {
    pub pattern: String,
    pub entity_type: String,
    #[serde(default)]
    pub is_regex: bool,
    #[serde(default = "default_true")]
    pub case_sensitive: bool,
    #[serde(default)]
    pub priority: u32,
    #[serde(default)]
    pub literal_token: bool,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub apply_to_surfaces: Option<HashSet<Surface>>,
}

/// Optional ML recognizer config (`[engine.ml]`): the `openai/privacy-filter`
/// token classifier on a native-Rust Candle CPU backend. Plain serde — parsed
/// even by a regex-only (`--no-default-features`) build, which simply never loads
/// a model. Activation is hot: the proxy loads the model in the background when
/// `enabled` flips true (see `MlStatus`), so masking keeps running (regex-only)
/// while it loads.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlConfig {
    /// Whether the ML recognizer should be active. Loading happens in the
    /// background; until the model is `Ready`, masking is regex-only.
    #[serde(default)]
    pub enabled: bool,
    /// Strict fail-closed mode. When true, enabled-but-not-Ready ML refuses
    /// maskable requests instead of degrading to regex-only. Recommended for
    /// `backend = "http"`; applies live because it is policy, not recognizer
    /// identity.
    #[serde(default)]
    pub required: bool,
    /// Where inference runs: local Candle backend or remote HTTP endpoint.
    /// Selecting a backend not compiled into this build fails explicitly.
    #[serde(default)]
    pub backend: MlBackend,
    /// HuggingFace repo id of a privacy-filter–compatible checkpoint.
    #[serde(default = "default_ml_model")]
    pub model: String,
    /// `backend = "http"` only: HF token-classification endpoint URL.
    /// Required for HTTP backend; must be `http://` or `https://`.
    ///
    /// Privacy: every un-cached leaf's raw text is sent to this endpoint.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// `backend = "http"` only: env var name for the bearer token. The token
    /// itself never lives in config files.
    #[serde(default)]
    pub auth_token_env: Option<String>,
    /// `backend = "http"` only: per-request timeout in seconds.
    #[serde(default = "default_ml_http_timeout_secs")]
    pub http_timeout_secs: u64,
    /// Optional pinned revision (branch/tag/commit); `None` ⇒ `main`.
    #[serde(default)]
    pub revision: Option<String>,
    /// Recognizer score floor; `None` ⇒ the spec default (0.5). Distinct from the
    /// engine-wide `score_threshold`, which is *also* applied to ML detections.
    #[serde(default)]
    pub min_score: Option<f32>,
    /// Try CUDA/Metal before CPU. Default `false` (CPU); the GPU backends are not
    /// compiled in by default, so this falls through to CPU regardless.
    #[serde(default)]
    pub prefer_gpu: bool,
    /// CPU activation-compute precision. **Default [`ComputePrecision::F32`]**
    /// (today's behavior, output bit-identical to historical detections).
    ///
    /// [`ComputePrecision::F16`] is a **recall-risk opt-in**: it halves
    /// activation memory and can speed up CPU matmul, but casting the
    /// bf16-stored weights down to f16 narrows the exponent range and may drop a
    /// true-positive PII span (a privacy regression). It MUST be validated by
    /// the recall gate before it is trusted, and is NEVER made the default.
    /// Ignored when the model runs on CUDA/Metal (those use BF16). Parsed even by
    /// a regex-only build; it only has an effect when the `ml` backend is loaded.
    #[serde(default)]
    pub compute_precision: ComputePrecision,
    /// MoE expert-weight storage precision. **Default [`Quantization::Bf16`]** —
    /// the recall-neutral CPU lever: expert weights are stored bf16 (the exact
    /// bits the model ships / the GPU runs) and upcast per-block to F32 before the
    /// matmul, so activations and accumulation stay F32. It is **golden-gate
    /// confirmed** recall-neutral (26/28 end-to-end, 4/6 ML-only — identical to
    /// F32, zero dropped spans, no score delta > 1e-3) and ~30% faster on the MoE
    /// matmuls. [`Quantization::None`] is the historical F32 CPU path.
    ///
    /// [`Quantization::Q8_0`] (8-bit) and [`Quantization::Bf16Vnni`] (native
    /// `vdpbf16ps`, rounds activations) are **recall-risk opt-ins** that MUST be
    /// validated by the recall gate before trust. Router, norms, embeddings, the
    /// score head, attention sinks, and all biases stay F32. Applies on every
    /// device (bf16 levers are a no-op on GPU, which already computes in bf16).
    /// Parsed even by a regex-only build; only effective when `ml` is loaded.
    #[serde(default = "default_ml_quant")]
    pub quant: Quantization,
    /// Banded-attention sparsity for long sequences. **Default `true`** — the
    /// recall gate (widened corpus incl. 3 long-doc fixtures) proves it drops zero
    /// true-positives with score delta < 1e-3, and it is ~48% faster on long
    /// inputs.
    ///
    /// The backend computes attention block-by-block over only the in-band key
    /// slice of each query block, skipping the fully out-of-band region of the
    /// score matrix. The band half-width and the softmax effective-logit set are
    /// identical to the dense path, so the output is bit-equivalent — and because
    /// the band geometry is content-independent (a fixed function of the model's
    /// sliding window, not of the text), the gate's proof generalizes to all
    /// inputs. The speedup applies only where `T` exceeds the band's full width
    /// (large tool outputs / file contents / transcripts); short inputs use the
    /// dense path regardless, unchanged. Set `false` for the historical dense
    /// `T x T` path. Parsed even by a regex-only build; only effective when the
    /// `ml` backend is loaded.
    #[serde(default = "default_ml_banded")]
    pub banded_attention: bool,
}

/// Where ML inference runs. Serde wire form is lowercase (`"local"`, `"http"`).
///
/// `Http` sends un-cached text leaves to [`MlConfig::endpoint`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MlBackend {
    /// In-process Candle inference (the `ml` feature).
    #[default]
    Local,
    /// Remote HF-token-classification endpoint (the `ml-http` feature).
    Http,
}

impl MlBackend {
    /// Per-variant byte for the recognizer-identity fingerprint
    /// ([`crate::compute_ml_fp`]). Exhaustive on purpose — see
    /// [`Quantization::fp_tag`].
    pub(crate) fn fp_tag(self) -> u8 {
        match self {
            MlBackend::Local => 0,
            MlBackend::Http => 1,
        }
    }
}

/// MoE expert-weight storage precision selector for the ML backend.
///
/// Serde wire form is lowercase (`"none"`, `"q8_0"`, `"bf16"`, `"bf16_vnni"`).
/// The operational default (see [`MlConfig`]) is `Bf16` — the recall-neutral,
/// half-RAM CPU lever (inference-neutral vs F32; the win is memory, not speed);
/// `None` is the historical F32 path; `Q8_0` and `Bf16Vnni` are recall-risk
/// opt-ins (see [`MlConfig::quant`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Quantization {
    /// No quantization — dense F32 experts, bit-identical to historical F32
    /// output. The enum `#[default]` (type identity / F32 escape hatch); the
    /// operational default is `Bf16`.
    #[default]
    None,
    /// Q8_0 quantization of MoE expert projection weights. Recall-risk; gate
    /// before enabling.
    #[serde(rename = "q8_0")]
    Q8_0,
    /// bf16 MoE expert weights (recall-neutral, half resident RAM; CPU inference
    /// ~neutral vs F32, span-identical). Maps to presidio `Quant::Bf16`. The
    /// recommended default.
    Bf16,
    /// Native AVX512-BF16 `vdpbf16ps` expert matmul (recall-RISK — rounds
    /// activations; CPU-only, Zen4+; falls back to `Bf16` without avx512bf16).
    /// Maps to presidio `Quant::Bf16Vnni`. Gate before enabling.
    #[serde(rename = "bf16_vnni")]
    Bf16Vnni,
}

/// CPU activation-compute precision selector for the ML backend.
///
/// Serde wire form is lowercase (`"f32"`, `"f16"`). **Default is `F32`** — the
/// safe, recall-neutral value; `F16` is the recall-risk opt-in (see
/// [`MlConfig::compute_precision`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComputePrecision {
    /// Full F32 activations — default, bit-identical to historical output.
    #[default]
    F32,
    /// F16 activations on CPU. Recall-risk; gate before enabling.
    F16,
}

impl Quantization {
    /// Per-variant byte for the recognizer-identity fingerprint
    /// ([`crate::compute_ml_fp`]). The match is EXHAUSTIVE on purpose: adding a
    /// `Quantization` variant is a compile error here until it is given a DISTINCT
    /// tag, so a new quant mode can never silently share a fingerprint with an
    /// existing one — which would serve stale cross-precision detections from the
    /// detection cache (a dropped/altered span = recall regression). Values need
    /// not be stable across releases (the cache is in-memory per-process); only
    /// distinctness is mandatory.
    pub(crate) fn fp_tag(self) -> u8 {
        match self {
            Quantization::None => 0,
            Quantization::Q8_0 => 1,
            Quantization::Bf16 => 2,
            Quantization::Bf16Vnni => 3,
        }
    }
}

impl ComputePrecision {
    /// Per-variant byte for the recognizer-identity fingerprint
    /// ([`crate::compute_ml_fp`]). Exhaustive on purpose — see
    /// [`Quantization::fp_tag`].
    pub(crate) fn fp_tag(self) -> u8 {
        match self {
            ComputePrecision::F32 => 0,
            ComputePrecision::F16 => 1,
        }
    }
}

fn default_ml_model() -> String {
    AUTHORIZED_ML_MODELS[0].to_string()
}

/// Serde default for [`MlConfig::http_timeout_secs`].
fn default_ml_http_timeout_secs() -> u64 {
    30
}

/// The HuggingFace repo ids ZlauDeR is authorized to fetch + load — an allowlist,
/// NOT an open `--model`. A model checkpoint is an executable-grade artifact (a
/// loader/tokenizer + tensor deserialization surface), so "download any repo" is a
/// supply-chain / RCE vector. Pinning here means a model-supplied (`/zlauder:privacy
/// model download <repo>`, `model on --model <repo>`), prompt-injected, or simply
/// typo'd repo id can never pull an arbitrary checkpoint — every fetch/load path
/// funnels through [`is_authorized_model`] and is rejected unless it names an entry
/// below. The first entry is the default. Authorized quantizations are added here as
/// explicit, validated entries; the surface never becomes an open string.
pub const AUTHORIZED_ML_MODELS: &[&str] = &["openai/privacy-filter"];

/// Whether `repo` is on the [`AUTHORIZED_ML_MODELS`] allowlist. The single predicate
/// the ML loader and the `--download-model` pre-warm both gate on, so no override path
/// can fetch an unlisted checkpoint.
pub fn is_authorized_model(repo: &str) -> bool {
    AUTHORIZED_ML_MODELS.contains(&repo)
}

/// Serde default for [`MlConfig::quant`]: the operational default is `Bf16` (the
/// golden-gate-confirmed recall-neutral lever), NOT the enum `#[default]` (`None`,
/// the F32 type-identity). Without an explicit serde default fn, a config that has
/// an `[ml]` table but omits `quant` would deserialize to `None` (the enum default)
/// and silently stay on F32 — which is *every* config that turns ML on.
fn default_ml_quant() -> Quantization {
    Quantization::Bf16
}

/// Serde default for [`MlConfig::banded_attention`]: `true`. Banded attention is
/// the gate-proven default — zero dropped true-positives and score delta < 1e-3 on
/// the long-doc fixtures, ~48% faster on long inputs, no-op on short ones. A config
/// with an `[ml]` table that omits `banded_attention` deserializes to this, not
/// `bool`'s `false` (which would silently leave long-doc detection on the slow
/// dense path).
fn default_ml_banded() -> bool {
    true
}

impl Default for MlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            required: false,
            backend: MlBackend::Local,
            model: default_ml_model(),
            endpoint: None,
            auth_token_env: None,
            http_timeout_secs: default_ml_http_timeout_secs(),
            revision: None,
            min_score: None,
            prefer_gpu: false,
            compute_precision: ComputePrecision::F32,
            // Golden-gate-confirmed recall-neutral (zero dropped spans, no score
            // delta > 1e-3 on the widened corpus) and HALF the resident RAM for
            // expert weights. CPU inference time is ~neutral vs F32 — the safe
            // kernel upcasts each weight block to F32 for the matmul, so the win is
            // memory, not throughput. Use Quantization::None for historical F32.
            quant: Quantization::Bf16,
            // Banded attention default-on: gate-proven recall-neutral, ~48% faster
            // on long inputs, no-op on short. See `banded_attention` field docs.
            banded_attention: true,
        }
    }
}

impl MlConfig {
    /// Do the *model-affecting* params match `other` (ignoring `enabled`)? The
    /// proxy's reconcile uses this to decide whether a config change requires
    /// rebuilding the recognizer vs. a no-op.
    pub fn same_model_params(&self, other: &Self) -> bool {
        if self.backend != other.backend {
            return false;
        }
        let common = self.min_score == other.min_score;
        match self.backend {
            MlBackend::Local => {
                common
                    && self.model == other.model
                    && self.revision == other.revision
                    && self.prefer_gpu == other.prefer_gpu
                    && self.compute_precision == other.compute_precision
                    && self.quant == other.quant
                    && self.banded_attention == other.banded_attention
            }
            MlBackend::Http => {
                common
                    && self.endpoint == other.endpoint
                    && self.auth_token_env == other.auth_token_env
                    && self.http_timeout_secs == other.http_timeout_secs
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct EngineConfig {
    /// Master switch. When `false` the engine is a transparent passthrough on the
    /// mask (request) path — no detection, no tokens. Unmasking (response path)
    /// still runs, so tokens already in the transcript keep decoding. Toggled live
    /// via the proxy's control endpoint or persisted per scope.
    pub enabled: bool,
    pub profile: Profile,
    pub score_threshold: f32,
    pub enabled_categories: HashSet<Category>,
    pub default_operator: Operator,
    #[serde(default)]
    pub entity_operators: HashMap<String, Operator>,
    #[serde(default = "default_language")]
    pub language: String,
    /// Deprecated compatibility field. Detection errors are always fail-closed;
    /// config values of `false` are ignored at policy-install time.
    #[serde(default = "default_true")]
    pub fail_closed: bool,
    #[serde(default)]
    pub disabled_surfaces: HashSet<Surface>,
    /// Not deserialized directly (`regex::Regex` is not `Deserialize`); the proxy
    /// config loader builds this from raw strings and assigns it.
    #[serde(skip)]
    pub allow_list: AllowList,
    #[serde(default)]
    pub custom_replacements: Vec<CustomReplacement>,
    /// Optional ML recognizer (`openai/privacy-filter`, CPU). Off by default.
    #[serde(default)]
    pub ml: MlConfig,

    /// Display-time decoration for un-masked assistant text (see [`RevealMarker`]).
    /// On by default (printable `⟦`/`⟧` markers); a display/apply-time concern, so it is NOT
    /// part of `detection_fingerprint` (changing it does not invalidate the detection cache).
    #[serde(default)]
    pub reveal_marker: RevealMarker,

    // --- Detection cache (Component 1) ------------------------------------
    /// Max entries in the in-memory detection cache (LRU). `0` disables + clears
    /// it live. Default ~50k leaves; an empty detection list (the ~95% clean-leaf
    /// case) is a tiny value, so this bounds memory well below it in practice.
    #[serde(default = "default_cache_cap")]
    pub detection_cache_cap: usize,

    // --- Deferred Component-3 / persistence scaffolding (INERT) ------------
    // The fields below are parsed and documented but currently NON-FUNCTIONAL.
    // They reserve the config surface so enabling the behavior later is not a
    // breaking schema change. See `glittery-bubbling-locket.md` Component 3.
    /// (INERT) Persist the detection cache to disk across proxy restarts.
    #[serde(default)]
    pub detection_cache_persist: bool,
    /// (INERT) Path for the persisted detection cache (`None` ⇒ a default under the
    /// proxy state dir, when persistence is built).
    #[serde(default)]
    pub detection_cache_path: Option<String>,
    /// (INERT) On the ML `Ready` transition, redact ("burn") values exposed in
    /// plaintext during the pre-ML window instead of re-tokenizing them.
    #[serde(default)]
    pub redact_exposed_on_ml: bool,
    /// (INERT) Leaf- vs value-scoped burn (see [`ExposureRedactionScope`]).
    #[serde(default)]
    pub exposure_redaction_scope: ExposureRedactionScope,
    /// (INERT) Salt scope (see [`SaltScope`]).
    #[serde(default)]
    pub salt_scope: SaltScope,
    /// (INERT) Drop `thinking` blocks following a retroactive redaction (the model
    /// saw the value un-redacted while producing that opaque thinking).
    #[serde(default)]
    pub drop_contaminated_thinking: bool,
}

/// Shadow of [`EngineConfig`] used ONLY for deserialization, so we can tell an
/// *absent* `score_threshold`/`enabled_categories`/`default_operator` apart from
/// one explicitly set to a default-looking value. This is what makes a load-bearing
/// `profile = "strict"` actually seed that profile's threshold/categories/operator:
/// a field left out of the config is `None` here and gets filled from
/// [`Profile::for_profile`]; an explicit field stays `Some` and OVERRIDES the seed.
///
/// `profile` itself keeps its serde default (Balanced) — the seed is a no-op when
/// no profile is set, because Balanced's defaults equal the historical serde
/// defaults, so a config with no `profile` is byte-for-byte unchanged.
// NOTE: deliberately NOT `deny_unknown_fields` — `WireConfig` deserializes via
// `#[serde(flatten)] engine: EngineConfig` alongside a sibling `allow_list` key,
// and flatten + deny_unknown_fields is unsupported by serde (the flattened struct
// would reject the sibling). Unknown keys are tolerated, matching prior behavior.
#[derive(Deserialize)]
struct EngineConfigShadow {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    profile: Profile,
    // The three profile-derived fields: absent ⇒ `None` ⇒ seed from `profile`.
    #[serde(default)]
    score_threshold: Option<f32>,
    #[serde(default)]
    enabled_categories: Option<HashSet<Category>>,
    #[serde(default)]
    default_operator: Option<Operator>,
    #[serde(default)]
    entity_operators: HashMap<String, Operator>,
    #[serde(default = "default_language")]
    language: String,
    #[serde(default = "default_true")]
    fail_closed: bool,
    #[serde(default)]
    disabled_surfaces: HashSet<Surface>,
    #[serde(default)]
    custom_replacements: Vec<CustomReplacement>,
    #[serde(default)]
    ml: MlConfig,
    #[serde(default)]
    reveal_marker: RevealMarker,
    #[serde(default = "default_cache_cap")]
    detection_cache_cap: usize,
    #[serde(default)]
    detection_cache_persist: bool,
    #[serde(default)]
    detection_cache_path: Option<String>,
    #[serde(default)]
    redact_exposed_on_ml: bool,
    #[serde(default)]
    exposure_redaction_scope: ExposureRedactionScope,
    #[serde(default)]
    salt_scope: SaltScope,
    #[serde(default)]
    drop_contaminated_thinking: bool,
}

impl<'de> Deserialize<'de> for EngineConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = EngineConfigShadow::deserialize(deserializer)?;
        // Seed any absent profile-derived field from the profile; an explicit value
        // (Some) overrides. With the default (Balanced) profile and all three fields
        // absent, this reproduces the historical serde defaults exactly.
        let score_threshold = s
            .score_threshold
            .unwrap_or_else(|| s.profile.default_threshold());
        let enabled_categories = s
            .enabled_categories
            .unwrap_or_else(|| s.profile.default_categories());
        let default_operator = s
            .default_operator
            .unwrap_or_else(|| s.profile.default_operator());
        Ok(EngineConfig {
            enabled: s.enabled,
            profile: s.profile,
            score_threshold,
            enabled_categories,
            default_operator,
            entity_operators: s.entity_operators,
            language: s.language,
            fail_closed: s.fail_closed,
            disabled_surfaces: s.disabled_surfaces,
            allow_list: AllowList::with_common_words(),
            custom_replacements: s.custom_replacements,
            ml: s.ml,
            reveal_marker: s.reveal_marker,
            detection_cache_cap: s.detection_cache_cap,
            detection_cache_persist: s.detection_cache_persist,
            detection_cache_path: s.detection_cache_path,
            redact_exposed_on_ml: s.redact_exposed_on_ml,
            exposure_redaction_scope: s.exposure_redaction_scope,
            salt_scope: s.salt_scope,
            drop_contaminated_thinking: s.drop_contaminated_thinking,
        })
    }
}

fn default_true() -> bool {
    true
}
fn default_language() -> String {
    "en".to_string()
}
fn default_cache_cap() -> usize {
    50_000
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            profile: Profile::Balanced,
            score_threshold: 0.5,
            enabled_categories: Profile::Balanced.default_categories(),
            default_operator: Operator::Token,
            entity_operators: HashMap::new(),
            language: "en".to_string(),
            fail_closed: true,
            disabled_surfaces: HashSet::new(),
            allow_list: AllowList::with_common_words(),
            custom_replacements: Vec::new(),
            ml: MlConfig::default(),
            reveal_marker: RevealMarker::default(),
            detection_cache_cap: default_cache_cap(),
            detection_cache_persist: false,
            detection_cache_path: None,
            redact_exposed_on_ml: false,
            exposure_redaction_scope: ExposureRedactionScope::default(),
            salt_scope: SaltScope::default(),
            drop_contaminated_thinking: false,
        }
    }
}

impl EngineConfig {
    /// A config seeded from a profile's threshold/categories/operator.
    pub fn for_profile(profile: Profile) -> Self {
        Self {
            profile,
            score_threshold: profile.default_threshold(),
            enabled_categories: profile.default_categories(),
            default_operator: profile.default_operator(),
            ..Self::default()
        }
    }

    /// Validate `entity_operators` keys against the FULL `presidio_core::EntityType`
    /// canonical Display set — NOT category membership. Returns the list of unknown
    /// / alias / typo'd keys so a caller can reject or warn.
    ///
    /// Why the full Display set, not [`Category::canonical_entity_types`]: a key is a
    /// valid, functional `entity_operators` lever as long as it names a real canonical
    /// `EntityType` Display string, even if that type is deliberately in NO category.
    /// Two such types are documented opt-in levers driven exactly through this map:
    /// `DATE_TIME` (re-enabled per deployment via an explicit `entity_operators` entry
    /// — proven by `date_time_unmapped_by_default_but_opt_in` in lib.rs) and `DOMAIN`
    /// (re-enable per deployment if wanted). Validating against category membership
    /// wrongly flagged both as unknown, 400-ing valid configs.
    ///
    /// Detection of typos vs aliases: resolve each key with
    /// [`presidio_core::EntityType::from_str`] (infallible — an unknown label becomes
    /// `Custom`):
    ///   - `Custom(_)`            ⇒ no canonical match at all ⇒ typo (e.g. "EMIAL"), flag.
    ///   - `canonical_name() != key` ⇒ a known label but an ALIAS spelling (e.g.
    ///     "IBAN" → "IBAN_CODE"); the lookup tables match on the canonical Display, so
    ///     the alias key is a silent no-op ⇒ flag.
    ///   - `canonical_name() == key` ⇒ a real canonical Display name (incl.
    ///     DATE_TIME / DOMAIN) ⇒ accept.
    ///
    /// WHY only `entity_operators` keys: an `entity_operators` key is a SILENT NO-OP
    /// if it is not a canonical Display name — `entity_enabled`/`operator_for` look it
    /// up by exact Display, so a typo or alias never matches a real detection and masks
    /// nothing. By contrast a `custom_replacement.entity_type` is NEVER a no-op: a
    /// custom rule is its own detector (it emits detections directly, bypassing the
    /// category gate — see `detect::run`), so it legitimately invents a fresh type
    /// name. A key that names one of those custom types is therefore ALSO valid (you
    /// can set an operator for your own custom type), so we treat a key as known if it
    /// is a canonical Display name OR names a declared `custom_replacement.entity_type`.
    ///
    /// THIRD known-key source — zlauder-local Custom entities in a CATEGORY. The four
    /// `Custom` labels emitted by the hard-context regex recognizers + the ML
    /// `private_date` remap (`DATE_OF_BIRTH`, `CREDIT_CARD_EXPIRATION`, `CVV`,
    /// `PRIVATE_DATE`) are NOT canonical `EntityType` Display names (they round-trip as
    /// `Custom(_)`), but they ARE wired into a real category via
    /// [`Category::entity_types`]. So `entity_operators.CVV = {kind="redact"}` is a
    /// FUNCTIONAL lever (it both gates and sets the operator) and must NOT be flagged
    /// as a typo. We accept any key that is a member of
    /// [`Category::canonical_entity_types`] before the canonical-Display check.
    pub fn unknown_entity_types(&self) -> Vec<String> {
        use std::str::FromStr;
        let custom: HashSet<&str> = self
            .custom_replacements
            .iter()
            .map(|c| c.entity_type.as_str())
            .collect();
        let category_members = Category::canonical_entity_types();
        self.entity_operators
            .keys()
            .filter(|k| {
                if custom.contains(k.as_str()) {
                    return false;
                }
                // A zlauder-local Custom entity that lives in a category (e.g. CVV,
                // DATE_OF_BIRTH) is a real, functional gate/operator lever — accept it
                // even though it round-trips as `Custom(_)`.
                if category_members.contains(k.as_str()) {
                    return false;
                }
                // Infallible: unknown labels become `Custom` verbatim.
                let et = presidio_core::EntityType::from_str(k).expect("from_str is infallible");
                match et {
                    // No canonical match at all ⇒ typo (e.g. "EMIAL"). (Its
                    // `canonical_name()` echoes the label, so we MUST match the
                    // variant rather than compare strings.) Flag.
                    presidio_core::EntityType::Custom(_) => true,
                    // A known label: accept only the exact canonical Display spelling;
                    // an ALIAS spelling (e.g. "IBAN" → "IBAN_CODE") differs ⇒ flag.
                    other => other.canonical_name() != k.as_str(),
                }
            })
            .cloned()
            .collect()
    }

    /// Is `entity_type` subject to masking — either in an enabled category or with
    /// an explicit per-type operator override?
    pub fn entity_enabled(&self, entity_type: &str) -> bool {
        if self.entity_operators.contains_key(entity_type) {
            return true;
        }
        self.enabled_categories
            .iter()
            .any(|c| c.entity_types().contains(&entity_type))
    }

    /// Resolve the operator for an entity type. Precedence (highest first):
    /// 1. an explicit per-type `entity_operators` override (user/project/local config);
    /// 2. a built-in per-type irreversible default ([`ENTITY_CVV`] → [`Operator::Redact`];
    ///    `CREDIT_CARD` → [`Operator::Mask`] keeping the last 4);
    /// 3. the profile/config `default_operator`.
    ///
    /// CVV is PCI Sensitive Authentication Data ("never store"). The reversible
    /// `Token` default would retain CVV in the in-memory `SessionStore` and surface
    /// its plaintext in the local monitor ledger for the session lifetime, so CVV
    /// masks irreversibly (`Redact`) OUT OF THE BOX. This is the LOWEST-precedence
    /// default, not a hard lock — an explicit `entity_operators.CVV` entry still wins
    /// (zlauder's everything-configurable contract), with a documented PCI-SAD warning.
    pub fn operator_for(&self, entity_type: &str) -> Operator {
        if let Some(op) = self.entity_operators.get(entity_type) {
            return *op;
        }
        if entity_type == ENTITY_CVV {
            return Operator::Redact;
        }
        // CREDIT_CARD masks irreversibly OUT OF THE BOX (last-4 preserved). The reversible
        // `Token` default would round-trip the full PAN through the SessionStore and the local
        // monitor ledger; `Mask` is lossy, so the full number never persists. Same lowest-
        // precedence built-in shape as CVV — an explicit `entity_operators.CREDIT_CARD` wins.
        if entity_type == "CREDIT_CARD" {
            return Operator::Mask {
                char: '*',
                from_end: 4,
            };
        }
        self.default_operator
    }

    pub fn surface_enabled(&self, surface: Surface) -> bool {
        !self.disabled_surfaces.contains(&surface)
    }

    /// Fingerprint of every DETECTION-affecting input (folded into the cache key;
    /// audit #3/#6). A change here yields a fresh key space, so stale entries become
    /// unreachable with nothing to hand-invalidate.
    ///
    /// INCLUDES: the detector-version constant (audit #1 — bundled regex/custom
    /// recognizer code identity), score_threshold, language, enabled_categories, the
    /// entity_operators KEY SET (key *presence* gates detection via `entity_enabled`),
    /// custom_replacements (the patterns ARE the detection), and the allow_list.
    ///
    /// EXCLUDES (so these apply WITHOUT a cache miss): operator VALUES and
    /// `default_operator` (resolved at apply time), the `enabled` master switch and
    /// `disabled_surfaces` (their effect is the un-cached early-return passthrough),
    /// `fail_closed` (deprecated/no-op error policy), `profile` (only a seed for the
    /// derived fields), `ml` (covered by the separate `ml_fp`), `reveal_marker`
    /// (a display/apply-time decoration; the marker strip happens before this
    /// fingerprint is consulted, so the cache key already reflects its effect), and
    /// the cache / Component-3 scaffolding fields.
    ///
    /// All maps/sets are serialized in a canonical (sorted) order so semantically
    /// identical configs hash identically (audit #6). `custom_replacements` is hashed
    /// in Vec order because order can decide same-priority overlap ties.
    pub fn detection_fingerprint(&self) -> u64 {
        let mut h = blake3::Hasher::new();
        h.update(b"zlauder-policy-fp-v1");
        h.update(&crate::detect::DETECTOR_VERSION.to_le_bytes());
        h.update(&self.score_threshold.to_bits().to_le_bytes());
        h.update(self.language.as_bytes());
        h.update(&[0xff]);

        // enabled_categories — sorted by discriminant for canonical order.
        let mut cats: Vec<u8> = self.enabled_categories.iter().map(|c| *c as u8).collect();
        cats.sort_unstable();
        h.update(&cats);
        h.update(&[0xff]);

        // entity_operators KEYS only (values are apply-time) — sorted.
        let mut keys: Vec<&str> = self.entity_operators.keys().map(String::as_str).collect();
        keys.sort_unstable();
        for k in keys {
            h.update(k.as_bytes());
            h.update(&[0]);
        }
        h.update(&[0xff]);

        // custom_replacements — Vec order preserved (same-priority order matters).
        for c in &self.custom_replacements {
            fp_custom(&mut h, c);
        }
        h.update(&[0xff]);

        fp_allow_list(&mut h, &self.allow_list);

        let digest = h.finalize();
        u64::from_le_bytes(digest.as_bytes()[..8].try_into().expect("32-byte digest"))
    }
}

/// Canonical fingerprint contribution of one custom replacement rule.
fn fp_custom(h: &mut blake3::Hasher, c: &CustomReplacement) {
    h.update(c.pattern.as_bytes());
    h.update(&[0]);
    h.update(c.entity_type.as_bytes());
    h.update(&[0]);
    h.update(&[
        c.is_regex as u8,
        c.case_sensitive as u8,
        c.literal_token as u8,
    ]);
    h.update(&c.priority.to_le_bytes());
    match &c.token {
        Some(t) => {
            h.update(&[1]);
            h.update(t.as_bytes());
        }
        None => {
            h.update(&[0]);
        }
    };
    h.update(&[0]);
    match &c.apply_to_surfaces {
        None => {
            h.update(&[0]);
        }
        Some(set) => {
            h.update(&[1]);
            let mut surfs: Vec<u8> = set.iter().map(|s| *s as u8).collect();
            surfs.sort_unstable();
            h.update(&surfs);
        }
    };
    h.update(&[0xfe]);
}

/// Canonical fingerprint contribution of the allow-list (sets sorted; patterns by
/// source string, in declared order).
fn fp_allow_list(h: &mut blake3::Hasher, al: &AllowList) {
    let mut exact: Vec<&str> = al.exact.iter().map(String::as_str).collect();
    exact.sort_unstable();
    for e in exact {
        h.update(e.as_bytes());
        h.update(&[0]);
    }
    h.update(&[0xfe]);
    let mut ci: Vec<&str> = al.exact_ci.iter().map(String::as_str).collect();
    ci.sort_unstable();
    for e in ci {
        h.update(e.as_bytes());
        h.update(&[0]);
    }
    h.update(&[0xfe]);
    for p in &al.patterns {
        h.update(p.as_str().as_bytes());
        h.update(&[0]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_toml(s: &str) -> EngineConfig {
        toml::from_str(s).expect("config should parse")
    }

    fn from_json(s: &str) -> EngineConfig {
        serde_json::from_str(s).expect("config should parse")
    }

    #[test]
    fn authorized_model_allowlist_admits_default_only() {
        // The compiled default is on the allowlist; arbitrary repos are not. This is
        // the supply-chain pin enforced at the ML fetch/load chokepoint.
        assert!(is_authorized_model(&default_ml_model()));
        assert!(is_authorized_model("openai/privacy-filter"));
        assert!(!is_authorized_model("attacker/evil-weights"));
        assert!(!is_authorized_model("openai/privacy-filter-but-evil"));
        assert!(!is_authorized_model(""));
        // The default is, by construction, the first authorized entry.
        assert_eq!(default_ml_model(), AUTHORIZED_ML_MODELS[0]);
    }

    #[test]
    fn same_model_params_uses_backend_specific_identity() {
        let lax = MlConfig {
            enabled: true,
            required: false,
            ..Default::default()
        };
        let strict = MlConfig {
            required: true,
            ..lax.clone()
        };
        assert!(
            lax.same_model_params(&strict),
            "a `required` flip must NOT count as a different recognizer"
        );

        let other_backend = MlConfig {
            backend: MlBackend::Http,
            ..lax.clone()
        };
        assert!(
            !lax.same_model_params(&other_backend),
            "a backend change IS a different recognizer"
        );

        let http = MlConfig {
            backend: MlBackend::Http,
            endpoint: Some("http://127.0.0.1:3007/detect".into()),
            ..lax.clone()
        };
        let http_local_knob_changed = MlConfig {
            model: "ignored/for-http".into(),
            revision: Some("ignored".into()),
            prefer_gpu: true,
            compute_precision: ComputePrecision::F16,
            quant: Quantization::Q8_0,
            banded_attention: false,
            ..http.clone()
        };
        assert!(
            http.same_model_params(&http_local_knob_changed),
            "http identity should ignore local-only Candle knobs"
        );

        let http_other_endpoint = MlConfig {
            endpoint: Some("http://127.0.0.1:3008/detect".into()),
            ..http
        };
        assert!(
            !http_local_knob_changed.same_model_params(&http_other_endpoint),
            "http endpoint changes require a new recognizer"
        );
    }

    #[test]
    fn ml_present_without_quant_defaults_to_bf16() {
        // A deployed `[ml]` block that ENABLES ml but omits `quant` must resolve to
        // the operational default Bf16 — NOT the enum `#[default]` None. Otherwise
        // the bf16 default is silently a no-op for every config that turns ML on
        // (the case `[ml]` present + `quant` absent), which is the only case that
        // matters since a fully-absent `[ml]` table means ML is off.
        let cfg = from_toml("[ml]\nenabled = true\nmodel = \"openai/privacy-filter\"\n");
        assert_eq!(
            cfg.ml.quant,
            Quantization::Bf16,
            "omitted quant under a present [ml] must default to Bf16"
        );
        // Explicit selectors are still honored, and the new wire forms round-trip.
        assert_eq!(
            from_toml("[ml]\nquant = \"none\"\n").ml.quant,
            Quantization::None
        );
        assert_eq!(
            from_toml("[ml]\nquant = \"q8_0\"\n").ml.quant,
            Quantization::Q8_0
        );
        assert_eq!(
            from_toml("[ml]\nquant = \"bf16\"\n").ml.quant,
            Quantization::Bf16
        );
        assert_eq!(
            from_toml("[ml]\nquant = \"bf16_vnni\"\n").ml.quant,
            Quantization::Bf16Vnni
        );
    }

    #[test]
    fn ml_present_without_banded_defaults_to_true() {
        // Same serde-default footgun as `quant`: a present `[ml]` block that omits
        // `banded_attention` must resolve to the operational default `true` (the
        // `default_ml_banded` fn), NOT `bool`'s `false`. Otherwise the banded
        // default is silently a no-op for every config that turns ML on, leaving
        // long-doc detection on the slow dense `T x T` path.
        let cfg = from_toml("[ml]\nenabled = true\nmodel = \"openai/privacy-filter\"\n");
        assert!(
            cfg.ml.banded_attention,
            "omitted banded_attention under a present [ml] must default to true"
        );
        // Explicit selectors are still honored.
        assert!(!from_toml("[ml]\nbanded_attention = false\n").ml.banded_attention);
        assert!(from_toml("[ml]\nbanded_attention = true\n").ml.banded_attention);
    }

    // --- profile lineup -----------------------------------------------------

    #[test]
    fn profile_lineup_values() {
        assert_eq!(Profile::Strict.default_threshold(), 0.4);
        assert_eq!(Profile::Balanced.default_threshold(), 0.5);
        assert_eq!(Profile::Minimal.default_threshold(), 0.6);
        assert_eq!(Profile::SecretsOnly.default_threshold(), 0.6);
        // Strict masks reversibly (Token), NOT an irreversible Redact.
        assert_eq!(Profile::Strict.default_operator(), Operator::Token);
        assert_eq!(
            Profile::SecretsOnly.default_categories(),
            [Category::Secrets].into_iter().collect()
        );
    }

    #[test]
    fn secrets_only_serializes_to_snake_case() {
        let v = serde_json::to_value(Profile::SecretsOnly).unwrap();
        assert_eq!(v, serde_json::json!("secrets_only"));
    }

    #[test]
    fn development_safe_alias_still_parses() {
        // Back-compat: an OLD config naming the renamed profile keeps loading and
        // resolves to SecretsOnly (with that profile's seeded fields).
        let cfg = from_toml("profile = \"development_safe\"\n");
        assert_eq!(cfg.profile, Profile::SecretsOnly);
        assert_eq!(cfg.score_threshold, 0.6);
        assert_eq!(
            cfg.enabled_categories,
            [Category::Secrets].into_iter().collect()
        );
        // The new spelling parses too.
        assert_eq!(
            from_toml("profile = \"secrets_only\"\n").profile,
            Profile::SecretsOnly
        );
    }

    // --- load-bearing profile= seeding (item 2b) ----------------------------

    #[test]
    fn profile_only_seeds_threshold_categories_operator() {
        // A config that sets ONLY `profile` must take that profile's threshold,
        // categories, and operator — NOT the serde/Balanced defaults.
        let cfg = from_toml("profile = \"strict\"\n");
        assert_eq!(cfg.profile, Profile::Strict);
        assert_eq!(cfg.score_threshold, 0.4, "strict threshold seeded");
        assert_eq!(
            cfg.enabled_categories,
            Profile::Strict.default_categories(),
            "strict categories seeded (incl. Personal)"
        );
        assert!(cfg.enabled_categories.contains(&Category::Personal));
        assert_eq!(cfg.default_operator, Operator::Token);
    }

    #[test]
    fn profile_only_minimal_seeds() {
        let cfg = from_json(r#"{"profile":"minimal"}"#);
        assert_eq!(cfg.score_threshold, 0.6);
        assert_eq!(
            cfg.enabled_categories,
            [Category::Secrets, Category::Financial]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn explicit_field_overrides_profile_seed() {
        // An explicit threshold beats the profile's seed; categories still seed.
        let cfg = from_toml("profile = \"strict\"\nscore_threshold = 0.9\n");
        assert_eq!(cfg.profile, Profile::Strict);
        assert_eq!(cfg.score_threshold, 0.9, "explicit threshold wins");
        assert_eq!(
            cfg.enabled_categories,
            Profile::Strict.default_categories(),
            "categories still seeded from profile"
        );

        // Explicit categories beat the seed; threshold still seeds.
        let cfg = from_toml("profile = \"strict\"\nenabled_categories = [\"secrets\"]\n");
        assert_eq!(cfg.score_threshold, 0.4, "threshold still seeded");
        assert_eq!(
            cfg.enabled_categories,
            [Category::Secrets].into_iter().collect(),
            "explicit categories win"
        );

        // Explicit operator beats the seed.
        let cfg = from_toml("profile = \"balanced\"\ndefault_operator = { kind = \"redact\" }\n");
        assert_eq!(cfg.default_operator, Operator::Redact);
    }

    #[test]
    fn no_profile_yields_historical_defaults() {
        // With NO profile and NO explicit fields, the config is byte-for-byte the
        // historical default (Balanced 0.5, Balanced categories, Token) — the seed
        // is a no-op because the default profile (Balanced) equals those defaults.
        let cfg = from_toml("");
        let def = EngineConfig::default();
        assert_eq!(cfg.profile, Profile::Balanced);
        assert_eq!(cfg.score_threshold, def.score_threshold);
        assert_eq!(cfg.enabled_categories, def.enabled_categories);
        assert_eq!(cfg.default_operator, def.default_operator);
        assert_eq!(cfg.score_threshold, 0.5);
    }

    #[test]
    fn explicit_fields_without_profile_are_honored() {
        // No profile, but explicit fields → exactly those values (default profile).
        let cfg = from_toml("score_threshold = 0.2\nenabled_categories = [\"contact\"]\n");
        assert_eq!(cfg.profile, Profile::Balanced);
        assert_eq!(cfg.score_threshold, 0.2);
        assert_eq!(
            cfg.enabled_categories,
            [Category::Contact].into_iter().collect()
        );
    }

    #[test]
    fn each_layer_independently_seeds_or_overrides() {
        // Exhaustive small matrix over the four (profile?, threshold?) combos.
        // (none,none) → balanced 0.5
        assert_eq!(from_toml("").score_threshold, 0.5);
        // (profile,none) → seed
        assert_eq!(from_toml("profile=\"minimal\"").score_threshold, 0.6);
        // (none,threshold) → explicit, balanced profile
        assert_eq!(from_toml("score_threshold=0.33").score_threshold, 0.33);
        // (profile,threshold) → explicit wins
        assert_eq!(
            from_toml("profile=\"minimal\"\nscore_threshold=0.11").score_threshold,
            0.11
        );
    }

    // --- entity-type validation (item 2c) -----------------------------------

    #[test]
    fn unknown_entity_types_flags_typos_and_aliases() {
        let mut cfg = EngineConfig::default();
        // Canonical key → fine.
        cfg.entity_operators
            .insert("EMAIL_ADDRESS".into(), Operator::Redact);
        // Alias (IBAN is the parse alias for IBAN_CODE) → flagged.
        cfg.entity_operators.insert("IBAN".into(), Operator::Redact);
        // Typo → flagged.
        cfg.entity_operators
            .insert("EMIAL".into(), Operator::Redact);
        let unknown = cfg.unknown_entity_types();
        assert!(unknown.contains(&"IBAN".to_string()));
        assert!(unknown.contains(&"EMIAL".to_string()));
        assert!(!unknown.contains(&"EMAIL_ADDRESS".to_string()));
    }

    #[test]
    fn entity_operators_opt_in_levers_not_flagged() {
        // DATE_TIME and DOMAIN are real canonical `EntityType` Display names that are
        // DELIBERATELY in NO category — they are the documented opt-in levers driven
        // through `entity_operators`. They must NOT be flagged as unknown even though
        // they appear in no `Category::entity_types()` list. (Validating against
        // category membership instead of the full Display set was the bug.)
        let mut cfg = EngineConfig::default();
        cfg.entity_operators
            .insert("DATE_TIME".into(), Operator::Redact);
        cfg.entity_operators
            .insert("DOMAIN".into(), Operator::Redact);
        assert!(
            cfg.unknown_entity_types().is_empty(),
            "DATE_TIME/DOMAIN are valid opt-in entity_operators keys"
        );

        // Aliases and typos still get flagged alongside them.
        cfg.entity_operators.insert("IBAN".into(), Operator::Redact); // alias of IBAN_CODE
        cfg.entity_operators
            .insert("EMIAL".into(), Operator::Redact); // typo
        let unknown = cfg.unknown_entity_types();
        assert!(unknown.contains(&"IBAN".to_string()));
        assert!(unknown.contains(&"EMIAL".to_string()));
        assert!(!unknown.contains(&"DATE_TIME".to_string()));
        assert!(!unknown.contains(&"DOMAIN".to_string()));
    }

    #[test]
    fn custom_replacement_type_is_never_flagged() {
        let mut cfg = EngineConfig::default();
        cfg.custom_replacements.push(CustomReplacement {
            pattern: "ACME-1".into(),
            entity_type: "PROJECT_CODE".into(),
            is_regex: false,
            case_sensitive: true,
            priority: 0,
            literal_token: false,
            token: None,
            apply_to_surfaces: None,
        });
        // A custom rule is its own detector (bypasses the category gate), so its
        // invented entity_type is NEVER a no-op and is not flagged — even with no
        // matching entity_operators entry. This is the `CUSTOM_KEYWORD` UI-mask case.
        assert!(cfg.unknown_entity_types().is_empty());

        // An entity_operators key that NAMES that custom type is also known (you can
        // set the operator for your own custom type).
        cfg.entity_operators
            .insert("PROJECT_CODE".into(), Operator::Token);
        assert!(cfg.unknown_entity_types().is_empty());

        // But an operator key that is neither canonical NOR a custom type → flagged.
        cfg.entity_operators.insert("TYPO".into(), Operator::Token);
        assert_eq!(cfg.unknown_entity_types(), vec!["TYPO".to_string()]);
    }

    #[test]
    fn canonical_entity_types_covers_all_categories() {
        let canon = Category::canonical_entity_types();
        for c in Category::ALL {
            for et in c.entity_types() {
                assert!(canon.contains(et), "{et} missing from canonical set");
            }
        }
    }

    // --- C3/C4/C8: zlauder-local Custom entity contract ---------------------

    #[test]
    fn custom_entity_consts_match_expected_strings() {
        // The literal contract later stages key on. A rename here is intentional and
        // must be reflected everywhere the consts are referenced (compile-wide).
        assert_eq!(ENTITY_DATE_OF_BIRTH, "DATE_OF_BIRTH");
        assert_eq!(ENTITY_CREDIT_CARD_EXPIRATION, "CREDIT_CARD_EXPIRATION");
        assert_eq!(ENTITY_EXPIRATION_DATE, "EXPIRATION_DATE");
        assert_eq!(ENTITY_CVV, "CVV");
        assert_eq!(ENTITY_PRIVATE_DATE, "PRIVATE_DATE");
        assert_eq!(ENTITY_URL_CREDENTIAL, "URL_CREDENTIAL");
    }

    // URL_CREDENTIAL's gate invariant: it lives in the always-on Secrets category, so an
    // in-URL credential stays masked even when Network (URL/IP/MAC) is OFF — the whole
    // point of the recognizer. Locked here next to the other custom-entity gate strings.
    #[test]
    fn url_credential_gates_on_under_balanced_with_network_off() {
        assert!(
            Category::Secrets
                .entity_types()
                .contains(&ENTITY_URL_CREDENTIAL),
            "URL_CREDENTIAL must be a Secrets-category member"
        );
        assert!(Category::canonical_entity_types().contains(ENTITY_URL_CREDENTIAL));
        let balanced = EngineConfig::default();
        assert!(
            !balanced.enabled_categories.contains(&Category::Network),
            "Balanced must NOT enable Network (precondition for this test)"
        );
        assert!(
            balanced.entity_enabled(ENTITY_URL_CREDENTIAL),
            "URL_CREDENTIAL must gate on under Balanced despite Network being off"
        );
        // And it is a valid per-entity operator key (not flagged as an unknown typo).
        let cfg = EngineConfig {
            entity_operators: [(ENTITY_URL_CREDENTIAL.to_string(), Operator::Redact)]
                .into_iter()
                .collect(),
            ..EngineConfig::default()
        };
        assert!(cfg.unknown_entity_types().is_empty());
    }

    #[test]
    fn expiration_date_neutral_sibling_in_financial_and_identity() {
        // FIX 1a: the neutral `EXPIRATION_DATE` label (weak-evidence sibling of
        // `CREDIT_CARD_EXPIRATION`) parses and lives in BOTH Financial AND Identity —
        // its trigger case spans financial cards (gift/credit) AND identity docs
        // (travel visas). `entity_enabled` ORs across enabled categories, so dual
        // membership means it masks when EITHER category is on.
        assert!(Category::Financial
            .entity_types()
            .contains(&ENTITY_EXPIRATION_DATE));
        assert!(Category::Identity
            .entity_types()
            .contains(&ENTITY_EXPIRATION_DATE));
        // The strong sibling stays Financial-only.
        assert!(Category::Financial
            .entity_types()
            .contains(&ENTITY_CREDIT_CARD_EXPIRATION));
        // Round-trips through the canonical (deduped) set — dual membership is safe
        // because the set dedups — so it is a valid entity_operators key, not a typo.
        assert!(Category::canonical_entity_types().contains(ENTITY_EXPIRATION_DATE));

        // Enabled under Balanced (Financial + Identity both on).
        let balanced = EngineConfig::default();
        assert!(
            balanced.entity_enabled(ENTITY_EXPIRATION_DATE),
            "EXPIRATION_DATE enabled under Balanced"
        );
        // Enabled under a Financial-ONLY profile (Identity off) — proves OR semantics.
        let financial_only = EngineConfig {
            enabled_categories: [Category::Financial].into_iter().collect(),
            ..EngineConfig::default()
        };
        assert!(
            financial_only.entity_enabled(ENTITY_EXPIRATION_DATE),
            "EXPIRATION_DATE enabled with ONLY Financial on"
        );
        // Enabled under an Identity-ONLY profile (Financial off) — proves OR semantics.
        let identity_only = EngineConfig {
            enabled_categories: [Category::Identity].into_iter().collect(),
            ..EngineConfig::default()
        };
        assert!(
            identity_only.entity_enabled(ENTITY_EXPIRATION_DATE),
            "EXPIRATION_DATE enabled with ONLY Identity on"
        );
        // Gated off when NEITHER category is on (secrets_only → Secrets only).
        let secrets = EngineConfig::for_profile(Profile::SecretsOnly);
        assert!(!secrets.entity_enabled(ENTITY_EXPIRATION_DATE));
    }

    #[test]
    fn custom_entities_are_in_their_categories() {
        // The four Custom labels must be category members on the EXACT string the
        // recognizers emit — a desync silently no-ops the category gate.
        assert!(Category::Identity
            .entity_types()
            .contains(&ENTITY_DATE_OF_BIRTH));
        assert!(Category::Identity
            .entity_types()
            .contains(&ENTITY_PRIVATE_DATE));
        assert!(Category::Financial
            .entity_types()
            .contains(&ENTITY_CREDIT_CARD_EXPIRATION));
        assert!(Category::Financial.entity_types().contains(&ENTITY_CVV));

        // And they round-trip through the canonical (deduped) set.
        let canon = Category::canonical_entity_types();
        for et in [
            ENTITY_DATE_OF_BIRTH,
            ENTITY_CREDIT_CARD_EXPIRATION,
            ENTITY_CVV,
            ENTITY_PRIVATE_DATE,
        ] {
            assert!(canon.contains(et), "{et} missing from canonical set");
        }
    }

    #[test]
    fn custom_entities_category_enabled_under_balanced() {
        // Balanced enables Secrets, Financial, Identity, Contact. All four Custom
        // entities are in Financial/Identity → enabled with NO per-type override.
        let cfg = EngineConfig::default(); // Balanced
        assert!(cfg.entity_enabled(ENTITY_DATE_OF_BIRTH), "DOB ∈ Identity");
        assert!(
            cfg.entity_enabled(ENTITY_CREDIT_CARD_EXPIRATION),
            "card expiry ∈ Financial"
        );
        assert!(cfg.entity_enabled(ENTITY_CVV), "CVV ∈ Financial");
        assert!(
            cfg.entity_enabled(ENTITY_PRIVATE_DATE),
            "PRIVATE_DATE ∈ Identity"
        );
    }

    #[test]
    fn custom_entities_disabled_under_secrets_only() {
        // secrets_only enables ONLY Secrets, so Financial/Identity Custom entities are
        // gated off (no per-type override) — the category gate is the lever.
        let cfg = EngineConfig::for_profile(Profile::SecretsOnly);
        assert!(!cfg.entity_enabled(ENTITY_DATE_OF_BIRTH));
        assert!(!cfg.entity_enabled(ENTITY_CREDIT_CARD_EXPIRATION));
        assert!(!cfg.entity_enabled(ENTITY_CVV));
        assert!(!cfg.entity_enabled(ENTITY_PRIVATE_DATE));
    }

    #[test]
    fn unknown_entity_types_accepts_custom_entities_but_flags_typo() {
        // The four zlauder-local Custom entities are valid entity_operators keys (they
        // are category members), so naming one is NOT a typo. A genuine typo alongside
        // them is still flagged.
        let mut cfg = EngineConfig::default();
        cfg.entity_operators
            .insert(ENTITY_CVV.into(), Operator::Redact);
        cfg.entity_operators
            .insert(ENTITY_DATE_OF_BIRTH.into(), Operator::Token);
        cfg.entity_operators
            .insert(ENTITY_CREDIT_CARD_EXPIRATION.into(), Operator::Token);
        cfg.entity_operators
            .insert(ENTITY_PRIVATE_DATE.into(), Operator::Token);
        assert!(
            cfg.unknown_entity_types().is_empty(),
            "the four Custom entities are valid entity_operators keys"
        );

        // A real typo is still caught alongside them.
        cfg.entity_operators
            .insert("CVVV".into(), Operator::Redact); // typo
        let unknown = cfg.unknown_entity_types();
        assert_eq!(unknown, vec!["CVVV".to_string()]);
    }

    #[test]
    fn cvv_defaults_to_redact_but_is_overridable() {
        // C8: CVV is PCI SAD → defaults to the irreversible Redact OUT OF THE BOX,
        // even though the profile default_operator is the reversible Token.
        let cfg = EngineConfig::default();
        assert_eq!(cfg.default_operator, Operator::Token);
        assert_eq!(
            cfg.operator_for(ENTITY_CVV),
            Operator::Redact,
            "CVV masks irreversibly by default (PCI SAD), not the Token default"
        );
        // CREDIT_CARD masks the last 4 irreversibly OUT OF THE BOX (built-in Mask), so the
        // full PAN never round-trips reversibly through the store / monitor ledger.
        assert!(
            matches!(cfg.operator_for("CREDIT_CARD"), Operator::Mask { from_end: 4, .. }),
            "CREDIT_CARD masks last-4 by default (built-in), not the reversible Token default"
        );
        // The two built-in irreversible defaults are CVV (Redact) and CREDIT_CARD (Mask). The
        // neutral date labels (CREDIT_CARD_EXPIRATION / EXPIRATION_DATE / DATE_OF_BIRTH /
        // PRIVATE_DATE) are reversible tokens, NOT SAD — assert by name so the no-SAD
        // fall-through is locked.
        assert_eq!(cfg.operator_for(ENTITY_CREDIT_CARD_EXPIRATION), Operator::Token);
        assert_eq!(cfg.operator_for(ENTITY_DATE_OF_BIRTH), Operator::Token);
        assert_eq!(cfg.operator_for(ENTITY_EXPIRATION_DATE), Operator::Token);
        assert_eq!(cfg.operator_for(ENTITY_PRIVATE_DATE), Operator::Token);

        // LOWEST precedence: an explicit user override wins (not hard-locked).
        let mut cfg = EngineConfig::default();
        cfg.entity_operators
            .insert(ENTITY_CVV.into(), Operator::Token);
        assert_eq!(
            cfg.operator_for(ENTITY_CVV),
            Operator::Token,
            "an explicit CVV override beats the built-in Redact default"
        );
        // Override to a different irreversible op is also honored.
        cfg.entity_operators
            .insert(ENTITY_CVV.into(), Operator::Hash);
        assert_eq!(cfg.operator_for(ENTITY_CVV), Operator::Hash);
    }
}
