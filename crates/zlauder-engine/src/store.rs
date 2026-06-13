//! AES-256-GCM reversible session store (ported from orchestr8-privacy `TokenStore`).
//!
//! Holds the per-session encryption key + token salt and a `token -> encrypted
//! plaintext` map. The salt is fixed for the session lifetime, so token minting
//! is deterministic (see [`crate::token::make_token`]). The store is never
//! serialized; plaintext lives only encrypted (and in-process under the session
//! key, which never leaves this process unless explicitly exported for audit).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::error::EngineError;
use crate::token::{BROKER_PREFIX, make_token, slugify};

/// Which class of token a `StoreEntry` is. `Pii` (and custom literal) tokens are
/// display-revealable; `Broker` tokens are resolvable ONLY at the tool-input
/// boundary — `reveal_for(tok, Pii)` on a broker token is `None`, so a leaked
/// manifest can never reveal a broker value on the display path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    Pii,
    Broker,
    /// "Owner-reveal" (local): reversible like `Pii`, but the display path reveals it
    /// while the tool-input path refuses it unless the handle is in `tool_promoted`.
    Local,
}

/// A successful kind-gated reveal: the plaintext plus, for a broker token, the EXACT
/// registered secret name (the per-secret policy authority — never parsed from the
/// token string).
#[derive(Clone, Debug)]
pub struct Revealed {
    pub value: String,
    pub secret_name: Option<String>,
}

#[derive(Clone, Debug)]
struct StoreEntry {
    original_encrypted: Vec<u8>,
    nonce: [u8; 12],
    kind: TokenKind,
    /// EXACT registered secret name (broker tokens only) — the policy authority.
    secret_name: Option<String>,
    /// Optional TTL deadline; past it, reveal returns `None` (resolves to placeholder).
    expires_at: Option<Instant>,
}

pub struct SessionStore {
    session_key: [u8; 32],
    salt: [u8; 16],
    token_map: HashMap<String, StoreEntry>,
    /// Tombstoned token handles: a `delete`d token never resolves again and cannot be
    /// re-interned (tombstone WINS over bind-and-remember re-resolution). The proxy
    /// persists these handles (DeletionLog) and replays them on restart so a
    /// salt-stable token can't resurrect after a checkpoint restore.
    tombstoned: HashSet<String>,
    /// Session-only set of `Local` token handles the operator has explicitly promoted
    /// for tool-input use ("allow this value into tool inputs"). In-memory, NEVER
    /// persisted — a fresh process starts with every local token tool-denied. Empty
    /// until the (deferred) promote UI/endpoint sets it.
    tool_promoted: HashSet<String>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    /// Fresh session: random key + salt from the OS RNG.
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut salt);
        Self {
            session_key: key,
            salt,
            token_map: HashMap::new(),
            tombstoned: HashSet::new(),
            tool_promoted: HashSet::new(),
        }
    }

    /// Reuse an explicit key + salt (the proxy passes the SessionStart-issued
    /// session bytes so the whole session shares one salt -> token determinism).
    pub fn with_key_and_salt(session_key: [u8; 32], salt: [u8; 16]) -> Self {
        Self {
            session_key,
            salt,
            token_map: HashMap::new(),
            tombstoned: HashSet::new(),
            tool_promoted: HashSet::new(),
        }
    }

    /// Reuse a salt (for token determinism across a proxy restart) but mint a
    /// FRESH random encryption key. The reversible map is in-memory only, so the
    /// key never needs to be stable across restarts — and not persisting it means
    /// the on-disk state file holds no decryption material.
    pub fn with_salt(salt: [u8; 16]) -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self {
            session_key: key,
            salt,
            token_map: HashMap::new(),
            tombstoned: HashSet::new(),
            tool_promoted: HashSet::new(),
        }
    }

    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.session_key
    }

    fn cipher(&self) -> Result<Aes256Gcm, EngineError> {
        Aes256Gcm::new_from_slice(&self.session_key)
            .map_err(|e| EngineError::EncryptionFailed(e.to_string()))
    }

    fn encrypt(&self, value: &str) -> Result<(Vec<u8>, [u8; 12]), EngineError> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = self
            .cipher()?
            .encrypt(nonce, value.as_bytes())
            .map_err(|e| EngineError::EncryptionFailed(e.to_string()))?;
        Ok((ct, nonce_bytes))
    }

    fn decrypt(&self, ct: &[u8], nonce_bytes: &[u8; 12]) -> Result<String, EngineError> {
        let nonce = Nonce::from_slice(nonce_bytes);
        let pt = self
            .cipher()?
            .decrypt(nonce, ct)
            .map_err(|e| EngineError::DecryptionFailed(e.to_string()))?;
        String::from_utf8(pt).map_err(|e| EngineError::DecryptionFailed(e.to_string()))
    }

    /// Mint-or-reuse a deterministic PII token for `(entity_type, plaintext)`.
    /// Determinism means the token itself is the dedup key.
    pub fn intern(&mut self, entity_type: &str, plaintext: &str) -> Result<String, EngineError> {
        let token = make_token(entity_type, plaintext, &self.salt);
        self.insert_if_absent(token.clone(), plaintext, TokenKind::Pii, None, None)?;
        Ok(token)
    }

    /// Register a caller-supplied fixed token (custom `literal_token` rules) so it
    /// is reversible on the unmask path.
    pub fn intern_fixed(&mut self, token: String, plaintext: &str) -> Result<(), EngineError> {
        self.insert_if_absent(token, plaintext, TokenKind::Pii, None, None)
    }

    /// Mint-or-reuse a deterministic BROKER token for a registered secret `name`.
    /// The token entity is a COSMETIC slug (`BROKER__<SLUG>`); the EXACT `name` is
    /// stored on the entry as the per-secret policy authority. Resolvable only via
    /// [`Self::reveal_for`]`(tok, Broker)` — never on the display path.
    pub fn intern_broker(
        &mut self,
        name: &str,
        plaintext: &str,
        ttl: Option<Duration>,
    ) -> Result<String, EngineError> {
        let entity = format!("{BROKER_PREFIX}{}", slugify(name));
        let token = make_token(&entity, plaintext, &self.salt);
        let expires_at = ttl.map(|d| Instant::now() + d);
        self.insert_if_absent(
            token.clone(),
            plaintext,
            TokenKind::Broker,
            Some(name.to_string()),
            expires_at,
        )?;
        Ok(token)
    }

    /// Mint-or-reuse a deterministic LOCAL ("owner-reveal") token for a registered secret
    /// `name`. Reversible like [`Self::intern`] (standard `[ENTITY_xxx]` grammar, NOT a
    /// `[BROKER__…]` prefix, so the display unmask resolves it), but `kind: Local`, so the
    /// tool-input unmask refuses it unless the handle was promoted. The name is slugified
    /// (like [`Self::intern_broker`]) so a name with a space/punctuation still mints a
    /// token-grammar-safe handle (today `Local` is bound to the clean `zlauder_admin_key`,
    /// but this keeps the door open for other owner-reveal secrets).
    pub fn intern_local(&mut self, name: &str, plaintext: &str) -> Result<String, EngineError> {
        let token = make_token(&slugify(name), plaintext, &self.salt);
        self.insert_if_absent(token.clone(), plaintext, TokenKind::Local, None, None)?;
        Ok(token)
    }

    fn insert_if_absent(
        &mut self,
        token: String,
        plaintext: &str,
        kind: TokenKind,
        secret_name: Option<String>,
        expires_at: Option<Instant>,
    ) -> Result<(), EngineError> {
        // Tombstone wins: a deleted token is never re-interned (no resurrection).
        if self.tombstoned.contains(&token) || self.token_map.contains_key(&token) {
            return Ok(());
        }
        let (original_encrypted, nonce) = self.encrypt(plaintext)?;
        self.token_map.insert(
            token,
            StoreEntry {
                original_encrypted,
                nonce,
                kind,
                secret_name,
                expires_at,
            },
        );
        Ok(())
    }

    /// True iff the entry is live (not past its TTL).
    fn live(entry: &StoreEntry) -> bool {
        match entry.expires_at {
            Some(deadline) => Instant::now() < deadline,
            None => true,
        }
    }

    /// Decrypt a token back to its plaintext — DISPLAY path, PII only. A broker token
    /// (or an expired/tombstoned token) returns `None`, so the display unmask can
    /// never reveal a broker value even if asked.
    pub fn reveal(&self, token: &str) -> Option<String> {
        let entry = self.token_map.get(token)?;
        if entry.kind != TokenKind::Pii || !Self::live(entry) {
            return None;
        }
        self.decrypt(&entry.original_encrypted, &entry.nonce).ok()
    }

    /// Kind-gated reveal: resolve `token` only if its stored kind matches `want` and
    /// it is live. Returns the plaintext plus (for broker) the exact registered name.
    /// `None` on kind-mismatch / expiry / tombstone / unknown.
    pub fn reveal_for(&self, token: &str, want: TokenKind) -> Option<Revealed> {
        let entry = self.token_map.get(token)?;
        if entry.kind != want || !Self::live(entry) {
            return None;
        }
        let value = self.decrypt(&entry.original_encrypted, &entry.nonce).ok()?;
        Some(Revealed {
            value,
            secret_name: entry.secret_name.clone(),
        })
    }

    /// Peek a token's CLASS (+ the registered name for a broker secret) WITHOUT decrypting,
    /// so an audit reveal can tell "unknown token" apart from "exists but isn't revealable
    /// here". `None` ⇒ unknown, expired, or tombstoned (a dead token can't be revealed
    /// anyway, so it reads as unknown). The plaintext is never touched.
    pub fn class_of(&self, token: &str) -> Option<(TokenKind, Option<String>)> {
        let entry = self.token_map.get(token)?;
        Self::live(entry).then(|| (entry.kind, entry.secret_name.clone()))
    }

    /// Every live LOCAL ("owner-reveal") token as a `(plaintext, handle)` pair. The monitor
    /// capture uses this to re-mask a `Local` value (the admin key) that is revealed on the
    /// display path and so can appear in a captured reply CROSS-TURN — when the model echoes
    /// the token in a turn whose request carries no plaintext, there is no `local` manifest
    /// entry that turn, so the manifest-only capture scrub would miss it. Tiny (one entry per
    /// Local secret); plaintext is decrypted in-process and handed straight back to the scrub.
    pub fn local_pairs(&self) -> Vec<(String, String)> {
        self.token_map
            .iter()
            .filter(|(_, e)| e.kind == TokenKind::Local && Self::live(e))
            .filter_map(|(handle, e)| {
                self.decrypt(&e.original_encrypted, &e.nonce)
                    .ok()
                    .map(|plain| (plain, handle.clone()))
            })
            .collect()
    }

    /// True iff `token` is a known LOCAL ("owner-reveal") token. Used by the unmask path
    /// to decide tool-input refusal for a token minted in an EARLIER turn (no manifest
    /// entry this turn). Within-turn the manifest's `local` flag is authoritative.
    pub fn is_local(&self, token: &str) -> bool {
        self.token_map
            .get(token)
            .is_some_and(|e| e.kind == TokenKind::Local)
    }

    /// Promote a `Local` token handle for SESSION tool-input use ("allow into tools").
    /// ONLY a `Local` handle is accepted: a `Pii` token already resolves into tools (so
    /// promoting it is meaningless) and a `Broker`/unknown token never consults this set,
    /// so the `tool_promoted` set is kept to exactly its documented contents. In-memory only.
    pub fn promote(&mut self, token: &str) {
        if matches!(self.token_map.get(token), Some(e) if e.kind == TokenKind::Local) {
            self.tool_promoted.insert(token.to_string());
        }
    }

    /// True iff `token` was promoted for tool-input use this session.
    pub fn is_tool_promoted(&self, token: &str) -> bool {
        self.tool_promoted.contains(token)
    }

    /// Delete (tombstone) a token: removes the entry and records the handle so it can
    /// never resolve or be re-interned again. Returns whether it was present.
    // Pre-existing store API exercised only by store.rs tests today (the live
    // deletion path seeds tombstones via DeletionLog replay); retained as API.
    #[allow(dead_code)]
    pub fn delete(&mut self, token: &str) -> bool {
        let removed = self.token_map.remove(token).is_some();
        self.tombstoned.insert(token.to_string());
        removed
    }

    /// Seed a tombstone (DeletionLog replay on restart) without requiring the entry
    /// to be present.
    #[allow(dead_code)] // see `delete` — store API, currently test-only callers.
    pub fn tombstone(&mut self, token: String) {
        self.token_map.remove(&token);
        self.tombstoned.insert(token);
    }

    pub fn len(&self) -> usize {
        self.token_map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_token_is_kind_gated() {
        let mut s = SessionStore::new();
        let tok = s.intern_broker("db_password", "hunter2", None).unwrap();
        assert!(tok.starts_with("[BROKER__DB_PASSWORD_"), "got {tok}");
        // Display path (PII reveal) refuses a broker token.
        assert_eq!(s.reveal(&tok), None);
        // Broker reveal returns the value + the EXACT registered name (not the slug).
        let r = s.reveal_for(&tok, TokenKind::Broker).unwrap();
        assert_eq!(r.value, "hunter2");
        assert_eq!(r.secret_name.as_deref(), Some("db_password"));
        // A PII-kind reveal of a broker token is `None`.
        assert!(s.reveal_for(&tok, TokenKind::Pii).is_none());
    }

    #[test]
    fn class_of_peeks_kind_and_name_without_decrypting() {
        let mut s = SessionStore::new();
        let broker = s.intern_broker("db_password", "hunter2", None).unwrap();
        let pii = s.intern("EMAIL_ADDRESS", "a@b.com").unwrap();
        let local = s.intern_local("ZLAUDER_ADMIN_KEY", "k").unwrap();
        // Broker: peeked as Broker + the EXACT registered name (so the audit endpoint can say
        // WHAT it is) — class_of NEVER decrypts the value.
        assert_eq!(
            s.class_of(&broker),
            Some((TokenKind::Broker, Some("db_password".to_string())))
        );
        assert_eq!(s.class_of(&pii), Some((TokenKind::Pii, None)));
        assert!(matches!(s.class_of(&local), Some((TokenKind::Local, _))));
        // Unknown handle ⇒ None (lets the audit endpoint say "unknown" vs "not revealable").
        assert_eq!(s.class_of("[NOPE_000000000000]"), None);
    }

    #[test]
    fn promote_accepts_only_local_handles() {
        let mut s = SessionStore::new();
        let local = s.intern_local("ZLAUDER_ADMIN_KEY", "k").unwrap();
        let pii = s.intern("EMAIL_ADDRESS", "a@b.com").unwrap();
        let broker = s.intern_broker("db", "v", None).unwrap();
        s.promote(&local);
        s.promote(&pii); // no-op: Pii already resolves into tools
        s.promote(&broker); // no-op: brokers never consult this set
        s.promote("[NOPE_000000000000]"); // no-op: unknown handle
        assert!(s.is_tool_promoted(&local), "a Local handle must be promotable");
        assert!(!s.is_tool_promoted(&pii), "a Pii handle must not enter the promote set");
        assert!(!s.is_tool_promoted(&broker), "a broker handle must not enter the promote set");
    }

    #[test]
    fn local_token_reveals_as_pii_path_no_then_local_yes() {
        let mut s = SessionStore::new();
        let tok = s.intern_local("ZLAUDER_ADMIN_KEY", "adminval").unwrap();
        assert!(tok.starts_with("[ZLAUDER_ADMIN_KEY_"), "got {tok}");
        assert!(s.is_local(&tok));
        // `reveal` (Pii-gated display fallback) does NOT resolve a Local token...
        assert_eq!(s.reveal(&tok), None);
        // ...it resolves via the kind-gated Local path.
        assert_eq!(s.reveal_for(&tok, TokenKind::Local).unwrap().value, "adminval");
        assert!(s.reveal_for(&tok, TokenKind::Pii).is_none());
    }

    #[test]
    fn pii_token_is_not_revealable_as_broker() {
        let mut s = SessionStore::new();
        let tok = s.intern("EMAIL_ADDRESS", "a@b.com").unwrap();
        assert_eq!(s.reveal(&tok).as_deref(), Some("a@b.com"));
        assert!(s.reveal_for(&tok, TokenKind::Broker).is_none());
        let r = s.reveal_for(&tok, TokenKind::Pii).unwrap();
        assert_eq!(r.value, "a@b.com");
        assert_eq!(r.secret_name, None);
    }

    #[test]
    fn delete_tombstones_and_blocks_resurrection() {
        let mut s = SessionStore::new();
        let tok = s.intern_broker("k", "v", None).unwrap();
        assert!(s.reveal_for(&tok, TokenKind::Broker).is_some());
        assert!(s.delete(&tok));
        assert!(s.reveal_for(&tok, TokenKind::Broker).is_none());
        // Re-intern the same (name,value) ⇒ same deterministic token, but the
        // tombstone WINS (no resurrection after delete).
        let tok2 = s.intern_broker("k", "v", None).unwrap();
        assert_eq!(tok, tok2);
        assert!(
            s.reveal_for(&tok2, TokenKind::Broker).is_none(),
            "tombstone wins over re-intern"
        );
    }

    #[test]
    fn ttl_deadline_blocks_reveal() {
        let mut s = SessionStore::new();
        // Deadline = now + 0 ⇒ already past, so reveal is `None` (placeholder).
        let tok = s
            .intern_broker("k", "v", Some(Duration::from_millis(0)))
            .unwrap();
        assert!(
            s.reveal_for(&tok, TokenKind::Broker).is_none(),
            "an expired broker token does not reveal"
        );
    }

    #[test]
    fn tombstone_seed_blocks_intern() {
        let mut s = SessionStore::new();
        // Pre-seed a tombstone (the proxy's DeletionLog replay on restart), then a
        // later intern of that exact token must not resurrect it.
        let tok = make_token("EMAIL_ADDRESS", "x@y.com", s.salt());
        s.tombstone(tok.clone());
        let again = s.intern("EMAIL_ADDRESS", "x@y.com").unwrap();
        assert_eq!(again, tok);
        assert_eq!(s.reveal(&again), None, "a tombstoned token never resolves");
    }
}
