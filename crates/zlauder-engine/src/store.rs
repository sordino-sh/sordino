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

    /// Delete (tombstone) a token: removes the entry and records the handle so it can
    /// never resolve or be re-interned again. Returns whether it was present.
    pub fn delete(&mut self, token: &str) -> bool {
        let removed = self.token_map.remove(token).is_some();
        self.tombstoned.insert(token.to_string());
        removed
    }

    /// Seed a tombstone (DeletionLog replay on restart) without requiring the entry
    /// to be present.
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
