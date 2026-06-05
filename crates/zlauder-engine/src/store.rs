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
use std::collections::HashMap;

use crate::error::EngineError;
use crate::token::make_token;

#[derive(Clone, Debug)]
struct StoreEntry {
    original_encrypted: Vec<u8>,
    nonce: [u8; 12],
}

pub struct SessionStore {
    session_key: [u8; 32],
    salt: [u8; 16],
    token_map: HashMap<String, StoreEntry>,
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
        }
    }

    /// Reuse an explicit key + salt (the proxy passes the SessionStart-issued
    /// session bytes so the whole session shares one salt -> token determinism).
    pub fn with_key_and_salt(session_key: [u8; 32], salt: [u8; 16]) -> Self {
        Self {
            session_key,
            salt,
            token_map: HashMap::new(),
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

    /// Mint-or-reuse a deterministic token for `(entity_type, plaintext)`.
    /// Determinism means the token itself is the dedup key.
    pub fn intern(&mut self, entity_type: &str, plaintext: &str) -> Result<String, EngineError> {
        let token = make_token(entity_type, plaintext, &self.salt);
        self.insert_if_absent(token.clone(), plaintext)?;
        Ok(token)
    }

    /// Register a caller-supplied fixed token (custom `literal_token` rules) so it
    /// is reversible on the unmask path.
    pub fn intern_fixed(&mut self, token: String, plaintext: &str) -> Result<(), EngineError> {
        self.insert_if_absent(token, plaintext)
    }

    fn insert_if_absent(&mut self, token: String, plaintext: &str) -> Result<(), EngineError> {
        if self.token_map.contains_key(&token) {
            return Ok(());
        }
        let (original_encrypted, nonce) = self.encrypt(plaintext)?;
        self.token_map.insert(
            token,
            StoreEntry {
                original_encrypted,
                nonce,
            },
        );
        Ok(())
    }

    /// Decrypt a token back to its plaintext. `None` if the token is unknown.
    pub fn reveal(&self, token: &str) -> Option<String> {
        let entry = self.token_map.get(token)?;
        self.decrypt(&entry.original_encrypted, &entry.nonce).ok()
    }

    pub fn len(&self) -> usize {
        self.token_map.len()
    }
}
