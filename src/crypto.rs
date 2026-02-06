//! # Cryptographic Operations
//!
//! Provides AES-256-GCM authenticated encryption for backup blobs.
//! Key derivation uses BLAKE3 keyed hashing of the user-supplied password,
//! producing a deterministic 256-bit key. Each blob is encrypted with a
//! unique random 96-bit nonce prepended to the ciphertext.
//!
//! ## Wire format
//!
//! ```text
//! ┌──────────────┬──────────────────────────────────────┐
//! │  Nonce (12B)  │  Ciphertext + Auth Tag (16B suffix)  │
//! └──────────────┴──────────────────────────────────────┘
//! ```

use crate::error::{CryptoError, Result};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};

/// Fixed nonce length for AES-256-GCM (96 bits).
const NONCE_LEN: usize = 12;

/// Derives a 256-bit encryption key from a password using BLAKE3 keyed hashing.
///
/// The key derivation context string ensures domain separation — the same password
/// produces different keys when used in different applications.
fn derive_key(password: &str) -> [u8; 32] {
    blake3::derive_key("but-next v1 encryption key", password.as_bytes())
}

/// Encrypts plaintext using AES-256-GCM with a random nonce.
///
/// Returns the nonce prepended to the ciphertext (nonce ‖ ciphertext ‖ tag).
pub fn encrypt(plaintext: &[u8], password: &str) -> Result<Vec<u8>> {
    let key = derive_key(password);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::InvalidKeyLength)?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    // Prepend nonce to ciphertext for self-contained storage
    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypts data produced by [`encrypt`].
///
/// Extracts the 12-byte nonce prefix, then decrypts and authenticates
/// the remaining ciphertext. Returns an error if the authentication
/// tag does not match (indicating corruption or wrong password).
pub fn decrypt(data: &[u8], password: &str) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN {
        return Err(CryptoError::DecryptionFailed.into());
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    let key = derive_key(password);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::InvalidKeyLength)?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encryption() {
        let password = "test-password-12345";
        let plaintext = b"Hello, but-next encryption!";

        let encrypted = encrypt(plaintext, password).unwrap();
        assert_ne!(encrypted.as_slice(), plaintext);
        assert!(encrypted.len() > plaintext.len());

        let decrypted = decrypt(&encrypted, password).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_password_fails() {
        let encrypted = encrypt(b"secret data", "correct-password").unwrap();
        let result = decrypt(&encrypted, "wrong-password");
        assert!(result.is_err());
    }

    #[test]
    fn empty_data_fails() {
        let result = decrypt(&[], "password");
        assert!(result.is_err());
    }

    #[test]
    fn short_data_fails() {
        let result = decrypt(&[0u8; 5], "password");
        assert!(result.is_err());
    }

    #[test]
    fn unique_nonces() {
        let a = encrypt(b"data", "pw").unwrap();
        let b = encrypt(b"data", "pw").unwrap();
        // Same plaintext + password should produce different ciphertext (random nonce)
        assert_ne!(a, b);
    }
}
