//! Hosted cryptography effects: SHA-1 hashing and AES-256-GCM. SHA-256
//! hashing is Roc's builtin `Crypto.SHA256`, so it is not offered here.
//! Random bytes come from `random.rs`.
//!
//! All operations are pure computation over the caller's bytes; nothing here
//! retains host state. Unsupported
//! inputs return a typed `CryptoErr` instead of panicking, since a panic
//! would take down the whole server.

use core::mem::ManuallyDrop;

use crate::abi::{
    roc_host, CryptBytesResult, CryptBytesResultPayload, CryptBytesResultTag, CryptEncryptedResult,
    CryptEncryptedResultPayload, CryptEncryptedResultTag, CryptEncryptedValue,
};
use crate::roc_platform_abi::*;

fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::{Digest, Sha1};

    let mut hex = String::with_capacity(40);
    for byte in Sha1::digest(bytes) {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

struct Encrypted {
    ciphertext: Vec<u8>,
    auth_tag: Vec<u8>,
}

fn encrypt_aes256_gcm(plaintext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Encrypted, String> {
    use aes_gcm::{aead::AeadInPlace, aead::KeyInit, Aes256Gcm, Key, Nonce};

    if key.len() != 32 {
        return Err("Key must be 32 bytes for AES-256-GCM".to_string());
    }
    if nonce.len() != 12 {
        return Err("Nonce must be 12 bytes for AES-256-GCM".to_string());
    }

    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new(key);

    let mut buffer = plaintext.to_vec();
    match cipher.encrypt_in_place_detached(nonce, b"", &mut buffer) {
        Ok(tag) => Ok(Encrypted {
            ciphertext: buffer,
            auth_tag: tag.as_slice().to_vec(),
        }),
        Err(error) => Err(format!("Encryption failed: {error:#?}")),
    }
}

fn decrypt_aes256_gcm(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    auth_tag: &[u8],
) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce};

    if key.len() != 32 {
        return Err("Key must be 32 bytes for AES-256-GCM".to_string());
    }
    if nonce.len() != 12 {
        return Err("Nonce must be 12 bytes for AES-256-GCM".to_string());
    }
    if auth_tag.len() != 16 {
        return Err("Auth tag must be 16 bytes for AES-256-GCM".to_string());
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|error| format!("bad key: {error:#?}"))?;
    let nonce = Nonce::from_slice(nonce);

    let mut buffer = Vec::with_capacity(ciphertext.len() + auth_tag.len());
    buffer.extend_from_slice(ciphertext);
    buffer.extend_from_slice(auth_tag);

    cipher
        .decrypt(nonce, buffer.as_slice())
        .map_err(|error| format!("Aes256Gcm::decrypt failed: {error:#?}"))
}

fn try_crypt_bytes(result: Result<Vec<u8>, String>, roc_host: &RocHost) -> CryptBytesResult {
    match result {
        Ok(bytes) => CryptBytesResult {
            payload: CryptBytesResultPayload {
                ok: ManuallyDrop::new(unsafe {
                    RocListWith::<u8, false>::from_slice(&bytes, roc_host)
                }),
            },
            tag: CryptBytesResultTag::Ok,
        },
        Err(message) => CryptBytesResult {
            payload: CryptBytesResultPayload {
                err: ManuallyDrop::new(RocStr::from_str(&message, roc_host)),
            },
            tag: CryptBytesResultTag::Err,
        },
    }
}

#[no_mangle]
pub extern "C" fn hosted_crypt_sha1(bytes: RocListWith<u8, false>) -> RocStr {
    let roc_host = roc_host();
    let digest = sha1_hex(bytes.as_slice());
    unsafe { bytes.decref(roc_host) };
    RocStr::from_str(&digest, roc_host)
}

#[no_mangle]
pub extern "C" fn hosted_crypt_encrypt_aes256_gcm(
    plaintext: RocListWith<u8, false>,
    key: RocListWith<u8, false>,
    nonce: RocListWith<u8, false>,
) -> CryptEncryptedResult {
    let roc_host = roc_host();
    let result = encrypt_aes256_gcm(plaintext.as_slice(), key.as_slice(), nonce.as_slice());
    unsafe {
        plaintext.decref(roc_host);
        key.decref(roc_host);
        nonce.decref(roc_host);
    }

    match result {
        Ok(encrypted) => CryptEncryptedResult {
            payload: CryptEncryptedResultPayload {
                ok: ManuallyDrop::new(CryptEncryptedValue {
                    auth_tag: unsafe {
                        RocListWith::<u8, false>::from_slice(&encrypted.auth_tag, roc_host)
                    },
                    ciphertext: unsafe {
                        RocListWith::<u8, false>::from_slice(&encrypted.ciphertext, roc_host)
                    },
                }),
            },
            tag: CryptEncryptedResultTag::Ok,
        },
        Err(message) => CryptEncryptedResult {
            payload: CryptEncryptedResultPayload {
                err: ManuallyDrop::new(RocStr::from_str(&message, roc_host)),
            },
            tag: CryptEncryptedResultTag::Err,
        },
    }
}

#[no_mangle]
pub extern "C" fn hosted_crypt_decrypt_aes256_gcm(
    ciphertext: RocListWith<u8, false>,
    key: RocListWith<u8, false>,
    nonce: RocListWith<u8, false>,
    auth_tag: RocListWith<u8, false>,
) -> CryptBytesResult {
    let roc_host = roc_host();
    let result = decrypt_aes256_gcm(
        ciphertext.as_slice(),
        key.as_slice(),
        nonce.as_slice(),
        auth_tag.as_slice(),
    );
    unsafe {
        ciphertext.decref(roc_host);
        key.decref(roc_host);
        nonce.decref(roc_host);
        auth_tag.decref(roc_host);
    }
    try_crypt_bytes(result, roc_host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_hex_produces_known_digest() {
        assert_eq!(
            sha1_hex(b"hello"),
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        );
    }

    #[test]
    fn aes256_gcm_round_trips() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let encrypted = encrypt_aes256_gcm(b"secret", &key, &nonce).unwrap();
        assert_eq!(encrypted.auth_tag.len(), 16);

        let plaintext =
            decrypt_aes256_gcm(&encrypted.ciphertext, &key, &nonce, &encrypted.auth_tag).unwrap();
        assert_eq!(plaintext, b"secret");
    }

    #[test]
    fn aes256_gcm_rejects_tampered_ciphertext() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let mut encrypted = encrypt_aes256_gcm(b"secret", &key, &nonce).unwrap();
        encrypted.ciphertext[0] ^= 0xFF;

        assert!(
            decrypt_aes256_gcm(&encrypted.ciphertext, &key, &nonce, &encrypted.auth_tag).is_err()
        );
    }
}
