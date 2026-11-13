//! Hosted cryptography effects: SHA-1 hashing, AES-256-GCM, and ES256 and
//! RS256 signature checks. SHA-256 hashing is Roc's builtin `Crypto.SHA256`,
//! so it is not offered here. Random bytes come from `random.rs`.
//!
//! All operations are pure computation over the caller's bytes; nothing here
//! retains host state. Unsupported
//! inputs return a typed `CryptoErr` instead of panicking, since a panic
//! would take down the whole server. A signature check answers only whether
//! the signature holds, so a malformed key or signature is one that does not.

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

/// `public_key` is an uncompressed SEC1 point (`0x04 || x || y`, 65 bytes),
/// which is the only encoding ring takes, and `signature` is DER-encoded, as
/// WebAuthn sends it. ring does not require a low S, so a high-S signature
/// holds: authenticators are not required to normalise S.
fn verify_es256(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};

    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(message, signature)
        .is_ok()
}

/// Whether `verify_es256` takes `public_key`.
///
/// ring has no public check of an ECDSA key alone, and every verification
/// failure is the same error. Its P-256 key agreement parses the peer's key
/// with the function ECDSA verification parses `public_key` with (an
/// uncompressed point, coordinates below p, on the curve), so agreeing on a
/// secret with a fresh ephemeral key succeeds exactly when verification would
/// take the key. A failing system random source refuses the key.
fn valid_es256_key(public_key: &[u8]) -> bool {
    use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256};
    use ring::rand::SystemRandom;

    let Ok(private_key) = EphemeralPrivateKey::generate(&ECDH_P256, &SystemRandom::new()) else {
        return false;
    };
    agree_ephemeral(
        private_key,
        &UnparsedPublicKey::new(&ECDH_P256, public_key),
        |_| (),
    )
    .is_ok()
}

/// `bytes` without its leading zero bytes. A COSE key's integers are
/// unsigned big-endian, and ring refuses a leading zero.
fn without_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    &bytes[start..]
}

/// `modulus` and `exponent` are big-endian unsigned integers, as a COSE RSA
/// key holds them. `RSA_PKCS1_2048_8192_SHA256` takes a modulus of 2048 to
/// 8192 bits.
fn verify_rs256(modulus: &[u8], exponent: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use ring::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};

    RsaPublicKeyComponents {
        n: without_leading_zeros(modulus),
        e: without_leading_zeros(exponent),
    }
    .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
    .is_ok()
}

const RSA_MIN_MODULUS_BYTES: usize = 2048 / 8;
const RSA_MAX_MODULUS_BYTES: usize = 8192 / 8;
const RSA_MIN_EXPONENT: u64 = 3;
const RSA_MAX_EXPONENT: u64 = (1 << 33) - 1;

/// Whether `verify_rs256` takes the key `modulus` and `exponent`.
///
/// ring has no public check of an RSA key alone, so these are the rules
/// `RSA_PKCS1_2048_8192_SHA256` checks a key with in ring 0.17: an odd
/// modulus of 256 to 1024 bytes without leading zeros, and an odd exponent
/// from 3 to 2^33 - 1. The tests hold the two to the same answers.
fn valid_rs256_key(modulus: &[u8], exponent: &[u8]) -> bool {
    let modulus = without_leading_zeros(modulus);
    let exponent = without_leading_zeros(exponent);
    let modulus_ok = (RSA_MIN_MODULUS_BYTES..=RSA_MAX_MODULUS_BYTES).contains(&modulus.len())
        && modulus.last().is_some_and(|byte| byte & 1 == 1);
    let exponent_ok = exponent.len() <= 5
        && (RSA_MIN_EXPONENT..=RSA_MAX_EXPONENT).contains(
            &exponent
                .iter()
                .fold(0u64, |value, byte| (value << 8) | u64::from(*byte)),
        )
        && exponent.last().is_some_and(|byte| byte & 1 == 1);
    modulus_ok && exponent_ok
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

#[no_mangle]
pub extern "C" fn hosted_crypt_verify_es256(
    public_key: RocListWith<u8, false>,
    message: RocListWith<u8, false>,
    signature: RocListWith<u8, false>,
) -> bool {
    let roc_host = roc_host();
    let holds = verify_es256(
        public_key.as_slice(),
        message.as_slice(),
        signature.as_slice(),
    );
    unsafe {
        public_key.decref(roc_host);
        message.decref(roc_host);
        signature.decref(roc_host);
    }
    holds
}

#[no_mangle]
pub extern "C" fn hosted_crypt_verify_rs256(
    modulus: RocListWith<u8, false>,
    exponent: RocListWith<u8, false>,
    message: RocListWith<u8, false>,
    signature: RocListWith<u8, false>,
) -> bool {
    let roc_host = roc_host();
    let holds = verify_rs256(
        modulus.as_slice(),
        exponent.as_slice(),
        message.as_slice(),
        signature.as_slice(),
    );
    unsafe {
        modulus.decref(roc_host);
        exponent.decref(roc_host);
        message.decref(roc_host);
        signature.decref(roc_host);
    }
    holds
}

#[no_mangle]
pub extern "C" fn hosted_crypt_valid_es256_key(public_key: RocListWith<u8, false>) -> bool {
    let roc_host = roc_host();
    let valid = valid_es256_key(public_key.as_slice());
    unsafe { public_key.decref(roc_host) };
    valid
}

#[no_mangle]
pub extern "C" fn hosted_crypt_valid_rs256_key(
    modulus: RocListWith<u8, false>,
    exponent: RocListWith<u8, false>,
) -> bool {
    let roc_host = roc_host();
    let valid = valid_rs256_key(modulus.as_slice(), exponent.as_slice());
    unsafe {
        modulus.decref(roc_host);
        exponent.decref(roc_host);
    }
    valid
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

    // Made with openssl: a P-256 key, an RSA-2048 key and an RSA-1024 key
    // (exponent 65537), each signing MESSAGE with SHA-256.
    const MESSAGE: &[u8] = b"webauthn assertion";
    const EC_PUBLIC_KEY: &str = "04d5c5640a5137d95c6d33c012df7384792091cbacdc9469f605a951bf600349681b446b83438feec51cf466dd845c7138ea859ae8ef4438389ef2a097c145c859";
    const EC_SIGNATURE: &str = "30460221008f1cc24df1039c0bcd32d8eb10429a7b96c089b06fc41dfa53dcad256a8630a00221008efea3a64ccb959a7cac4a9909780ad900f58d81d15512c271cbc9ba84df4c52";
    const RSA_MODULUS: &str = "da312b486e3a81c44d73ac92af9c837dbc21704a2d1cbcd567954e36b67578af9a85a3aac6f776765905885405182141e677f8ed6558a00a443d74109a89ef20ea328d8015d66108dae65f5cd8583b4d23a00010f7152f3cf71d419897cb6ec5efcc992f23674d48d4cff23b7aa5860f4f47b6b00a495faa6167ba5c95b5228078dbcedfee6b629df4ea714d8f16a156b7299306eef953535aaabc4718ba2f543e84b1557b8164ea1035ac598d0bca44da1d276715fcacdb1e784838bb4a7100649b9bcadf1013791eca0f69945cc98320df3161d64af9c4dc81e632c689b858589d2d31fa1bf0225fd308def835638864aacd1ecb56bc675af1bf61ffbe9cfb";
    const RSA_SIGNATURE: &str = "cbf51b45971caf7436a311392cdbeac65eb0b94a528c4e87c279f5590bd365cc8613df1413e376e778418c166a1d8dee1f38f461cb50a2aea10470628a305ea55825789c426cae9c687fc835f5b126d56ab6e45ac4ae0aeadd84364077777107e1131ebcd37033d3c4e510ba779974feb9bd03cd9ce3caf169fea966241af82ccb05bef6c4e5a1afd04b3876618b5c86cda5069840e44083130e8278808894b3cf7dcd4e719452a7bbecde344611b6a6d7ce7b168e974636d48a230fcba80bf82478701a0efaed77d09ab04dd97965125c59c161fa9e9aa517e0a1ba66fc3f37eab5579db1d29c222157e2f2f7703ac2b307ba7a479dcf4bf6dbf80633b09164";
    const RSA_1024_MODULUS: &str = "b919db52865105595e2c55c9c28621ec28ac38872cd0e467318e01e392d18882b0d01473bbf602f825cd51a41f5103baf0cd9c4e704b893b66eafc2b0e385cb4a39135f0634aba15683de7c0a9a9093bd73621ec97f6711a4e39e5b622dbb15217095953441035b7ca4eeeafcef9d6bed0ba0ace5917591ef8a9e6df89850313";
    const RSA_1024_SIGNATURE: &str = "5cfcfa86105f486c9ba2e7da34d4a023df0ff1593a89f71b217a3c35513c77713137f08233e500cee531fd926bf24e27888acadf54e37565a2f6cc3c9b4baf1b750cea93dd080e8ca79f5a8d031c0eee6391f1186e69e86dd28c3a64f5cf59cd133002c4f1e0676f7f1e479a93df4c67e4abf7b228ce59eb24b1fba88ea85d09";
    const RSA_EXPONENT: &[u8] = &[0x01, 0x00, 0x01];
    // The order n of P-256's group, and n / 2 rounded down.
    const P256_ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    const P256_HALF_ORDER: &str =
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8";

    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The r and s of EC_SIGNATURE, 32 bytes each.
    fn ec_r_and_s() -> (Vec<u8>, Vec<u8>) {
        let signature = bytes(EC_SIGNATURE);
        // 30 46, 02 21 00 r, 02 21 00 s
        (signature[5..37].to_vec(), signature[40..72].to_vec())
    }

    /// A DER ECDSA-Sig-Value of two 32-byte unsigned integers.
    fn der_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
        fn integer(value: &[u8]) -> Vec<u8> {
            let value = match without_leading_zeros(value) {
                [] => &[0u8][..],
                value => value,
            };
            let mut out = vec![0x02];
            if value[0] & 0x80 != 0 {
                out.push(value.len() as u8 + 1);
                out.push(0x00);
            } else {
                out.push(value.len() as u8);
            }
            out.extend_from_slice(value);
            out
        }
        let body = [integer(r), integer(s)].concat();
        [vec![0x30, body.len() as u8], body].concat()
    }

    /// `n - value` for two 32-byte big-endian integers, `value` below `n`.
    fn order_minus(value: &[u8]) -> Vec<u8> {
        let n = bytes(P256_ORDER);
        let mut out = vec![0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let digit = i16::from(n[i]) - i16::from(value[i]) - borrow;
            borrow = i16::from(digit < 0);
            out[i] = (digit + 256 * borrow) as u8;
        }
        assert_eq!(borrow, 0);
        out
    }

    /// The compressed SEC1 form of an uncompressed P-256 point, which names
    /// the same point.
    fn compressed(uncompressed: &[u8]) -> Vec<u8> {
        let mut out = vec![0x02 | (uncompressed[64] & 1)];
        out.extend_from_slice(&uncompressed[1..33]);
        out
    }

    #[test]
    fn es256_accepts_its_signature_with_a_high_or_a_low_s() {
        let key = bytes(EC_PUBLIC_KEY);
        let (r, s) = ec_r_and_s();
        // The vector's S is above n / 2, as authenticators may send it.
        assert!(s.as_slice() > bytes(P256_HALF_ORDER).as_slice());
        assert!(verify_es256(&key, MESSAGE, &bytes(EC_SIGNATURE)));

        // Its counterpart n - S is the same signature with a low S.
        let low_s = order_minus(&s);
        assert!(low_s.as_slice() <= bytes(P256_HALF_ORDER).as_slice());
        assert!(verify_es256(&key, MESSAGE, &der_signature(&r, &low_s)));
    }

    #[test]
    fn es256_refuses_another_message_or_a_changed_signature() {
        let key = bytes(EC_PUBLIC_KEY);
        let signature = bytes(EC_SIGNATURE);
        assert!(!verify_es256(&key, b"another message", &signature));
        assert!(!verify_es256(&key, b"", &signature));

        let mut flipped = signature.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;
        assert!(!verify_es256(&key, MESSAGE, &flipped));
    }

    #[test]
    fn es256_refuses_compressed_and_other_key_encodings() {
        let key = bytes(EC_PUBLIC_KEY);
        let signature = bytes(EC_SIGNATURE);
        // The same point compressed, under both prefixes.
        let point = compressed(&key);
        assert!(!verify_es256(&point, MESSAGE, &signature));
        let mut other_prefix = point.clone();
        other_prefix[0] ^= 0x01;
        assert!(!verify_es256(&other_prefix, MESSAGE, &signature));
        // A hybrid point (0x06 or 0x07) and the bare coordinates.
        let mut hybrid = key.clone();
        hybrid[0] = 0x06 | (key[64] & 1);
        assert!(!verify_es256(&hybrid, MESSAGE, &signature));
        assert!(!verify_es256(&key[1..], MESSAGE, &signature));
        // Truncated, extended, off the curve, the point at infinity, empty.
        assert!(!verify_es256(&key[..64], MESSAGE, &signature));
        assert!(!verify_es256(
            &[key.as_slice(), &[0]].concat(),
            MESSAGE,
            &signature
        ));
        let mut off_curve = key.clone();
        off_curve[64] ^= 0x01;
        assert!(!verify_es256(&off_curve, MESSAGE, &signature));
        assert!(!verify_es256(&[0x00], MESSAGE, &signature));
        assert!(!verify_es256(&[], MESSAGE, &signature));
    }

    #[test]
    fn es256_refuses_broken_der() {
        let key = bytes(EC_PUBLIC_KEY);
        let signature = bytes(EC_SIGNATURE);
        let (r, s) = ec_r_and_s();

        assert!(!verify_es256(&key, MESSAGE, &[]));
        assert!(!verify_es256(&key, MESSAGE, &signature[..10]));
        assert!(!verify_es256(
            &key,
            MESSAGE,
            &signature[..signature.len() - 1]
        ));
        assert!(!verify_es256(
            &key,
            MESSAGE,
            &[signature.as_slice(), &[0]].concat()
        ));
        // The fixed-size r || s form instead of DER.
        assert!(!verify_es256(&key, MESSAGE, &[r.as_slice(), &s].concat()));
        // A SET instead of a SEQUENCE, and a wrong outer length.
        let mut set = signature.clone();
        set[0] = 0x31;
        assert!(!verify_es256(&key, MESSAGE, &set));
        let mut long = signature.clone();
        long[1] += 1;
        assert!(!verify_es256(&key, MESSAGE, &long));
        // r with a needless leading zero, which DER does not allow.
        let padded = [vec![0x30, 0x47, 0x02, 0x22, 0x00], signature[4..].to_vec()].concat();
        assert!(!verify_es256(&key, MESSAGE, &padded));
        // r or s of zero, and s of n.
        assert!(!verify_es256(&key, MESSAGE, &der_signature(&[0; 32], &s)));
        assert!(!verify_es256(&key, MESSAGE, &der_signature(&r, &[0; 32])));
        assert!(!verify_es256(
            &key,
            MESSAGE,
            &der_signature(&r, &bytes(P256_ORDER))
        ));
    }

    #[test]
    fn es256_keys_are_valid_by_the_rules_verification_uses() {
        let key = bytes(EC_PUBLIC_KEY);
        assert!(valid_es256_key(&key));

        let mut off_curve = key.clone();
        off_curve[64] ^= 0x01;
        let mut hybrid = key.clone();
        hybrid[0] = 0x06 | (key[64] & 1);
        // x = p, which is not below p, with the y of the vector.
        let mut x_is_p = key.clone();
        x_is_p[1..33].copy_from_slice(&bytes(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        ));
        let refused: [&[u8]; 9] = [
            &off_curve,
            &compressed(&key),
            &hybrid,
            &x_is_p,
            &key[..64],
            &key[1..],
            &[key.as_slice(), &[0]].concat(),
            &[0x00],
            &[],
        ];
        for refused_key in refused {
            assert!(!valid_es256_key(refused_key), "{refused_key:02x?}");
            assert!(!verify_es256(refused_key, MESSAGE, &bytes(EC_SIGNATURE)));
        }
    }

    #[test]
    fn rs256_accepts_its_signature() {
        let modulus = bytes(RSA_MODULUS);
        let signature = bytes(RSA_SIGNATURE);
        assert!(verify_rs256(&modulus, RSA_EXPONENT, MESSAGE, &signature));
        // Leading zero bytes do not change the integers.
        let padded_modulus = [&[0u8, 0][..], &modulus].concat();
        let padded_exponent = [&[0u8][..], RSA_EXPONENT].concat();
        assert!(verify_rs256(
            &padded_modulus,
            &padded_exponent,
            MESSAGE,
            &signature
        ));
    }

    #[test]
    fn rs256_refuses_another_message_or_a_changed_signature() {
        let modulus = bytes(RSA_MODULUS);
        let signature = bytes(RSA_SIGNATURE);
        assert!(!verify_rs256(
            &modulus,
            RSA_EXPONENT,
            b"another message",
            &signature
        ));

        let mut flipped = signature.clone();
        flipped[0] ^= 0x01;
        assert!(!verify_rs256(&modulus, RSA_EXPONENT, MESSAGE, &flipped));
        assert!(!verify_rs256(&modulus, &[0x03], MESSAGE, &signature));
        // The signature must be exactly as long as the modulus.
        assert!(!verify_rs256(
            &modulus,
            RSA_EXPONENT,
            MESSAGE,
            &signature[1..]
        ));
        let longer = [&[0u8][..], &signature].concat();
        assert!(!verify_rs256(&modulus, RSA_EXPONENT, MESSAGE, &longer));
        assert!(!verify_rs256(&modulus, RSA_EXPONENT, MESSAGE, &[]));
        // A signature not below the modulus.
        assert!(!verify_rs256(&modulus, RSA_EXPONENT, MESSAGE, &[0xff; 256]));
    }

    #[test]
    fn rs256_refuses_a_correct_signature_by_a_1024_bit_key() {
        use ring::signature::{
            RsaPublicKeyComponents, RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
        };

        let modulus = bytes(RSA_1024_MODULUS);
        let signature = bytes(RSA_1024_SIGNATURE);
        // The signature itself holds, by ring's legacy check for short keys.
        assert!(RsaPublicKeyComponents {
            n: modulus.as_slice(),
            e: RSA_EXPONENT,
        }
        .verify(
            &RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            MESSAGE,
            &signature
        )
        .is_ok());
        assert!(!verify_rs256(&modulus, RSA_EXPONENT, MESSAGE, &signature));
        assert!(!valid_rs256_key(&modulus, RSA_EXPONENT));
    }

    #[test]
    fn rs256_keys_are_valid_by_the_rules_verification_uses() {
        let modulus = bytes(RSA_MODULUS);
        let signature = bytes(RSA_SIGNATURE);
        assert!(valid_rs256_key(&modulus, RSA_EXPONENT));
        assert!(valid_rs256_key(&modulus, &[0x03]));
        assert!(valid_rs256_key(
            &[&[0u8][..], &modulus].concat(),
            &[0, 1, 0, 1]
        ));
        assert!(valid_rs256_key(&modulus, &[0x01, 0xff, 0xff, 0xff, 0xff]));
        assert!(valid_rs256_key(&[0xff; 1024], RSA_EXPONENT));

        let mut even = modulus.clone();
        *even.last_mut().unwrap() &= 0xfe;
        let refused_moduli: [&[u8]; 8] = [
            &even,
            &modulus[1..],
            &bytes(RSA_1024_MODULUS),
            &[0xff; 1025],
            &[0x03],
            &[0x00],
            &[0; 256],
            &[],
        ];
        for refused in refused_moduli {
            assert!(
                !valid_rs256_key(refused, RSA_EXPONENT),
                "modulus {refused:02x?}"
            );
            assert!(!verify_rs256(refused, RSA_EXPONENT, MESSAGE, &signature));
        }

        let refused_exponents: [&[u8]; 7] = [
            &[0x01],
            &[0x02],
            &[0x01, 0x00, 0x00],
            &[0x02, 0x00, 0x00, 0x00, 0x01],
            &[0x01, 0x00, 0x00, 0x00, 0x00, 0x01],
            &[0x00],
            &[],
        ];
        for refused in refused_exponents {
            assert!(
                !valid_rs256_key(&modulus, refused),
                "exponent {refused:02x?}"
            );
            assert!(!verify_rs256(&modulus, refused, MESSAGE, &signature));
        }
    }
}
