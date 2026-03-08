//! **EIP-2335**: BLS12-381 keystore v4 — encrypted storage for BLS secret keys.
//!
//! Implements the EIP-2335 JSON keystore format used by Ethereum beacon chain
//! clients (Prysm, Lighthouse, Teku, etc.) for validator key management.
//!
//! # Format
//! Scrypt KDF + AES-128-CTR encryption + SHA-256 checksum.

use crate::error::SignerError;
use aes::cipher::{KeyIvInit, StreamCipher};
use core::fmt;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// AES-128-CTR cipher type alias.
type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;

/// EIP-2335 keystore version.
pub const VERSION: u32 = 4;

/// Scrypt parameters for BLS keystore encryption.
#[derive(Debug, Clone)]
pub struct BlsScryptParams {
    /// Log2 of the CPU/memory cost parameter.
    pub n: u32,
    /// Block size.
    pub r: u32,
    /// Parallelization.
    pub p: u32,
    /// Derived key length.
    pub dklen: u32,
}

impl Default for BlsScryptParams {
    /// Default parameters matching EIP-2335 spec (N=262144, r=8, p=1).
    fn default() -> Self {
        Self {
            n: 262144,
            r: 8,
            p: 1,
            dklen: 32,
        }
    }
}

impl BlsScryptParams {
    /// Light parameters for testing (faster, less secure).
    #[must_use]
    pub fn light() -> Self {
        Self {
            n: 4096,
            r: 8,
            p: 1,
            dklen: 32,
        }
    }
}

/// An encrypted BLS keystore (EIP-2335 v4 format).
#[derive(Clone)]
pub struct BlsKeystore {
    /// UUID for this keystore.
    pub uuid: String,
    /// BLS public key (48 bytes, hex-encoded without 0x prefix).
    pub pubkey: String,
    /// Path used for key derivation (e.g., "m/12381/3600/0/0/0").
    pub path: String,
    /// Scrypt parameters.
    scrypt_params: BlsScryptParams,
    /// Scrypt salt (32 bytes).
    salt: Vec<u8>,
    /// AES-128-CTR IV (16 bytes).
    iv: Vec<u8>,
    /// Encrypted secret key ciphertext.
    ciphertext: Vec<u8>,
    /// SHA-256 checksum.
    checksum: [u8; 32],
}

impl BlsKeystore {
    /// Encrypt a BLS secret key into an EIP-2335 keystore.
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt(
        secret_key: &[u8],
        pubkey_bytes: &[u8],
        password: &[u8],
        path: &str,
        params: &BlsScryptParams,
    ) -> Result<Self, SignerError> {
        if secret_key.len() != 32 {
            return Err(SignerError::InvalidPrivateKey(
                "BLS secret key must be 32 bytes".into(),
            ));
        }

        let mut salt = vec![0u8; 32];
        crate::security::secure_random(&mut salt)?;
        let mut iv = vec![0u8; 16];
        crate::security::secure_random(&mut iv)?;

        let mut uuid_bytes = [0u8; 16];
        crate::security::secure_random(&mut uuid_bytes)?;
        uuid_bytes[6] = (uuid_bytes[6] & 0x0F) | 0x40;
        uuid_bytes[8] = (uuid_bytes[8] & 0x3F) | 0x80;
        let uuid = format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            u32::from_be_bytes([uuid_bytes[0], uuid_bytes[1], uuid_bytes[2], uuid_bytes[3]]),
            u16::from_be_bytes([uuid_bytes[4], uuid_bytes[5]]),
            u16::from_be_bytes([uuid_bytes[6], uuid_bytes[7]]),
            u16::from_be_bytes([uuid_bytes[8], uuid_bytes[9]]),
            u64::from_be_bytes([
                0,
                0,
                uuid_bytes[10],
                uuid_bytes[11],
                uuid_bytes[12],
                uuid_bytes[13],
                uuid_bytes[14],
                uuid_bytes[15],
            ])
        );

        let dk = derive_scrypt_key(password, &salt, params)?;
        let aes_key = &dk[..16];
        let checksum_key = &dk[16..32];

        let mut ciphertext = secret_key.to_vec();
        let mut cipher = Aes128Ctr::new(aes_key.into(), iv.as_slice().into());
        cipher.apply_keystream(&mut ciphertext);

        let mut hasher = Sha256::new();
        hasher.update(checksum_key);
        hasher.update(&ciphertext);
        let checksum_result = hasher.finalize();
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&checksum_result);

        Ok(Self {
            uuid,
            pubkey: hex::encode(pubkey_bytes),
            path: path.to_string(),
            scrypt_params: params.clone(),
            salt,
            iv,
            ciphertext,
            checksum,
        })
    }

    /// Decrypt the BLS secret key from this keystore.
    pub fn decrypt(&self, password: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignerError> {
        let dk = derive_scrypt_key(password, &self.salt, &self.scrypt_params)?;
        let aes_key = &dk[..16];
        let checksum_key = &dk[16..32];

        let mut hasher = Sha256::new();
        hasher.update(checksum_key);
        hasher.update(&self.ciphertext);
        let expected = hasher.finalize();

        if expected[..].ct_eq(&self.checksum).unwrap_u8() == 0 {
            return Err(SignerError::ParseError(
                "EIP-2335: checksum mismatch (wrong password?)".into(),
            ));
        }

        let mut plaintext = Zeroizing::new(self.ciphertext.clone());
        let mut cipher = Aes128Ctr::new(aes_key.into(), self.iv.as_slice().into());
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    }

    /// Serialize the keystore to EIP-2335 JSON format.
    #[must_use]
    pub fn to_json(&self) -> String {
        let salt_hex = hex::encode(&self.salt);
        let checksum_hex = hex::encode(self.checksum);
        let iv_hex = hex::encode(&self.iv);
        let ct_hex = hex::encode(&self.ciphertext);

        let mut j = String::with_capacity(600);
        j.push_str("{\"crypto\":{\"kdf\":{\"function\":\"scrypt\",\"params\":{");
        j.push_str(&format!(
            "\"dklen\":{},\"n\":{},\"r\":{},\"p\":{},\"salt\":\"{}\"",
            self.scrypt_params.dklen,
            self.scrypt_params.n,
            self.scrypt_params.r,
            self.scrypt_params.p,
            salt_hex
        ));
        j.push_str("},\"message\":\"\"},\"checksum\":{\"function\":\"sha256\",\"params\":{},\"message\":\"");
        j.push_str(&checksum_hex);
        j.push_str("\"},\"cipher\":{\"function\":\"aes-128-ctr\",\"params\":{\"iv\":\"");
        j.push_str(&iv_hex);
        j.push_str("\"},\"message\":\"");
        j.push_str(&ct_hex);
        j.push_str("\"}},\"description\":\"\",\"pubkey\":\"");
        j.push_str(&self.pubkey);
        j.push_str("\",\"path\":\"");
        j.push_str(&self.path);
        j.push_str("\",\"uuid\":\"");
        j.push_str(&self.uuid);
        j.push_str(&format!("\",\"version\":{}}}", VERSION));
        j
    }
}

impl fmt::Debug for BlsKeystore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlsKeystore")
            .field("uuid", &self.uuid)
            .field("pubkey", &self.pubkey)
            .field("path", &self.path)
            .field("ciphertext", &"[REDACTED]")
            .field("checksum", &"[REDACTED]")
            .finish()
    }
}

// ─── Internal Helpers ──────────────────────────────────────────────

fn derive_scrypt_key(
    password: &[u8],
    salt: &[u8],
    params: &BlsScryptParams,
) -> Result<Zeroizing<Vec<u8>>, SignerError> {
    let log_n = (params.n as f64).log2() as u8;
    let scrypt_params = scrypt::Params::new(log_n, params.r, params.p, params.dklen as usize)
        .map_err(|e| SignerError::ParseError(format!("scrypt params: {e}")))?;

    let mut dk = Zeroizing::new(vec![0u8; params.dklen as usize]);
    scrypt::scrypt(password, salt, &scrypt_params, &mut dk)
        .map_err(|e| SignerError::ParseError(format!("scrypt failed: {e}")))?;
    Ok(dk)
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn light() -> BlsScryptParams {
        BlsScryptParams::light()
    }

    #[test]
    fn test_bls_keystore_encrypt_decrypt_roundtrip() {
        let sk = [0x42u8; 32];
        let pk = [0xAA; 48];
        let password = b"test-password";

        let keystore =
            BlsKeystore::encrypt(&sk, &pk, password, "m/12381/3600/0/0/0", &light()).unwrap();
        let decrypted = keystore.decrypt(password).unwrap();
        assert_eq!(&*decrypted, &sk);
    }

    #[test]
    fn test_bls_keystore_wrong_password_fails() {
        let sk = [0x42u8; 32];
        let pk = [0xAA; 48];

        let keystore =
            BlsKeystore::encrypt(&sk, &pk, b"correct", "m/12381/3600/0/0/0", &light()).unwrap();
        let result = keystore.decrypt(b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_bls_keystore_pubkey_matches() {
        let sk = [0x42u8; 32];
        let pk = [0xBB; 48];

        let keystore =
            BlsKeystore::encrypt(&sk, &pk, b"pass", "m/12381/3600/0/0/0", &light()).unwrap();
        assert_eq!(keystore.pubkey, hex::encode(pk));
    }

    #[test]
    fn test_bls_keystore_path_stored() {
        let sk = [0x42u8; 32];
        let pk = [0xAA; 48];

        let keystore =
            BlsKeystore::encrypt(&sk, &pk, b"pass", "m/12381/3600/5/0/0", &light()).unwrap();
        assert_eq!(keystore.path, "m/12381/3600/5/0/0");
    }

    #[test]
    fn test_bls_keystore_json_format() {
        let sk = [0x42u8; 32];
        let pk = [0xAA; 48];

        let keystore =
            BlsKeystore::encrypt(&sk, &pk, b"pass", "m/12381/3600/0/0/0", &light()).unwrap();
        let json = keystore.to_json();

        assert!(json.contains("\"version\":4"));
        assert!(json.contains("\"function\":\"scrypt\""));
        assert!(json.contains("\"function\":\"aes-128-ctr\""));
        assert!(json.contains("\"function\":\"sha256\""));
        assert!(json.contains(&format!("\"pubkey\":\"{}\"", hex::encode(pk))));
    }

    #[test]
    fn test_bls_keystore_unique_salts() {
        let sk = [0x42u8; 32];
        let pk = [0xAA; 48];

        let ks1 = BlsKeystore::encrypt(&sk, &pk, b"pass", "", &light()).unwrap();
        let ks2 = BlsKeystore::encrypt(&sk, &pk, b"pass", "", &light()).unwrap();
        assert_ne!(ks1.salt, ks2.salt);
        assert_ne!(ks1.iv, ks2.iv);
        assert_ne!(ks1.uuid, ks2.uuid);
    }

    #[test]
    fn test_bls_keystore_invalid_key_length() {
        let result = BlsKeystore::encrypt(&[0u8; 31], &[0u8; 48], b"pass", "", &light());
        assert!(result.is_err());
    }

    #[test]
    fn test_bls_keystore_with_real_bls_key() {
        use crate::bls::BlsSigner;
        use crate::traits::{KeyPair, Signer, Verifier};

        let signer = BlsSigner::generate().unwrap();
        let sk = signer.private_key_bytes();
        let pk = signer.public_key().to_bytes();

        let keystore =
            BlsKeystore::encrypt(&sk, &pk, b"validator-pass", "m/12381/3600/0/0/0", &light())
                .unwrap();
        let decrypted = keystore.decrypt(b"validator-pass").unwrap();

        let restored = BlsSigner::from_bytes(&decrypted).unwrap();
        let msg = b"attestation";
        let sig = restored.sign(msg).unwrap();
        let verifier = crate::bls::BlsVerifier::from_public_key_bytes(&pk).unwrap();
        assert!(verifier.verify(msg, &sig).unwrap());
    }
}
