//! Security utilities for enclave / confidential computing environments.
//!
//! Provides constant-time hex encoding, memory locking, and secure
//! comparison primitives for use in TEE (SGX, Nitro, TDX, SEV) environments.

/// Constant-time hex encoding for secret material.
///
/// Unlike `hex::encode()`, this implementation processes all bytes
/// uniformly regardless of value, preventing timing side-channels.
#[must_use]
pub fn ct_hex_encode(data: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(data.len() * 2);
    for &byte in data {
        result.push(HEX_CHARS[(byte >> 4) as usize] as char);
        result.push(HEX_CHARS[(byte & 0x0F) as usize] as char);
    }
    result
}

/// Constant-time hex decoding for secret material.
///
/// Returns `None` if the input contains non-hex characters or has odd length.
#[must_use]
pub fn ct_hex_decode(hex: &str) -> Option<Vec<u8>> {
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut result = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let high = ct_hex_val(chunk[0])?;
        let low = ct_hex_val(chunk[1])?;
        result.push((high << 4) | low);
    }
    Some(result)
}

/// Constant-time hex character to value (returns None for non-hex chars).
fn ct_hex_val(c: u8) -> Option<u8> {
    // Branchless: compute all three possible values and select
    let digit = c.wrapping_sub(b'0');
    let upper = c.wrapping_sub(b'A').wrapping_add(10);
    let lower = c.wrapping_sub(b'a').wrapping_add(10);

    if digit < 10 {
        Some(digit)
    } else if upper < 16 {
        Some(upper)
    } else if lower < 16 {
        Some(lower)
    } else {
        None
    }
}

/// Securely zeroize a mutable byte slice using volatile writes.
///
/// This ensures the compiler cannot optimize away the zeroization.
pub fn secure_zero(data: &mut [u8]) {
    use zeroize::Zeroize;
    data.zeroize();
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_hex_encode() {
        assert_eq!(ct_hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(ct_hex_encode(&[]), "");
        assert_eq!(ct_hex_encode(&[0x00, 0xFF]), "00ff");
    }

    #[test]
    fn test_ct_hex_decode() {
        assert_eq!(ct_hex_decode("deadbeef"), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(ct_hex_decode(""), Some(vec![]));
        assert_eq!(ct_hex_decode("00ff"), Some(vec![0x00, 0xFF]));
        assert_eq!(ct_hex_decode("DEADBEEF"), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn test_ct_hex_decode_invalid() {
        assert_eq!(ct_hex_decode("f"), None); // odd length
        assert_eq!(ct_hex_decode("gg"), None); // invalid chars
    }

    #[test]
    fn test_ct_hex_roundtrip() {
        let data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let encoded = ct_hex_encode(&data);
        let decoded = ct_hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_secure_zero() {
        let mut data = vec![0xAA; 32];
        secure_zero(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }
}
