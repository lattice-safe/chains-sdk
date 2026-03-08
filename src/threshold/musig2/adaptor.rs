//! MuSig2 Adaptor Signatures and Key Aggregation Coefficient Caching.
//!
//! Extends MuSig2 with:
//! - **Adaptor Signatures**: Encrypt partial signatures under an adaptor point.
//!   The final signature reveals the adaptor secret (useful for atomic swaps).
//! - **Key Aggregation Caching**: Cache expensive key aggregation computations
//!   for repeated signing sessions with the same key set.

use crate::error::SignerError;
use core::fmt;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar};

use super::signing::{KeyAggContext, PartialSignature};

// ═══════════════════════════════════════════════════════════════════
// Adaptor Signatures
// ═══════════════════════════════════════════════════════════════════

/// An adaptor (pre-)signature that can be completed with the adaptor secret.
#[derive(Clone)]
pub struct AdaptorSignature {
    /// The adaptor point `T` (compressed, 33 bytes).
    pub adaptor_point: [u8; 33],
    /// The adapted nonce point `R' = R + T` x-coordinate (32 bytes).
    pub adapted_r: [u8; 32],
    /// The partial adaptor signature scalar `s'`.
    pub s_adaptor: Scalar,
}

impl fmt::Debug for AdaptorSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdaptorSignature")
            .field("adaptor_point", &hex::encode(self.adaptor_point))
            .field("adapted_r", &hex::encode(self.adapted_r))
            .field("s_adaptor", &"[REDACTED]")
            .finish()
    }
}

impl AdaptorSignature {
    /// Complete the adaptor signature by revealing the adaptor secret.
    ///
    /// Given the adaptor secret scalar `t`, computes the final signature `s = s' + t`.
    ///
    /// # Returns
    /// A 64-byte Schnorr signature `(R', s)`.
    #[must_use]
    pub fn complete(&self, adaptor_secret: &Scalar) -> [u8; 64] {
        let s = self.s_adaptor + adaptor_secret;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.adapted_r);
        sig[32..].copy_from_slice(&s.to_bytes());
        sig
    }

    /// Extract the adaptor secret from a completed signature.
    ///
    /// Given the completed signature `s` and the adaptor signature `s'`,
    /// computes `t = s - s'` to learn the adaptor secret.
    #[must_use]
    pub fn extract_secret(&self, completed_s: &Scalar) -> Scalar {
        *completed_s - self.s_adaptor
    }
}

/// Create an adaptor partial signature.
///
/// The adaptor point `T = t * G` is publicly known. The signer creates
/// a signature encrypted under `T`, such that completing it reveals `t`.
///
/// # Arguments
/// - `partial_sig` — The standard MuSig2 partial signature scalar
/// - `adaptor_point` — The public adaptor point (33 bytes compressed)
/// - `agg_nonce_r_x` — The x-coordinate of the aggregated nonce R (32 bytes)
pub fn create_adaptor_signature(
    partial_sig: &PartialSignature,
    adaptor_point: &[u8; 33],
    agg_nonce_r_x: &[u8; 32],
) -> Result<AdaptorSignature, SignerError> {
    // Parse adaptor point
    let t_affine = {
        let ct = AffinePoint::from_bytes(adaptor_point.into());
        if !bool::from(ct.is_some()) {
            return Err(SignerError::InvalidPublicKey(
                "invalid adaptor point".into(),
            ));
        }
        #[allow(clippy::unwrap_used)]
        ct.unwrap()
    };

    // Parse R point
    let r_affine = {
        let mut r_bytes = [0u8; 33];
        r_bytes[0] = 0x02;
        r_bytes[1..].copy_from_slice(agg_nonce_r_x);
        let ct = AffinePoint::from_bytes((&r_bytes).into());
        if !bool::from(ct.is_some()) {
            return Err(SignerError::InvalidPublicKey(
                "invalid nonce R point".into(),
            ));
        }
        #[allow(clippy::unwrap_used)]
        ct.unwrap()
    };

    // R' = R + T (adapted nonce)
    let adapted = ProjectivePoint::from(r_affine) + ProjectivePoint::from(t_affine);
    let adapted_affine = adapted.to_affine();
    let adapted_encoded = adapted_affine.to_encoded_point(false);
    let mut adapted_r = [0u8; 32];
    if let Some(x) = adapted_encoded.x() {
        adapted_r.copy_from_slice(&x[..]);
    }

    Ok(AdaptorSignature {
        adaptor_point: *adaptor_point,
        adapted_r,
        s_adaptor: partial_sig.s,
    })
}

// ═══════════════════════════════════════════════════════════════════
// Key Aggregation Caching
// ═══════════════════════════════════════════════════════════════════

/// Cached key aggregation state for repeated signing with the same key set.
///
/// Pre-computes the expensive key aggregation coefficients and aggregate key
/// so they can be reused across multiple signing sessions.
#[derive(Clone)]
pub struct CachedKeyAgg {
    /// The underlying key aggregation context.
    pub context: KeyAggContext,
    /// Cache of the individual public keys.
    pub pubkeys: Vec<[u8; 33]>,
}

impl fmt::Debug for CachedKeyAgg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedKeyAgg")
            .field("num_keys", &self.pubkeys.len())
            .field("aggregate_key", &hex::encode(self.context.x_only_pubkey))
            .finish()
    }
}

impl CachedKeyAgg {
    /// Create a cached key aggregation from public keys.
    ///
    /// This performs the key aggregation once and caches the result
    /// for reuse in multiple signing sessions.
    pub fn new(pubkeys: &[[u8; 33]]) -> Result<Self, SignerError> {
        let context = super::signing::key_agg(pubkeys)?;
        Ok(Self {
            context,
            pubkeys: pubkeys.to_vec(),
        })
    }

    /// Get the aggregate public key (x-only, 32 bytes).
    #[must_use]
    pub fn aggregate_pubkey(&self) -> [u8; 32] {
        self.context.x_only_pubkey
    }

    /// Get the number of signers.
    #[must_use]
    pub fn num_signers(&self) -> usize {
        self.pubkeys.len()
    }

    /// Check if a specific public key is part of this key aggregation.
    #[must_use]
    pub fn contains_key(&self, pubkey: &[u8; 33]) -> bool {
        self.pubkeys.contains(pubkey)
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::signing;
    use super::*;
    use k256::elliptic_curve::ops::Reduce;

    #[test]
    fn test_cached_key_agg() {
        let sk1 = [0x01u8; 32];
        let sk2 = [0x02u8; 32];
        let pk1 = signing::individual_pubkey(&sk1).unwrap();
        let pk2 = signing::individual_pubkey(&sk2).unwrap();

        let cached = CachedKeyAgg::new(&[pk1, pk2]).unwrap();
        assert_eq!(cached.num_signers(), 2);
        assert!(cached.contains_key(&pk1));
        assert!(cached.contains_key(&pk2));
        assert!(!cached.contains_key(&[0xFF; 33]));

        let agg_pk = cached.aggregate_pubkey();
        assert_ne!(agg_pk, [0u8; 32]);
    }

    #[test]
    fn test_cached_key_agg_deterministic() {
        let sk1 = [0x01u8; 32];
        let sk2 = [0x02u8; 32];
        let pk1 = signing::individual_pubkey(&sk1).unwrap();
        let pk2 = signing::individual_pubkey(&sk2).unwrap();

        let cached1 = CachedKeyAgg::new(&[pk1, pk2]).unwrap();
        let cached2 = CachedKeyAgg::new(&[pk1, pk2]).unwrap();
        assert_eq!(cached1.aggregate_pubkey(), cached2.aggregate_pubkey());
    }

    #[test]
    fn test_adaptor_complete_extract_roundtrip() {
        let adaptor_secret = Scalar::from(42u64);
        let adaptor_point_proj = ProjectivePoint::GENERATOR * adaptor_secret;
        let adaptor_affine = adaptor_point_proj.to_affine();
        let adaptor_bytes: [u8; 33] = adaptor_affine.to_bytes().into();

        let dummy_s = Scalar::from(100u64);
        let partial = PartialSignature { s: dummy_s };

        // R = 7*G
        let r_point = ProjectivePoint::GENERATOR * Scalar::from(7u64);
        let r_affine = r_point.to_affine();
        let r_encoded = r_affine.to_encoded_point(false);
        let mut r_x = [0u8; 32];
        if let Some(x) = r_encoded.x() {
            r_x.copy_from_slice(x.as_slice());
        }

        let adaptor_sig = create_adaptor_signature(&partial, &adaptor_bytes, &r_x).unwrap();
        let completed = adaptor_sig.complete(&adaptor_secret);
        let completed_s_bytes: [u8; 32] = completed[32..].try_into().unwrap();
        let completed_s = <Scalar as Reduce<k256::U256>>::reduce_bytes(&completed_s_bytes.into());

        let extracted = adaptor_sig.extract_secret(&completed_s);
        assert_eq!(extracted, adaptor_secret);
    }

    #[test]
    fn test_adaptor_signature_structure() {
        let adaptor_secret = Scalar::from(99u64);
        let adaptor_point_proj = ProjectivePoint::GENERATOR * adaptor_secret;
        let adaptor_affine = adaptor_point_proj.to_affine();
        let adaptor_bytes: [u8; 33] = adaptor_affine.to_bytes().into();

        let partial = PartialSignature {
            s: Scalar::from(50u64),
        };
        let r = ProjectivePoint::GENERATOR * Scalar::from(3u64);
        let r_affine = r.to_affine();
        let r_encoded = r_affine.to_encoded_point(false);
        let mut r_x = [0u8; 32];
        if let Some(x) = r_encoded.x() {
            r_x.copy_from_slice(x.as_slice());
        }

        let adaptor = create_adaptor_signature(&partial, &adaptor_bytes, &r_x).unwrap();
        assert_eq!(adaptor.adaptor_point, adaptor_bytes);
        assert_ne!(adaptor.adapted_r, [0u8; 32]);
    }
}
