//! FROST Distributed Key Generation (DKG) — Pedersen-based protocol.
//!
//! Implements a simplified DKG where each participant acts as a dealer,
//! shares their polynomial commitments, and combines shares to derive
//! their final FROST key package without any single trusted dealer.
//!
//! # Protocol Flow
//!
//! 1. **Round 1 — Commitment**: Each participant generates a random polynomial,
//!    computes VSS commitments, and broadcasts them.
//! 2. **Round 2 — Share Distribution**: Each participant evaluates their polynomial
//!    at every other participant's identifier and sends the share privately.
//! 3. **Finalization**: Each participant sums all received shares to get their
//!    final secret share.

use super::keygen::{self, KeyPackage, VssCommitments};
use crate::error::SignerError;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use zeroize::Zeroizing;

/// Round 1 output from a DKG participant.
#[derive(Clone)]
pub struct DkgRound1Package {
    /// This participant's identifier (1-based).
    pub identifier: u16,
    /// VSS commitments for this participant's polynomial.
    pub commitments: VssCommitments,
    /// The secret polynomial (kept private, used in round 2).
    secret_coefficients: Zeroizing<Vec<Scalar>>,
}

impl Drop for DkgRound1Package {
    fn drop(&mut self) {
        // Zeroizing handles cleanup
    }
}

/// Round 2 secret share from one participant to another.
#[derive(Clone)]
pub struct DkgRound2Package {
    /// Sender identifier.
    pub sender: u16,
    /// Receiver identifier.
    pub receiver: u16,
    /// The secret share value.
    pub share: Zeroizing<Scalar>,
}

impl Drop for DkgRound2Package {
    fn drop(&mut self) {
        // Zeroizing handles cleanup
    }
}

/// Generate Round 1 packages for all DKG participants.
///
/// Each participant generates their own random polynomial, computes VSS
/// commitments, and prepares for share distribution.
///
/// # Arguments
/// - `min_signers` — Threshold (t), minimum number of signers needed
/// - `max_signers` — Total number of participants (n)
///
/// # Returns
/// A vector of Round 1 packages, one per participant.
pub fn dkg_round1(
    min_signers: u16,
    max_signers: u16,
) -> Result<Vec<DkgRound1Package>, SignerError> {
    if min_signers < 2 || max_signers < min_signers {
        return Err(SignerError::ParseError(
            "DKG requires min_signers >= 2 and max_signers >= min_signers".into(),
        ));
    }

    let mut packages = Vec::with_capacity(max_signers as usize);

    for i in 1..=max_signers {
        // Generate random polynomial of degree (t-1)
        let mut coefficients = Vec::with_capacity(min_signers as usize);
        for _ in 0..min_signers {
            coefficients.push(keygen::random_scalar()?);
        }

        // Compute VSS commitments: C_k = G * a_k
        let commitment_points = coefficients
            .iter()
            .map(|c| (ProjectivePoint::GENERATOR * c).to_affine())
            .collect();

        packages.push(DkgRound1Package {
            identifier: i,
            commitments: VssCommitments {
                commitments: commitment_points,
            },
            secret_coefficients: Zeroizing::new(coefficients),
        });
    }

    Ok(packages)
}

/// Generate Round 2 packages — secret shares from each participant to every other.
///
/// Each participant evaluates their secret polynomial at every other participant's
/// identifier and creates a share for them.
pub fn dkg_round2(
    round1_packages: &[DkgRound1Package],
) -> Result<Vec<Vec<DkgRound2Package>>, SignerError> {
    let n = round1_packages.len();
    let mut all_shares = Vec::with_capacity(n);

    for sender_pkg in round1_packages {
        let mut shares_from_sender = Vec::with_capacity(n);

        for receiver_pkg in round1_packages {
            let receiver_id = receiver_pkg.identifier;
            let x = Scalar::from(u64::from(receiver_id));

            let share = keygen::polynomial_evaluate(&x, &sender_pkg.secret_coefficients);

            shares_from_sender.push(DkgRound2Package {
                sender: sender_pkg.identifier,
                receiver: receiver_id,
                share: Zeroizing::new(share),
            });
        }

        all_shares.push(shares_from_sender);
    }

    Ok(all_shares)
}

/// Finalize the DKG: each participant combines all received shares.
///
/// # Arguments
/// - `participant_id` — This participant's identifier  
/// - `round1_packages` — All Round 1 packages (for verification and group key)
/// - `received_shares` — Round 2 shares received by this participant
/// - `min_signers` — Threshold
/// - `max_signers` — Total participants
///
/// # Returns
/// A `KeyPackage` compatible with the existing FROST signing module, and the group public key.
pub fn dkg_finalize(
    participant_id: u16,
    round1_packages: &[DkgRound1Package],
    received_shares: &[DkgRound2Package],
    min_signers: u16,
    max_signers: u16,
) -> Result<(KeyPackage, AffinePoint), SignerError> {
    // Verify all received shares against VSS commitments
    for share in received_shares {
        let sender_idx = match share.sender.checked_sub(1) {
            Some(idx) => idx as usize,
            None => {
                return Err(SignerError::ParseError(
                    "invalid sender id: must be >= 1".into(),
                ))
            }
        };
        if sender_idx >= round1_packages.len() {
            return Err(SignerError::ParseError("invalid sender id".into()));
        }
        let valid = round1_packages[sender_idx]
            .commitments
            .verify_share(participant_id, &share.share);
        if !valid {
            return Err(SignerError::SigningFailed(format!(
                "VSS verification failed for share from participant {}",
                share.sender
            )));
        }
    }

    // Sum all received shares to get the final secret share
    let mut final_share = Scalar::ZERO;
    for share in received_shares {
        final_share += share.share.as_ref();
    }

    // Compute the group public key: sum of all C_0 commitments
    let mut group_pk = ProjectivePoint::IDENTITY;
    for pkg in round1_packages {
        if pkg.commitments.commitments.is_empty() {
            return Err(SignerError::ParseError(
                "DKG round1 package has empty commitments".into(),
            ));
        }
        group_pk += ProjectivePoint::from(pkg.commitments.commitments[0]);
    }
    let group_public_key = group_pk.to_affine();

    let key_package = KeyPackage {
        identifier: participant_id,
        secret_share: Zeroizing::new(final_share),
        group_public_key,
        min_participants: min_signers,
        max_participants: max_signers,
    };

    Ok((key_package, group_public_key))
}

// ═══════════════════════════════════════════════════════════════════
// Key Resharing
// ═══════════════════════════════════════════════════════════════════

/// Reshare key packages to a new set of participants.
///
/// This allows changing the threshold or the participant set without
/// changing the group public key.
///
/// # Arguments
/// - `old_key_packages` — Existing key packages from old participants
/// - `new_min_signers` — New threshold
/// - `new_max_signers` — New number of participants
pub fn reshare(
    old_key_packages: &[KeyPackage],
    new_min_signers: u16,
    new_max_signers: u16,
) -> Result<Vec<KeyPackage>, SignerError> {
    if old_key_packages.is_empty() {
        return Err(SignerError::ParseError("no key packages to reshare".into()));
    }
    if new_min_signers < 2 || new_max_signers < new_min_signers {
        return Err(SignerError::ParseError(
            "reshare requires new_min >= 2, new_max >= new_min".into(),
        ));
    }

    let min_old = old_key_packages[0].min_participants as usize;
    if old_key_packages.len() < min_old {
        return Err(SignerError::ParseError(
            "need at least min_signers old packages for resharing".into(),
        ));
    }

    // Reconstruct the group secret using Lagrange interpolation
    let participants: Vec<Scalar> = old_key_packages[..min_old]
        .iter()
        .map(|kp| Scalar::from(u64::from(kp.identifier)))
        .collect();

    let mut group_secret = Scalar::ZERO;
    for (i, kp) in old_key_packages[..min_old].iter().enumerate() {
        let lambda = keygen::derive_interpolating_value(&participants[i], &participants)?;
        group_secret += *kp.secret_share() * lambda;
    }

    // Re-split with new parameters
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&group_secret.to_bytes());
    let output = keygen::trusted_dealer_keygen(&secret_bytes, new_min_signers, new_max_signers)?;

    Ok(output.key_packages)
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_dkg_round1() {
        let packages = dkg_round1(2, 3).unwrap();
        assert_eq!(packages.len(), 3);
        for (i, pkg) in packages.iter().enumerate() {
            assert_eq!(pkg.identifier, (i + 1) as u16);
            assert_eq!(pkg.commitments.commitments.len(), 2); // degree t-1 = 1
        }
    }

    #[test]
    fn test_dkg_round2() {
        let round1 = dkg_round1(2, 3).unwrap();
        let round2 = dkg_round2(&round1).unwrap();
        assert_eq!(round2.len(), 3);
        for shares in &round2 {
            assert_eq!(shares.len(), 3);
        }
    }

    #[test]
    fn test_dkg_full_protocol() {
        let round1 = dkg_round1(2, 3).unwrap();
        let round2 = dkg_round2(&round1).unwrap();

        let shares_for_1: Vec<DkgRound2Package> = round2
            .iter()
            .filter_map(|ss| ss.iter().find(|s| s.receiver == 1).cloned())
            .collect();
        let (key1, gpk1) = dkg_finalize(1, &round1, &shares_for_1, 2, 3).unwrap();

        let shares_for_2: Vec<DkgRound2Package> = round2
            .iter()
            .filter_map(|ss| ss.iter().find(|s| s.receiver == 2).cloned())
            .collect();
        let (key2, gpk2) = dkg_finalize(2, &round1, &shares_for_2, 2, 3).unwrap();

        // All participants agree on the group public key
        assert_eq!(gpk1, gpk2);
        assert_eq!(key1.identifier, 1);
        assert_eq!(key2.identifier, 2);
    }

    #[test]
    fn test_dkg_invalid_params() {
        assert!(dkg_round1(1, 3).is_err());
        assert!(dkg_round1(4, 3).is_err());
    }

    #[test]
    fn test_dkg_3_of_5() {
        let round1 = dkg_round1(3, 5).unwrap();
        assert_eq!(round1.len(), 5);
        for pkg in &round1 {
            assert_eq!(pkg.commitments.commitments.len(), 3);
        }
    }

    #[test]
    fn test_reshare_changes_threshold() {
        let secret = [0x42u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        let new_packages = reshare(&kgen.key_packages, 3, 5).unwrap();
        assert_eq!(new_packages.len(), 5);
        assert_eq!(new_packages[0].min_participants, 3);
        assert_eq!(new_packages[0].max_participants, 5);
    }

    #[test]
    fn test_reshare_preserves_group_key() {
        let secret = [0x42u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        let original_gpk = kgen.group_public_key;
        let new_packages = reshare(&kgen.key_packages, 2, 4).unwrap();
        // Group public key should be preserved
        assert_eq!(new_packages[0].group_public_key, original_gpk);
    }
}
