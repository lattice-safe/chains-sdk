//! Serde roundtrip tests for all serializable types.
//!
//! Verifies Serialize → JSON → Deserialize → to_bytes produces identical bytes.

#[cfg(all(feature = "serde", feature = "ethereum"))]
#[test]
fn serde_ethereum_signature_roundtrip() {
    use trad_signer::ethereum::EthereumSignature;
    let sig = EthereumSignature {
        r: [0xAA; 32],
        s: [0xBB; 32],
        v: 28,
    };
    let json = serde_json::to_string(&sig).unwrap();
    let restored: EthereumSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig.to_bytes(), restored.to_bytes());
}

#[cfg(all(feature = "serde", feature = "bitcoin"))]
#[test]
fn serde_bitcoin_signature_roundtrip() {
    use trad_signer::bitcoin::BitcoinSigner;
    use trad_signer::traits::{KeyPair, Signer};

    let signer = BitcoinSigner::generate().unwrap();
    let sig = signer.sign(b"serde test").unwrap();
    let json = serde_json::to_string(&sig).unwrap();
    let restored: trad_signer::bitcoin::BitcoinSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig.to_bytes(), restored.to_bytes());
}

#[cfg(all(feature = "serde", feature = "bitcoin"))]
#[test]
fn serde_schnorr_signature_roundtrip() {
    use trad_signer::bitcoin::schnorr::SchnorrSignature;
    let sig = SchnorrSignature { bytes: [0x33; 64] };
    let json = serde_json::to_string(&sig).unwrap();
    let restored: SchnorrSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig.to_bytes(), restored.to_bytes());
}

#[cfg(all(feature = "serde", feature = "solana"))]
#[test]
fn serde_solana_signature_roundtrip() {
    use trad_signer::solana::SolanaSignature;
    let sig = SolanaSignature { bytes: [0x55; 64] };
    let json = serde_json::to_string(&sig).unwrap();
    let restored: SolanaSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig.to_bytes(), restored.to_bytes());
}

#[cfg(all(feature = "serde", feature = "xrp"))]
#[test]
fn serde_xrp_signature_roundtrip() {
    use trad_signer::traits::{KeyPair, Signer};
    use trad_signer::xrp::XrpEcdsaSigner;

    let signer = XrpEcdsaSigner::generate().unwrap();
    let sig = signer.sign(b"serde test").unwrap();
    let json = serde_json::to_string(&sig).unwrap();
    let restored: trad_signer::xrp::XrpSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig.bytes, restored.bytes);
}

#[cfg(all(feature = "serde", feature = "neo"))]
#[test]
fn serde_neo_signature_roundtrip() {
    use trad_signer::neo::NeoSignature;
    let sig = NeoSignature { bytes: [0x77; 64] };
    let json = serde_json::to_string(&sig).unwrap();
    let restored: NeoSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig.to_bytes(), restored.to_bytes());
}

#[cfg(all(feature = "serde", feature = "bls"))]
#[test]
fn serde_bls_signature_roundtrip() {
    use trad_signer::bls::BlsSignature;
    let sig = BlsSignature { bytes: [0xAA; 96] };
    let json = serde_json::to_string(&sig).unwrap();
    let restored: BlsSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig.to_bytes(), restored.to_bytes());
}

#[cfg(all(feature = "serde", feature = "bls"))]
#[test]
fn serde_bls_pubkey_roundtrip() {
    use trad_signer::bls::BlsPublicKey;
    let pk = BlsPublicKey { bytes: [0xBB; 48] };
    let json = serde_json::to_string(&pk).unwrap();
    let restored: BlsPublicKey = serde_json::from_str(&json).unwrap();
    assert_eq!(pk.bytes, restored.bytes);
}

#[cfg(all(feature = "serde", feature = "frost"))]
#[test]
fn serde_frost_signature_roundtrip() {
    use trad_signer::threshold::frost::signing::FrostSignature;
    let sig = FrostSignature {
        r_bytes: vec![0x02; 33],
        s_bytes: [0xCC; 32],
    };
    let json = serde_json::to_string(&sig).unwrap();
    let restored: FrostSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig.to_bytes(), restored.to_bytes());
}

#[cfg(all(feature = "serde", feature = "musig2"))]
#[test]
fn serde_musig2_signature_roundtrip() {
    use trad_signer::threshold::musig2::signing::MuSig2Signature;
    let sig = MuSig2Signature {
        r: [0xDD; 32],
        s: [0xEE; 32],
    };
    let json = serde_json::to_string(&sig).unwrap();
    let restored: MuSig2Signature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig.to_bytes(), restored.to_bytes());
}

#[cfg(all(feature = "serde", feature = "ethereum"))]
#[test]
fn serde_ethereum_signature_json_fields() {
    use trad_signer::ethereum::EthereumSignature;
    let sig = EthereumSignature {
        r: [1; 32],
        s: [2; 32],
        v: 27,
    };
    let json = serde_json::to_string(&sig).unwrap();
    assert!(json.contains("\"v\":27"));
    assert!(json.contains("\"r\""));
    assert!(json.contains("\"s\""));
}
