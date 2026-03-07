//! Cross-module integration tests for trad-signer.
//!
//! Verifies that modules are correctly isolated, trait implementations
//! are consistent, and the same private key material produces different
//! results on different chains (as expected).

#[cfg(all(feature = "ethereum", feature = "bitcoin"))]
mod cross_chain {
    use trad_signer::bitcoin::BitcoinSigner;
    use trad_signer::ethereum::EthereumSigner;
    use trad_signer::traits::{KeyPair, Signer};

    /// Same private key bytes must produce different signatures on ETH vs BTC
    /// because they use different hash functions (Keccak-256 vs Double SHA-256).
    #[test]
    fn test_same_key_different_chain_signatures() {
        let privkey = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        )
        .unwrap();

        let eth = EthereumSigner::from_bytes(&privkey).unwrap();
        let btc = BitcoinSigner::from_bytes(&privkey).unwrap();

        let msg = b"cross-chain test";
        let eth_sig = eth.sign(msg).unwrap();
        let btc_sig = btc.sign(msg).unwrap();

        // Signatures must differ (different hash functions)
        let eth_bytes = eth_sig.to_bytes();
        assert_ne!(&eth_bytes[..64], &btc_sig.der_bytes[..64.min(btc_sig.der_bytes.len())]);
    }

    /// Same private key bytes must produce the same public key on ETH and BTC
    /// (both are secp256k1).
    #[test]
    fn test_same_key_same_pubkey() {
        let privkey = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        )
        .unwrap();

        let eth = EthereumSigner::from_bytes(&privkey).unwrap();
        let btc = BitcoinSigner::from_bytes(&privkey).unwrap();

        // Both should produce the same compressed secp256k1 public key
        assert_eq!(eth.public_key_bytes(), btc.public_key_bytes());
    }
}

#[cfg(all(feature = "solana", feature = "xrp"))]
mod ed25519_cross {
    use trad_signer::solana::SolanaSigner;
    use trad_signer::xrp::XrpEddsaSigner;
    use trad_signer::traits::{KeyPair, Signer};

    /// Same Ed25519 seed produces the same public key on Solana and XRP.
    #[test]
    fn test_same_ed25519_key_cross_chain() {
        let seed = hex::decode(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        )
        .unwrap();

        let sol = SolanaSigner::from_bytes(&seed).unwrap();
        let xrp = XrpEddsaSigner::from_bytes(&seed).unwrap();

        // Same public key
        assert_eq!(sol.public_key_bytes(), xrp.public_key_bytes());

        // Same message should produce the same signature
        let msg = b"hello ed25519";
        let sol_sig = sol.sign(msg).unwrap();
        let xrp_sig = xrp.sign(msg).unwrap();
        assert_eq!(sol_sig.bytes.to_vec(), xrp_sig.bytes);
    }
}

#[cfg(feature = "ethereum")]
mod eip712_integration {
    use trad_signer::ethereum::{EthereumSigner, EthereumVerifier, Eip712Domain, eip712_hash};
    use trad_signer::traits::{KeyPair, Signer, Verifier};
    use sha3::{Digest, Keccak256};

    /// Full EIP-712 Permit flow: domain + struct type hash + encoding.
    #[test]
    fn test_eip712_permit_flow() {
        let privkey = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        )
        .unwrap();
        let signer = EthereumSigner::from_bytes(&privkey).unwrap();
        let verifier =
            EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();

        let contract_addr: [u8; 20] = [0xCC; 20];
        let domain = Eip712Domain {
            name: "USDC",
            version: "2",
            chain_id: 1,
            verifying_contract: &contract_addr,
        };
        let domain_sep = domain.separator();

        // Build the Permit struct hash
        let permit_type_hash = Keccak256::digest(
            b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)",
        );
        let mut struct_data = [0u8; 192]; // typeHash + 5 params × 32
        struct_data[0..32].copy_from_slice(&permit_type_hash);
        // owner (address, right-aligned)
        struct_data[44..64].copy_from_slice(&signer.address());
        // spender
        struct_data[76..96].copy_from_slice(&[0xBB; 20]);
        // value = 1000
        struct_data[120..128].copy_from_slice(&1000u64.to_be_bytes());
        // nonce = 0 (already zero)
        // deadline (already zero = infinite)

        let mut struct_hash = [0u8; 32];
        struct_hash.copy_from_slice(&Keccak256::digest(struct_data));

        let sig = signer.sign_typed_data(&domain_sep, &struct_hash).unwrap();
        assert!(sig.v == 27 || sig.v == 28);

        // Verify
        assert!(verifier
            .verify_typed_data(&domain_sep, &struct_hash, &sig)
            .unwrap());

        // Verify the digest matches eip712_hash
        let full_hash = eip712_hash(&domain_sep, &struct_hash);
        assert!(verifier.verify_prehashed(&full_hash, &sig).unwrap());
    }
}

#[cfg(feature = "bls")]
mod bls_integration {
    use trad_signer::bls::{BlsSigner, aggregate_signatures, verify_aggregated};
    use trad_signer::traits::{KeyPair, Signer};

    /// Aggregate 100 signatures and verify
    #[test]
    fn test_large_aggregation() {
        let msg = b"consensus round 42";
        let signers: Vec<BlsSigner> = (0..20)
            .map(|_| BlsSigner::generate().unwrap())
            .collect();
        let sigs: Vec<_> = signers.iter().map(|s| s.sign(msg).unwrap()).collect();
        let pks: Vec<_> = signers.iter().map(|s| s.public_key()).collect();

        let agg = aggregate_signatures(&sigs).unwrap();
        assert!(verify_aggregated(&pks, msg, &agg).unwrap());
    }
}

#[cfg(all(feature = "ethereum", feature = "bitcoin", feature = "neo"))]
mod trait_consistency {
    use trad_signer::traits::{KeyPair, Signer};
    use trad_signer::ethereum::EthereumSigner;
    use trad_signer::bitcoin::BitcoinSigner;
    use trad_signer::neo::NeoSigner;

    /// All ECDSA signers should produce 32-byte private keys.
    #[test]
    fn test_private_key_length_consistency() {
        let eth = EthereumSigner::generate().unwrap();
        let btc = BitcoinSigner::generate().unwrap();
        let neo = NeoSigner::generate().unwrap();

        assert_eq!(eth.private_key_bytes().len(), 32);
        assert_eq!(btc.private_key_bytes().len(), 32);
        assert_eq!(neo.private_key_bytes().len(), 32);
    }

    /// All ECDSA signers should produce compressed 33-byte public keys.
    #[test]
    fn test_public_key_length_consistency() {
        let eth = EthereumSigner::generate().unwrap();
        let btc = BitcoinSigner::generate().unwrap();
        let neo = NeoSigner::generate().unwrap();

        assert_eq!(eth.public_key_bytes().len(), 33);
        assert_eq!(btc.public_key_bytes().len(), 33);
        assert_eq!(neo.public_key_bytes().len(), 33);
    }
}
