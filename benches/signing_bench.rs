//! Benchmarks for trad-signer signing operations.
//!
//! Run with: `cargo bench --all-features`

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_ethereum(c: &mut Criterion) {
    use trad_signer::ethereum::{EthereumSigner, EthereumVerifier};
    use trad_signer::traits::{KeyPair, Signer, Verifier};

    let signer = EthereumSigner::generate().unwrap();
    let verifier = EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
    let msg = b"benchmark message for ethereum ecdsa";
    let sig = signer.sign(msg).unwrap();

    c.bench_function("eth_keygen", |b| {
        b.iter(|| EthereumSigner::generate().unwrap())
    });
    c.bench_function("eth_sign", |b| {
        b.iter(|| signer.sign(black_box(msg)).unwrap())
    });
    c.bench_function("eth_verify", |b| {
        b.iter(|| verifier.verify(black_box(msg), black_box(&sig)).unwrap())
    });
    c.bench_function("eth_personal_sign", |b| {
        b.iter(|| signer.personal_sign(black_box(msg)).unwrap())
    });
}

fn bench_bitcoin(c: &mut Criterion) {
    use trad_signer::bitcoin::{BitcoinSigner, BitcoinVerifier};
    use trad_signer::traits::{KeyPair, Signer, Verifier};

    let signer = BitcoinSigner::generate().unwrap();
    let verifier = BitcoinVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
    let msg = b"benchmark message for bitcoin ecdsa";
    let sig = signer.sign(msg).unwrap();

    c.bench_function("btc_keygen", |b| {
        b.iter(|| BitcoinSigner::generate().unwrap())
    });
    c.bench_function("btc_sign", |b| {
        b.iter(|| signer.sign(black_box(msg)).unwrap())
    });
    c.bench_function("btc_verify", |b| {
        b.iter(|| verifier.verify(black_box(msg), black_box(&sig)).unwrap())
    });
}

fn bench_schnorr(c: &mut Criterion) {
    use trad_signer::bitcoin::schnorr::{SchnorrSigner, SchnorrVerifier};
    use trad_signer::traits::{KeyPair, Signer, Verifier};

    let signer = SchnorrSigner::generate().unwrap();
    let verifier = SchnorrVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
    let msg = b"benchmark message for schnorr bip340";
    let sig = signer.sign(msg).unwrap();

    c.bench_function("schnorr_keygen", |b| {
        b.iter(|| SchnorrSigner::generate().unwrap())
    });
    c.bench_function("schnorr_sign", |b| {
        b.iter(|| signer.sign(black_box(msg)).unwrap())
    });
    c.bench_function("schnorr_verify", |b| {
        b.iter(|| verifier.verify(black_box(msg), black_box(&sig)).unwrap())
    });
}

fn bench_solana(c: &mut Criterion) {
    use trad_signer::solana::{SolanaSigner, SolanaVerifier};
    use trad_signer::traits::{KeyPair, Signer, Verifier};

    let signer = SolanaSigner::generate().unwrap();
    let verifier = SolanaVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
    let msg = b"benchmark message for solana ed25519";
    let sig = signer.sign(msg).unwrap();

    c.bench_function("sol_keygen", |b| {
        b.iter(|| SolanaSigner::generate().unwrap())
    });
    c.bench_function("sol_sign", |b| {
        b.iter(|| signer.sign(black_box(msg)).unwrap())
    });
    c.bench_function("sol_verify", |b| {
        b.iter(|| verifier.verify(black_box(msg), black_box(&sig)).unwrap())
    });
}

fn bench_bls(c: &mut Criterion) {
    use trad_signer::bls::{BlsSigner, BlsVerifier, aggregate_signatures, verify_aggregated};
    use trad_signer::traits::{KeyPair, Signer, Verifier};

    let signer = BlsSigner::generate().unwrap();
    let verifier = BlsVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
    let msg = b"benchmark message for bls12-381";
    let sig = signer.sign(msg).unwrap();

    c.bench_function("bls_keygen", |b| {
        b.iter(|| BlsSigner::generate().unwrap())
    });
    c.bench_function("bls_sign", |b| {
        b.iter(|| signer.sign(black_box(msg)).unwrap())
    });
    c.bench_function("bls_verify", |b| {
        b.iter(|| verifier.verify(black_box(msg), black_box(&sig)).unwrap())
    });

    // Aggregation benchmark (10 signatures)
    let signers: Vec<BlsSigner> = (0..10).map(|_| BlsSigner::generate().unwrap()).collect();
    let sigs: Vec<_> = signers.iter().map(|s| s.sign(msg).unwrap()).collect();
    let pks: Vec<_> = signers.iter().map(|s| s.public_key()).collect();
    let agg = aggregate_signatures(&sigs).unwrap();

    c.bench_function("bls_aggregate_10", |b| {
        b.iter(|| aggregate_signatures(black_box(&sigs)).unwrap())
    });
    c.bench_function("bls_verify_agg_10", |b| {
        b.iter(|| verify_aggregated(black_box(&pks), black_box(msg), black_box(&agg)).unwrap())
    });
}

criterion_group!(
    benches,
    bench_ethereum,
    bench_bitcoin,
    bench_schnorr,
    bench_solana,
    bench_bls,
    bench_xrp,
    bench_neo,
    bench_hd_key,
    bench_musig2,
    bench_frost,
    bench_mnemonic,
);
criterion_main!(benches);

fn bench_xrp(c: &mut Criterion) {
    use trad_signer::xrp::{XrpEcdsaSigner, XrpEcdsaVerifier, XrpEddsaSigner, XrpEddsaVerifier};
    use trad_signer::traits::{KeyPair, Signer, Verifier};

    let msg = b"benchmark message for xrp";

    // ECDSA
    let ecdsa = XrpEcdsaSigner::generate().unwrap();
    let ecdsa_v = XrpEcdsaVerifier::from_public_key_bytes(&ecdsa.public_key_bytes()).unwrap();
    let ecdsa_sig = ecdsa.sign(msg).unwrap();

    c.bench_function("xrp_ecdsa_sign", |b| {
        b.iter(|| ecdsa.sign(black_box(msg)).unwrap())
    });
    c.bench_function("xrp_ecdsa_verify", |b| {
        b.iter(|| ecdsa_v.verify(black_box(msg), black_box(&ecdsa_sig)).unwrap())
    });

    // EdDSA
    let eddsa = XrpEddsaSigner::generate().unwrap();
    let eddsa_v = XrpEddsaVerifier::from_public_key_bytes(&eddsa.public_key_bytes()).unwrap();
    let eddsa_sig = eddsa.sign(msg).unwrap();

    c.bench_function("xrp_eddsa_sign", |b| {
        b.iter(|| eddsa.sign(black_box(msg)).unwrap())
    });
    c.bench_function("xrp_eddsa_verify", |b| {
        b.iter(|| eddsa_v.verify(black_box(msg), black_box(&eddsa_sig)).unwrap())
    });
}

fn bench_neo(c: &mut Criterion) {
    use trad_signer::neo::{NeoSigner, NeoVerifier};
    use trad_signer::traits::{KeyPair, Signer, Verifier};

    let signer = NeoSigner::generate().unwrap();
    let verifier = NeoVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
    let msg = b"benchmark message for neo p256";
    let sig = signer.sign(msg).unwrap();

    c.bench_function("neo_keygen", |b| {
        b.iter(|| NeoSigner::generate().unwrap())
    });
    c.bench_function("neo_sign", |b| {
        b.iter(|| signer.sign(black_box(msg)).unwrap())
    });
    c.bench_function("neo_verify", |b| {
        b.iter(|| verifier.verify(black_box(msg), black_box(&sig)).unwrap())
    });
}

fn bench_hd_key(c: &mut Criterion) {
    use trad_signer::hd_key::{ExtendedPrivateKey, DerivationPath};

    let seed = [0x42u8; 64];
    let master = ExtendedPrivateKey::from_seed(&seed).unwrap();

    c.bench_function("hd_derive_eth_m44_60_0_0_0", |b| {
        b.iter(|| {
            master.derive_path(black_box(&DerivationPath::ethereum(0))).unwrap()
        })
    });
    c.bench_function("hd_derive_btc_m84_0_0_0_0", |b| {
        b.iter(|| {
            master.derive_path(black_box(&DerivationPath::bitcoin_segwit(0))).unwrap()
        })
    });
}

fn bench_musig2(c: &mut Criterion) {
    use trad_signer::threshold::musig2::signing::*;

    let sk1 = [0x11u8; 32];
    let sk2 = [0x22u8; 32];
    let pk1 = individual_pubkey(&sk1).unwrap();
    let pk2 = individual_pubkey(&sk2).unwrap();
    let ctx = key_agg(&[pk1, pk2]).unwrap();
    let msg = b"musig2 bench";

    c.bench_function("musig2_2of2_full_sign", |b| {
        b.iter(|| {
            let (s1, p1) = nonce_gen(&sk1, &pk1, &ctx, msg, &[]).unwrap();
            let (s2, p2) = nonce_gen(&sk2, &pk2, &ctx, msg, &[]).unwrap();
            let an = nonce_agg(&[p1, p2]).unwrap();
            let ps1 = sign(s1, &sk1, &ctx, &an, msg).unwrap();
            let ps2 = sign(s2, &sk2, &ctx, &an, msg).unwrap();
            let sig = partial_sig_agg(&[ps1, ps2], &an, &ctx, msg).unwrap();
            black_box(sig)
        })
    });
}

fn bench_frost(c: &mut Criterion) {
    use trad_signer::threshold::frost::{keygen, signing};

    let secret = [0x42u8; 32];
    let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
    let group_pk = kgen.group_public_key;
    let msg = b"frost bench";

    c.bench_function("frost_2of3_full_sign", |b| {
        b.iter(|| {
            let n1 = signing::commit(&kgen.key_packages[0]).unwrap();
            let n2 = signing::commit(&kgen.key_packages[1]).unwrap();
            let comms = vec![n1.commitments.clone(), n2.commitments.clone()];
            let s1 = signing::sign(&kgen.key_packages[0], n1, &comms, msg).unwrap();
            let s2 = signing::sign(&kgen.key_packages[1], n2, &comms, msg).unwrap();
            let sig = signing::aggregate(&comms, &[s1, s2], &group_pk, msg).unwrap();
            black_box(sig)
        })
    });
}

fn bench_mnemonic(c: &mut Criterion) {
    use trad_signer::mnemonic::Mnemonic;

    c.bench_function("mnemonic_generate_12", |b| {
        b.iter(|| Mnemonic::generate(12).unwrap())
    });
    c.bench_function("mnemonic_to_seed", |b| {
        let m = Mnemonic::generate(12).unwrap();
        b.iter(|| m.to_seed(black_box("")))
    });
}
