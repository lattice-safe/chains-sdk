#![no_main]
use libfuzzer_sys::fuzz_target;
use trad_signer::bitcoin::BitcoinSigner;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // BitcoinSigner::from_wif must never panic on arbitrary input
        let _ = BitcoinSigner::from_wif(s);
    }
});
