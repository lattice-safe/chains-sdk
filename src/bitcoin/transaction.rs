//! Bitcoin transaction serialization and ID computation.
//!
//! Provides lightweight, consensus-correct serialization for Bitcoin
//! transactions (both legacy and SegWit/witness formats).

use crate::crypto;
use crate::encoding;

// ─── Transaction Components ─────────────────────────────────────────

/// A transaction outpoint (reference to a previous output).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutPoint {
    /// Previous transaction ID (32 bytes, internal byte order).
    pub txid: [u8; 32],
    /// Output index within that transaction.
    pub vout: u32,
}

/// A transaction input.
#[derive(Clone, Debug)]
pub struct TxIn {
    /// The outpoint being spent.
    pub previous_output: OutPoint,
    /// The scriptSig (empty for SegWit inputs).
    pub script_sig: Vec<u8>,
    /// Sequence number (0xFFFFFFFF = final).
    pub sequence: u32,
}

/// A transaction output.
#[derive(Clone, Debug)]
pub struct TxOut {
    /// Value in satoshis.
    pub value: u64,
    /// The scriptPubKey.
    pub script_pubkey: Vec<u8>,
}

/// A Bitcoin transaction with optional witness data.
#[derive(Clone, Debug)]
pub struct Transaction {
    /// Transaction version (typically 1 or 2).
    pub version: i32,
    /// Transaction inputs.
    pub inputs: Vec<TxIn>,
    /// Transaction outputs.
    pub outputs: Vec<TxOut>,
    /// Per-input witness stacks (empty for legacy transactions).
    pub witnesses: Vec<Vec<Vec<u8>>>,
    /// Lock time.
    pub locktime: u32,
}

impl Transaction {
    /// Create a new empty transaction.
    #[must_use]
    pub fn new(version: i32) -> Self {
        Self {
            version,
            inputs: Vec::new(),
            outputs: Vec::new(),
            witnesses: Vec::new(),
            locktime: 0,
        }
    }

    /// Returns true if any input has witness data.
    #[must_use]
    pub fn has_witness(&self) -> bool {
        self.witnesses.iter().any(|w| !w.is_empty())
    }

    /// Serialize without witness data (used for txid computation).
    #[must_use]
    pub fn serialize_legacy(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        // Version (4 bytes LE)
        buf.extend_from_slice(&self.version.to_le_bytes());

        // Input count
        encoding::encode_compact_size(&mut buf, self.inputs.len() as u64);
        for input in &self.inputs {
            buf.extend_from_slice(&input.previous_output.txid);
            buf.extend_from_slice(&input.previous_output.vout.to_le_bytes());
            encoding::encode_compact_size(&mut buf, input.script_sig.len() as u64);
            buf.extend_from_slice(&input.script_sig);
            buf.extend_from_slice(&input.sequence.to_le_bytes());
        }

        // Output count
        encoding::encode_compact_size(&mut buf, self.outputs.len() as u64);
        for output in &self.outputs {
            buf.extend_from_slice(&output.value.to_le_bytes());
            encoding::encode_compact_size(&mut buf, output.script_pubkey.len() as u64);
            buf.extend_from_slice(&output.script_pubkey);
        }

        // Locktime (4 bytes LE)
        buf.extend_from_slice(&self.locktime.to_le_bytes());

        buf
    }

    /// Serialize with witness data (BIP-144 format).
    ///
    /// If no witnesses exist, falls back to legacy serialization.
    #[must_use]
    pub fn serialize_witness(&self) -> Vec<u8> {
        if !self.has_witness() {
            return self.serialize_legacy();
        }

        let mut buf = Vec::with_capacity(512);

        // Version
        buf.extend_from_slice(&self.version.to_le_bytes());

        // Witness marker + flag
        buf.push(0x00); // marker
        buf.push(0x01); // flag

        // Inputs
        encoding::encode_compact_size(&mut buf, self.inputs.len() as u64);
        for input in &self.inputs {
            buf.extend_from_slice(&input.previous_output.txid);
            buf.extend_from_slice(&input.previous_output.vout.to_le_bytes());
            encoding::encode_compact_size(&mut buf, input.script_sig.len() as u64);
            buf.extend_from_slice(&input.script_sig);
            buf.extend_from_slice(&input.sequence.to_le_bytes());
        }

        // Outputs
        encoding::encode_compact_size(&mut buf, self.outputs.len() as u64);
        for output in &self.outputs {
            buf.extend_from_slice(&output.value.to_le_bytes());
            encoding::encode_compact_size(&mut buf, output.script_pubkey.len() as u64);
            buf.extend_from_slice(&output.script_pubkey);
        }

        // Witness data for each input
        for (i, _input) in self.inputs.iter().enumerate() {
            let witness_stack = self.witnesses.get(i);
            match witness_stack {
                Some(stack) if !stack.is_empty() => {
                    encoding::encode_compact_size(&mut buf, stack.len() as u64);
                    for item in stack {
                        encoding::encode_compact_size(&mut buf, item.len() as u64);
                        buf.extend_from_slice(item);
                    }
                }
                _ => {
                    buf.push(0x00); // empty witness
                }
            }
        }

        // Locktime
        buf.extend_from_slice(&self.locktime.to_le_bytes());

        buf
    }

    /// Compute the transaction ID (double-SHA256 of legacy serialization, reversed).
    ///
    /// The txid is displayed in reversed byte order by convention.
    #[must_use]
    pub fn txid(&self) -> [u8; 32] {
        let mut hash = crypto::double_sha256(&self.serialize_legacy());
        hash.reverse(); // Bitcoin displays txid in reversed byte order
        hash
    }

    /// Compute the witness transaction ID (wtxid).
    ///
    /// For legacy transactions, wtxid == txid.
    #[must_use]
    pub fn wtxid(&self) -> [u8; 32] {
        let mut hash = crypto::double_sha256(&self.serialize_witness());
        hash.reverse();
        hash
    }

    /// Compute the virtual size (vsize) for fee calculation.
    ///
    /// `vsize = ceil((weight + 3) / 4)` where
    /// `weight = base_size * 3 + total_size`
    #[must_use]
    pub fn vsize(&self) -> usize {
        let base_size = self.serialize_legacy().len();
        let total_size = self.serialize_witness().len();
        let weight = base_size * 3 + total_size;
        weight.div_ceil(4)
    }
}

/// Parse a raw unsigned transaction (no witness) into a `Transaction` struct.
///
/// This is the inverse of `Transaction::serialize_legacy()`. Used by the PSBT
/// signer to reconstruct the transaction for sighash computation.
pub fn parse_unsigned_tx(data: &[u8]) -> Result<Transaction, crate::error::SignerError> {
    use crate::error::SignerError;

    /// Convert u64 to usize, rejecting overflow on 32-bit platforms.
    fn safe_usize(val: u64) -> Result<usize, SignerError> {
        usize::try_from(val).map_err(|_| SignerError::ParseError(
            format!("compact size {val} exceeds platform usize")
        ))
    }

    let mut off;

    // version (4 bytes LE)
    if data.len() < 4 {
        return Err(SignerError::ParseError("tx too short for version".into()));
    }
    let version = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    off = 4;

    // input count
    let input_count = safe_usize(encoding::read_compact_size(data, &mut off)?)?;

    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        if off + 36 > data.len() {
            return Err(SignerError::ParseError("tx truncated in input outpoint".into()));
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[off..off + 32]);
        off += 32;
        let vout = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        off += 4;

        let script_len = safe_usize(encoding::read_compact_size(data, &mut off)?)?;
        if off + script_len > data.len() {
            return Err(SignerError::ParseError("tx truncated in scriptSig".into()));
        }
        let script_sig = data[off..off + script_len].to_vec();
        off += script_len;

        if off + 4 > data.len() {
            return Err(SignerError::ParseError("tx truncated in sequence".into()));
        }
        let sequence = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        off += 4;

        inputs.push(TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig,
            sequence,
        });
    }

    // output count
    let output_count = safe_usize(encoding::read_compact_size(data, &mut off)?)?;

    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        if off + 8 > data.len() {
            return Err(SignerError::ParseError("tx truncated in output value".into()));
        }
        let mut val_bytes = [0u8; 8];
        val_bytes.copy_from_slice(&data[off..off + 8]);
        let value = u64::from_le_bytes(val_bytes);
        off += 8;

        let spk_len = safe_usize(encoding::read_compact_size(data, &mut off)?)?;
        if off + spk_len > data.len() {
            return Err(SignerError::ParseError("tx truncated in scriptPubKey".into()));
        }
        let script_pubkey = data[off..off + spk_len].to_vec();
        off += spk_len;

        outputs.push(TxOut { value, script_pubkey });
    }

    // locktime (4 bytes LE)
    if off + 4 > data.len() {
        return Err(SignerError::ParseError("tx truncated in locktime".into()));
    }
    let locktime = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
    off += 4;

    // Strict parsing: reject trailing bytes
    if off != data.len() {
        return Err(SignerError::ParseError(format!(
            "tx has {} trailing bytes after locktime", data.len() - off
        )));
    }

    Ok(Transaction {
        version,
        inputs,
        outputs,
        witnesses: Vec::new(),
        locktime,
    })
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_tx() -> Transaction {
        let mut tx = Transaction::new(2);
        tx.inputs.push(TxIn {
            previous_output: OutPoint {
                txid: [0xAA; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        });
        tx.outputs.push(TxOut {
            value: 50_000,
            script_pubkey: vec![0x00, 0x14, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
                0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
                0xBB, 0xBB, 0xBB, 0xBB], // P2WPKH scriptPubKey
        });
        tx
    }

    #[test]
    fn test_legacy_serialization_structure() {
        let tx = sample_tx();
        let raw = tx.serialize_legacy();
        // version(4) + input_count(1) + prevout(32+4) + scriptsig_len(1) + seq(4)
        // + output_count(1) + value(8) + spk_len(1) + spk(22) + locktime(4)
        // = 4 + 1 + 36 + 1 + 4 + 1 + 8 + 1 + 22 + 4 = 82
        assert_eq!(raw.len(), 82);
        // Version should be 2
        assert_eq!(&raw[..4], &2i32.to_le_bytes());
    }

    #[test]
    fn test_witness_serialization_no_witness() {
        let tx = sample_tx();
        // No witnesses → witness serialization == legacy
        assert_eq!(tx.serialize_legacy(), tx.serialize_witness());
        assert!(!tx.has_witness());
    }

    #[test]
    fn test_witness_serialization_with_witness() {
        let mut tx = sample_tx();
        tx.witnesses.push(vec![
            vec![0x30; 72], // mock DER signature
            vec![0x02; 33], // mock compressed pubkey
        ]);
        assert!(tx.has_witness());
        let witness_raw = tx.serialize_witness();
        let legacy_raw = tx.serialize_legacy();
        // Witness serialization should be longer (marker+flag+witness data)
        assert!(witness_raw.len() > legacy_raw.len());
        // Witness marker/flag at bytes 4-5
        assert_eq!(witness_raw[4], 0x00); // marker
        assert_eq!(witness_raw[5], 0x01); // flag
    }

    #[test]
    fn test_txid_is_deterministic() {
        let tx = sample_tx();
        assert_eq!(tx.txid(), tx.txid());
    }

    #[test]
    fn test_txid_ne_wtxid_with_witness() {
        let mut tx = sample_tx();
        tx.witnesses.push(vec![vec![0x01; 64]]);
        // txid excludes witness, wtxid includes it
        assert_ne!(tx.txid(), tx.wtxid());
    }

    #[test]
    fn test_txid_eq_wtxid_without_witness() {
        let tx = sample_tx();
        assert_eq!(tx.txid(), tx.wtxid());
    }

    #[test]
    fn test_vsize_legacy() {
        let tx = sample_tx();
        let base = tx.serialize_legacy().len();
        // No witness → vsize == base_size (weight = 4*base, vsize = base)
        assert_eq!(tx.vsize(), base);
    }

    #[test]
    fn test_vsize_segwit_is_discounted() {
        let mut tx = sample_tx();
        tx.witnesses.push(vec![vec![0x30; 72], vec![0x02; 33]]);
        let base = tx.serialize_legacy().len();
        let total = tx.serialize_witness().len();
        let vsize = tx.vsize();
        // With witness, vsize should be less than total_size but >= base_size
        assert!(vsize < total);
        assert!(vsize >= base);
    }

    #[test]
    fn test_outpoint_equality() {
        let o1 = OutPoint { txid: [0x01; 32], vout: 0 };
        let o2 = OutPoint { txid: [0x01; 32], vout: 0 };
        let o3 = OutPoint { txid: [0x02; 32], vout: 0 };
        assert_eq!(o1, o2);
        assert_ne!(o1, o3);
    }

    #[test]
    fn test_empty_transaction() {
        let tx = Transaction::new(1);
        let raw = tx.serialize_legacy();
        // version(4) + input_count(1=0) + output_count(1=0) + locktime(4) = 10
        assert_eq!(raw.len(), 10);
    }

    #[test]
    fn test_multiple_inputs_outputs() {
        let mut tx = Transaction::new(2);
        for i in 0..3 {
            tx.inputs.push(TxIn {
                previous_output: OutPoint { txid: [i as u8; 32], vout: 0 },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            });
        }
        for _ in 0..2 {
            tx.outputs.push(TxOut {
                value: 10_000,
                script_pubkey: vec![0x76, 0xa9, 0x14],
            });
        }
        let raw = tx.serialize_legacy();
        assert!(raw.len() > 10);
        // Ensure it round-trips the input/output counts correctly
        assert_eq!(raw[4], 3); // 3 inputs
    }
}
