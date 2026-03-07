//! Serde bridge for `Zeroizing<Vec<u8>>` fields.
//!
//! Use with `#[serde(with = "crate::serde_zeroizing")]` on struct fields.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// Serialize the inner `Vec<u8>` by dereferencing the `Zeroizing` wrapper.
#[allow(dead_code)]
pub fn serialize<S: Serializer>(val: &Zeroizing<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
    let inner: &Vec<u8> = val;
    inner.serialize(s)
}

/// Deserialize into a `Vec<u8>` and then wrap it in `Zeroizing`.
#[allow(dead_code)]
pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<Vec<u8>>, D::Error> {
    let v = Vec::<u8>::deserialize(d)?;
    Ok(Zeroizing::new(v))
}
