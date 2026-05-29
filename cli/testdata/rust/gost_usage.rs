// GOST R 34.11 / Streebog hash via RustCrypto streebog crate
// EXPECTED: GOST3411 | hash | | info |
use streebog::Streebog256;
use streebog::Digest;

fn hash_data(data: &[u8]) -> Vec<u8> {
    let mut hasher = Streebog256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
