use std::fs;
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stwo::core::fields::m31::{M31, BaseField};
use stwo::core::vcs::blake2_merkle::Blake2sMerkleHasher;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs::verifier::{MerkleVerifier, MerkleDecommitment};
use stwo::core::vcs::MerkleHasher;

fn main() {
    // Load proof witness
    let data = fs::read_to_string("/tmp/witness_out/proof_witness.json").unwrap();
    let json: Value = serde_json::from_str(&data).unwrap();

    let proof = &json["proof"];
    let tree_idx = 1;

    // Get commitment as Blake2sHash
    let commitment_words: Vec<u32> = proof["commitments"][tree_idx]["words"]
        .as_array().unwrap()
        .iter().map(|v| v.as_u64().unwrap() as u32).collect();
    let mut commitment_bytes = [0u8; 32];
    for i in 0..8 {
        commitment_bytes[i*4..i*4+4].copy_from_slice(&commitment_words[i].to_le_bytes());
    }
    let commitment = Blake2sHash(commitment_bytes);
    println!("Tree 1 Commitment: {:?}", commitment);

    // Get queried values as M31
    let queried_values: Vec<BaseField> = proof["queried_values"][tree_idx]
        .as_array().unwrap()
        .iter()
        .map(|v| M31::from(v["value"].as_u64().unwrap() as u32))
        .collect();
    println!("Queried values ({} total): {:?}", queried_values.len(), queried_values);

    // Get hash witnesses as Blake2sHash
    let hash_witnesses: Vec<Blake2sHash> = proof["decommitments"][tree_idx]["hash_witness"]
        .as_array().unwrap()
        .iter()
        .map(|h| {
            let words: Vec<u32> = h["words"].as_array().unwrap()
                .iter().map(|v| v.as_u64().unwrap() as u32).collect();
            let mut bytes = [0u8; 32];
            for i in 0..8 {
                bytes[i*4..i*4+4].copy_from_slice(&words[i].to_le_bytes());
            }
            Blake2sHash(bytes)
        })
        .collect();
    println!("Hash witnesses: {} total", hash_witnesses.len());

    // Get column_witness (should be empty for this tree)
    let column_witness: Vec<BaseField> = proof["decommitments"][tree_idx]["column_witness"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .map(|v| M31::from(v["value"].as_u64().unwrap_or(0) as u32))
        .collect();
    println!("Column witness: {} values", column_witness.len());

    // Create decommitment
    let decommitment = MerkleDecommitment {
        hash_witness: hash_witnesses,
        column_witness,
    };

    // Tree 1 has columns with log_size 4, with blowup factor 1 -> extended log_size 5
    // All 3 columns have the same log_size
    let column_log_sizes = vec![5u32, 5, 5]; // Extended log sizes

    // Create verifier
    let verifier = MerkleVerifier::<Blake2sMerkleHasher>::new(commitment, column_log_sizes);

    // Query positions computed from Fiat-Shamir transcript
    // For columns with extended log_size 5, query positions are in range [0, 31]
    let query_positions = vec![15usize, 18, 26];
    let mut queries_per_log_size: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    queries_per_log_size.insert(5, query_positions.clone());

    println!("\nVerifying with query positions: {:?}", query_positions);

    // Verify
    match verifier.verify(&queries_per_log_size, queried_values.clone(), decommitment) {
        Ok(()) => println!("Verification SUCCESS!"),
        Err(e) => println!("Verification FAILED: {:?}", e),
    }

    // Let's also try to figure out the correct positions by testing
    println!("\n=== Trying different query positions ===");

    // Maybe the positions are different. Let's just verify that hashing works correctly
    // by computing what stwo would compute.
    println!("\n=== Manual hash verification ===");
    let num_cols = 3;
    for (q, &pos) in [15usize, 18, 26].iter().enumerate() {
        let start = q * num_cols;
        let values = &queried_values[start..start+num_cols];
        let hash = Blake2sMerkleHasher::hash_node(None, values);
        println!("Query {} at pos {}: values={:?}", q, pos, values);
        println!("  Leaf hash: {:?}", hash);
    }
}
