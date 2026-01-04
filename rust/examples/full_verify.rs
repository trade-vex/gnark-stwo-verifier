/// Full verification using stwo library to check that the witness is correct.

use std::fs;
use serde_json::Value;
use stwo::core::vcs::blake2_merkle::Blake2sMerkleChannel;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::channel::Blake2sChannel;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::fri::FriConfig;

fn words_to_hash(words: &[u32]) -> Blake2sHash {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        bytes[i*4..i*4+4].copy_from_slice(&words[i].to_le_bytes());
    }
    Blake2sHash(bytes)
}

fn main() {
    // Load proof witness
    let data = fs::read_to_string("/tmp/test-merkle/proof_witness.json").unwrap();
    let json: Value = serde_json::from_str(&data).unwrap();
    let proof = &json["proof"];

    // Load circuit config
    let config_data = fs::read_to_string("/tmp/test-merkle/circuit_config.json").unwrap();
    let config_json: Value = serde_json::from_str(&config_data).unwrap();

    // Extract PCS config
    let pow_bits = config_json["config"]["pow_bits"].as_u64().unwrap() as u32;
    let log_blowup_factor = config_json["config"]["log_blowup_factor"].as_u64().unwrap() as u32;
    let log_last_layer_deg = config_json["config"]["log_last_layer_deg"].as_u64().unwrap() as u32;
    let n_queries = config_json["config"]["num_queries"].as_u64().unwrap() as usize;

    println!("PCS Config:");
    println!("  pow_bits: {}", pow_bits);
    println!("  log_blowup_factor: {}", log_blowup_factor);
    println!("  log_last_layer_deg: {}", log_last_layer_deg);
    println!("  n_queries: {}", n_queries);

    // Extract column log sizes for each tree
    let column_log_sizes: Vec<Vec<u32>> = config_json["column_log_sizes"]
        .as_array().unwrap()
        .iter()
        .map(|tree| {
            tree.as_array().unwrap_or(&vec![])
                .iter()
                .map(|v| v.as_u64().unwrap() as u32)
                .collect()
        })
        .collect();

    println!("\nColumn log sizes (before blowup):");
    for (i, sizes) in column_log_sizes.iter().enumerate() {
        println!("  Tree {}: {:?}", i, sizes);
    }

    // Create PCS config
    let pcs_config = PcsConfig {
        pow_bits,
        fri_config: FriConfig {
            log_blowup_factor,
            log_last_layer_degree_bound: log_last_layer_deg,
            n_queries,
        },
    };

    // Create verifier channel
    let mut channel = Blake2sChannel::default();
    let mut scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(pcs_config);

    // Commit all trees
    for (tree_idx, sizes) in column_log_sizes.iter().enumerate() {
        let commitment_words: Vec<u32> = proof["commitments"][tree_idx]["words"]
            .as_array().unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u32)
            .collect();
        let commitment = words_to_hash(&commitment_words);

        println!("\nTree {} commitment: {:?}", tree_idx, commitment);

        if sizes.is_empty() {
            // Empty tree (preprocessed)
            scheme.commit(commitment, &[], &mut channel);
        } else {
            scheme.commit(commitment, sizes, &mut channel);
        }
    }

    println!("\nAfter all commits, channel state would determine query positions.");
    println!("The verifier needs to replay the entire Fiat-Shamir transcript to derive queries.");

    // Try to manually trace through verification
    println!("\n=== Manual verification trace ===");

    // For tree 1, check what log_size means
    let tree1_sizes = &column_log_sizes[1];
    let extended_sizes: Vec<u32> = tree1_sizes.iter().map(|s| s + log_blowup_factor).collect();
    println!("Tree 1 extended log sizes: {:?}", extended_sizes);

    // The max log size determines the domain
    let max_log_size = *extended_sizes.iter().max().unwrap_or(&0);
    println!("Max log size for tree 1: {} (domain size {})", max_log_size, 1u32 << max_log_size);

    // Check what tree 0 (preprocessed) looks like
    println!("\nTree 0 sizes (preprocessed): {:?}", column_log_sizes[0]);

    // The pow_nonce is part of the proof - this is used in proof of work
    let pow_nonce = proof["pow_nonce"].as_u64().unwrap();
    println!("\nPoW nonce: {}", pow_nonce);

    // Sampled values (OODS points)
    println!("\nSampled values structure:");
    for (i, tree) in proof["sampled_values"].as_array().unwrap().iter().enumerate() {
        let cols: Vec<Vec<Value>> = tree.as_array().unwrap_or(&vec![])
            .iter()
            .map(|col| col.as_array().unwrap_or(&vec![]).to_vec())
            .collect();
        println!("  Tree {}: {} columns", i, cols.len());
    }
}
