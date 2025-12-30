//! Convert a Cairo proof to gnark witness format.
//!
//! Usage:
//!   cargo run -- <proof_path> <output_path>
//!
//! Example:
//!   cargo run -- ../../../../stwo-cairo/stwo_cairo_prover/test_data/test_prove_verify_ret_opcode/proof.json witness.json

use std::env;
use std::path::Path;

use cairo_air::utils::{deserialize_proof_from_file, ProofFormat};
use stwo::core::vcs::poseidon252_merkle::Poseidon252MerkleHasher;
use stwo_gnark::verifier::stwo_conversion::convert_stark_proof_poseidon;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <proof_path> <output_path>", args[0]);
        eprintln!("Example: {} ../../../../stwo-cairo/stwo_cairo_prover/test_data/test_prove_verify_ret_opcode/proof.json witness.json", args[0]);
        std::process::exit(1);
    }

    let proof_path = Path::new(&args[1]);
    let output_path = &args[2];

    println!("Loading Cairo proof from: {}", proof_path.display());

    // Use cairo-air's deserialize function (test data uses Poseidon252)
    let cairo_proof = deserialize_proof_from_file::<Poseidon252MerkleHasher>(
        proof_path,
        ProofFormat::CairoSerde,
    ).expect("Failed to deserialize Cairo proof");

    println!("Cairo proof loaded successfully");

    // Extract column log sizes from the claim
    let log_sizes = cairo_proof.claim.log_sizes();
    let column_log_sizes: Vec<Vec<u32>> = log_sizes.iter().cloned().collect();

    println!("Trees: {}", column_log_sizes.len());
    for (i, tree) in column_log_sizes.iter().enumerate() {
        println!("  Tree {}: {} columns", i, tree.len());
    }

    // Convert StarkProof to gnark witness format
    println!("Converting to gnark witness format...");
    let witness = convert_stark_proof_poseidon(&cairo_proof.stark_proof, column_log_sizes);

    // Write to output file
    witness.write_to_file(output_path)
        .expect("Failed to write witness");

    println!("Witness written to: {}", output_path);
}
