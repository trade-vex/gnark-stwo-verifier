//! Stwo-Gnark: Witness generator for stwo proof verification in gnark.
//!
//! This crate provides tools to convert stwo proofs into witness format
//! that can be consumed by the gnark verifier circuit.
//!
//! # Overview
//!
//! The gnark verifier is implemented as a direct circuit (not an opcode interpreter).
//! This crate handles:
//!
//! 1. **Witness Generation**: Converting stwo proofs to the JSON format expected by gnark
//! 2. **FFI Exports**: C-compatible functions for calling from Go via CGO
//! 3. **Proof Generation**: Generate example proofs for testing
//!
//! # Usage
//!
//! ```rust,ignore
//! use stwo_gnark::{ProofConverter, VerifierConfig, WitnessInput};
//!
//! let config = VerifierConfig::default();
//! let converter = ProofConverter::new(config);
//! let witness = converter.create_mock_witness();
//! witness.write_to_file("witness.json").unwrap();
//! ```

pub mod builder;
pub mod ffi;
pub mod proof_generators;
pub mod verifier;
pub mod witness;

pub use builder::{Constraint, ConstraintBuilder};
pub use proof_generators::{generate_proving_an_air, generate_static_lookups};
pub use verifier::{ProofConverter, VerifierConfig};
pub use witness::{
    Blake2sHash, FriLayerProof, FriProof, M31, MerkleDecommitment, PcsConfig, PublicInputs, QM31,
    StwoProofWitness, WitnessInput,
};

// Re-export stwo conversion when the feature is enabled
#[cfg(feature = "stwo_support")]
pub use verifier::stwo_conversion::convert_stark_proof;
