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
//! 2. **Circuit Definition**: Intermediate format for constraint evaluation
//! 3. **FFI Exports**: C-compatible functions for calling from Go via CGO
//! 4. **Proof Generation**: Generate example proofs for testing
//!
//! # Architecture
//!
//! The system works in two phases:
//!
//! 1. **Build Phase**: Extract circuit definition from FrameworkEval
//!    - Run Rust code to extract constraints, relations, and LogUp config
//!    - Output `circuit_def.json` containing everything needed for gnark
//!
//! 2. **Runtime Phase**: Build gnark circuit from definition
//!    - Go code parses `circuit_def.json`
//!    - Constructs constraint evaluation circuit
//!    - Uses proof witness for actual values
//!
//! # Usage
//!
//! ```rust,ignore
//! use stwo_gnark::{CircuitDefinition, convert_stark_proof};
//!
//! // Build circuit definition for your AIR
//! let circuit_def = CircuitDefBuilder::new("my_air")
//!     .composition_log_degree_bound(5)
//!     .add_component(component)
//!     .build();
//! circuit_def.write_to_file("circuit_def.json").unwrap();
//!
//! // Convert proof to witness
//! let witness = convert_stark_proof(&proof, column_log_sizes);
//! witness.write_to_file("witness.json").unwrap();
//! ```

pub mod builder;
pub mod circuit_def;
#[cfg(feature = "stwo_support")]
pub mod extractor;
pub mod ffi;
pub mod proof_generators;
pub mod verifier;
pub mod witness;

pub use builder::{Constraint, ConstraintBuilder};
pub use circuit_def::{
    CircuitDefinition, ComponentDef, ConstraintDef, ExprDef, FinalizeMode,
    FractionDef, LogupDef, MaskDef, MaskItem, QM31Def, RelationDef, TreeStructure,
    CircuitDefBuilder, ComponentDefBuilder,
};
pub use proof_generators::{generate_proving_an_air, generate_static_lookups};
pub use verifier::{ProofConverter, VerifierConfig};
pub use witness::{
    Blake2sHash, FriLayerProof, FriProof, M31, MerkleDecommitment, PcsConfig, PublicInputs, QM31,
    StwoProofWitness, WitnessInput,
};

// Re-export stwo conversion when the feature is enabled
#[cfg(feature = "stwo_support")]
pub use verifier::stwo_conversion::convert_stark_proof;

// Re-export extractor when the feature is enabled
#[cfg(feature = "stwo_support")]
pub use extractor::{extract_component_def, extract_circuit_def, ConstraintExtractor};
