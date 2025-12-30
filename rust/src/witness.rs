//! Witness generation for gnark circuit.
//!
//! This module handles the conversion of stwo proofs into witness format
//! that can be consumed by the gnark verifier circuit.

use serde::{Deserialize, Serialize};

/// Represents a Mersenne-31 field element.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct M31 {
    pub value: u32,
}

impl M31 {
    pub fn new(value: u32) -> Self {
        Self { value: value % ((1u64 << 31) - 1) as u32 }
    }

    pub fn zero() -> Self {
        Self { value: 0 }
    }
}

/// Represents a QM31 field element (quartic extension).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QM31 {
    /// Four M31 components: (a + bi) + (c + di)u
    pub values: [M31; 4],
}

impl QM31 {
    pub fn new(a: u32, b: u32, c: u32, d: u32) -> Self {
        Self {
            values: [M31::new(a), M31::new(b), M31::new(c), M31::new(d)],
        }
    }

    pub fn zero() -> Self {
        Self {
            values: [M31::zero(), M31::zero(), M31::zero(), M31::zero()],
        }
    }
}

/// Blake2s hash (256 bits = 8 x 32-bit words).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blake2sHash {
    pub words: [u32; 8],
}

impl Blake2sHash {
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut words = [0u32; 8];
        for i in 0..8 {
            words[i] = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
        }
        Self { words }
    }
}

/// Merkle decommitment proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleDecommitment {
    /// Sibling hashes along the path
    pub hash_witness: Vec<Blake2sHash>,
    /// Column values at the queried positions
    pub column_witness: Vec<M31>,
}

/// FRI layer proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriLayerProof {
    /// Commitment to this layer
    pub commitment: Blake2sHash,
    /// Evaluation values at query positions
    pub eval_values: Vec<QM31>,
    /// Merkle decommitment
    pub decommitment: MerkleDecommitment,
}

/// Complete FRI proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriProof {
    /// First layer (circle-to-line folding)
    pub first_layer: FriLayerProof,
    /// Inner layers (line folding)
    pub inner_layers: Vec<FriLayerProof>,
    /// Last layer polynomial coefficients
    pub last_layer_poly: Vec<QM31>,
}

/// Complete stwo proof in gnark-consumable format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StwoProofWitness {
    /// Merkle commitments for each tree
    pub commitments: Vec<Blake2sHash>,
    /// Sampled values at OOD point (per tree, per column)
    pub sampled_values: Vec<Vec<Vec<QM31>>>,
    /// Merkle decommitments for query positions
    pub decommitments: Vec<MerkleDecommitment>,
    /// Values at query positions
    pub queried_values: Vec<Vec<M31>>,
    /// Proof-of-work nonce
    pub pow_nonce: u64,
    /// FRI proof
    pub fri_proof: FriProof,
}

/// Public inputs for the verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    /// Hash of all public inputs
    pub public_input_hash: Blake2sHash,
}

/// Complete witness input for the gnark circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessInput {
    /// Public inputs
    pub public: PublicInputs,
    /// The proof witness
    pub proof: StwoProofWitness,
    /// Configuration
    pub config: PcsConfig,
    /// Column log sizes per tree
    pub column_log_sizes: Vec<Vec<u32>>,
}

/// PCS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcsConfig {
    /// Proof-of-work bits
    pub pow_bits: u32,
    /// Log of blowup factor
    pub log_blowup_factor: u32,
    /// Log of last layer degree bound
    pub log_last_layer_deg: u32,
    /// Number of FRI queries
    pub num_queries: u32,
}

impl WitnessInput {
    /// Create a new witness input.
    pub fn new(
        public: PublicInputs,
        proof: StwoProofWitness,
        config: PcsConfig,
        column_log_sizes: Vec<Vec<u32>>,
    ) -> Self {
        Self {
            public,
            proof,
            config,
            column_log_sizes,
        }
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Write to file.
    pub fn write_to_file(&self, path: &str) -> std::io::Result<()> {
        let json = self.to_json().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;
        std::fs::write(path, json)
    }

    /// Read from file.
    pub fn read_from_file(path: &str) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        Self::from_json(&json).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })
    }
}

/// Trait for converting stwo types to witness types.
pub trait ToWitness {
    type Output;
    fn to_witness(&self) -> Self::Output;
}
