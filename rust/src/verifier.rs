//! Verifier proof conversion for gnark.
//!
//! This module provides functions to convert stwo proofs into the format
//! expected by the gnark verifier circuit.

use crate::witness::{
    Blake2sHash, FriLayerProof, FriProof, M31, MerkleDecommitment, PcsConfig, PublicInputs, QM31,
    StwoProofWitness, WitnessInput,
};

/// Configuration for proof conversion.
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// Number of preprocessed columns
    pub num_preprocessed_columns: usize,
    /// Number of trace columns
    pub num_trace_columns: usize,
    /// Number of interaction columns
    pub num_interaction_columns: usize,
    /// Log size of the trace
    pub log_trace_size: u32,
    /// PCS configuration
    pub pcs_config: PcsConfig,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            num_preprocessed_columns: 0,
            num_trace_columns: 2,
            num_interaction_columns: 4,
            log_trace_size: 20,
            pcs_config: PcsConfig {
                pow_bits: 16,
                log_blowup_factor: 1,
                log_last_layer_deg: 0,
                num_queries: 70,
            },
        }
    }
}

/// Proof converter for generating gnark witness.
pub struct ProofConverter {
    config: VerifierConfig,
}

impl ProofConverter {
    /// Create a new proof converter with the given configuration.
    pub fn new(config: VerifierConfig) -> Self {
        Self { config }
    }

    /// Create a mock witness for testing.
    /// This generates a valid-looking witness structure without actual proof data.
    pub fn create_mock_witness(&self) -> WitnessInput {
        let num_queries = self.config.pcs_config.num_queries as usize;
        let log_domain_size = self.config.log_trace_size + self.config.pcs_config.log_blowup_factor;
        let num_fri_layers = log_domain_size - self.config.pcs_config.log_last_layer_deg;

        // Create mock commitments (4 trees: preprocessed, trace, interaction, composition)
        let commitments = (0..4)
            .map(|i| Blake2sHash {
                words: [i as u32; 8],
            })
            .collect();

        // Create mock sampled values at OOD point
        let sampled_values = self.create_mock_sampled_values();

        // Create mock decommitments
        let decommitments = self.create_mock_decommitments(num_queries, log_domain_size as usize);

        // Create mock queried values
        let queried_values = self.create_mock_queried_values(num_queries);

        // Create mock FRI proof
        let fri_proof = self.create_mock_fri_proof(num_queries, num_fri_layers as usize);

        // Create column log sizes
        let column_log_sizes = vec![
            vec![self.config.log_trace_size; self.config.num_preprocessed_columns],
            vec![self.config.log_trace_size; self.config.num_trace_columns],
            vec![self.config.log_trace_size; self.config.num_interaction_columns],
            vec![self.config.log_trace_size; 8], // composition columns
        ];

        WitnessInput {
            public: PublicInputs {
                public_input_hash: Blake2sHash { words: [0; 8] },
            },
            proof: StwoProofWitness {
                commitments,
                sampled_values,
                decommitments,
                queried_values,
                pow_nonce: 12345,
                fri_proof,
            },
            config: self.config.pcs_config.clone(),
            column_log_sizes,
        }
    }

    fn create_mock_sampled_values(&self) -> Vec<Vec<Vec<QM31>>> {
        // For each tree, for each column, sample a QM31 value
        vec![
            // Preprocessed tree
            (0..self.config.num_preprocessed_columns)
                .map(|_| vec![QM31::new(1, 0, 0, 0)])
                .collect(),
            // Trace tree
            (0..self.config.num_trace_columns)
                .map(|_| vec![QM31::new(2, 0, 0, 0)])
                .collect(),
            // Interaction tree
            (0..self.config.num_interaction_columns)
                .map(|_| vec![QM31::new(3, 0, 0, 0)])
                .collect(),
            // Composition tree (8 columns typically)
            (0..8).map(|_| vec![QM31::new(4, 0, 0, 0)]).collect(),
        ]
    }

    fn create_mock_decommitments(
        &self,
        num_queries: usize,
        log_domain_size: usize,
    ) -> Vec<MerkleDecommitment> {
        // One decommitment per tree
        (0..4)
            .map(|_| MerkleDecommitment {
                hash_witness: (0..log_domain_size * num_queries)
                    .map(|i| Blake2sHash {
                        words: [i as u32; 8],
                    })
                    .collect(),
                column_witness: (0..num_queries * 4)
                    .map(|i| M31::new(i as u32))
                    .collect(),
            })
            .collect()
    }

    fn create_mock_queried_values(&self, num_queries: usize) -> Vec<Vec<M31>> {
        (0..num_queries)
            .map(|q| (0..16).map(|i| M31::new((q * 16 + i) as u32)).collect())
            .collect()
    }

    fn create_mock_fri_proof(&self, num_queries: usize, num_layers: usize) -> FriProof {
        let create_layer = |layer_idx: usize| FriLayerProof {
            commitment: Blake2sHash {
                words: [layer_idx as u32; 8],
            },
            eval_values: (0..num_queries * 2)
                .map(|i| QM31::new(i as u32, 0, 0, 0))
                .collect(),
            decommitment: MerkleDecommitment {
                hash_witness: (0..num_layers * num_queries)
                    .map(|i| Blake2sHash {
                        words: [i as u32; 8],
                    })
                    .collect(),
                column_witness: vec![],
            },
        };

        FriProof {
            first_layer: create_layer(0),
            inner_layers: (1..num_layers).map(|i| create_layer(i)).collect(),
            last_layer_poly: vec![QM31::new(42, 0, 0, 0)],
        }
    }
}

/// Conversion from stwo v1.0.0 proof types.
#[cfg(feature = "stwo_support")]
pub mod stwo_conversion {
    use super::*;
    use stwo::core::fields::m31::BaseField;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::pcs::quotients::CommitmentSchemeProof;
    use stwo::core::proof::StarkProof;
    use stwo::core::vcs::blake2_hash::Blake2sHash as StwoBlake2sHash;
    use stwo::core::vcs::blake2_merkle::Blake2sMerkleHasher;
    use stwo::core::vcs::poseidon252_merkle::Poseidon252MerkleHasher;
    use starknet_ff::FieldElement as FieldElement252;

    /// Convert a stwo StarkProof to gnark witness format.
    pub fn convert_stark_proof(
        proof: &StarkProof<Blake2sMerkleHasher>,
        column_log_sizes: Vec<Vec<u32>>,
    ) -> WitnessInput {
        let commitment_proof: &CommitmentSchemeProof<Blake2sMerkleHasher> = &proof.0;

        // Convert commitments
        let commitments = commitment_proof
            .commitments
            .iter()
            .map(|h| convert_blake2s_hash(h))
            .collect();

        // Convert sampled values
        let sampled_values = commitment_proof
            .sampled_values
            .iter()
            .map(|tree_samples| {
                tree_samples
                    .iter()
                    .map(|col_samples| {
                        col_samples.iter().map(|v| convert_secure_field(v)).collect()
                    })
                    .collect()
            })
            .collect();

        // Convert decommitments
        let decommitments = commitment_proof
            .decommitments
            .iter()
            .map(|d| MerkleDecommitment {
                hash_witness: d.hash_witness.iter().map(|h| convert_blake2s_hash(h)).collect(),
                column_witness: d.column_witness.iter().map(|v| convert_base_field(v)).collect(),
            })
            .collect();

        // Convert queried values
        let queried_values = commitment_proof
            .queried_values
            .iter()
            .map(|tree_values| tree_values.iter().map(|v| convert_base_field(v)).collect())
            .collect();

        // Convert FRI proof
        let fri_proof = convert_fri_proof(&commitment_proof.fri_proof);

        // Create column log sizes in correct format
        let column_log_sizes_converted: Vec<Vec<u32>> = column_log_sizes;

        WitnessInput {
            public: PublicInputs {
                public_input_hash: Blake2sHash { words: [0; 8] }, // Will be computed by circuit
            },
            proof: StwoProofWitness {
                commitments,
                sampled_values,
                decommitments,
                queried_values,
                pow_nonce: commitment_proof.proof_of_work,
                fri_proof,
            },
            config: PcsConfig {
                pow_bits: commitment_proof.config.pow_bits,
                log_blowup_factor: commitment_proof.config.fri_config.log_blowup_factor,
                log_last_layer_deg: commitment_proof.config.fri_config.log_last_layer_degree_bound,
                num_queries: commitment_proof.config.fri_config.n_queries as u32,
            },
            column_log_sizes: column_log_sizes_converted,
        }
    }

    fn convert_blake2s_hash(hash: &StwoBlake2sHash) -> Blake2sHash {
        let bytes = hash.0;
        let mut words = [0u32; 8];
        for i in 0..8 {
            words[i] = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
        }
        Blake2sHash { words }
    }

    fn convert_base_field(v: &BaseField) -> M31 {
        M31 { value: v.0 }
    }

    fn convert_secure_field(v: &SecureField) -> QM31 {
        QM31 {
            values: [
                M31 { value: v.0 .0 .0 },
                M31 { value: v.0 .1 .0 },
                M31 { value: v.1 .0 .0 },
                M31 { value: v.1 .1 .0 },
            ],
        }
    }

    fn convert_fri_proof(
        fri_proof: &stwo::core::fri::FriProof<Blake2sMerkleHasher>,
    ) -> FriProof {
        FriProof {
            first_layer: convert_fri_layer_proof(&fri_proof.first_layer),
            inner_layers: fri_proof
                .inner_layers
                .iter()
                .map(|layer| convert_fri_layer_proof(layer))
                .collect(),
            // LinePoly implements Deref to [SecureField], so we can iterate directly
            last_layer_poly: fri_proof
                .last_layer_poly
                .iter()
                .map(|v| convert_secure_field(v))
                .collect(),
        }
    }

    fn convert_fri_layer_proof(
        layer: &stwo::core::fri::FriLayerProof<Blake2sMerkleHasher>,
    ) -> FriLayerProof {
        FriLayerProof {
            commitment: convert_blake2s_hash(&layer.commitment),
            eval_values: layer.fri_witness.iter().map(|v| convert_secure_field(v)).collect(),
            decommitment: MerkleDecommitment {
                hash_witness: layer
                    .decommitment
                    .hash_witness
                    .iter()
                    .map(|h| convert_blake2s_hash(h))
                    .collect(),
                column_witness: layer
                    .decommitment
                    .column_witness
                    .iter()
                    .map(|v| convert_base_field(v))
                    .collect(),
            },
        }
    }

    // ========================================================================
    // Poseidon252 proof conversion
    // ========================================================================

    /// Convert a stwo StarkProof (Poseidon252) to gnark witness format.
    pub fn convert_stark_proof_poseidon(
        proof: &StarkProof<Poseidon252MerkleHasher>,
        column_log_sizes: Vec<Vec<u32>>,
    ) -> WitnessInput {
        let commitment_proof: &CommitmentSchemeProof<Poseidon252MerkleHasher> = &proof.0;

        // Convert commitments
        let commitments = commitment_proof
            .commitments
            .iter()
            .map(|h| convert_poseidon_hash(h))
            .collect();

        // Convert sampled values
        let sampled_values = commitment_proof
            .sampled_values
            .iter()
            .map(|tree_samples| {
                tree_samples
                    .iter()
                    .map(|col_samples| {
                        col_samples.iter().map(|v| convert_secure_field(v)).collect()
                    })
                    .collect()
            })
            .collect();

        // Convert decommitments
        let decommitments = commitment_proof
            .decommitments
            .iter()
            .map(|d| MerkleDecommitment {
                hash_witness: d.hash_witness.iter().map(|h| convert_poseidon_hash(h)).collect(),
                column_witness: d.column_witness.iter().map(|v| convert_base_field(v)).collect(),
            })
            .collect();

        // Convert queried values
        let queried_values = commitment_proof
            .queried_values
            .iter()
            .map(|tree_values| tree_values.iter().map(|v| convert_base_field(v)).collect())
            .collect();

        // Convert FRI proof
        let fri_proof = convert_fri_proof_poseidon(&commitment_proof.fri_proof);

        WitnessInput {
            public: PublicInputs {
                public_input_hash: Blake2sHash { words: [0; 8] },
            },
            proof: StwoProofWitness {
                commitments,
                sampled_values,
                decommitments,
                queried_values,
                pow_nonce: commitment_proof.proof_of_work,
                fri_proof,
            },
            config: PcsConfig {
                pow_bits: commitment_proof.config.pow_bits,
                log_blowup_factor: commitment_proof.config.fri_config.log_blowup_factor,
                log_last_layer_deg: commitment_proof.config.fri_config.log_last_layer_degree_bound,
                num_queries: commitment_proof.config.fri_config.n_queries as u32,
            },
            column_log_sizes,
        }
    }

    fn convert_poseidon_hash(hash: &FieldElement252) -> Blake2sHash {
        let bytes = hash.to_bytes_be();
        let mut words = [0u32; 8];
        for i in 0..8 {
            words[i] = u32::from_be_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
        }
        Blake2sHash { words }
    }

    fn convert_fri_proof_poseidon(
        fri_proof: &stwo::core::fri::FriProof<Poseidon252MerkleHasher>,
    ) -> FriProof {
        FriProof {
            first_layer: convert_fri_layer_proof_poseidon(&fri_proof.first_layer),
            inner_layers: fri_proof
                .inner_layers
                .iter()
                .map(|layer| convert_fri_layer_proof_poseidon(layer))
                .collect(),
            last_layer_poly: fri_proof
                .last_layer_poly
                .iter()
                .map(|v| convert_secure_field(v))
                .collect(),
        }
    }

    fn convert_fri_layer_proof_poseidon(
        layer: &stwo::core::fri::FriLayerProof<Poseidon252MerkleHasher>,
    ) -> FriLayerProof {
        FriLayerProof {
            commitment: convert_poseidon_hash(&layer.commitment),
            eval_values: layer.fri_witness.iter().map(|v| convert_secure_field(v)).collect(),
            decommitment: MerkleDecommitment {
                hash_witness: layer
                    .decommitment
                    .hash_witness
                    .iter()
                    .map(|h| convert_poseidon_hash(h))
                    .collect(),
                column_witness: layer
                    .decommitment
                    .column_witness
                    .iter()
                    .map(|v| convert_base_field(v))
                    .collect(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_witness_creation() {
        let config = VerifierConfig::default();
        let converter = ProofConverter::new(config);
        let witness = converter.create_mock_witness();

        assert_eq!(witness.proof.commitments.len(), 4);
        assert_eq!(witness.proof.decommitments.len(), 4);
    }

    #[test]
    fn test_witness_serialization() {
        let config = VerifierConfig::default();
        let converter = ProofConverter::new(config);
        let witness = converter.create_mock_witness();

        let json = witness.to_json().unwrap();
        let parsed = WitnessInput::from_json(&json).unwrap();

        assert_eq!(parsed.proof.pow_nonce, witness.proof.pow_nonce);
    }
}
