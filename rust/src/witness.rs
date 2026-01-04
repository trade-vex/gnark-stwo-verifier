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

// ============================================================================
// Split Witness File Types
// ============================================================================

/// Structure metadata for a single FRI layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriLayerStructure {
    pub eval_count: usize,
    pub hash_witness_count: usize,
    pub column_witness_count: usize,
}

/// Structure metadata for the complete FRI proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriStructure {
    pub first_layer_eval_count: usize,
    pub first_layer_hash_witness_count: usize,
    pub first_layer_column_witness_count: usize,
    pub inner_layers: Vec<FriLayerStructure>,
    pub last_layer_poly_degree: usize,
}

/// Structure metadata for array sizing during circuit compilation.
/// This allows the circuit to be compiled without the actual proof values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStructure {
    /// Number of commitment trees
    pub num_commitments: usize,
    /// Sampled values shape: sampled_values_shape[tree][column] = num_samples
    pub sampled_values_shape: Vec<Vec<usize>>,
    /// Hash witness sizes per tree decommitment
    pub decommitment_hash_sizes: Vec<usize>,
    /// Column witness sizes per tree decommitment
    pub decommitment_column_sizes: Vec<usize>,
    /// Queried values count per tree
    pub queried_values_sizes: Vec<usize>,
    /// FRI proof structure
    pub fri_structure: FriStructure,
}

/// Circuit configuration file - contains everything needed for circuit compilation.
/// This is the smallest file needed for setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitConfig {
    /// PCS configuration parameters
    pub config: PcsConfig,
    /// Column log sizes per tree
    pub column_log_sizes: Vec<Vec<u32>>,
    /// Structure metadata for array sizing
    pub structure: ProofStructure,
    /// AIR constraints for composition polynomial verification (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub air_constraints: Option<AIRConstraints>,
}

impl CircuitConfig {
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
}

/// Proof witness file - contains the actual proof data (private witness for Groth16).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofWitnessFile {
    /// The proof witness data
    pub proof: StwoProofWitness,
}

impl ProofWitnessFile {
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
}

/// Public inputs file - contains only the public input hash (for Groth16 verification).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputsFile {
    /// The public input hash
    pub public_input_hash: Blake2sHash,
}

impl PublicInputsFile {
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
}

/// Result of splitting a WitnessInput into three files.
pub struct SplitWitness {
    pub circuit_config: CircuitConfig,
    pub proof_witness: ProofWitnessFile,
    pub public_inputs: PublicInputsFile,
}

impl WitnessInput {
    /// Compute expected (maximum) structure from config parameters.
    /// This ensures consistent circuit sizes regardless of query positions.
    ///
    /// The structure sizes are computed as upper bounds based on n_queries and domain sizes,
    /// not extracted from actual proof data which can vary.
    pub fn compute_expected_structure(&self) -> ProofStructure {
        let n_queries = self.config.num_queries as usize;
        let log_blowup = self.config.log_blowup_factor;
        let log_last_layer_deg = self.config.log_last_layer_deg;

        // Sampled values shape doesn't depend on queries - extract from actual proof
        let sampled_values_shape: Vec<Vec<usize>> = self.proof.sampled_values.iter()
            .map(|tree| tree.iter().map(|col| col.len()).collect())
            .collect();

        // Find max log size across all trees
        let max_log_size = self.column_log_sizes.iter()
            .flat_map(|sizes| sizes.iter())
            .copied()
            .max()
            .unwrap_or(0);

        // Compute tree depths (extended domain size = 2^(log_size + log_blowup))
        let tree_depths: Vec<u32> = self.column_log_sizes.iter()
            .map(|sizes| {
                sizes.iter().copied().max().unwrap_or(0) + log_blowup
            })
            .collect();

        // Maximum decommitment hash sizes: n_queries * depth per tree
        // This is the worst case when all queries are maximally spread in the Merkle tree
        let decommitment_hash_sizes: Vec<usize> = tree_depths.iter()
            .map(|&depth| n_queries * depth as usize)
            .collect();

        // Column witnesses are typically 0 for our use case
        let decommitment_column_sizes: Vec<usize> = self.column_log_sizes.iter()
            .map(|_| 0)
            .collect();

        // Queried values: n_queries * num_columns per tree
        let queried_values_sizes: Vec<usize> = self.column_log_sizes.iter()
            .map(|sizes| n_queries * sizes.len())
            .collect();

        // FRI structure
        // Constants from stwo
        const CIRCLE_TO_LINE_FOLD_STEP: u32 = 1;
        const FOLD_STEP: u32 = 1;

        // First layer domain size after circle-to-line fold
        // Circle domain is 2^(max_log_size + log_blowup + 1), folds to line domain 2^(max_log_size + log_blowup)
        let first_layer_log_size = max_log_size + log_blowup;

        // Number of inner FRI layers
        // After first layer: degree bound = max_log_size - CIRCLE_TO_LINE_FOLD_STEP
        // Each inner layer reduces by FOLD_STEP until we reach log_last_layer_deg
        let degree_after_first = max_log_size.saturating_sub(CIRCLE_TO_LINE_FOLD_STEP);
        let num_inner_layers = if degree_after_first > log_last_layer_deg {
            ((degree_after_first - log_last_layer_deg) / FOLD_STEP) as usize
        } else {
            0
        };

        // Inner layer structures
        let inner_layers: Vec<FriLayerStructure> = (0..num_inner_layers)
            .map(|i| {
                // Each inner layer has domain size decreasing by FOLD_STEP
                let layer_log_size = first_layer_log_size - (i as u32 + 1) * FOLD_STEP;
                FriLayerStructure {
                    eval_count: n_queries,
                    // Maximum hash witnesses for this layer depth
                    hash_witness_count: n_queries * layer_log_size as usize,
                    column_witness_count: 0,
                }
            })
            .collect();

        // Last layer poly degree
        let last_layer_poly_degree = 1usize << log_last_layer_deg;

        ProofStructure {
            num_commitments: self.proof.commitments.len(),
            sampled_values_shape,
            decommitment_hash_sizes,
            decommitment_column_sizes,
            queried_values_sizes,
            fri_structure: FriStructure {
                first_layer_eval_count: n_queries,
                first_layer_hash_witness_count: n_queries * first_layer_log_size as usize,
                first_layer_column_witness_count: 0,
                inner_layers,
                last_layer_poly_degree,
            },
        }
    }

    /// Pad proof data to match expected structure sizes.
    /// This ensures the proof can be assigned to a circuit compiled with expected sizes.
    pub fn pad_to_expected_structure(&mut self, expected: &ProofStructure) {
        // Pad decommitment hash witnesses
        for (i, decommit) in self.proof.decommitments.iter_mut().enumerate() {
            let expected_size = expected.decommitment_hash_sizes.get(i).copied().unwrap_or(0);
            while decommit.hash_witness.len() < expected_size {
                decommit.hash_witness.push(Blake2sHash { words: [0; 8] });
            }
        }

        // Pad queried values
        for (i, values) in self.proof.queried_values.iter_mut().enumerate() {
            let expected_size = expected.queried_values_sizes.get(i).copied().unwrap_or(0);
            while values.len() < expected_size {
                values.push(M31::zero());
            }
        }

        // Pad FRI first layer
        let fri = &mut self.proof.fri_proof;
        while fri.first_layer.eval_values.len() < expected.fri_structure.first_layer_eval_count {
            fri.first_layer.eval_values.push(QM31::zero());
        }
        while fri.first_layer.decommitment.hash_witness.len() < expected.fri_structure.first_layer_hash_witness_count {
            fri.first_layer.decommitment.hash_witness.push(Blake2sHash { words: [0; 8] });
        }

        // Pad FRI inner layers
        for (i, layer) in fri.inner_layers.iter_mut().enumerate() {
            if let Some(expected_layer) = expected.fri_structure.inner_layers.get(i) {
                while layer.eval_values.len() < expected_layer.eval_count {
                    layer.eval_values.push(QM31::zero());
                }
                while layer.decommitment.hash_witness.len() < expected_layer.hash_witness_count {
                    layer.decommitment.hash_witness.push(Blake2sHash { words: [0; 8] });
                }
            }
        }
    }

    /// Extract structure metadata from this witness (legacy method).
    /// NOTE: This extracts actual sizes which can vary. Use compute_expected_structure() instead.
    pub fn extract_structure(&self) -> ProofStructure {
        ProofStructure {
            num_commitments: self.proof.commitments.len(),
            sampled_values_shape: self.proof.sampled_values.iter()
                .map(|tree| tree.iter().map(|col| col.len()).collect())
                .collect(),
            decommitment_hash_sizes: self.proof.decommitments.iter()
                .map(|d| d.hash_witness.len())
                .collect(),
            decommitment_column_sizes: self.proof.decommitments.iter()
                .map(|d| d.column_witness.len())
                .collect(),
            queried_values_sizes: self.proof.queried_values.iter()
                .map(|v| v.len())
                .collect(),
            fri_structure: FriStructure {
                first_layer_eval_count: self.proof.fri_proof.first_layer.eval_values.len(),
                first_layer_hash_witness_count: self.proof.fri_proof.first_layer.decommitment.hash_witness.len(),
                first_layer_column_witness_count: self.proof.fri_proof.first_layer.decommitment.column_witness.len(),
                inner_layers: self.proof.fri_proof.inner_layers.iter()
                    .map(|l| FriLayerStructure {
                        eval_count: l.eval_values.len(),
                        hash_witness_count: l.decommitment.hash_witness.len(),
                        column_witness_count: l.decommitment.column_witness.len(),
                    })
                    .collect(),
                last_layer_poly_degree: self.proof.fri_proof.last_layer_poly.len(),
            },
        }
    }

    /// Split this witness into three separate file structures.
    pub fn split(self) -> SplitWitness {
        self.split_with_constraints(None)
    }

    /// Split this witness into three separate file structures with optional AIR constraints.
    pub fn split_with_constraints(self, air_constraints: Option<AIRConstraints>) -> SplitWitness {
        let structure = self.extract_structure();

        SplitWitness {
            circuit_config: CircuitConfig {
                config: self.config,
                column_log_sizes: self.column_log_sizes,
                structure,
                air_constraints,
            },
            proof_witness: ProofWitnessFile {
                proof: self.proof,
            },
            public_inputs: PublicInputsFile {
                public_input_hash: self.public.public_input_hash,
            },
        }
    }

    /// Write split witness files to a directory.
    /// Uses computed expected structure (maximum sizes) and pads proof data accordingly.
    pub fn write_split_to_dir(&self, dir: &str) -> std::io::Result<()> {
        self.write_split_to_dir_with_constraints(dir, None)
    }

    /// Write split witness files to a directory with optional AIR constraints.
    /// Uses computed expected structure (maximum sizes) and pads proof data accordingly.
    pub fn write_split_to_dir_with_constraints(
        &self,
        dir: &str,
        air_constraints: Option<AIRConstraints>,
    ) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;

        // Compute expected structure (maximum sizes based on config)
        let expected_structure = self.compute_expected_structure();

        // Clone and pad the proof data to match expected sizes
        let mut padded_witness = self.clone();
        padded_witness.pad_to_expected_structure(&expected_structure);

        let circuit_config = CircuitConfig {
            config: self.config.clone(),
            column_log_sizes: self.column_log_sizes.clone(),
            structure: expected_structure,
            air_constraints,
        };
        circuit_config.write_to_file(&format!("{}/circuit_config.json", dir))?;

        let proof_witness = ProofWitnessFile {
            proof: padded_witness.proof,
        };
        proof_witness.write_to_file(&format!("{}/proof_witness.json", dir))?;

        let public_inputs = PublicInputsFile {
            public_input_hash: self.public.public_input_hash.clone(),
        };
        public_inputs.write_to_file(&format!("{}/public_inputs.json", dir))?;

        Ok(())
    }
}

// ============================================================================
// Constraint Expression Types for AIR Composition Polynomial Verification
// ============================================================================

/// Operation type in a constraint expression.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ConstraintOp {
    Add,
    Sub,
    Mul,
    Neg,
    Const,
    Col,
}

/// A node in a constraint expression tree.
/// Constraints are polynomial expressions over trace column values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintExpr {
    pub op: ConstraintOp,

    /// For binary ops (add, sub, mul)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub left: Option<Box<ConstraintExpr>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub right: Option<Box<ConstraintExpr>>,

    /// For unary ops (neg)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child: Option<Box<ConstraintExpr>>,

    /// For const op - the constant value as [a, b, c, d] for QM31
    #[serde(skip_serializing_if = "Option::is_none")]
    pub const_val: Option<[u32; 4]>,

    /// For col op - column reference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tree_idx: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col_idx: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_off: Option<i32>,
}

impl ConstraintExpr {
    /// Create an addition expression.
    pub fn add(left: ConstraintExpr, right: ConstraintExpr) -> Self {
        Self {
            op: ConstraintOp::Add,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
            child: None,
            const_val: None,
            tree_idx: None,
            col_idx: None,
            row_off: None,
        }
    }

    /// Create a subtraction expression.
    pub fn sub(left: ConstraintExpr, right: ConstraintExpr) -> Self {
        Self {
            op: ConstraintOp::Sub,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
            child: None,
            const_val: None,
            tree_idx: None,
            col_idx: None,
            row_off: None,
        }
    }

    /// Create a multiplication expression.
    pub fn mul(left: ConstraintExpr, right: ConstraintExpr) -> Self {
        Self {
            op: ConstraintOp::Mul,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
            child: None,
            const_val: None,
            tree_idx: None,
            col_idx: None,
            row_off: None,
        }
    }

    /// Create a negation expression.
    pub fn neg(child: ConstraintExpr) -> Self {
        Self {
            op: ConstraintOp::Neg,
            left: None,
            right: None,
            child: Some(Box::new(child)),
            const_val: None,
            tree_idx: None,
            col_idx: None,
            row_off: None,
        }
    }

    /// Create a constant expression.
    pub fn constant(a: u32, b: u32, c: u32, d: u32) -> Self {
        Self {
            op: ConstraintOp::Const,
            left: None,
            right: None,
            child: None,
            const_val: Some([a, b, c, d]),
            tree_idx: None,
            col_idx: None,
            row_off: None,
        }
    }

    /// Create a constant from M31 (extends to QM31 with zeros).
    pub fn constant_m31(v: u32) -> Self {
        Self::constant(v, 0, 0, 0)
    }

    /// Create a column reference expression.
    pub fn col(tree_idx: usize, col_idx: usize, row_off: i32) -> Self {
        Self {
            op: ConstraintOp::Col,
            left: None,
            right: None,
            child: None,
            const_val: None,
            tree_idx: Some(tree_idx),
            col_idx: Some(col_idx),
            row_off: Some(row_off),
        }
    }

    /// Create a column reference for trace columns (tree index 1).
    pub fn trace_col(col_idx: usize) -> Self {
        Self::col(1, col_idx, 0)
    }

    /// Create a column reference for interaction columns (tree index 2).
    pub fn interaction_col(col_idx: usize, row_off: i32) -> Self {
        Self::col(2, col_idx, row_off)
    }
}

/// Simple column reference for LogUp relations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColRef {
    pub tree_idx: usize,
    pub col_idx: usize,
    pub row_off: i32,
}

/// LogUp lookup relation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogUpRelation {
    /// Lookup elements (random field values from Fiat-Shamir)
    pub lookup_elements: Vec<QM31>,

    /// Columns involved in this relation
    pub columns: Vec<ColRef>,

    /// Multiplicity expression
    pub multiplicity: ConstraintExpr,
}

/// Complete AIR constraint specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIRConstraints {
    /// Polynomial constraints that must evaluate to zero
    pub constraints: Vec<ConstraintExpr>,

    /// LogUp relations for lookup arguments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logup_relations: Option<Vec<LogUpRelation>>,

    /// Claimed LogUp sum (should be zero for valid proofs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claimed_logup_sum: Option<[u32; 4]>,

    /// Composition log degree bound
    pub composition_log_degree_bound: u32,
}

impl AIRConstraints {
    /// Create a new AIRConstraints with just polynomial constraints.
    pub fn new(constraints: Vec<ConstraintExpr>, composition_log_degree_bound: u32) -> Self {
        Self {
            constraints,
            logup_relations: None,
            claimed_logup_sum: None,
            composition_log_degree_bound,
        }
    }

    /// Add LogUp relations.
    pub fn with_logup(
        mut self,
        relations: Vec<LogUpRelation>,
        claimed_sum: [u32; 4],
    ) -> Self {
        self.logup_relations = Some(relations);
        self.claimed_logup_sum = Some(claimed_sum);
        self
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Extended witness input that includes AIR constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessInputWithConstraints {
    /// Base witness input
    #[serde(flatten)]
    pub witness: WitnessInput,

    /// AIR constraints for composition polynomial verification
    pub air_constraints: AIRConstraints,
}

impl WitnessInputWithConstraints {
    /// Create a new extended witness.
    pub fn new(witness: WitnessInput, air_constraints: AIRConstraints) -> Self {
        Self {
            witness,
            air_constraints,
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
}

#[cfg(test)]
mod constraint_tests {
    use super::*;

    #[test]
    fn test_constraint_expr_serialization() {
        // Create: col[1,0] * col[1,1] + col[1,0] - col[1,2]
        let col0 = ConstraintExpr::trace_col(0);
        let col1 = ConstraintExpr::trace_col(1);
        let col2 = ConstraintExpr::trace_col(2);

        let expr = ConstraintExpr::sub(
            ConstraintExpr::add(
                ConstraintExpr::mul(col0.clone(), col1),
                col0,
            ),
            col2,
        );

        let constraints = AIRConstraints::new(vec![expr], 20);
        let json = constraints.to_json().unwrap();
        println!("Serialized constraints:\n{}", json);

        // Verify round-trip
        let parsed = AIRConstraints::from_json(&json).unwrap();
        assert_eq!(parsed.constraints.len(), 1);
        assert_eq!(parsed.composition_log_degree_bound, 20);
    }
}
