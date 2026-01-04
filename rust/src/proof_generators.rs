//! Proof generators for FFI.
//!
//! This module contains functions that generate stwo proofs and convert them
//! to gnark witness format. These are called from the FFI layer.

#[cfg(feature = "stwo_support")]
use num_traits::{identities::Zero, One};
#[cfg(feature = "stwo_support")]
use rand::Rng;
#[cfg(feature = "stwo_support")]
use stwo::core::{
    air::Component,
    channel::{Blake2sChannel, Channel},
    fields::{m31::M31, qm31::QM31},
    pcs::{CommitmentSchemeVerifier, PcsConfig},
    poly::circle::CanonicCoset,
    vcs::blake2_merkle::Blake2sMerkleChannel,
    verifier::verify,
    ColumnVec,
};
#[cfg(feature = "stwo_support")]
use stwo::prover::{
    backend::{
        simd::{
            column::BaseColumn,
            m31::{LOG_N_LANES, N_LANES},
            qm31::PackedSecureField,
            SimdBackend,
        },
        Column,
    },
    poly::{
        circle::{CircleEvaluation, PolyOps},
        BitReversedOrder,
    },
    prove, CommitmentSchemeProver,
};
#[cfg(feature = "stwo_support")]
use stwo_constraint_framework::{
    preprocessed_columns::PreProcessedColumnId, relation, EvalAtRow, FrameworkComponent,
    FrameworkEval, LogupTraceGenerator, Relation, RelationEntry, TraceLocationAllocator,
};

use crate::witness::{AIRConstraints, ConstraintExpr, WitnessInput, WitnessInputWithConstraints};

#[cfg(feature = "stwo_support")]
use crate::verifier::stwo_conversion::convert_stark_proof;

/// Result type for proof generation.
pub type ProofResult = Result<WitnessInput, String>;

/// Result type for proof generation with AIR constraints.
pub type ProofWithConstraintsResult = Result<WitnessInputWithConstraints, String>;

// ============================================================================
// Simple AIR (proving_an_air)
// ============================================================================

#[cfg(feature = "stwo_support")]
struct SimpleTestEval {
    log_size: u32,
}

#[cfg(feature = "stwo_support")]
impl FrameworkEval for SimpleTestEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let col_1 = eval.next_trace_mask();
        let col_2 = eval.next_trace_mask();
        let col_3 = eval.next_trace_mask();
        // Constraint: col_1 * col_2 + col_1 - col_3 = 0
        eval.add_constraint(col_1.clone() * col_2.clone() + col_1.clone() - col_3.clone());
        eval
    }
}

/// Generate a simple AIR proof and return witness JSON.
#[cfg(feature = "stwo_support")]
pub fn generate_proving_an_air() -> ProofResult {
    let num_rows = N_LANES;
    let log_num_rows = LOG_N_LANES;

    // Create the table
    let mut col_1 = BaseColumn::zeros(num_rows);
    col_1.set(0, M31::from(1));
    col_1.set(1, M31::from(7));

    let mut col_2 = BaseColumn::zeros(num_rows);
    col_2.set(0, M31::from(5));
    col_2.set(1, M31::from(11));

    let mut col_3 = BaseColumn::zeros(num_rows);
    col_3.set(0, col_1.at(0) * col_2.at(0) + col_1.at(0));
    col_3.set(1, col_1.at(1) * col_2.at(1) + col_1.at(1));

    // Convert table to trace polynomials
    let domain = CanonicCoset::new(log_num_rows).circle_domain();
    let trace: ColumnVec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>> =
        vec![col_1, col_2, col_3]
            .into_iter()
            .map(|col| CircleEvaluation::new(domain, col))
            .collect();

    // Config for FRI and PoW
    let config = PcsConfig::default();

    // Precompute twiddles
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_num_rows + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    // Create the channel and commitment scheme
    let channel = &mut Blake2sChannel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

    // Commit to the preprocessed trace (empty)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    // Commit to the size of the trace
    channel.mix_u64(log_num_rows as u64);

    // Commit to the original trace
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(channel);

    // Create a component
    let component = FrameworkComponent::<SimpleTestEval>::new(
        &mut TraceLocationAllocator::default(),
        SimpleTestEval {
            log_size: log_num_rows,
        },
        QM31::zero(),
    );

    // Prove
    let proof = prove(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("Failed to generate proof: {:?}", e))?;

    // Verify the stwo proof
    let channel = &mut Blake2sChannel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();

    commitment_scheme.commit(proof.commitments[0], &sizes[0], channel);
    channel.mix_u64(log_num_rows as u64);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], channel);

    verify(&[&component], channel, commitment_scheme, proof.clone())
        .map_err(|e| format!("Failed to verify proof: {:?}", e))?;

    // Convert to gnark witness format
    let column_log_sizes = vec![
        vec![],                                        // Tree 0: preprocessed (empty)
        vec![log_num_rows, log_num_rows, log_num_rows], // Tree 1: trace (3 columns)
        vec![log_num_rows; 8],                         // Tree 2: composition (8 columns)
    ];

    Ok(convert_stark_proof(&proof, column_log_sizes))
}

/// Generate a simple AIR proof with AIR constraints included.
/// The constraint is: col_1 * col_2 + col_1 - col_3 = 0
#[cfg(feature = "stwo_support")]
pub fn generate_proving_an_air_with_constraints() -> ProofWithConstraintsResult {
    // Generate the base proof
    let witness = generate_proving_an_air()?;

    // Create the AIR constraint: col_1 * col_2 + col_1 - col_3 = 0
    // Tree 1 contains the trace columns (col_1=0, col_2=1, col_3=2)
    let col_1 = ConstraintExpr::trace_col(0);  // col(1, 0, 0)
    let col_2 = ConstraintExpr::trace_col(1);  // col(1, 1, 0)
    let col_3 = ConstraintExpr::trace_col(2);  // col(1, 2, 0)

    // constraint = col_1 * col_2 + col_1 - col_3
    let mul_term = ConstraintExpr::mul(col_1.clone(), col_2);
    let add_term = ConstraintExpr::add(mul_term, col_1);
    let constraint = ConstraintExpr::sub(add_term, col_3);

    // Composition log degree bound = log_size + 1 (from max_constraint_log_degree_bound)
    let log_size = 4; // LOG_N_LANES = 4
    let air_constraints = AIRConstraints::new(vec![constraint], log_size + 1);

    Ok(WitnessInputWithConstraints::new(witness, air_constraints))
}

/// Extract circuit definition for the simple AIR.
#[cfg(feature = "stwo_support")]
pub fn extract_simple_air_circuit_def() -> Result<crate::circuit_def::CircuitDefinition, String> {
    use crate::extractor::extract_component_def;

    let log_num_rows = LOG_N_LANES;

    let eval = SimpleTestEval {
        log_size: log_num_rows,
    };

    // Extract the component definition
    let component_def = extract_component_def("simple_air", &eval, QM31::zero());

    // Create the circuit definition
    let circuit_def = crate::circuit_def::CircuitDefinition {
        name: "simple_air".to_string(),
        components: vec![component_def],
        composition_log_degree_bound: eval.max_constraint_log_degree_bound(),
    };

    Ok(circuit_def)
}

// ============================================================================
// LogUp (static_lookups)
// ============================================================================

#[cfg(feature = "stwo_support")]
struct RangeCheckColumn {
    pub log_size: u32,
}

#[cfg(feature = "stwo_support")]
impl RangeCheckColumn {
    pub fn new(log_size: u32) -> Self {
        Self { log_size }
    }

    pub fn gen_column(&self) -> CircleEvaluation<SimdBackend, M31, BitReversedOrder> {
        let col = BaseColumn::from_iter((0..(1 << self.log_size)).map(|i| M31::from(i)));
        CircleEvaluation::new(CanonicCoset::new(self.log_size).circle_domain(), col)
    }

    pub fn id(&self) -> PreProcessedColumnId {
        PreProcessedColumnId {
            id: format!("range_check_{}_bits", self.log_size),
        }
    }
}

#[cfg(feature = "stwo_support")]
relation!(SmallerThan16Elements, 1);

#[cfg(feature = "stwo_support")]
struct LogupTestEval {
    range_check_id: PreProcessedColumnId,
    log_size: u32,
    lookup_elements: SmallerThan16Elements,
}

#[cfg(feature = "stwo_support")]
const LOG_CONSTRAINT_EVAL_BLOWUP_FACTOR: u32 = 1;

#[cfg(feature = "stwo_support")]
impl FrameworkEval for LogupTestEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + LOG_CONSTRAINT_EVAL_BLOWUP_FACTOR
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let range_check_col = eval.get_preprocessed_column(self.range_check_id.clone());

        let lookup_col_1 = eval.next_trace_mask();
        let lookup_col_2 = eval.next_trace_mask();
        let multiplicity_col = eval.next_trace_mask();

        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            -E::EF::from(multiplicity_col),
            &[range_check_col],
        ));

        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            E::EF::one(),
            &[lookup_col_1],
        ));

        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            E::EF::one(),
            &[lookup_col_2],
        ));

        eval.finalize_logup_batched(&vec![0, 1, 1]);

        eval
    }
}

#[cfg(feature = "stwo_support")]
fn gen_logup_trace(
    range_log_size: u32,
    log_size: u32,
    range_check_col: &BaseColumn,
    lookup_col_1: &BaseColumn,
    lookup_col_2: &BaseColumn,
    multiplicity_col: &BaseColumn,
    lookup_elements: &SmallerThan16Elements,
) -> (
    Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>>,
    stwo::core::fields::qm31::SecureField,
) {
    let mut logup_gen = LogupTraceGenerator::new(range_log_size);

    let mut col_gen = logup_gen.new_col();
    for simd_row in 0..(1 << (range_log_size - LOG_N_LANES)) {
        let numerator: PackedSecureField =
            PackedSecureField::from(multiplicity_col.data[simd_row]);
        let denom: PackedSecureField = lookup_elements.combine(&[range_check_col.data[simd_row]]);
        col_gen.write_frac(simd_row, -numerator, denom);
    }
    col_gen.finalize_col();

    let mut col_gen = logup_gen.new_col();
    for simd_row in 0..(1 << (log_size - LOG_N_LANES)) {
        let lookup_col_1_val: PackedSecureField =
            lookup_elements.combine(&[lookup_col_1.data[simd_row]]);
        let lookup_col_2_val: PackedSecureField =
            lookup_elements.combine(&[lookup_col_2.data[simd_row]]);
        let numerator = lookup_col_1_val + lookup_col_2_val;
        let denom = lookup_col_1_val * lookup_col_2_val;
        col_gen.write_frac(simd_row, numerator, denom);
    }
    col_gen.finalize_col();

    logup_gen.finalize_last()
}

/// Generate a LogUp proof and return witness JSON.
#[cfg(feature = "stwo_support")]
pub fn generate_static_lookups() -> ProofResult {
    use stwo::core::fields::qm31::SecureField;

    let range_log_size = LOG_N_LANES;
    let log_num_rows = range_log_size;

    // Config for FRI and PoW
    let config = PcsConfig::default();

    // Precompute twiddles
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(
            log_num_rows + LOG_CONSTRAINT_EVAL_BLOWUP_FACTOR + config.fri_config.log_blowup_factor,
        )
        .circle_domain()
        .half_coset,
    );

    // Create the channel and commitment scheme
    let channel = &mut Blake2sChannel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

    // Create and commit to the preprocessed columns
    let range_check_col = RangeCheckColumn::new(range_log_size).gen_column();
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![range_check_col.clone()]);
    tree_builder.commit(channel);

    // Commit to the size of the trace
    channel.mix_u64(log_num_rows as u64);

    // Create and commit to the trace columns
    let mut rng = rand::thread_rng();
    let lookup_col_1 =
        BaseColumn::from_iter((0..(1 << log_num_rows)).map(|_| M31::from(rng.gen_range(0..16))));
    let lookup_col_2 =
        BaseColumn::from_iter((0..(1 << log_num_rows)).map(|_| M31::from(rng.gen_range(0..16))));

    let mut multiplicity_col = BaseColumn::zeros(1 << log_num_rows);
    lookup_col_1
        .as_slice()
        .iter()
        .chain(lookup_col_2.as_slice().iter())
        .for_each(|value| {
            let index = value.0 as usize;
            multiplicity_col.set(index, multiplicity_col.at(index) + M31::from(1));
        });

    let domain = CanonicCoset::new(log_num_rows).circle_domain();
    let trace: Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>> = vec![
        lookup_col_1.clone(),
        lookup_col_2.clone(),
        multiplicity_col.clone(),
    ]
    .into_iter()
    .map(|col| CircleEvaluation::new(domain, col))
    .collect();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(channel);

    // Draw random elements
    let lookup_elements = SmallerThan16Elements::draw(channel);

    // Create and commit to the LogUp columns
    let (logup_cols, claimed_sum) = gen_logup_trace(
        range_log_size,
        log_num_rows,
        &range_check_col,
        &lookup_col_1,
        &lookup_col_2,
        &multiplicity_col,
        &lookup_elements,
    );
    let num_logup_cols = logup_cols.len();
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(logup_cols);
    tree_builder.commit(channel);

    // Create a component
    let component = FrameworkComponent::<LogupTestEval>::new(
        &mut TraceLocationAllocator::default(),
        LogupTestEval {
            range_check_id: RangeCheckColumn::new(range_log_size).id(),
            log_size: log_num_rows,
            lookup_elements,
        },
        claimed_sum,
    );

    // Prove
    let proof = prove(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("Failed to generate proof: {:?}", e))?;

    // Verify
    assert_eq!(claimed_sum, SecureField::zero());

    let channel = &mut Blake2sChannel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();

    commitment_scheme.commit(proof.commitments[0], &sizes[0], channel);
    channel.mix_u64(log_num_rows as u64);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], channel);
    commitment_scheme.commit(proof.commitments[2], &sizes[2], channel);

    verify(&[&component], channel, commitment_scheme, proof.clone())
        .map_err(|e| format!("Failed to verify proof: {:?}", e))?;

    // Convert to gnark witness format
    let column_log_sizes = vec![
        vec![log_num_rows],                              // Tree 0: preprocessed (1 column)
        vec![log_num_rows, log_num_rows, log_num_rows],  // Tree 1: trace (3 columns)
        vec![log_num_rows; num_logup_cols],              // Tree 2: LogUp columns
        vec![log_num_rows; 8],                           // Tree 3: composition (8 columns)
    ];

    Ok(convert_stark_proof(&proof, column_log_sizes))
}

// Fallback when stwo_support feature is not enabled
#[cfg(not(feature = "stwo_support"))]
pub fn generate_proving_an_air() -> ProofResult {
    Err("stwo_support feature not enabled".to_string())
}

#[cfg(not(feature = "stwo_support"))]
pub fn generate_static_lookups() -> ProofResult {
    Err("stwo_support feature not enabled".to_string())
}

#[cfg(feature = "stwo_support")]
pub fn generate_static_lookups_with_debug() -> ProofResult {
    use stwo::core::fields::qm31::SecureField;

    let range_log_size = LOG_N_LANES;
    let log_num_rows = range_log_size;
    let config = PcsConfig::default();

    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_num_rows + LOG_CONSTRAINT_EVAL_BLOWUP_FACTOR + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let channel = &mut Blake2sChannel::default();
    let mut commitment_scheme = CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

    let range_check_col = RangeCheckColumn::new(range_log_size).gen_column();
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![range_check_col.clone()]);
    tree_builder.commit(channel);

    channel.mix_u64(log_num_rows as u64);

    let mut rng = rand::thread_rng();
    let lookup_col_1 = BaseColumn::from_iter((0..(1 << log_num_rows)).map(|_| M31::from(rng.gen_range(0..16))));
    let lookup_col_2 = BaseColumn::from_iter((0..(1 << log_num_rows)).map(|_| M31::from(rng.gen_range(0..16))));

    let mut multiplicity_col = BaseColumn::zeros(1 << log_num_rows);
    lookup_col_1.as_slice().iter().chain(lookup_col_2.as_slice().iter()).for_each(|value| {
        let index = value.0 as usize;
        multiplicity_col.set(index, multiplicity_col.at(index) + M31::from(1));
    });

    let domain = CanonicCoset::new(log_num_rows).circle_domain();
    let trace: Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>> = vec![
        lookup_col_1.clone(), lookup_col_2.clone(), multiplicity_col.clone(),
    ].into_iter().map(|col| CircleEvaluation::new(domain, col)).collect();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(channel);

    let lookup_elements = SmallerThan16Elements::draw(channel);

    let (logup_cols, claimed_sum) = gen_logup_trace(
        range_log_size, log_num_rows, &range_check_col,
        &lookup_col_1, &lookup_col_2, &multiplicity_col, &lookup_elements,
    );
    let num_logup_cols = logup_cols.len();
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(logup_cols);
    tree_builder.commit(channel);

    let component = FrameworkComponent::<LogupTestEval>::new(
        &mut TraceLocationAllocator::default(),
        LogupTestEval {
            range_check_id: RangeCheckColumn::new(range_log_size).id(),
            log_size: log_num_rows, lookup_elements,
        },
        claimed_sum,
    );

    let proof = prove(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("Failed to generate proof: {:?}", e))?;

    // DEBUG: Print actual witness counts BEFORE conversion
    eprintln!("=== DEBUG: Pre-conversion witness counts ===");
    eprintln!("First layer fri_witness: {} elements", proof.0.fri_proof.first_layer.fri_witness.len());
    for (i, w) in proof.0.fri_proof.first_layer.fri_witness.iter().enumerate() {
        eprintln!("  [{}]: {:?}", i, w);
    }
    for (layer_idx, layer) in proof.0.fri_proof.inner_layers.iter().enumerate() {
        eprintln!("Inner layer {} fri_witness: {} elements", layer_idx, layer.fri_witness.len());
    }

    assert_eq!(claimed_sum, SecureField::zero());

    let channel = &mut Blake2sChannel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();

    commitment_scheme.commit(proof.commitments[0], &sizes[0], channel);
    channel.mix_u64(log_num_rows as u64);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], channel);
    commitment_scheme.commit(proof.commitments[2], &sizes[2], channel);

    verify(&[&component], channel, commitment_scheme, proof.clone())
        .map_err(|e| format!("Failed to verify proof: {:?}", e))?;

    let column_log_sizes = vec![
        vec![log_num_rows],
        vec![log_num_rows, log_num_rows, log_num_rows],
        vec![log_num_rows; num_logup_cols],
        vec![log_num_rows; 8],
    ];

    Ok(convert_stark_proof(&proof, column_log_sizes))
}

/// Extract circuit definition for the static lookups circuit.
/// Note: The lookup_elements are drawn from the channel during proof generation,
/// so we use dummy elements here for circuit structure extraction.
#[cfg(feature = "stwo_support")]
pub fn extract_static_lookups_circuit_def() -> Result<crate::circuit_def::CircuitDefinition, String> {
    use crate::extractor::extract_component_def;

    let range_log_size = LOG_N_LANES;
    let log_num_rows = range_log_size;

    // Use dummy lookup elements for structure extraction
    // The actual values will be provided at proof time
    let lookup_elements = SmallerThan16Elements::dummy();

    let eval = LogupTestEval {
        range_check_id: RangeCheckColumn::new(range_log_size).id(),
        log_size: log_num_rows,
        lookup_elements,
    };

    // Extract the component definition
    let component_def = extract_component_def("static_lookups", &eval, QM31::zero());

    // Create the circuit definition
    let circuit_def = crate::circuit_def::CircuitDefinition {
        name: "static_lookups".to_string(),
        components: vec![component_def],
        composition_log_degree_bound: eval.max_constraint_log_degree_bound(),
    };

    Ok(circuit_def)
}

// ============================================================================
// Dynamic Lookups (permutation argument)
// ============================================================================

#[cfg(feature = "stwo_support")]
relation!(DynamicLookupElements, 1);

#[cfg(feature = "stwo_support")]
struct DynamicLookupEval {
    log_size: u32,
    lookup_elements: DynamicLookupElements,
}

#[cfg(feature = "stwo_support")]
impl FrameworkEval for DynamicLookupEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + LOG_CONSTRAINT_EVAL_BLOWUP_FACTOR
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let col_a = eval.next_trace_mask();
        let col_b = eval.next_trace_mask();

        // Add positive contribution for col_a: +1 / (col_a - α)
        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            E::EF::one(),
            &[col_a],
        ));

        // Add negative contribution for col_b: -1 / (col_b - α)
        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            -E::EF::one(),
            &[col_b],
        ));

        // Use finalize_logup_in_pairs for dynamic lookups
        eval.finalize_logup_in_pairs();

        eval
    }
}

#[cfg(feature = "stwo_support")]
fn gen_dynamic_lookup_trace(
    log_size: u32,
    col_a: &BaseColumn,
    col_b: &BaseColumn,
    lookup_elements: &DynamicLookupElements,
) -> (
    Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>>,
    stwo::core::fields::qm31::SecureField,
) {
    let mut logup_gen = LogupTraceGenerator::new(log_size);

    let mut col_gen = logup_gen.new_col();
    for row in 0..(1 << (log_size - LOG_N_LANES)) {
        // 1/a - 1/b = (b - a) / (a * b)
        let val_a: PackedSecureField = lookup_elements.combine(&[col_a.data[row]]);
        let val_b: PackedSecureField = lookup_elements.combine(&[col_b.data[row]]);
        col_gen.write_frac(row, val_b - val_a, val_a * val_b);
    }
    col_gen.finalize_col();

    logup_gen.finalize_last()
}

/// Generate a dynamic lookup proof (permutation argument) and return witness JSON.
#[cfg(feature = "stwo_support")]
pub fn generate_dynamic_lookups() -> ProofResult {
    use stwo::core::fields::qm31::SecureField;
    use rand::prelude::SliceRandom;

    let log_size = LOG_N_LANES;
    let config = PcsConfig::default();

    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_CONSTRAINT_EVAL_BLOWUP_FACTOR + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let channel = &mut Blake2sChannel::default();
    let mut commitment_scheme = CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

    // Empty preprocessed tree
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    channel.mix_u64(log_size as u64);

    // Generate two columns that are permutations of each other
    let mut rng = rand::thread_rng();
    let values: Vec<u32> = (0..(1 << log_size)).collect();

    let mut values_a = values.clone();
    values_a.shuffle(&mut rng);
    let col_a = BaseColumn::from_iter(values_a.iter().map(|v| M31::from(*v)));

    let mut values_b = values.clone();
    values_b.shuffle(&mut rng);
    let col_b = BaseColumn::from_iter(values_b.iter().map(|v| M31::from(*v)));

    // Commit to trace
    let domain = CanonicCoset::new(log_size).circle_domain();
    let trace: Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>> = vec![
        CircleEvaluation::new(domain, col_a.clone()),
        CircleEvaluation::new(domain, col_b.clone()),
    ];
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(channel);

    // Draw lookup elements
    let lookup_elements = DynamicLookupElements::draw(channel);

    // Generate LogUp trace
    let (logup_cols, claimed_sum) = gen_dynamic_lookup_trace(
        log_size, &col_a, &col_b, &lookup_elements,
    );
    let num_logup_cols = logup_cols.len();
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(logup_cols);
    tree_builder.commit(channel);

    // Create component
    let component = FrameworkComponent::<DynamicLookupEval>::new(
        &mut TraceLocationAllocator::default(),
        DynamicLookupEval {
            log_size,
            lookup_elements,
        },
        claimed_sum,
    );

    // Prove
    let proof = prove(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("Failed to generate proof: {:?}", e))?;

    // Verify claimed_sum is zero (permutations cancel out)
    assert_eq!(claimed_sum, SecureField::zero());

    let column_log_sizes = vec![
        vec![],
        vec![log_size, log_size],
        vec![log_size; num_logup_cols],
        vec![log_size; 8],
    ];

    Ok(convert_stark_proof(&proof, column_log_sizes))
}

#[cfg(not(feature = "stwo_support"))]
pub fn generate_dynamic_lookups() -> ProofResult {
    Err("stwo_support feature not enabled".to_string())
}

/// Extract circuit definition for the dynamic lookups circuit.
#[cfg(feature = "stwo_support")]
pub fn extract_dynamic_lookups_circuit_def() -> Result<crate::circuit_def::CircuitDefinition, String> {
    use crate::extractor::extract_component_def;

    let log_size = LOG_N_LANES;

    // Use dummy lookup elements for structure extraction
    let lookup_elements = DynamicLookupElements::dummy();

    let eval = DynamicLookupEval {
        log_size,
        lookup_elements,
    };

    let component_def = extract_component_def("dynamic_lookups", &eval, QM31::zero());

    let circuit_def = crate::circuit_def::CircuitDefinition {
        name: "dynamic_lookups".to_string(),
        components: vec![component_def],
        composition_log_degree_bound: eval.max_constraint_log_degree_bound(),
    };

    Ok(circuit_def)
}

#[cfg(not(feature = "stwo_support"))]
pub fn extract_dynamic_lookups_circuit_def() -> Result<crate::circuit_def::CircuitDefinition, String> {
    Err("stwo_support feature not enabled".to_string())
}

// ============================================================================
// Combined Circuit (Simple AIR + Dynamic Lookups + Static Lookups)
// ============================================================================

/// Generate a combined proof with Simple AIR, Dynamic Lookups, and Static Lookups.
#[cfg(feature = "stwo_support")]
pub fn generate_combined_circuit() -> ProofResult {
    use stwo::core::fields::qm31::SecureField;
    use rand::prelude::SliceRandom;

    let log_size = LOG_N_LANES;
    let config = PcsConfig::default();

    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_CONSTRAINT_EVAL_BLOWUP_FACTOR + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let channel = &mut Blake2sChannel::default();
    let mut commitment_scheme = CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

    // ========================================
    // Tree 0: Preprocessed columns (range_check from static lookups)
    // ========================================
    let range_check_col = RangeCheckColumn::new(log_size).gen_column();
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![range_check_col.clone()]);
    tree_builder.commit(channel);

    channel.mix_u64(log_size as u64);

    // ========================================
    // Generate trace data for all components
    // ========================================
    let domain = CanonicCoset::new(log_size).circle_domain();
    let mut rng = rand::thread_rng();

    // Simple AIR: col_1 * col_2 + col_1 - col_3 = 0
    let mut simple_col_1 = BaseColumn::zeros(N_LANES);
    simple_col_1.set(0, M31::from(1));
    simple_col_1.set(1, M31::from(7));
    let mut simple_col_2 = BaseColumn::zeros(N_LANES);
    simple_col_2.set(0, M31::from(5));
    simple_col_2.set(1, M31::from(11));
    let mut simple_col_3 = BaseColumn::zeros(N_LANES);
    simple_col_3.set(0, simple_col_1.at(0) * simple_col_2.at(0) + simple_col_1.at(0));
    simple_col_3.set(1, simple_col_1.at(1) * simple_col_2.at(1) + simple_col_1.at(1));

    // Dynamic Lookups: permutation of same values
    let values: Vec<u32> = (0..(1 << log_size)).collect();
    let mut values_a = values.clone();
    values_a.shuffle(&mut rng);
    let dyn_col_a = BaseColumn::from_iter(values_a.iter().map(|v| M31::from(*v)));
    let mut values_b = values.clone();
    values_b.shuffle(&mut rng);
    let dyn_col_b = BaseColumn::from_iter(values_b.iter().map(|v| M31::from(*v)));

    // Static Lookups: lookup with multiplicity
    let stat_lookup_1 = BaseColumn::from_iter((0..(1 << log_size)).map(|_| M31::from(rng.gen_range(0..16))));
    let stat_lookup_2 = BaseColumn::from_iter((0..(1 << log_size)).map(|_| M31::from(rng.gen_range(0..16))));
    let mut stat_multiplicity = BaseColumn::zeros(1 << log_size);
    stat_lookup_1.as_slice().iter().chain(stat_lookup_2.as_slice().iter()).for_each(|value| {
        let index = value.0 as usize;
        stat_multiplicity.set(index, stat_multiplicity.at(index) + M31::from(1));
    });

    // ========================================
    // Tree 1: All trace columns combined
    // ========================================
    let all_trace: Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>> = vec![
        // Simple AIR columns (3)
        CircleEvaluation::new(domain, simple_col_1),
        CircleEvaluation::new(domain, simple_col_2),
        CircleEvaluation::new(domain, simple_col_3),
        // Dynamic Lookups columns (2)
        CircleEvaluation::new(domain, dyn_col_a.clone()),
        CircleEvaluation::new(domain, dyn_col_b.clone()),
        // Static Lookups columns (3)
        CircleEvaluation::new(domain, stat_lookup_1.clone()),
        CircleEvaluation::new(domain, stat_lookup_2.clone()),
        CircleEvaluation::new(domain, stat_multiplicity.clone()),
    ];
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(all_trace);
    tree_builder.commit(channel);

    // ========================================
    // Draw lookup elements for both components
    // ========================================
    let dyn_lookup_elements = DynamicLookupElements::draw(channel);
    let stat_lookup_elements = SmallerThan16Elements::draw(channel);

    // ========================================
    // Tree 2: All LogUp columns combined
    // ========================================
    let (dyn_logup_cols, dyn_claimed_sum) = gen_dynamic_lookup_trace(
        log_size, &dyn_col_a, &dyn_col_b, &dyn_lookup_elements,
    );
    let num_dyn_logup_cols = dyn_logup_cols.len();

    let (stat_logup_cols, stat_claimed_sum) = gen_logup_trace(
        log_size, log_size, &range_check_col,
        &stat_lookup_1, &stat_lookup_2, &stat_multiplicity, &stat_lookup_elements,
    );
    let num_stat_logup_cols = stat_logup_cols.len();

    // Combine all logup columns into one tree
    let mut all_logup = Vec::new();
    all_logup.extend(dyn_logup_cols);
    all_logup.extend(stat_logup_cols);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(all_logup);
    tree_builder.commit(channel);

    // ========================================
    // Create components
    // ========================================
    let mut allocator = TraceLocationAllocator::default();

    let simple_component = FrameworkComponent::<SimpleTestEval>::new(
        &mut allocator,
        SimpleTestEval { log_size },
        SecureField::zero(),
    );

    let dynamic_component = FrameworkComponent::<DynamicLookupEval>::new(
        &mut allocator,
        DynamicLookupEval {
            log_size,
            lookup_elements: dyn_lookup_elements,
        },
        dyn_claimed_sum,
    );

    let static_component = FrameworkComponent::<LogupTestEval>::new(
        &mut allocator,
        LogupTestEval {
            range_check_id: RangeCheckColumn::new(log_size).id(),
            log_size,
            lookup_elements: stat_lookup_elements,
        },
        stat_claimed_sum,
    );

    // ========================================
    // Prove with all 3 components
    // ========================================
    let proof = prove(
        &[&simple_component, &dynamic_component, &static_component],
        channel,
        commitment_scheme,
    ).map_err(|e| format!("Failed to generate proof: {:?}", e))?;

    // Verify claimed sums are zero
    assert_eq!(dyn_claimed_sum, SecureField::zero());
    assert_eq!(stat_claimed_sum, SecureField::zero());

    // Column log sizes for all trees
    let column_log_sizes = vec![
        vec![log_size],                                              // Tree 0: preprocessed (1 column)
        vec![log_size; 8],                                           // Tree 1: trace (3+2+3 = 8 columns)
        vec![log_size; num_dyn_logup_cols + num_stat_logup_cols],    // Tree 2: all LogUp columns
        vec![log_size; 8],                                           // Tree 3: composition
    ];

    Ok(convert_stark_proof(&proof, column_log_sizes))
}

#[cfg(not(feature = "stwo_support"))]
pub fn generate_combined_circuit() -> ProofResult {
    Err("stwo_support feature not enabled".to_string())
}

#[cfg(all(test, feature = "stwo_support"))]
mod circuit_def_tests {
    use super::*;
    use crate::FinalizeMode;

    #[test]
    fn test_extract_simple_air_circuit_def() {
        let circuit_def = extract_simple_air_circuit_def().unwrap();
        
        // Print the circuit definition as JSON
        let json = circuit_def.to_json().unwrap();
        println!("Simple AIR Circuit Definition:\n{}", json);
        
        // Verify structure
        assert_eq!(circuit_def.name, "simple_air");
        assert_eq!(circuit_def.components.len(), 1);
        
        let component = &circuit_def.components[0];
        assert_eq!(component.name, "simple_air");
        assert_eq!(component.log_size, LOG_N_LANES);
        
        // Should have one constraint: col_1 * col_2 + col_1 - col_3 = 0
        assert_eq!(component.constraints.len(), 1);
        
        // No LogUp in simple AIR
        assert!(component.logup.is_none());
    }

    #[test]
    fn test_extract_static_lookups_circuit_def() {
        let circuit_def = extract_static_lookups_circuit_def().unwrap();
        
        // Print the circuit definition as JSON
        let json = circuit_def.to_json().unwrap();
        println!("Static Lookups Circuit Definition:\n{}", json);
        
        // Verify structure
        assert_eq!(circuit_def.name, "static_lookups");
        assert_eq!(circuit_def.components.len(), 1);
        
        let component = &circuit_def.components[0];
        assert_eq!(component.name, "static_lookups");
        assert_eq!(component.log_size, LOG_N_LANES);
        
        // Should have LogUp configuration
        assert!(component.logup.is_some());
        
        let logup = component.logup.as_ref().unwrap();
        assert_eq!(logup.fractions.len(), 3); // 3 relation entries
    }

    #[test]
    fn test_extract_dynamic_lookups_circuit_def() {
        let circuit_def = extract_dynamic_lookups_circuit_def().unwrap();

        // Print the circuit definition as JSON
        let json = circuit_def.to_json().unwrap();
        println!("Dynamic Lookups Circuit Definition:\n{}", json);

        // Verify structure
        assert_eq!(circuit_def.name, "dynamic_lookups");
        assert_eq!(circuit_def.components.len(), 1);

        let component = &circuit_def.components[0];
        assert_eq!(component.name, "dynamic_lookups");
        assert_eq!(component.log_size, LOG_N_LANES);

        // Should have LogUp configuration with 2 fractions (paired)
        assert!(component.logup.is_some());

        let logup = component.logup.as_ref().unwrap();
        assert_eq!(logup.fractions.len(), 2); // 2 relation entries paired together
        assert!(matches!(logup.finalize_mode, FinalizeMode::Pairs));
    }
}
