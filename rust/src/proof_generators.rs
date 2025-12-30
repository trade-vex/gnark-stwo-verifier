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

use crate::witness::WitnessInput;

#[cfg(feature = "stwo_support")]
use crate::verifier::stwo_conversion::convert_stark_proof;

/// Result type for proof generation.
pub type ProofResult = Result<WitnessInput, String>;

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
