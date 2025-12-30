//! Example: Generate a stwo proof with LogUp protocol and export to gnark witness format.
//!
//! This example demonstrates a more complex flow:
//! 1. Create a range check preprocessed column
//! 2. Create trace columns with lookups into the range check
//! 3. Generate LogUp auxiliary columns
//! 4. Generate a stwo proof
//! 5. Convert to gnark witness format
//! 6. Write to JSON file

use num_traits::{identities::Zero, One};
use rand::Rng;
use stwo::core::{
    air::Component,
    channel::{Blake2sChannel, Channel},
    fields::{m31::M31, qm31::SecureField},
    pcs::{CommitmentSchemeVerifier, PcsConfig},
    poly::circle::CanonicCoset,
    vcs::blake2_merkle::Blake2sMerkleChannel,
    verifier::verify,
};
use stwo::prover::{
    backend::simd::{column::BaseColumn, m31::LOG_N_LANES, qm31::PackedSecureField, SimdBackend},
    backend::Column,
    poly::{
        circle::{CircleEvaluation, PolyOps},
        BitReversedOrder,
    },
    prove, CommitmentSchemeProver,
};
use stwo_constraint_framework::{
    preprocessed_columns::PreProcessedColumnId, relation, EvalAtRow, FrameworkComponent,
    FrameworkEval, LogupTraceGenerator, Relation, RelationEntry, TraceLocationAllocator,
};
use stwo_gnark::convert_stark_proof;

// Range check column for values 0..16
struct RangeCheckColumn {
    pub log_size: u32,
}

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

// The AIR evaluation with LogUp constraints
struct TestEval {
    range_check_id: PreProcessedColumnId,
    log_size: u32,
    lookup_elements: SmallerThan16Elements,
}

impl FrameworkEval for TestEval {
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

        // LogUp constraint: sum(-multiplicity / (x - i)) + sum(1 / (x - lookup_val)) = 0
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

const LOG_CONSTRAINT_EVAL_BLOWUP_FACTOR: u32 = 1;

relation!(SmallerThan16Elements, 1);

fn gen_trace(log_size: u32) -> Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>> {
    // Create a table with random values in range [0, 16)
    let mut rng = rand::thread_rng();
    let lookup_col_1 =
        BaseColumn::from_iter((0..(1 << log_size)).map(|_| M31::from(rng.gen_range(0..16))));
    let lookup_col_2 =
        BaseColumn::from_iter((0..(1 << log_size)).map(|_| M31::from(rng.gen_range(0..16))));

    // Multiplicity column: count how many times each value appears
    let mut multiplicity_col = BaseColumn::zeros(1 << log_size);
    lookup_col_1
        .as_slice()
        .iter()
        .chain(lookup_col_2.as_slice().iter())
        .for_each(|value| {
            let index = value.0 as usize;
            multiplicity_col.set(index, multiplicity_col.at(index) + M31::from(1));
        });

    // Convert table to trace polynomials
    let domain = CanonicCoset::new(log_size).circle_domain();
    vec![
        lookup_col_1.clone(),
        lookup_col_2.clone(),
        multiplicity_col.clone(),
    ]
    .into_iter()
    .map(|col| CircleEvaluation::new(domain, col))
    .collect()
}

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
    SecureField,
) {
    let mut logup_gen = LogupTraceGenerator::new(range_log_size);

    // First column: -multiplicity / (x - range_val)
    let mut col_gen = logup_gen.new_col();
    for simd_row in 0..(1 << (range_log_size - LOG_N_LANES)) {
        let numerator: PackedSecureField =
            PackedSecureField::from(multiplicity_col.data[simd_row]);
        let denom: PackedSecureField = lookup_elements.combine(&[range_check_col.data[simd_row]]);
        col_gen.write_frac(simd_row, -numerator, denom);
    }
    col_gen.finalize_col();

    // Second column: 1/(x - lookup1) + 1/(x - lookup2)
    let mut col_gen = logup_gen.new_col();
    for simd_row in 0..(1 << (log_size - LOG_N_LANES)) {
        let lookup_col_1_val: PackedSecureField =
            lookup_elements.combine(&[lookup_col_1.data[simd_row]]);
        let lookup_col_2_val: PackedSecureField =
            lookup_elements.combine(&[lookup_col_2.data[simd_row]]);
        // 1 / denom1 + 1 / denom2 = (denom1 + denom2) / (denom1 * denom2)
        let numerator = lookup_col_1_val + lookup_col_2_val;
        let denom = lookup_col_1_val * lookup_col_2_val;
        col_gen.write_frac(simd_row, numerator, denom);
    }
    col_gen.finalize_col();

    logup_gen.finalize_last()
}

fn main() {
    let range_log_size = LOG_N_LANES;
    let log_num_rows = range_log_size;

    println!("=== Static Lookups Example ===");
    println!("Log size: {}", log_num_rows);
    println!("Domain size: {}", 1 << log_num_rows);

    // Config for FRI and PoW
    let config = PcsConfig::default();

    // Precompute twiddles for evaluating and interpolating the trace
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
    println!("Preprocessed column committed (1 column)");

    // Commit to the size of the trace
    channel.mix_u64(log_num_rows as u64);

    // Create and commit to the trace columns
    let trace = gen_trace(log_num_rows);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace.clone());
    tree_builder.commit(channel);
    println!("Trace columns committed (3 columns)");

    // Draw random elements to use when creating the random linear combination
    let lookup_elements = SmallerThan16Elements::draw(channel);

    // Create and commit to the LogUp columns
    let (logup_cols, claimed_sum) = gen_logup_trace(
        range_log_size,
        log_num_rows,
        &range_check_col,
        &trace[0],
        &trace[1],
        &trace[2],
        &lookup_elements,
    );
    let num_logup_cols = logup_cols.len();
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(logup_cols);
    tree_builder.commit(channel);
    println!("LogUp columns committed ({} columns)", num_logup_cols);

    // Create a component
    let component = FrameworkComponent::<TestEval>::new(
        &mut TraceLocationAllocator::default(),
        TestEval {
            range_check_id: RangeCheckColumn::new(range_log_size).id(),
            log_size: log_num_rows,
            lookup_elements,
        },
        claimed_sum,
    );

    // Prove
    println!("\nGenerating stwo proof...");
    let proof = prove(&[&component], channel, commitment_scheme).unwrap();
    println!("Stwo proof generated successfully!");
    println!("Proof size: {} bytes", proof.size_estimate());

    // Verify
    assert_eq!(claimed_sum, SecureField::zero());

    let channel = &mut Blake2sChannel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();

    commitment_scheme.commit(proof.commitments[0], &sizes[0], channel);
    channel.mix_u64(log_num_rows as u64);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], channel);
    commitment_scheme.commit(proof.commitments[2], &sizes[2], channel);

    verify(&[&component], channel, commitment_scheme, proof.clone()).unwrap();
    println!("Stwo proof verified successfully!");

    // Convert to gnark witness format
    // Tree structure:
    // - Tree 0: preprocessed (1 range check column)
    // - Tree 1: trace (3 columns: lookup1, lookup2, multiplicity)
    // - Tree 2: LogUp interaction columns
    // - Tree 3: composition columns
    let column_log_sizes = vec![
        vec![log_num_rows],                              // Tree 0: preprocessed (1 column)
        vec![log_num_rows, log_num_rows, log_num_rows],  // Tree 1: trace (3 columns)
        vec![log_num_rows; num_logup_cols],              // Tree 2: LogUp columns
        vec![log_num_rows; 8],                           // Tree 3: composition (8 columns)
    ];

    println!("\nConverting to gnark witness format...");
    let witness = convert_stark_proof(&proof, column_log_sizes);

    // Write to JSON
    let output_path = "witness_static_lookups.json";
    witness.write_to_file(output_path).unwrap();
    println!("Gnark witness written to: {}", output_path);

    // Print some statistics
    println!("\nWitness statistics:");
    println!("  Commitments: {}", witness.proof.commitments.len());
    println!(
        "  Sampled values trees: {}",
        witness.proof.sampled_values.len()
    );
    println!("  Decommitments: {}", witness.proof.decommitments.len());
    println!(
        "  FRI inner layers: {}",
        witness.proof.fri_proof.inner_layers.len()
    );
    println!("  PoW nonce: {}", witness.proof.pow_nonce);
}
