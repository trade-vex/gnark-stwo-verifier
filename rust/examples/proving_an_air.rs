//! Example: Generate a stwo proof and export to gnark witness format.
//!
//! This example demonstrates the full flow:
//! 1. Create a simple AIR (col_1 * col_2 + col_1 - col_3 = 0)
//! 2. Generate a stwo proof
//! 3. Convert to gnark witness format
//! 4. Write to JSON file

use num_traits::Zero;
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
use stwo::prover::{
    backend::{
        simd::{
            column::BaseColumn,
            m31::{LOG_N_LANES, N_LANES},
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
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};
use stwo_gnark::convert_stark_proof;

struct TestEval {
    log_size: u32,
}

impl FrameworkEval for TestEval {
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
        eval.add_constraint(col_1.clone() * col_2.clone() + col_1.clone() - col_3.clone());
        eval
    }
}

fn main() {
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
    let component = FrameworkComponent::<TestEval>::new(
        &mut TraceLocationAllocator::default(),
        TestEval {
            log_size: log_num_rows,
        },
        QM31::zero(),
    );

    // Prove
    let proof = prove(&[&component], channel, commitment_scheme).unwrap();

    println!("Stwo proof generated successfully!");
    println!("Proof size: {} bytes", proof.size_estimate());

    // Verify the stwo proof first
    let channel = &mut Blake2sChannel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();

    commitment_scheme.commit(proof.commitments[0], &sizes[0], channel);
    channel.mix_u64(log_num_rows as u64);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], channel);

    // Print channel state before verify_values to debug
    println!("DEBUG: Channel digest before verify: {:?}", channel.digest());

    verify(&[&component], channel, commitment_scheme, proof.clone()).unwrap();
    println!("Stwo proof verified successfully!");

    // Convert to gnark witness format
    // All committed columns participate in FRI quotient verification.
    // Tree 2 (composition) uses the same log_size as trace for FRI domain.
    let column_log_sizes = vec![
        vec![],                                        // Tree 0: preprocessed (empty)
        vec![log_num_rows, log_num_rows, log_num_rows], // Tree 1: trace (3 columns)
        vec![log_num_rows; 8],                         // Tree 2: composition (8 columns)
    ];

    let witness = convert_stark_proof(&proof, column_log_sizes);

    // Write to JSON
    let output_path = "witness_proving_an_air.json";
    witness.write_to_file(output_path).unwrap();
    println!("Gnark witness written to: {}", output_path);

    // Print some statistics
    println!("\nWitness statistics:");
    println!("  Commitments: {}", witness.proof.commitments.len());
    println!("  Sampled values trees: {}", witness.proof.sampled_values.len());
    println!("  Decommitments: {}", witness.proof.decommitments.len());
    println!("  FRI inner layers: {}", witness.proof.fri_proof.inner_layers.len());
    println!("  PoW nonce: {}", witness.proof.pow_nonce);
}
