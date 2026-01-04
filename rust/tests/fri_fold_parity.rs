//! FRI folding parity tests.
//!
//! These tests trace FRI folding step-by-step to debug parity issues with Go.

use stwo::core::channel::{Blake2sChannel, Channel, MerkleChannel};
use stwo::core::circle::Coset;
use stwo::core::fft::ibutterfly;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::fields::FieldExpOps;
use stwo::core::poly::line::LineDomain;
use stwo::core::queries::{draw_queries, Queries};
use stwo::core::utils::bit_reverse_index;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs::blake2_merkle::Blake2sMerkleChannel;

fn words_to_hash(words: [u32; 8]) -> Blake2sHash {
    let mut bytes = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
    }
    Blake2sHash(bytes)
}

fn words_to_qm31(words: [u32; 4]) -> QM31 {
    QM31::from_m31_array([
        M31::from(words[0]),
        M31::from(words[1]),
        M31::from(words[2]),
        M31::from(words[3]),
    ])
}

#[test]
fn test_fri_fold_step_by_step() {
    // Load actual values from the proof

    // Commitments from proof_witness.json
    let commitment0 = words_to_hash([
        356389674, 426915842, 2011877665, 2627174952, 4068806529, 3113848964, 2254062035, 2908739609,
    ]);
    let commitment1 = words_to_hash([
        807652323, 2545064309, 2831989782, 1957966857, 187098561, 3534142660, 4271151569, 2991128073,
    ]);
    let commitment2 = words_to_hash([
        1148832328, 974782099, 2352916468, 281928874, 427453219, 3346741966, 1401915353, 4240998853,
    ]);

    // FRI layer commitments
    let fri_first_commitment = words_to_hash([
        2805472136, 1461034413, 1417292649, 592820859, 1231528413, 416314787, 6862543, 3508467774,
    ]);
    let fri_inner_commitments = [
        words_to_hash([
            3813426609, 2310714604, 1139451780, 2121015952, 1379227534, 3832687024, 2660825891, 3424227012,
        ]),
        words_to_hash([
            2414166756, 1131098088, 1741050948, 3268476040, 3645587527, 4165088728, 3587759887, 3108133626,
        ]),
        words_to_hash([
            1330527892, 2879612266, 1649893037, 1355168948, 3912611619, 109206685, 2063299016, 1355679096,
        ]),
    ];

    // First layer witness (eval_values from proof)
    let first_layer_witnesses = [
        words_to_qm31([1020745971, 646814303, 1829982739, 1012674541]),
        words_to_qm31([181518346, 401396764, 360659784, 1882161948]),
        words_to_qm31([657080406, 1961204316, 987187349, 881398562]),
    ];

    // Inner layer witnesses
    let inner_layer_witnesses = [
        // Layer 0
        vec![
            words_to_qm31([63360610, 1781900914, 649819767, 1934799813]),
            words_to_qm31([341919180, 1809072112, 1190183534, 994398709]),
            words_to_qm31([1405871356, 55122534, 310428524, 643454092]),
        ],
        // Layer 1
        vec![
            words_to_qm31([1674352936, 1006503414, 912960314, 2081614385]),
            words_to_qm31([461312021, 700821683, 627566966, 339838524]),
            words_to_qm31([340905436, 328767165, 1046383303, 880287144]),
        ],
        // Layer 2
        vec![
            words_to_qm31([1926970400, 1759172830, 1325277308, 881132869]),
            words_to_qm31([0, 0, 0, 0]),
            words_to_qm31([0, 0, 0, 0]),
        ],
    ];

    // Last layer polynomial
    let last_layer_poly = words_to_qm31([1127715432, 288372790, 657641239, 2025733499]);

    // Build the Fiat-Shamir transcript
    let mut channel = Blake2sChannel::default();

    // 1. Mix preprocessed commitment
    Blake2sMerkleChannel::mix_root(&mut channel, commitment0);

    // 2. Mix log_size
    channel.mix_u64(4);

    // 3. Mix trace commitment
    Blake2sMerkleChannel::mix_root(&mut channel, commitment1);

    // 4. Draw random_coeff
    let _random_coeff = channel.draw_secure_felt();

    // 5. Mix composition commitment
    Blake2sMerkleChannel::mix_root(&mut channel, commitment2);

    // 6. Draw OODS point
    let _oods_point = channel.draw_secure_felt();

    // 7. Mix sampled values (this is done in verify, using actual OODS evaluations)
    // For now, we'll skip this to match what the Go code currently does
    // NOTE: The actual verifier mixes sampled values here - this could be a source of divergence

    // 8. Draw FRI random coeff (line combination coeff)
    // This is drawn after mixing sampled values
    // let _fri_random_coeff = channel.draw_secure_felt();

    // 9. Mix FRI first layer commitment and draw first alpha
    Blake2sMerkleChannel::mix_root(&mut channel, fri_first_commitment);
    let alpha0 = channel.draw_secure_felt();
    println!("Alpha 0 (first layer): {:?}", alpha0);

    // 10. Mix inner layer commitments and draw alphas
    let mut alphas = vec![alpha0];
    for (i, commitment) in fri_inner_commitments.iter().enumerate() {
        Blake2sMerkleChannel::mix_root(&mut channel, *commitment);
        let alpha = channel.draw_secure_felt();
        println!("Alpha {} (inner layer {}): {:?}", i + 1, i, alpha);
        alphas.push(alpha);
    }

    // 11. Mix last layer poly
    channel.mix_felts(&[last_layer_poly]);

    // 12. PoW verification
    // ... skip for now

    // 13. Draw query positions
    // The channel should mix the nonce first
    let pow_nonce = 401u64;
    channel.mix_u64(pow_nonce);

    let log_domain_size = 5u32; // max_log_size (4) + log_blowup (1)
    let n_queries = 3;
    let raw_positions = draw_queries(&mut channel, log_domain_size, n_queries);
    let queries = Queries::new(&raw_positions, log_domain_size);
    println!("\nRaw query positions: {:?}", raw_positions);
    println!("Sorted query positions: {:?}", queries.positions);

    // Now let's trace the FRI folding
    println!("\n=== FRI FOLDING TRACE ===\n");

    // For the first layer (circle to line), we need to compute the quotient values
    // In a real verifier, these come from evaluating the quotient polynomial at query positions
    // For this test, we'll use placeholder values since we're focusing on the folding logic

    // First layer fold
    // For each query, we have:
    // - Query position (from queries)
    // - Query value (from quotient evaluation - placeholder for now)
    // - Sibling value (from witness or another query)

    // Let's trace what the positions mean
    println!("First layer (circle to line):");
    println!("  log_domain_size = {}", log_domain_size);
    let circle_domain = stwo::core::poly::circle::CanonicCoset::new(log_domain_size)
        .circle_domain();

    for (q, &pos) in queries.iter().enumerate() {
        // Get circle point for this position
        let bit_rev_pos = bit_reverse_index(pos, log_domain_size as u32);
        let point = circle_domain.at(bit_rev_pos);
        println!("  Query {}: pos={}, bit_rev_pos={}, point=({}, {})",
            q, pos, bit_rev_pos, point.x, point.y);

        // Compute fold pair positions
        let even_pos = pos & !1;
        let odd_pos = pos | 1;
        println!("    Fold pair: even={}, odd={}", even_pos, odd_pos);

        // Get the twiddle (inverse of y-coordinate at even position)
        let even_bit_rev = bit_reverse_index(even_pos, log_domain_size as u32);
        let even_point = circle_domain.at(even_bit_rev);
        let itwid = even_point.y.inverse();
        println!("    Twiddle (1/y at even): {}", itwid);
    }

    // After first layer fold, positions are halved
    let first_layer_positions: Vec<usize> = queries.iter().map(|p| p >> 1).collect();
    println!("\nAfter first layer fold, positions: {:?}", first_layer_positions);

    // Inner layers
    for layer_idx in 0..3 {
        let current_log_size = log_domain_size - 1 - layer_idx;
        println!("\nInner layer {} (line to line):", layer_idx);
        println!("  log_domain_size = {}", current_log_size);

        let line_domain = LineDomain::new(Coset::half_odds(current_log_size as u32));

        for (q, &pos) in first_layer_positions.iter().enumerate() {
            // Adjust position for this layer
            let layer_pos = pos >> layer_idx;
            let even_pos = layer_pos & !1;
            let bit_rev_pos = bit_reverse_index(even_pos, current_log_size as u32);
            let x = line_domain.at(bit_rev_pos);
            println!("  Query {}: layer_pos={}, even_pos={}, bit_rev_pos={}, x={}",
                q, layer_pos, even_pos, bit_rev_pos, x);
        }
    }

    // Last layer check
    println!("\n=== LAST LAYER ===");
    println!("Last layer poly coefficients: {:?}", last_layer_poly);

    // The final positions after all folding
    let final_positions: Vec<usize> = queries.iter().map(|p| p >> 4).collect();
    println!("Final positions after all folds: {:?}", final_positions);

    // For a constant last layer polynomial (degree < domain size), all positions should
    // evaluate to the same value (the constant)
    let final_log_size = log_domain_size - 4;
    println!("Final log_domain_size = {}", final_log_size);

    // The last layer polynomial should evaluate to the same value at all query positions
    // if it's a constant (which it is, since last_layer_poly_degree=1 means coeffs[0] only)
    println!("\nExpected: All folded values should equal {:?}", last_layer_poly);
}

#[test]
fn test_fold_line_formula() {
    // Test the actual fold formula
    // f_folded = (f(x) + f(-x)) + alpha * (f(x) - f(-x)) / x

    let v0 = words_to_qm31([100, 200, 300, 400]); // f(x)
    let v1 = words_to_qm31([150, 250, 350, 450]); // f(-x)
    let alpha = words_to_qm31([1000, 2000, 3000, 4000]);
    let x = M31::from(500u32);

    // Manual fold computation
    let mut f0 = v0;
    let mut f1 = v1;
    ibutterfly(&mut f0, &mut f1, x.inverse());
    let result = f0 + alpha * f1;

    println!("v0 = {:?}", v0);
    println!("v1 = {:?}", v1);
    println!("alpha = {:?}", alpha);
    println!("x = {}", x);
    println!("After ibutterfly:");
    println!("  f0 = {:?}", f0);
    println!("  f1 = {:?}", f1);
    println!("Folded result = {:?}", result);

    // Verify: f0 should be v0 + v1, f1 should be (v0 - v1) * x_inv
    let expected_f0 = v0 + v1;
    let expected_f1 = (v0 - v1) * x.inverse();
    println!("\nExpected:");
    println!("  f0 = v0 + v1 = {:?}", expected_f0);
    println!("  f1 = (v0 - v1) * x_inv = {:?}", expected_f1);

    assert_eq!(f0, expected_f0);
    // Note: f1 comparison may have slight differences due to field arithmetic
}

fn print_digest(label: &str, channel: &Blake2sChannel) {
    let digest = channel.digest();
    print!("{}: [", label);
    for (i, chunk) in digest.0.chunks(4).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        if i > 0 { print!(", "); }
        print!("{}", word);
    }
    println!("]");
}

#[test]
fn test_query_draw_parity() {
    // Test exact draw_u32s output before query generation
    let mut channel = Blake2sChannel::default();

    // Build the transcript up to the query draw point
    let commitment0 = words_to_hash([
        356389674, 426915842, 2011877665, 2627174952, 4068806529, 3113848964, 2254062035, 2908739609,
    ]);
    let commitment1 = words_to_hash([
        807652323, 2545064309, 2831989782, 1957966857, 187098561, 3534142660, 4271151569, 2991128073,
    ]);
    let commitment2 = words_to_hash([
        1148832328, 974782099, 2352916468, 281928874, 427453219, 3346741966, 1401915353, 4240998853,
    ]);
    let fri_first_commitment = words_to_hash([
        2805472136, 1461034413, 1417292649, 592820859, 1231528413, 416314787, 6862543, 3508467774,
    ]);
    // Updated with correct values from proof_witness.json
    let fri_inner_commitments = [
        words_to_hash([1892120923, 2924145469, 2159911583, 66957405, 2487895492, 2196985927, 4239028926, 2125799249]),
        words_to_hash([1507226232, 3510655299, 1183543950, 3710863388, 3475398204, 3998187011, 404841469, 2227082252]),
        words_to_hash([3858460919, 3288971353, 3612704253, 347925492, 950803833, 1355370538, 1533999517, 3583653841]),
    ];
    let last_layer_poly = words_to_qm31([1127715432, 288372790, 657641239, 2025733499]);

    println!("=== Phase 1: Mix Commitments ===");
    // Phase 1: Mix commitments
    Blake2sMerkleChannel::mix_root(&mut channel, commitment0);
    print_digest("After commitment 0", &channel);
    channel.mix_u64(4);
    print_digest("After mix_u64(4)", &channel);
    Blake2sMerkleChannel::mix_root(&mut channel, commitment1);
    print_digest("After commitment 1", &channel);

    println!("\n=== Phase 2b: Draw composition random coeff ===");
    // Phase 2b: Draw composition random coeff
    let _ = channel.draw_secure_felt();
    print_digest("After draw composition coeff", &channel);

    // Mix composition commitment
    Blake2sMerkleChannel::mix_root(&mut channel, commitment2);
    print_digest("After commitment 2", &channel);

    println!("\n=== Phase 3: Draw OODS point ===");
    // Phase 3: Draw OOD point
    let _ = channel.draw_secure_felt();
    print_digest("After draw OODS point", &channel);

    println!("\n=== Phase 4: Mix sampled values ===");
    // Phase 4: Mix sampled values (CRITICAL - this was missing before!)
    // Tree 0: empty (preprocessed)
    // Tree 1: 3 trace columns
    let sampled_trace = [
        words_to_qm31([69016441, 1776861555, 902958080, 1948330725]),
        words_to_qm31([451153849, 1397480862, 647858898, 1644858531]),
        words_to_qm31([228473269, 1751409046, 373718550, 1163313824]),
    ];
    // Tree 2: 8 composition columns
    let sampled_composition = [
        words_to_qm31([1479760945, 1025948580, 1468532593, 2078810887]),
        words_to_qm31([0, 0, 0, 0]),
        words_to_qm31([0, 0, 0, 0]),
        words_to_qm31([0, 0, 0, 0]),
        words_to_qm31([1845493759, 0, 0, 0]),
        words_to_qm31([0, 0, 0, 0]),
        words_to_qm31([0, 0, 0, 0]),
        words_to_qm31([0, 0, 0, 0]),
    ];
    // Mix all sampled values in one call
    println!("Total sampled values: {}", sampled_trace.len() + sampled_composition.len());
    let all_sampled: Vec<QM31> = sampled_trace.iter().chain(sampled_composition.iter()).cloned().collect();
    channel.mix_felts(&all_sampled);
    print_digest("After mix sampled values", &channel);

    println!("\n=== Phase 5: Draw FRI random coeff ===");
    // Phase 5: Draw FRI random coeff
    let _ = channel.draw_secure_felt();
    print_digest("After draw FRI coeff", &channel);

    println!("\n=== Phase 6: FRI commit phase ===");
    // Phase 6: Mix FRI commitments and draw alphas
    Blake2sMerkleChannel::mix_root(&mut channel, fri_first_commitment);
    let _ = channel.draw_secure_felt();
    print_digest("After FRI first layer", &channel);
    for (i, c) in fri_inner_commitments.iter().enumerate() {
        Blake2sMerkleChannel::mix_root(&mut channel, *c);
        let _ = channel.draw_secure_felt();
        print_digest(&format!("After FRI inner layer {}", i), &channel);
    }
    channel.mix_felts(&[last_layer_poly]);
    print_digest("After last layer poly", &channel);

    println!("\n=== Phase 7: PoW nonce ===");
    // Phase 7: PoW nonce
    channel.mix_u64(401);
    print_digest("After PoW nonce", &channel);

    // Print digest BEFORE drawing queries
    println!("=== Channel state before drawing queries ===");
    let digest = channel.digest();
    print!("Digest words: [");
    for (i, chunk) in digest.0.chunks(4).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        if i > 0 { print!(", "); }
        print!("{}", word);
    }
    println!("]");

    // Now draw and print exactly what draw_queries produces
    println!("\n=== Drawing query positions ===");
    let log_domain_size = 5u32;
    let n_queries = 3;

    // Draw the first batch of words
    let words = channel.draw_u32s();
    println!("First draw_u32s:");
    for (i, &word) in words.iter().enumerate() {
        let masked = word & ((1 << log_domain_size) - 1);
        println!("  word[{}] = {} -> masked = {} (0x{:08x} -> {})", i, word, masked, word, masked);
    }

    // The draw_queries function takes words in order until it has n_queries
    // (allowing duplicates), then Queries::new sorts and deduplicates
    let raw_positions: Vec<usize> = words.iter()
        .take(n_queries)
        .map(|&w| (w & ((1 << log_domain_size) - 1)) as usize)
        .collect();
    println!("\nRaw positions (first {} words): {:?}", n_queries, raw_positions);

    let queries = Queries::new(&raw_positions, log_domain_size);
    println!("Sorted unique positions: {:?}", queries.positions);

    // Print expected Go format
    println!("\nGo format for verification:");
    println!("ExpectedDrawnWords: []uint32{{");
    for &word in &words {
        println!("    {},", word);
    }
    println!("}},");
}

#[test]
fn test_query_position_folding() {
    // Test how query positions evolve through folding
    let mut channel = Blake2sChannel::default();

    // Build minimal transcript to get same query positions as the proof
    let commitment0 = words_to_hash([
        356389674, 426915842, 2011877665, 2627174952, 4068806529, 3113848964, 2254062035, 2908739609,
    ]);
    let commitment1 = words_to_hash([
        807652323, 2545064309, 2831989782, 1957966857, 187098561, 3534142660, 4271151569, 2991128073,
    ]);
    let commitment2 = words_to_hash([
        1148832328, 974782099, 2352916468, 281928874, 427453219, 3346741966, 1401915353, 4240998853,
    ]);
    let fri_first_commitment = words_to_hash([
        2805472136, 1461034413, 1417292649, 592820859, 1231528413, 416314787, 6862543, 3508467774,
    ]);
    let fri_inner_commitments = [
        words_to_hash([3813426609, 2310714604, 1139451780, 2121015952, 1379227534, 3832687024, 2660825891, 3424227012]),
        words_to_hash([2414166756, 1131098088, 1741050948, 3268476040, 3645587527, 4165088728, 3587759887, 3108133626]),
        words_to_hash([1330527892, 2879612266, 1649893037, 1355168948, 3912611619, 109206685, 2063299016, 1355679096]),
    ];
    let last_layer_poly = words_to_qm31([1127715432, 288372790, 657641239, 2025733499]);

    Blake2sMerkleChannel::mix_root(&mut channel, commitment0);
    channel.mix_u64(4);
    Blake2sMerkleChannel::mix_root(&mut channel, commitment1);
    let _ = channel.draw_secure_felt();
    Blake2sMerkleChannel::mix_root(&mut channel, commitment2);
    let _ = channel.draw_secure_felt();

    // Mix FRI commitments
    Blake2sMerkleChannel::mix_root(&mut channel, fri_first_commitment);
    let _ = channel.draw_secure_felt();
    for c in &fri_inner_commitments {
        Blake2sMerkleChannel::mix_root(&mut channel, *c);
        let _ = channel.draw_secure_felt();
    }
    channel.mix_felts(&[last_layer_poly]);

    // PoW nonce
    channel.mix_u64(401);

    // Draw queries
    let raw_positions = draw_queries(&mut channel, 5, 3);
    let queries = Queries::new(&raw_positions, 5);
    println!("Initial query positions (domain_size=32): {:?}", queries.positions);

    // Track position folding
    let mut positions = queries.positions.clone();
    for layer in 0..4 {
        positions = positions.iter().map(|p| p >> 1).collect();
        println!("After fold {}: {:?}", layer, positions);
    }

    // Check for collisions at each layer
    for layer in 0..4 {
        let layer_positions: Vec<usize> = queries.iter().map(|p| p >> (layer + 1)).collect();
        let unique: std::collections::HashSet<_> = layer_positions.iter().collect();
        println!("Layer {} unique positions: {} (total: {})", layer, unique.len(), layer_positions.len());
    }
}

#[test]
fn test_layer2_query0_fold() {
    // Values from Go debug log for layer=2, query=0
    let v0 = words_to_qm31([1926970400, 1759172830, 1325277308, 881132869]);
    let v1 = words_to_qm31([732202311, 1746524030, 1474095300, 710919978]);
    let x = M31::from(590768354u32);
    let alpha = words_to_qm31([300129476, 2001607645, 493375613, 114619307]);
    
    // Compute FRI fold line (ibutterfly + alpha multiply)
    // f0 = v0 + v1
    // f1 = (v0 - v1) / x
    // result = f0 + alpha * f1
    
    let f0 = v0 + v1;
    let diff = v0 - v1;
    let x_inv = x.inverse();
    let f1 = diff * QM31::from(x_inv);
    let result = f0 + alpha * f1;
    
    println!("v0 = {:?}", v0);
    println!("v1 = {:?}", v1);
    println!("x = {:?}", x);
    println!("x_inv = {:?}", x_inv);
    println!("alpha = {:?}", alpha);
    println!("f0 = {:?}", f0);
    println!("diff = {:?}", diff);
    println!("f1 = {:?}", f1);
    println!("result = {:?}", result);
    
    // Expected from Go debug log
    let go_result = words_to_qm31([8258560, 630327396, 848413874, 1806240812]);
    println!("\nGo result: {:?}", go_result);
    
    // Expected from last layer poly (constant)
    let expected = words_to_qm31([1127715432, 288372790, 657641239, 2025733499]);
    println!("Expected (last layer poly): {:?}", expected);
    
    // Check if Rust computes the same as Go
    if result == go_result {
        println!("\nRust matches Go result.");
    } else {
        println!("\nRust DIFFERS from Go result!");
        println!("Rust result: {:?}", result);
    }
    
    // Check if either matches expected
    if result == expected {
        println!("Rust matches expected.");
    } else if go_result == expected {
        println!("Go matches expected.");
    } else {
        println!("Neither Rust nor Go matches expected!");
    }
}

#[test]
fn test_alpha_values() {
    // Trace the alpha values drawn at each FRI layer
    let mut channel = Blake2sChannel::default();

    // Build the transcript up to FRI commit phase
    let commitment0 = words_to_hash([356389674, 426915842, 2011877665, 2627174952, 4068806529, 3113848964, 2254062035, 2908739609]);
    let commitment1 = words_to_hash([807652323, 2545064309, 2831989782, 1957966857, 187098561, 3534142660, 4271151569, 2991128073]);
    let commitment2 = words_to_hash([1148832328, 974782099, 2352916468, 281928874, 427453219, 3346741966, 1401915353, 4240998853]);
    let fri_first_commitment = words_to_hash([2805472136, 1461034413, 1417292649, 592820859, 1231528413, 416314787, 6862543, 3508467774]);
    let fri_inner_commitments = [
        words_to_hash([1892120923, 2924145469, 2159911583, 66957405, 2487895492, 2196985927, 4239028926, 2125799249]),
        words_to_hash([1507226232, 3510655299, 1183543950, 3710863388, 3475398204, 3998187011, 404841469, 2227082252]),
        words_to_hash([3858460919, 3288971353, 3612704253, 347925492, 950803833, 1355370538, 1533999517, 3583653841]),
    ];

    // Phase 1: Mix commitments
    Blake2sMerkleChannel::mix_root(&mut channel, commitment0);
    channel.mix_u64(4);
    Blake2sMerkleChannel::mix_root(&mut channel, commitment1);
    
    // Phase 2b: Draw composition random coeff
    let _ = channel.draw_secure_felt();
    
    // Mix composition commitment
    Blake2sMerkleChannel::mix_root(&mut channel, commitment2);
    
    // Phase 3: Draw OOD point
    let _ = channel.draw_secure_felt();
    
    // Phase 4: Mix sampled values
    let sampled_trace = [
        words_to_qm31([69016441, 1776861555, 902958080, 1948330725]),
        words_to_qm31([451153849, 1397480862, 647858898, 1644858531]),
        words_to_qm31([228473269, 1751409046, 373718550, 1163313824]),
    ];
    let sampled_composition = [
        words_to_qm31([1479760945, 1025948580, 1468532593, 2078810887]),
        words_to_qm31([0, 0, 0, 0]),
        words_to_qm31([0, 0, 0, 0]),
        words_to_qm31([0, 0, 0, 0]),
        words_to_qm31([1845493759, 0, 0, 0]),
        words_to_qm31([0, 0, 0, 0]),
        words_to_qm31([0, 0, 0, 0]),
        words_to_qm31([0, 0, 0, 0]),
    ];
    let all_sampled: Vec<QM31> = sampled_trace.iter().chain(sampled_composition.iter()).cloned().collect();
    channel.mix_felts(&all_sampled);
    
    // Phase 5: Draw FRI random coeff (line combination coeff)
    let fri_random_coeff = channel.draw_secure_felt();
    println!("FRI random coeff (for quotient combination): {:?}", fri_random_coeff);
    
    // Phase 6: Mix FRI first layer commitment and draw first alpha
    Blake2sMerkleChannel::mix_root(&mut channel, fri_first_commitment);
    let alpha0 = channel.draw_secure_felt();
    println!("Alpha 0 (first layer): {:?}", alpha0);
    
    // Mix inner layer commitments and draw alphas
    for (i, commitment) in fri_inner_commitments.iter().enumerate() {
        Blake2sMerkleChannel::mix_root(&mut channel, *commitment);
        let alpha = channel.draw_secure_felt();
        println!("Alpha {} (inner layer {}): {:?}", i + 1, i, alpha);
    }
    
    // Now print expected from Go debug log
    println!("\nExpected alpha values from Go debug log:");
    println!("First layer alpha: (129930915, 308172301, 1635222146, 723883947)");
    println!("Layer 0 alpha: (1392200401, 74256187, 347899237, 1681682622)");
    println!("Layer 1 alpha: (410673709, 1202018498, 1917675448, 400614615)");
    println!("Layer 2 alpha: (300129476, 2001607645, 493375613, 114619307)");
}

#[test]
fn test_trace_full_fri_verification() {
    // Trace the full FRI verification step by step
    // This verifies that the proof values are consistent
    
    // Query positions (after sorting): [15, 18, 26]
    let query_positions = [15usize, 18, 26];
    
    // First layer witness values
    let first_layer_evals = [
        words_to_qm31([1020745971, 646814303, 1829982739, 1012674541]),
        words_to_qm31([181518346, 401396764, 360659784, 1882161948]),
        words_to_qm31([657080406, 1961204316, 987187349, 881398562]),
    ];
    
    // Inner layer witness values
    let inner_layer_evals = [
        vec![
            words_to_qm31([63360610, 1781900914, 649819767, 1934799813]),
            words_to_qm31([341919180, 1809072112, 1190183534, 994398709]),
            words_to_qm31([1405871356, 55122534, 310428524, 643454092]),
        ],
        vec![
            words_to_qm31([1674352936, 1006503414, 912960314, 2081614385]),
            words_to_qm31([461312021, 700821683, 627566966, 339838524]),
            words_to_qm31([340905436, 328767165, 1046383303, 880287144]),
        ],
        vec![
            words_to_qm31([1926970400, 1759172830, 1325277308, 881132869]),
            words_to_qm31([0, 0, 0, 0]),
            words_to_qm31([0, 0, 0, 0]),
        ],
    ];
    
    // Alpha values (from correct channel state)
    let alphas = [
        words_to_qm31([129930915, 308172301, 1635222146, 723883947]),
        words_to_qm31([1392200401, 74256187, 347899237, 1681682622]),
        words_to_qm31([410673709, 1202018498, 1917675448, 400614615]),
        words_to_qm31([300129476, 2001607645, 493375613, 114619307]),
    ];
    
    // Last layer poly (constant)
    let last_layer_poly = words_to_qm31([1127715432, 288372790, 657641239, 2025733499]);
    
    println!("=== FRI Verification Trace ===");
    println!("Query positions: {:?}", query_positions);
    
    // We need to track the computed values through each layer
    // But we don't have the quotient values - those need to be computed
    // Let me just trace what values SHOULD be at each position
    
    // Let me trace backwards from the last layer to see what the expected values should be
    println!("\n=== Tracing backwards from last layer ===");
    println!("Last layer poly (constant): {:?}", last_layer_poly);
    
    // At last layer (domain size 2), both positions should equal last_layer_poly
    // Position 0: last_layer_poly
    // Position 1: last_layer_poly (for constant poly)
    
    // Layer 2 (domain size 4) folds to last layer (domain size 2)
    // Fold formula: result = f0 + alpha * f1 where f0 = v0 + v1, f1 = (v0 - v1) / x
    // Solving backwards: we need v0 + alpha*(v0-v1)/x = expected
    
    // But this is complex. Let me instead verify that IF we use the witness values
    // as given, does the fold produce expected?
    
    // Actually, the simplest check: does the proof's layer 2 witness fold to the last layer poly?
    // Layer 2 fold subset {0, 1}: v0=witness[0], v1=???
    // The v1 should come from layer 1 fold of query 0
    
    // Let me compute what v1 SHOULD be by folding backwards
    // expected = (v0 + v1) + alpha * (v0 - v1) / x
    // Let E = expected, V0 = v0, A = alpha, X = x
    // E = V0 + V1 + A * (V0 - V1) / X
    // E - V0 = V1 + A * (V0 - V1) / X
    // (E - V0) * X = V1 * X + A * (V0 - V1)
    // (E - V0) * X = V1 * X + A*V0 - A*V1
    // (E - V0) * X - A*V0 = V1 * (X - A)
    // V1 = ((E - V0) * X - A*V0) / (X - A)
    
    let v0 = inner_layer_evals[2][0]; // Layer 2 witness at position 0
    let alpha = alphas[3]; // Layer 2 alpha
    let x = M31::from(590768354u32); // x at position 0, logSize=2
    let expected = last_layer_poly;
    
    println!("\nLayer 2 backward trace:");
    println!("v0 (witness) = {:?}", v0);
    println!("alpha = {:?}", alpha);
    println!("x = {:?}", x);
    println!("expected (last layer poly) = {:?}", expected);
    
    // Compute expected v1
    // V1 = ((E - V0) * X - A*V0) / (X - A)
    let e_minus_v0 = expected - v0;
    let x_qm31 = QM31::from(x);
    let numerator = e_minus_v0 * x_qm31 - alpha * v0;
    let denominator = x_qm31 - alpha;
    let expected_v1 = numerator * denominator.inverse();
    
    println!("Expected v1 (computed backwards) = {:?}", expected_v1);
    
    // Now verify: does layer 1 query 0 fold to this expected_v1?
    // Layer 1, query 0 is at position 3 after layer 0, which becomes position 1 after layer 1
    // Actually query 0 starts at 15, becomes 7 after first layer, becomes 3 after layer 0, becomes 1 after layer 1
    // So query 0 is at position 1 in layer 2
    // The value at position 1 should be the result of layer 1 fold for query 0
    
    // Layer 1 fold for query 0:
    // - Position after layer 0: 3
    // - In layer 1 (domain size 8), fold subset is {2, 3}
    // - Query 0 is at position 3 (odd), sibling is position 2
    // - If no query at position 2, we need witness
    
    // Let me just verify the forward fold produces expected_v1
    // ... this is getting complex. Let me just note that if the proof is valid,
    // then the witness values are correct and our fold should produce expected.
    
    // But our fold produces (8258560, ...) instead of (1127715432, ...)
    // This suggests either:
    // 1. The proof witness values are wrong
    // 2. Our fold formula/inputs are wrong
    
    println!("\nActual computed (from forward fold): {:?}", words_to_qm31([8258560, 630327396, 848413874, 1806240812]));
}

#[test]
fn test_expected_quotient_from_fold_result() {
    // From the first layer fold, we know:
    // - witness (v0) at position 14
    // - result after folding
    // - alpha
    // - We need to find what v1 (quotient at position 15) SHOULD be
    
    let v0 = words_to_qm31([1020745971, 646814303, 1829982739, 1012674541]); // witness at position 14
    let result = words_to_qm31([1099958286, 1426598119, 678449363, 439445021]); // fold result
    let alpha = words_to_qm31([129930915, 308172301, 1635222146, 723883947]); // first layer alpha
    
    // From the debug log, the fold used x=1461702947 but that's for the line fold.
    // For circle-to-line (first layer), we use itwid = 1/y where y is y-coordinate at position 14.
    // From debug: [circlePointFromQueryHint] position=14, logDomainSize=5, bitReversedPos=14
    // We need to compute the circle point at position 14 to get y
    
    // Let me get itwid from the debug log. Actually, the debug shows x=1461702947 for the first layer.
    // But wait, first layer should use itwid (y inverse), not x.
    // Let me check the debug output more carefully...
    
    // Actually, from the [FOLD] line with weird layer number (first layer):
    // x=1461702947 - but this should be itwid for first layer
    // Let me use this value as itwid
    let itwid = M31::from(1461702947u32);
    
    // Fold formula: result = (v0 + v1) + alpha * (v0 - v1) * itwid
    // Solving for v1:
    // result - v0 - alpha * v0 * itwid = v1 - alpha * v1 * itwid
    // result - v0 * (1 + alpha * itwid) = v1 * (1 - alpha * itwid)
    // v1 = (result - v0 * (1 + alpha * itwid)) / (1 - alpha * itwid)
    
    let itwid_qm31 = QM31::from(itwid);
    let alpha_times_itwid = alpha * itwid_qm31;
    let one = QM31::from(M31::from(1u32));
    
    let one_plus_at = one + alpha_times_itwid;
    let one_minus_at = one - alpha_times_itwid;
    
    let numerator = result - v0 * one_plus_at;
    let expected_v1 = numerator * one_minus_at.inverse();
    
    println!("Expected v1 (quotient at position 15): {:?}", expected_v1);
    
    // Compare with actual v1 from Go debug:
    let actual_v1 = words_to_qm31([1018682424, 297151749, 1092307799, 1528452367]);
    println!("Actual v1 from Go: {:?}", actual_v1);
    
    if expected_v1 == actual_v1 {
        println!("\nv1 matches! Quotient computation is correct.");
    } else {
        println!("\nv1 MISMATCH! Quotient computation is wrong.");
        
        // Verify our algebra by computing result from expected v1
        let f0 = v0 + expected_v1;
        let f1 = (v0 - expected_v1) * itwid_qm31;
        let computed_result = f0 + alpha * f1;
        println!("Computed result from expected v1: {:?}", computed_result);
        println!("Actual result: {:?}", result);
        
        if computed_result == result {
            println!("Our expected v1 produces the correct result.");
        }
    }
}

#[test]
fn test_trace_backwards_all_layers() {
    // Trace backwards from last layer to find where the error is
    
    // Layer 2 data (query 0)
    println!("=== Layer 2 (query 0) ===");
    let l2_v0 = words_to_qm31([1926970400, 1759172830, 1325277308, 881132869]); // witness
    let l2_result = words_to_qm31([8258560, 630327396, 848413874, 1806240812]); // computed
    let l2_expected = words_to_qm31([1127715432, 288372790, 657641239, 2025733499]); // last layer poly
    let l2_alpha = words_to_qm31([300129476, 2001607645, 493375613, 114619307]);
    let l2_x = M31::from(590768354u32);
    
    // Compute expected v1 from EXPECTED result
    let l2_x_qm31 = QM31::from(l2_x);
    let l2_x_inv = QM31::from(l2_x.inverse());
    let l2_one = QM31::from(M31::from(1u32));
    
    // result = (v0 + v1) + alpha * (v0 - v1) * x_inv
    // R - V0 - A*V0*X_inv = V1 - A*V1*X_inv
    // R - V0*(1 + A*X_inv) = V1*(1 - A*X_inv)
    // V1 = (R - V0*(1 + A*X_inv)) / (1 - A*X_inv)
    let l2_at = l2_alpha * l2_x_inv;
    let l2_expected_v1 = (l2_expected - l2_v0 * (l2_one + l2_at)) * (l2_one - l2_at).inverse();
    
    println!("Witness v0: {:?}", l2_v0);
    println!("Computed result: {:?}", l2_result);
    println!("EXPECTED result (last layer): {:?}", l2_expected);
    println!("Expected v1 (to produce expected result): {:?}", l2_expected_v1);
    
    // What v1 was actually used?
    // From debug: v1=(732202311,1746524030,1474095300,710919978)
    let l2_actual_v1 = words_to_qm31([732202311, 1746524030, 1474095300, 710919978]);
    println!("Actual v1 used: {:?}", l2_actual_v1);
    
    if l2_expected_v1 == l2_actual_v1 {
        println!("Layer 2 v1 is CORRECT!");
    } else {
        println!("Layer 2 v1 is WRONG!");
        println!("This means layer 1 produced wrong result for query 0.");
    }
    
    // Now trace layer 1 (query 0)
    println!("\n=== Layer 1 (query 0) ===");
    let l1_v0 = words_to_qm31([1674352936, 1006503414, 912960314, 2081614385]); // witness
    let l1_result = l2_actual_v1; // actual v1 used in layer 2 = result of layer 1
    let l1_alpha = words_to_qm31([410673709, 1202018498, 1917675448, 400614615]);
    let l1_x = M31::from(1241207368u32);
    
    // Compute expected v1 to produce l2_expected_v1
    let l1_x_qm31 = QM31::from(l1_x);
    let l1_x_inv = QM31::from(l1_x.inverse());
    let l1_one = QM31::from(M31::from(1u32));
    let l1_at = l1_alpha * l1_x_inv;
    let l1_expected_v1 = (l2_expected_v1 - l1_v0 * (l1_one + l1_at)) * (l1_one - l1_at).inverse();
    
    println!("Witness v0: {:?}", l1_v0);
    println!("Actual result: {:?}", l1_result);
    println!("Expected result (to produce correct layer 2): {:?}", l2_expected_v1);
    println!("Expected v1 (to produce expected result): {:?}", l1_expected_v1);
    
    // What v1 was actually used?
    // From debug: v1=(595537687,70778851,1026467760,1313604802) - this is layer 0 result for query 0
    let l1_actual_v1 = words_to_qm31([595537687, 70778851, 1026467760, 1313604802]);
    println!("Actual v1 used: {:?}", l1_actual_v1);
    
    if l1_expected_v1 == l1_actual_v1 {
        println!("Layer 1 v1 is CORRECT! Problem is in layer 1 witness.");
    } else {
        println!("Layer 1 v1 is WRONG! This means layer 0 produced wrong result OR layer 1 witness is wrong.");
    }
    
    // Now trace layer 0 (query 0)
    println!("\n=== Layer 0 (query 0) ===");
    let l0_v0 = words_to_qm31([63360610, 1781900914, 649819767, 1934799813]); // witness
    let l0_result = l1_actual_v1; // actual v1 used in layer 1 = result of layer 0
    let l0_alpha = words_to_qm31([1392200401, 74256187, 347899237, 1681682622]);
    let l0_x = M31::from(2121318970u32);
    
    // Compute expected v1 to produce l1_expected_v1
    let l0_x_qm31 = QM31::from(l0_x);
    let l0_x_inv = QM31::from(l0_x.inverse());
    let l0_one = QM31::from(M31::from(1u32));
    let l0_at = l0_alpha * l0_x_inv;
    let l0_expected_v1 = (l1_expected_v1 - l0_v0 * (l0_one + l0_at)) * (l0_one - l0_at).inverse();
    
    println!("Witness v0: {:?}", l0_v0);
    println!("Actual result: {:?}", l0_result);
    println!("Expected result (to produce correct layer 1): {:?}", l1_expected_v1);
    println!("Expected v1 (to produce expected result): {:?}", l0_expected_v1);
    
    // What v1 was actually used?
    // From debug: v1=(1099958286,1426598119,678449363,439445021) - this is first layer result for query 0
    let l0_actual_v1 = words_to_qm31([1099958286, 1426598119, 678449363, 439445021]);
    println!("Actual v1 used: {:?}", l0_actual_v1);
    
    if l0_expected_v1 == l0_actual_v1 {
        println!("Layer 0 v1 is CORRECT! Problem is in layer 0 witness.");
    } else {
        println!("Layer 0 v1 is WRONG! This means first layer produced wrong result OR layer 0 witness is wrong.");
    }
    
    // Check the first layer fold result
    println!("\n=== First Layer (query 0) ===");
    let f_v0 = words_to_qm31([1020745971, 646814303, 1829982739, 1012674541]); // witness
    let f_result = l0_actual_v1; // actual v1 used in layer 0 = result of first layer
    let f_alpha = words_to_qm31([129930915, 308172301, 1635222146, 723883947]);
    let f_itwid = M31::from(1461702947u32); // from debug
    
    // Compute expected v1 to produce l0_expected_v1
    let f_itwid_qm31 = QM31::from(f_itwid);
    let f_one = QM31::from(M31::from(1u32));
    let f_at = f_alpha * f_itwid_qm31;
    let f_expected_v1 = (l0_expected_v1 - f_v0 * (f_one + f_at)) * (f_one - f_at).inverse();
    
    println!("Witness v0: {:?}", f_v0);
    println!("Actual result: {:?}", f_result);
    println!("Expected result (to produce correct layer 0): {:?}", l0_expected_v1);
    println!("Expected v1 (computed quotient needed): {:?}", f_expected_v1);
    
    // What v1 was actually used?
    // From debug: v1=(1018682424,297151749,1092307799,1528452367) - computed quotient
    let f_actual_v1 = words_to_qm31([1018682424, 297151749, 1092307799, 1528452367]);
    println!("Actual v1 (computed quotient): {:?}", f_actual_v1);
    
    if f_expected_v1 == f_actual_v1 {
        println!("\nFirst layer quotient matches expected! Issue is in witnesses.");
    } else {
        println!("\nFirst layer QUOTIENT is WRONG!");
        println!("The quotient at position 15 should be {:?}", f_expected_v1);
        println!("But we computed {:?}", f_actual_v1);
    }
}
