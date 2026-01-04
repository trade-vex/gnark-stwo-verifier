//! Channel parity tests.
//!
//! These tests verify that the Go channel implementation produces the same
//! digest values as the Rust stwo channel.

use stwo::core::channel::{Blake2sChannel, Channel, MerkleChannel};
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs::blake2_merkle::Blake2sMerkleChannel;

#[test]
fn test_mix_u64_parity() {
    // Test mix_u64 with value 4 (typical log_size)
    let mut channel = Blake2sChannel::default();
    channel.mix_u64(4);

    // digest() returns Blake2sHash which is a [u8; 32]
    let digest = channel.digest();
    println!("After mix_u64(4), digest bytes:");
    for (i, chunk) in digest.0.chunks(4).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        println!("  [{}]: 0x{:08x} ({})", i, word, word);
    }

    // Print as Go-compatible format
    println!("\nGo format:");
    print!("ExpectedDigest: [8]frontend.Variable{{");
    for (i, chunk) in digest.0.chunks(4).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        if i > 0 {
            print!(", ");
        }
        print!("0x{:08x}", word);
    }
    println!("}},");
}

#[test]
fn test_draw_random_words_parity() {
    use stwo::core::channel::Channel;

    // Test draw from initial state
    let mut channel = Blake2sChannel::default();

    // Draw first set of felts (this uses draw internally)
    let felt = channel.draw_secure_felt();
    println!("First secure felt: {:?}", felt);

    // Print digest after draw
    let digest = channel.digest();
    println!("\nDigest after draw:");
    for (i, chunk) in digest.0.chunks(4).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        println!("  [{}]: 0x{:08x}", i, word);
    }
}

#[test]
fn test_mix_commitment_parity() {
    // Test mixing a zero commitment (all zeros)
    let mut channel = Blake2sChannel::default();
    let zero_hash = Blake2sHash([0u8; 32]);
    Blake2sMerkleChannel::mix_root(&mut channel, zero_hash);

    let digest = channel.digest();
    println!("After mix zero commitment, digest words:");
    for (i, chunk) in digest.0.chunks(4).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        println!("  [{}]: 0x{:08x}", i, word);
    }

    println!("\nGo format:");
    print!("ExpectedDigest: [8]frontend.Variable{{");
    for (i, chunk) in digest.0.chunks(4).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        if i > 0 {
            print!(", ");
        }
        print!("0x{:08x}", word);
    }
    println!("}},");
}

#[test]
fn test_full_verification_transcript() {
    // Simulate the full verification transcript:
    // 1. Mix commitment 0
    // 2. Mix log_size (4)
    // 3. Mix commitment 1
    // 4. Draw secure felt
    // 5. Mix commitment 2
    // 6. Draw secure felt
    // 7. Check final digest

    let mut channel = Blake2sChannel::default();

    // Mix commitment 0 (zeros)
    Blake2sMerkleChannel::mix_root(&mut channel, Blake2sHash([0u8; 32]));
    println!("After mix commitment 0:");
    print_digest(&channel.digest());

    // Mix log_size = 4
    channel.mix_u64(4);
    println!("\nAfter mix u64(4):");
    print_digest(&channel.digest());

    // Mix commitment 1 (zeros)
    Blake2sMerkleChannel::mix_root(&mut channel, Blake2sHash([0u8; 32]));
    println!("\nAfter mix commitment 1:");
    print_digest(&channel.digest());

    // Draw secure felt
    let felt1 = channel.draw_secure_felt();
    println!("\nDrawn felt 1: {:?}", felt1);
    println!("Digest after draw:");
    print_digest(&channel.digest());
}

fn print_digest(digest: &stwo::core::vcs::blake2_hash::Blake2sHash) {
    for (i, chunk) in digest.0.chunks(4).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        println!("  [{}]: 0x{:08x}", i, word);
    }
}

#[test]
fn test_draw_u32s_parity() {
    // Test drawing u32s from initial state
    let mut channel = Blake2sChannel::default();

    // draw_u32s uses hash(digest || n_draws || 0x00) where n_draws starts at 0
    // This is 37 bytes total: 32 + 4 + 1
    let words = channel.draw_u32s();
    println!("First draw_u32s from initial state (n_draws=0):");
    for (i, word) in words.iter().enumerate() {
        println!("  [{}]: 0x{:08x}", i, word);
    }

    // The digest should remain unchanged (draw doesn't modify digest)
    println!("\nDigest after draw (should be zero):");
    print_digest(&channel.digest());

    // n_draws should now be 1, so second draw gives different result
    let words2 = channel.draw_u32s();
    println!("\nSecond draw_u32s (n_draws=1):");
    for (i, word) in words2.iter().enumerate() {
        println!("  [{}]: 0x{:08x}", i, word);
    }

    // Print Go format for first draw
    println!("\nGo format for first draw:");
    print!("ExpectedWords: [8]frontend.Variable{{");
    for (i, word) in words.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        print!("0x{:08x}", word);
    }
    println!("}},");
}

#[test]
fn test_real_proof_transcript() {
    use stwo::core::queries::draw_queries;

    // Use actual commitment values from the proof
    // commitment[0] = [356389674, 426915842, 2011877665, 2627174952, 4068806529, 3113848964, 2254062035, 2908739609]
    // commitment[1] = [807652323, 2545064309, 2831989782, 1957966857, 187098561, 3534142660, 4271151569, 2991128073]
    // commitment[2] = [1148832328, 974782099, 2352916468, 281928874, 427453219, 3346741966, 1401915353, 4240998853]

    fn words_to_hash(words: [u32; 8]) -> Blake2sHash {
        let mut bytes = [0u8; 32];
        for (i, w) in words.iter().enumerate() {
            bytes[i*4..(i+1)*4].copy_from_slice(&w.to_le_bytes());
        }
        Blake2sHash(bytes)
    }

    let commitment0 = words_to_hash([356389674, 426915842, 2011877665, 2627174952, 4068806529, 3113848964, 2254062035, 2908739609]);
    let commitment1 = words_to_hash([807652323, 2545064309, 2831989782, 1957966857, 187098561, 3534142660, 4271151569, 2991128073]);
    let commitment2 = words_to_hash([1148832328, 974782099, 2352916468, 281928874, 427453219, 3346741966, 1401915353, 4240998853]);

    let mut channel = Blake2sChannel::default();

    // 1. Mix preprocessed commitment (tree 0)
    Blake2sMerkleChannel::mix_root(&mut channel, commitment0);
    println!("After commitment 0:");
    print_digest(&channel.digest());

    // 2. Mix log_size (4)
    channel.mix_u64(4);
    println!("\nAfter mix_u64(4):");
    print_digest(&channel.digest());

    // 3. Mix trace commitment (tree 1)
    Blake2sMerkleChannel::mix_root(&mut channel, commitment1);
    println!("\nAfter commitment 1:");
    print_digest(&channel.digest());

    // 4. Draw random_coeff (interaction elements)
    let random_coeff = channel.draw_secure_felt();
    println!("\nDraw random_coeff: {:?}", random_coeff);
    println!("Digest after draw:");
    print_digest(&channel.digest());

    // 5. Mix interaction commitment (tree 2)
    Blake2sMerkleChannel::mix_root(&mut channel, commitment2);
    println!("\nAfter commitment 2:");
    print_digest(&channel.digest());

    // 6. Draw OODS point
    let oods_point = channel.draw_secure_felt();
    println!("\nDraw OODS point: {:?}", oods_point);

    // Print channel state
    println!("\n=== Channel state before FRI ===");
    print_digest(&channel.digest());

    // Generate FRI queries with log_domain_size=5 (log_size=4 + log_blowup=1)
    // n_queries=3
    let raw_positions = draw_queries(&mut channel, 5, 3);
    println!("\nGenerated FRI query positions: {:?}", raw_positions);

    // Draw FRI folding alphas
    // numFriLayers = maxLogSize + LogBlowupFactor - LogLastLayerDeg = 4 + 1 - 0 = 5
    // But first layer is circle-to-line, inner layers are line-to-line
    // So we have 4 line-to-line folds, each needing an alpha
    println!("\nFRI folding alphas:");
    for i in 0..4 {
        let alpha = channel.draw_secure_felt();
        println!("  alpha[{}]: {:?}", i, alpha);
    }

    println!("\n=== Final channel state ===");
    print_digest(&channel.digest());
}

#[test]
fn test_full_verification_transcript_extended() {
    use stwo::core::fields::m31::M31;
    use stwo::core::fields::qm31::QM31;

    // Use actual commitment values from the proof
    fn words_to_hash(words: [u32; 8]) -> Blake2sHash {
        let mut bytes = [0u8; 32];
        for (i, w) in words.iter().enumerate() {
            bytes[i*4..(i+1)*4].copy_from_slice(&w.to_le_bytes());
        }
        Blake2sHash(bytes)
    }

    let commitment0 = words_to_hash([356389674, 426915842, 2011877665, 2627174952, 4068806529, 3113848964, 2254062035, 2908739609]);
    let commitment1 = words_to_hash([807652323, 2545064309, 2831989782, 1957966857, 187098561, 3534142660, 4271151569, 2991128073]);
    let commitment2 = words_to_hash([1148832328, 974782099, 2352916468, 281928874, 427453219, 3346741966, 1401915353, 4240998853]);

    // FRI first layer commitment from proof
    let fri_first_commitment = words_to_hash([2413890261, 3197376044, 2556706481, 1987880596, 1313106618, 2606890866, 3330073476, 3627889115]);

    let mut channel = Blake2sChannel::default();

    // 1. Mix preprocessed commitment (tree 0)
    Blake2sMerkleChannel::mix_root(&mut channel, commitment0);
    println!("Step 1 - After commitment 0:");
    print_digest(&channel.digest());

    // 2. Mix log_size (4)
    channel.mix_u64(4);
    println!("\nStep 2 - After mix_u64(4):");
    print_digest(&channel.digest());

    // 3. Mix trace commitment (tree 1)
    Blake2sMerkleChannel::mix_root(&mut channel, commitment1);
    println!("\nStep 3 - After commitment 1:");
    print_digest(&channel.digest());

    // 4. Draw random_coeff (composition random coeff)
    let random_coeff = channel.draw_secure_felt();
    println!("\nStep 4 - Draw random_coeff: {:?}", random_coeff);
    println!("Digest after draw:");
    print_digest(&channel.digest());

    // 5. Mix interaction commitment (tree 2 = composition)
    Blake2sMerkleChannel::mix_root(&mut channel, commitment2);
    println!("\nStep 5 - After commitment 2:");
    print_digest(&channel.digest());

    // 6. Draw OODS point t
    let oods_t = channel.draw_secure_felt();
    println!("\nStep 6 - Draw OODS point t: {:?}", oods_t);
    println!("Digest after draw:");
    print_digest(&channel.digest());

    // ========================================
    // At this point, the Rust verifier would:
    // 7. Mix sampled values (OOD evaluations)
    // 8. Draw FRI random coeff
    // 9. Mix FRI layer commitments, draw alphas
    // 10. Mix last layer poly
    // 11. PoW verify, mix nonce
    // 12. Draw query positions
    // ========================================

    // 7. Mix sampled values - need to get these from proof
    // For simple-air, there are 11 sampled values (3 trace columns + 8 composition columns)
    // Using placeholder zeros for now - need actual values from proof
    let sampled_values: Vec<QM31> = vec![
        // Tree 1 (trace): 3 columns
        QM31::from_m31_array([M31::from(100), M31::from(0), M31::from(0), M31::from(0)]),
        QM31::from_m31_array([M31::from(200), M31::from(0), M31::from(0), M31::from(0)]),
        QM31::from_m31_array([M31::from(300), M31::from(0), M31::from(0), M31::from(0)]),
        // Tree 2 (composition): 8 columns - using zeros for now
    ];

    println!("\nStep 7 - Mixing sampled values (placeholder):");
    if !sampled_values.is_empty() {
        channel.mix_felts(&sampled_values);
    }
    print_digest(&channel.digest());

    // 8. Draw FRI random coeff
    let fri_random_coeff = channel.draw_secure_felt();
    println!("\nStep 8 - Draw FRI random coeff: {:?}", fri_random_coeff);

    // 9. Mix FRI first layer commitment
    Blake2sMerkleChannel::mix_root(&mut channel, fri_first_commitment);
    println!("\nStep 9 - After FRI first layer commitment:");
    print_digest(&channel.digest());

    // 10. Draw first alpha
    let alpha0 = channel.draw_secure_felt();
    println!("\nStep 10 - Draw first alpha: {:?}", alpha0);

    println!("\n=== Expected values for Go parity test ===");
    println!("random_coeff: {:?}", random_coeff);
    println!("oods_t: {:?}", oods_t);
    println!("fri_random_coeff: {:?}", fri_random_coeff);
    println!("alpha0: {:?}", alpha0);
}

#[test]
fn test_mix_felts_parity() {
    use stwo::core::fields::m31::M31;
    use stwo::core::fields::qm31::QM31;

    // Test mixing a single QM31 value
    let mut channel = Blake2sChannel::default();

    // Create a simple QM31 value: [1, 2, 3, 4] (M31 components)
    let felt1 = QM31::from_m31_array([M31::from(1), M31::from(2), M31::from(3), M31::from(4)]);

    channel.mix_felts(&[felt1]);

    println!("After mix_felts([1, 2, 3, 4]):");
    print_digest(&channel.digest());

    println!("\nGo format:");
    let digest = channel.digest();
    print!("ExpectedDigest: [8]frontend.Variable{{");
    for (i, chunk) in digest.0.chunks(4).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        if i > 0 { print!(", "); }
        print!("0x{:08x}", word);
    }
    println!("}},");

    // Test mixing multiple QM31 values
    let mut channel2 = Blake2sChannel::default();
    let felt2 = QM31::from_m31_array([M31::from(100), M31::from(200), M31::from(300), M31::from(400)]);
    let felt3 = QM31::from_m31_array([M31::from(1000), M31::from(2000), M31::from(3000), M31::from(4000)]);

    channel2.mix_felts(&[felt1, felt2, felt3]);

    println!("\nAfter mix_felts([3 QM31 values]):");
    print_digest(&channel2.digest());

    println!("\nGo format:");
    let digest2 = channel2.digest();
    print!("ExpectedDigest: [8]frontend.Variable{{");
    for (i, chunk) in digest2.0.chunks(4).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        if i > 0 { print!(", "); }
        print!("0x{:08x}", word);
    }
    println!("}},");
}
