//! Test file to replay the channel sequence from the witness and print intermediate values.
//!
//! This file produces reference values from Rust's stwo Blake2sChannel to compare with Go.
//!
//! Run with:
//!   rustup run nightly-2025-07-14 cargo test --features stwo_support channel_parity -- --nocapture

#[cfg(feature = "stwo_support")]
mod tests {
    use stwo::core::channel::{Blake2sChannel, Channel, MerkleChannel};
    use stwo::core::fields::m31::M31;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::vcs::blake2_merkle::Blake2sMerkleChannel;
    use stwo::core::vcs::blake2_hash::Blake2sHash;

    /// Witness data structures matching the JSON format
    #[derive(serde::Deserialize)]
    struct WitnessJSON {
        proof: ProofJSON,
        config: ConfigJSON,
        column_log_sizes: Vec<Vec<u32>>,
    }

    #[derive(serde::Deserialize)]
    struct ProofJSON {
        commitments: Vec<Blake2sHashJSON>,
        sampled_values: Vec<Vec<Vec<QM31JSON>>>,
        pow_nonce: u64,
        fri_proof: FriProofJSON,
    }

    #[derive(serde::Deserialize)]
    struct FriProofJSON {
        first_layer: FriLayerJSON,
        inner_layers: Vec<FriLayerJSON>,
        last_layer_poly: Vec<QM31JSON>,
    }

    #[derive(serde::Deserialize)]
    struct FriLayerJSON {
        commitment: Blake2sHashJSON,
        #[serde(default)]
        eval_values: Vec<QM31JSON>,
    }

    #[derive(serde::Deserialize, Clone)]
    struct Blake2sHashJSON {
        words: [u32; 8],
    }

    #[derive(serde::Deserialize, Clone)]
    struct QM31JSON {
        values: [M31JSON; 4],
    }

    #[derive(serde::Deserialize, Clone, Copy)]
    struct M31JSON {
        value: u32,
    }

    #[derive(serde::Deserialize)]
    struct ConfigJSON {
        pow_bits: u32,
        log_blowup_factor: u32,
        log_last_layer_deg: u32,
        num_queries: u32,
    }

    impl From<&Blake2sHashJSON> for Blake2sHash {
        fn from(h: &Blake2sHashJSON) -> Self {
            let mut bytes = [0u8; 32];
            for i in 0..8 {
                let word_bytes = h.words[i].to_le_bytes();
                bytes[i*4..i*4+4].copy_from_slice(&word_bytes);
            }
            Blake2sHash(bytes)
        }
    }

    impl From<&QM31JSON> for SecureField {
        fn from(q: &QM31JSON) -> Self {
            SecureField::from_m31_array([
                M31::from(q.values[0].value),
                M31::from(q.values[1].value),
                M31::from(q.values[2].value),
                M31::from(q.values[3].value),
            ])
        }
    }

    fn format_hash(h: &Blake2sHash) -> String {
        format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...",
            h.0[0], h.0[1], h.0[2], h.0[3], h.0[4], h.0[5], h.0[6], h.0[7])
    }

    fn format_qm31(q: &SecureField) -> String {
        let arr = q.to_m31_array();
        format!("({}, {}, {}, {})", arr[0].0, arr[1].0, arr[2].0, arr[3].0)
    }

    fn digest_to_words(digest: &Blake2sHash) -> [u32; 8] {
        let mut words = [0u32; 8];
        for i in 0..8 {
            words[i] = u32::from_le_bytes([
                digest.0[i*4], digest.0[i*4+1], digest.0[i*4+2], digest.0[i*4+3]
            ]);
        }
        words
    }

    fn print_digest(channel: &Blake2sChannel, label: &str) {
        let digest = channel.digest();
        let words = digest_to_words(&digest);
        println!("{}: words=[{}, {}, {}, {}, {}, {}, {}, {}]",
            label, words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7]);
        println!("       hex: {}", format_hash(&digest));
    }

    /// Draw u32s from random bytes (v1.0.0 uses draw_random_bytes instead of draw_u32s)
    fn draw_u32s(channel: &mut Blake2sChannel) -> Vec<u32> {
        let bytes = channel.draw_random_bytes();
        bytes.chunks(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect()
    }

    #[test]
    fn test_channel_parity() {
        println!("\n=== RUST Channel Parity Test ===\n");

        // Load witness file
        let witness_path = concat!(env!("CARGO_MANIFEST_DIR"), "/witness_proving_an_air.json");
        let witness_data = std::fs::read_to_string(witness_path)
            .expect("Failed to read witness file");
        let witness: WitnessJSON = serde_json::from_str(&witness_data)
            .expect("Failed to parse witness JSON");

        println!("Loaded witness with {} commitments, {} FRI inner layers",
            witness.proof.commitments.len(),
            witness.proof.fri_proof.inner_layers.len());
        println!("Config: pow_bits={}, log_blowup={}, log_last_layer_deg={}, num_queries={}",
            witness.config.pow_bits,
            witness.config.log_blowup_factor,
            witness.config.log_last_layer_deg,
            witness.config.num_queries);

        // Compute log domain size
        let max_log_size = witness.column_log_sizes.iter()
            .flat_map(|tree| tree.iter())
            .max()
            .copied()
            .unwrap_or(0);
        let log_domain_size = max_log_size + witness.config.log_blowup_factor;
        println!("Max column log size: {}, Domain log size: {}\n", max_log_size, log_domain_size);

        // Create channel
        let mut channel = Blake2sChannel::default();
        print_digest(&channel, "Step 0: Initial state");

        // Step 1: Mix all tree commitments
        println!("\n--- Phase 1: Mix Commitments ---");
        for (i, comm) in witness.proof.commitments.iter().enumerate() {
            let hash = Blake2sHash::from(comm);
            Blake2sMerkleChannel::mix_root(&mut channel, hash);
            print_digest(&channel, &format!("After mixing commitment[{}]", i));
        }

        // Step 2: Draw random_coeff (composition random coefficient)
        println!("\n--- Phase 2: Draw random_coeff (composition) ---");
        let random_coeff = channel.draw_secure_felt();
        println!("random_coeff: {}", format_qm31(&random_coeff));
        print_digest(&channel, "After drawing random_coeff");

        // Step 3: Draw OOD point parameter t
        println!("\n--- Phase 3: Draw OOD point t ---");
        let ood_t = channel.draw_secure_felt();
        println!("OOD t: {}", format_qm31(&ood_t));
        print_digest(&channel, "After drawing OOD t");

        // Step 4: Mix sampled values (OOD evaluations)
        println!("\n--- Phase 4: Mix sampled values ---");
        let mut all_sampled: Vec<SecureField> = Vec::new();
        for tree in &witness.proof.sampled_values {
            for col in tree {
                for val in col {
                    all_sampled.push(SecureField::from(val));
                }
            }
        }
        println!("Total sampled values to mix: {}", all_sampled.len());
        if !all_sampled.is_empty() {
            channel.mix_felts(&all_sampled);
            print_digest(&channel, "After mixing sampled values");
        }

        // Step 5: Draw FRI random coeff
        println!("\n--- Phase 5: Draw FRI random coeff ---");
        let fri_random_coeff = channel.draw_secure_felt();
        println!("FRI random coeff: {}", format_qm31(&fri_random_coeff));
        print_digest(&channel, "After drawing FRI random coeff");

        // Step 6: FRI Commit Phase
        println!("\n--- Phase 6: FRI Commit Phase ---");

        // First layer
        let first_layer_hash = Blake2sHash::from(&witness.proof.fri_proof.first_layer.commitment);
        Blake2sMerkleChannel::mix_root(&mut channel, first_layer_hash);
        print_digest(&channel, "After mixing FRI first layer commitment");

        let alpha0 = channel.draw_secure_felt();
        println!("FRI alpha[0]: {}", format_qm31(&alpha0));
        print_digest(&channel, "After drawing alpha[0]");

        // Inner layers
        for (i, layer) in witness.proof.fri_proof.inner_layers.iter().enumerate() {
            let layer_hash = Blake2sHash::from(&layer.commitment);
            Blake2sMerkleChannel::mix_root(&mut channel, layer_hash);
            print_digest(&channel, &format!("After mixing FRI inner layer[{}] commitment", i));

            let alpha = channel.draw_secure_felt();
            println!("FRI alpha[{}]: {}", i + 1, format_qm31(&alpha));
            print_digest(&channel, &format!("After drawing alpha[{}]", i + 1));
        }

        // Step 7: Mix last layer poly
        println!("\n--- Phase 7: Mix last layer poly ---");
        let last_layer_felts: Vec<SecureField> = witness.proof.fri_proof.last_layer_poly
            .iter()
            .map(SecureField::from)
            .collect();
        println!("Last layer poly: {:?}", last_layer_felts.iter().map(format_qm31).collect::<Vec<_>>());
        channel.mix_felts(&last_layer_felts);
        print_digest(&channel, "After mixing last layer poly");

        // Step 8: PoW verification and mix nonce
        println!("\n--- Phase 8: PoW verification and nonce mix ---");
        println!("PoW nonce: {}", witness.proof.pow_nonce);
        // In v1.0.0, PoW check is done via trailing_zeros on the digest
        let trailing = channel.trailing_zeros();
        println!("Trailing zeros in digest: {}, need: {}", trailing, witness.config.pow_bits);
        channel.mix_u64(witness.proof.pow_nonce);
        print_digest(&channel, "After mixing PoW nonce");

        // Step 9: Draw query positions
        println!("\n--- Phase 9: Draw query positions ---");
        let n_queries = witness.config.num_queries as usize;
        let query_mask = (1u32 << log_domain_size) - 1;
        let mut raw_queries = Vec::new();

        while raw_queries.len() < n_queries {
            let words = draw_u32s(&mut channel);
            println!("Draw words: {:?}", words);
            for word in words {
                let pos = word & query_mask;
                raw_queries.push(pos as usize);
                if raw_queries.len() == n_queries {
                    break;
                }
            }
        }

        println!("Raw query positions: {:?}", raw_queries);

        // Sort and deduplicate (Queries::new uses BTreeSet)
        let mut sorted_queries: Vec<usize> = raw_queries.iter().copied().collect();
        sorted_queries.sort();
        sorted_queries.dedup();
        println!("Sorted/deduped query positions: {:?}", sorted_queries);

        print_digest(&channel, "Final channel state");

        println!("\n=== END RUST Channel Parity Test ===\n");
    }

    /// Test that just checks basic Blake2s channel operations match expected values
    #[test]
    fn test_basic_channel_operations() {
        println!("\n=== Basic Channel Operations Test ===\n");

        let mut channel = Blake2sChannel::default();

        // Test mix_u64
        channel.mix_u64(0x1111222233334444);
        let digest = channel.digest();
        let expected: [u8; 32] = [
            0xbc, 0x9e, 0x3f, 0xc1, 0xd2, 0x4e, 0x88, 0x97, 0x95, 0x6d, 0x33, 0x59, 0x32, 0x73,
            0x97, 0x24, 0x9d, 0x6b, 0xca, 0xcd, 0x22, 0x4d, 0x92, 0x74, 0x4, 0xe7, 0xba, 0x4a,
            0x77, 0xdc, 0x6e, 0xce
        ];
        assert_eq!(digest.0, expected, "mix_u64 digest mismatch");
        println!("mix_u64(0x1111222233334444) -> {:?}", hex::encode(&digest.0));

        // Test mix_u32s
        let mut channel2 = Blake2sChannel::default();
        channel2.mix_u32s(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let digest2 = channel2.digest();
        let expected2: [u8; 32] = [
            0x70, 0x91, 0x76, 0x83, 0x57, 0xbb, 0x1b, 0xb3, 0x34, 0x6f, 0xda, 0xb6, 0xb3, 0x57,
            0xd7, 0xfa, 0x46, 0xb8, 0xfb, 0xe3, 0x2c, 0x2e, 0x43, 0x24, 0xa0, 0xff, 0xc2, 0x94,
            0xcb, 0xf9, 0xa1, 0xc7
        ];
        assert_eq!(digest2.0, expected2, "mix_u32s digest mismatch");
        println!("mix_u32s([1..9]) -> {:?}", hex::encode(&digest2.0));

        println!("\n=== END Basic Channel Operations Test ===\n");
    }
}
