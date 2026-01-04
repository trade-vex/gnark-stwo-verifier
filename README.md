# gnark-stwo

A gnark circuit for generating Groth16 proofs that verify stwo Circle STARK proofs. This enables on-chain verification of stwo proofs on EVM chains.

## Overview

This project wraps stwo STARK proofs in Groth16 proofs, enabling:
- **Constant-size proofs** (~192 bytes) regardless of STARK proof size
- **Fast on-chain verification** (~1ms)
- **EVM compatibility** via gnark's Solidity verifier export

## Requirements

- Go 1.21+
- Rust (nightly-2024-01-04 or compatible)
- gnark v0.11.0

## Integration

### Step 1: Add Dependency

Add `stwo_gnark` to your Rust project:

```toml
[dependencies]
stwo_gnark = { path = "path/to/gnark-stwo/go/stwo/rust" }
```

### Step 2: Generate stwo Proof and Convert to Witness

Use your existing stwo proof generation code, then convert the proof to gnark witness format:

```rust
use stwo_gnark::verifier::stwo_conversion::convert_stark_proof;

// Your existing stwo code - define AIR as usual
struct MyEval { log_size: u32 }

impl FrameworkEval for MyEval {
    fn log_size(&self) -> u32 { self.log_size }
    fn max_constraint_log_degree_bound(&self) -> u32 { self.log_size + 1 }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let col1 = eval.next_trace_mask();
        let col2 = eval.next_trace_mask();
        let col3 = eval.next_trace_mask();
        // Your constraint - no special syntax needed
        eval.add_constraint(col1.clone() * col2 + col1 - col3);
        eval
    }
}

// Generate proof using normal stwo API
let component = FrameworkComponent::<MyEval>::new(
    &mut TraceLocationAllocator::default(),
    MyEval { log_size },
    claimed_sum,
);
let proof = prove(&[&component], channel, commitment_scheme)?;

// Convert to gnark witness format
let column_log_sizes = vec![
    vec![],                      // Tree 0: preprocessed
    vec![log_size; 3],           // Tree 1: trace columns
    vec![log_size; 8],           // Tree 2: composition
];
let witness = convert_stark_proof(&proof, column_log_sizes);

// Write witness files for Go circuit
witness.write_split_to_dir("./output")?;
```

This generates three files:
- `circuit_config.json` - Circuit structure for compilation
- `proof_witness.json` - STARK proof data (private witness)
- `public_inputs.json` - Public input hash

### Step 3: Generate Groth16 Proof (Go)

Build and run the Go CLI:

```bash
cd go/stwo
go build -o groth16-cli ./cmd/groth16/

./groth16-cli full \
  --config ./output/circuit_config.json \
  --proof-witness ./output/proof_witness.json \
  --public ./output/public_inputs.json
```

For production, run setup once per circuit structure:

```bash
# Setup (one-time)
./groth16-cli setup --config circuit_config.json --pk proving.key --vk verifying.key

# Prove (per proof)
./groth16-cli prove --config circuit_config.json --proof-witness proof_witness.json \
  --public public_inputs.json --pk proving.key --proof groth16.proof

# Verify
./groth16-cli verify --proof groth16.proof --vk verifying.key
```

## Performance

Benchmarks on AWS c5.4xlarge (16 vCPU, 32GB RAM):

| Circuit | Constraints | Compile | Setup | Prove | Verify |
|---------|-------------|---------|-------|-------|--------|
| simple_air | 10.5M | 1m 11s | 3m 42s | 13.1s | 0.8ms |
| dynamic_lookups | 12.1M | 1m 21s | 3m 55s | 13.6s | 0.9ms |
| static_lookups | 13.5M | 1m 31s | 4m 32s | 12.7s | 0.9ms |

## Project Structure

```
rust/src/
├── lib.rs              # Public API
├── verifier.rs         # convert_stark_proof()
├── witness.rs          # Witness types and serialization
├── extractor.rs        # AIR constraint extraction
└── proof_generators.rs # Example implementations

go/stwo/
├── cmd/groth16/        # Groth16 CLI
├── verifier_full.go    # Full verifier circuit
├── build.go            # Circuit compilation
└── prove.go            # Groth16 proving
```

## On-Chain Verification

Export Solidity verifier after setup:

```go
vk := ... // verifying key
f, _ := os.Create("Verifier.sol")
vk.ExportSolidity(f)
```

## License

MIT License
