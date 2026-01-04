// Command stwo-gnark-verifier provides the CLI for generating Groth16 proofs from stwo proofs.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	stwo "github.com/gnark-stwo/stwo"
)

func main() {
	// Subcommands
	buildCmd := flag.NewFlagSet("build", flag.ExitOnError)
	keygenCmd := flag.NewFlagSet("keygen", flag.ExitOnError)
	proveCmd := flag.NewFlagSet("prove", flag.ExitOnError)
	verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)

	// Build command flags (uses circuit config for structure)
	buildConfig := buildCmd.String("config", "", "Path to circuit config JSON file (required)")
	buildOutput := buildCmd.String("output", "circuit.r1cs", "Output path for compiled circuit")

	// Keygen command flags
	keygenCircuit := keygenCmd.String("circuit", "", "Path to compiled circuit file (required)")
	keygenPK := keygenCmd.String("pk", "proving.key", "Output path for proving key")
	keygenVK := keygenCmd.String("vk", "verifying.key", "Output path for verifying key")

	// Prove command flags (uses split witness files)
	proveConfig := proveCmd.String("config", "", "Path to circuit config JSON file (required)")
	proveWitness := proveCmd.String("witness", "", "Path to proof witness JSON file (required)")
	provePublicInput := proveCmd.String("public-input", "", "Path to public inputs JSON file (required)")
	proveCircuit := proveCmd.String("circuit", "", "Path to compiled circuit file (required)")
	provePK := proveCmd.String("pk", "", "Path to proving key (required)")
	proveOutput := proveCmd.String("output", "proof.bin", "Output path for proof")
	provePublicOutput := proveCmd.String("public-output", "public_witness.bin", "Output path for public witness")

	// Verify command flags
	verifyProof := verifyCmd.String("proof", "", "Path to proof file (required)")
	verifyVK := verifyCmd.String("vk", "", "Path to verifying key (required)")
	verifyPublic := verifyCmd.String("public", "", "Path to public witness file (required)")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "build":
		buildCmd.Parse(os.Args[2:])
		if *buildConfig == "" {
			fmt.Println("Error: --config is required")
			buildCmd.Usage()
			os.Exit(1)
		}
		runBuild(*buildConfig, *buildOutput)
	case "keygen":
		keygenCmd.Parse(os.Args[2:])
		if *keygenCircuit == "" {
			fmt.Println("Error: --circuit is required")
			keygenCmd.Usage()
			os.Exit(1)
		}
		runKeygen(*keygenCircuit, *keygenPK, *keygenVK)
	case "prove":
		proveCmd.Parse(os.Args[2:])
		if *proveConfig == "" || *proveWitness == "" || *provePublicInput == "" || *proveCircuit == "" || *provePK == "" {
			fmt.Println("Error: --config, --witness, --public-input, --circuit, and --pk are required")
			proveCmd.Usage()
			os.Exit(1)
		}
		runProve(*proveConfig, *proveWitness, *provePublicInput, *proveCircuit, *provePK, *proveOutput, *provePublicOutput)
	case "verify":
		verifyCmd.Parse(os.Args[2:])
		if *verifyProof == "" || *verifyVK == "" || *verifyPublic == "" {
			fmt.Println("Error: --proof, --vk, and --public are required")
			verifyCmd.Usage()
			os.Exit(1)
		}
		runVerify(*verifyProof, *verifyVK, *verifyPublic)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: stwo-verifier <command> [options]")
	fmt.Println()
	fmt.Println("Generate Groth16 proofs for stwo Circle STARK proofs.")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  build    Compile circuit from circuit config")
	fmt.Println("  keygen   Generate proving/verifying keys from circuit")
	fmt.Println("  prove    Generate a Groth16 proof")
	fmt.Println("  verify   Verify an existing proof")
	fmt.Println()
	fmt.Println("Workflow:")
	fmt.Println("  1. Generate witness files from your stwo proof using the Rust library:")
	fmt.Println("     use stwo_gnark::WitnessInput;")
	fmt.Println("     let witness = WitnessInput::new(&proof, column_log_sizes);")
	fmt.Println("     witness.write_split_files(\"./output\")?;")
	fmt.Println("     // Creates: circuit_config.json, proof_witness.json, public_inputs.json")
	fmt.Println()
	fmt.Println("  2. Build circuit, generate keys, prove, and verify:")
	fmt.Println("     stwo-verifier build --config circuit_config.json --output circuit.r1cs")
	fmt.Println("     stwo-verifier keygen --circuit circuit.r1cs --pk proving.key --vk verifying.key")
	fmt.Println("     stwo-verifier prove --config circuit_config.json --witness proof_witness.json \\")
	fmt.Println("                         --public-input public_inputs.json --circuit circuit.r1cs --pk proving.key")
	fmt.Println("     stwo-verifier verify --proof proof.bin --vk verifying.key --public public_witness.bin")
	fmt.Println()
	fmt.Println("Use '<command> -h' for more information about a command.")
}

func runBuild(configPath, outputPath string) {
	fmt.Printf("Loading circuit config from: %s\n", configPath)
	startTime := time.Now()
	cfg, err := stwo.LoadCircuitConfig(configPath)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Config loaded in %v\n", time.Since(startTime))

	printConfigInfo(cfg)

	// Compile the circuit
	fmt.Println("\nCompiling verifier circuit from config structure...")
	startTime = time.Now()
	cs, err := stwo.CompileCircuitFromConfig(cfg)
	if err != nil {
		fmt.Printf("Error compiling circuit: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Circuit compiled in %v\n", time.Since(startTime))
	fmt.Printf("Constraints: %d\n", cs.GetNbConstraints())

	// Save circuit
	fmt.Printf("\nSaving circuit to: %s\n", outputPath)
	if err := stwo.SaveCircuit(cs, outputPath); err != nil {
		fmt.Printf("Error saving circuit: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nBuild complete!")
}

func runKeygen(circuitPath, pkPath, vkPath string) {
	fmt.Printf("Loading circuit from: %s\n", circuitPath)
	startTime := time.Now()
	cs, err := stwo.LoadCircuit(circuitPath)
	if err != nil {
		fmt.Printf("Error loading circuit: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Circuit loaded in %v\n", time.Since(startTime))
	fmt.Printf("Constraints: %d\n", cs.GetNbConstraints())

	// Generate keys
	fmt.Println("\nGenerating Groth16 keys...")
	startTime = time.Now()
	pk, vk, err := stwo.GenerateKeys(cs)
	if err != nil {
		fmt.Printf("Error generating keys: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Keys generated in %v\n", time.Since(startTime))

	// Save proving key
	fmt.Printf("\nSaving proving key to: %s\n", pkPath)
	if err := stwo.SaveProvingKey(pk, pkPath); err != nil {
		fmt.Printf("Error saving proving key: %v\n", err)
		os.Exit(1)
	}

	// Save verifying key
	fmt.Printf("Saving verifying key to: %s\n", vkPath)
	if err := stwo.SaveVerifyingKey(vk, vkPath); err != nil {
		fmt.Printf("Error saving verifying key: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nKey generation complete!")
}

func runProve(configPath, witnessPath, publicInputPath, circuitPath, pkPath, proofPath, publicOutputPath string) {
	// Load all required files
	fmt.Printf("Loading circuit config from: %s\n", configPath)
	startTime := time.Now()
	cfg, err := stwo.LoadCircuitConfig(configPath)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Loading proof witness from: %s\n", witnessPath)
	pw, err := stwo.LoadProofWitness(witnessPath)
	if err != nil {
		fmt.Printf("Error loading proof witness: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Loading public inputs from: %s\n", publicInputPath)
	pi, err := stwo.LoadPublicInputs(publicInputPath)
	if err != nil {
		fmt.Printf("Error loading public inputs: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Files loaded in %v\n", time.Since(startTime))

	printConfigInfo(cfg)

	// Load circuit
	fmt.Printf("\nLoading circuit from: %s\n", circuitPath)
	cs, err := stwo.LoadCircuit(circuitPath)
	if err != nil {
		fmt.Printf("Error loading circuit: %v\n", err)
		os.Exit(1)
	}

	// Load proving key
	fmt.Printf("Loading proving key from: %s\n", pkPath)
	pk, err := stwo.LoadProvingKey(pkPath)
	if err != nil {
		fmt.Printf("Error loading proving key: %v\n", err)
		os.Exit(1)
	}

	// Generate proof using split files
	fmt.Println("\nGenerating Groth16 proof...")
	startTime = time.Now()
	proveResult, err := stwo.ProveFromSplit(cs, pk, cfg, pw, pi)
	if err != nil {
		fmt.Printf("Error generating proof: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Proof generated in %v\n", time.Since(startTime))

	// Save proof
	fmt.Printf("\nSaving proof to: %s\n", proofPath)
	if err := stwo.SaveProof(proveResult.Proof, proofPath); err != nil {
		fmt.Printf("Error saving proof: %v\n", err)
		os.Exit(1)
	}

	// Save public witness
	fmt.Printf("Saving public witness to: %s\n", publicOutputPath)
	if err := stwo.SavePublicWitness(proveResult.PublicWitness, publicOutputPath); err != nil {
		fmt.Printf("Error saving public witness: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nProof generation complete!")
}

func runVerify(proofPath, vkPath, publicPath string) {
	fmt.Printf("Loading verifying key from: %s\n", vkPath)
	fmt.Printf("Loading proof from: %s\n", proofPath)
	fmt.Printf("Loading public witness from: %s\n", publicPath)

	startTime := time.Now()
	err := stwo.VerifyFromFiles(vkPath, proofPath, publicPath)
	if err != nil {
		fmt.Printf("Verification FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Verification SUCCEEDED in %v\n", time.Since(startTime))
}

func printConfigInfo(cfg *stwo.CircuitConfigJSON) {
	fmt.Println("\nCircuit Configuration:")
	fmt.Printf("  Column trees: %d\n", len(cfg.ColumnLogSizes))
	fmt.Printf("  Config: pow_bits=%d, log_blowup=%d, log_last_layer_deg=%d, num_queries=%d\n",
		cfg.Config.PowBits,
		cfg.Config.LogBlowupFactor,
		cfg.Config.LogLastLayerDeg,
		cfg.Config.NumQueries)
	if cfg.AIRConstraints != nil {
		fmt.Printf("  AIR constraints: %d\n", len(cfg.AIRConstraints.Constraints))
	}
}
