// Command stwo-gnark-verifier provides the CLI for generating Groth16 proofs from stwo proofs.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	stwo "github.com/gnark-stwo/stwo"
	"github.com/gnark-stwo/stwo/ffi"
)

func main() {
	// Subcommands
	exampleCmd := flag.NewFlagSet("example", flag.ExitOnError)
	buildCmd := flag.NewFlagSet("build", flag.ExitOnError)
	keygenCmd := flag.NewFlagSet("keygen", flag.ExitOnError)
	proveCmd := flag.NewFlagSet("prove", flag.ExitOnError)
	verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)

	// Example command flags (for testing only)
	exampleName := exampleCmd.String("name", "", "Example to generate: 'fibonacci' or 'poseidon'")
	exampleOutput := exampleCmd.String("output", "witness.json", "Output path for witness JSON")

	// Build command flags
	buildWitness := buildCmd.String("witness", "", "Path to witness JSON file (required)")
	buildOutput := buildCmd.String("output", "circuit.r1cs", "Output path for compiled circuit")

	// Keygen command flags
	keygenCircuit := keygenCmd.String("circuit", "", "Path to compiled circuit file (required)")
	keygenPK := keygenCmd.String("pk", "proving.key", "Output path for proving key")
	keygenVK := keygenCmd.String("vk", "verifying.key", "Output path for verifying key")

	// Prove command flags
	proveWitness := proveCmd.String("witness", "", "Path to witness JSON file (required)")
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
	case "example":
		exampleCmd.Parse(os.Args[2:])
		if *exampleName == "" {
			fmt.Println("Error: --name is required")
			fmt.Println("Available examples: fibonacci, poseidon")
			exampleCmd.Usage()
			os.Exit(1)
		}
		runExample(*exampleName, *exampleOutput)
	case "build":
		buildCmd.Parse(os.Args[2:])
		if *buildWitness == "" {
			fmt.Println("Error: --witness is required")
			buildCmd.Usage()
			os.Exit(1)
		}
		runBuild(*buildWitness, *buildOutput)
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
		if *proveWitness == "" || *proveCircuit == "" || *provePK == "" {
			fmt.Println("Error: --witness, --circuit, and --pk are required")
			proveCmd.Usage()
			os.Exit(1)
		}
		runProve(*proveWitness, *proveCircuit, *provePK, *proveOutput, *provePublicOutput)
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
	fmt.Println("  build    Compile circuit from witness structure")
	fmt.Println("  keygen   Generate proving/verifying keys from circuit")
	fmt.Println("  prove    Generate a Groth16 proof")
	fmt.Println("  verify   Verify an existing proof")
	fmt.Println("  example  Generate example witness for testing (fibonacci, poseidon)")
	fmt.Println()
	fmt.Println("Workflow:")
	fmt.Println("  1. Generate witness JSON from your stwo proof using the Rust library:")
	fmt.Println("     use stwo_gnark::convert_stark_proof;")
	fmt.Println("     let witness = convert_stark_proof(&proof, column_log_sizes);")
	fmt.Println("     witness.write_to_file(\"witness.json\")?;")
	fmt.Println()
	fmt.Println("  2. Build circuit, generate keys, prove, and verify:")
	fmt.Println("     stwo-verifier build --witness witness.json --output circuit.r1cs")
	fmt.Println("     stwo-verifier keygen --circuit circuit.r1cs --pk proving.key --vk verifying.key")
	fmt.Println("     stwo-verifier prove --witness witness.json --circuit circuit.r1cs --pk proving.key")
	fmt.Println("     stwo-verifier verify --proof proof.bin --vk verifying.key --public public_witness.bin")
	fmt.Println()
	fmt.Println("For testing with built-in examples:")
	fmt.Println("  stwo-verifier example --name fibonacci --output witness.json")
	fmt.Println()
	fmt.Println("Use '<command> -h' for more information about a command.")
}

func runExample(name, outputPath string) {
	fmt.Printf("Generating %s example witness via Rust SDK...\n", name)
	fmt.Printf("SDK version: %s\n", ffi.GetVersion())

	startTime := time.Now()
	var witnessJSON string
	var err error

	switch name {
	case "fibonacci":
		witnessJSON, err = ffi.GenerateProvingAnAirWitness()
	case "poseidon":
		witnessJSON, err = ffi.GenerateStaticLookupsWitness()
	default:
		fmt.Printf("Unknown example: %s\n", name)
		fmt.Println("Available examples: fibonacci, poseidon")
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("Error generating witness: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Witness generated in %v\n", time.Since(startTime))

	// Parse to validate and show info
	witness, err := stwo.ParseWitnessJSON(witnessJSON)
	if err != nil {
		fmt.Printf("Error parsing witness: %v\n", err)
		os.Exit(1)
	}

	printWitnessInfo(witness)

	// Write to file
	if err := os.WriteFile(outputPath, []byte(witnessJSON), 0644); err != nil {
		fmt.Printf("Error writing witness file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nWitness saved to: %s\n", outputPath)
}

func runBuild(witnessPath, outputPath string) {
	fmt.Printf("Loading witness from: %s\n", witnessPath)
	startTime := time.Now()
	witness, err := stwo.LoadWitnessFromJSON(witnessPath)
	if err != nil {
		fmt.Printf("Error loading witness: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Witness loaded in %v\n", time.Since(startTime))

	printWitnessInfo(witness)

	// Compile the circuit
	fmt.Println("\nCompiling verifier circuit from witness structure...")
	startTime = time.Now()
	cs, err := stwo.CompileCircuit(witness)
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

func runProve(witnessPath, circuitPath, pkPath, proofPath, publicPath string) {
	fmt.Printf("Loading witness from: %s\n", witnessPath)
	startTime := time.Now()
	witness, err := stwo.LoadWitnessFromJSON(witnessPath)
	if err != nil {
		fmt.Printf("Error loading witness: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Witness loaded in %v\n", time.Since(startTime))

	printWitnessInfo(witness)

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

	// Generate proof
	fmt.Println("\nGenerating Groth16 proof...")
	startTime = time.Now()
	proveResult, err := stwo.Prove(cs, pk, witness)
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
	fmt.Printf("Saving public witness to: %s\n", publicPath)
	if err := stwo.SavePublicWitness(proveResult.PublicWitness, publicPath); err != nil {
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

func printWitnessInfo(witness *stwo.WitnessJSON) {
	fmt.Println("\nWitness Information:")
	fmt.Printf("  Commitments: %d\n", len(witness.Proof.Commitments))
	fmt.Printf("  Sampled value trees: %d\n", len(witness.Proof.SampledValues))
	fmt.Printf("  Decommitments: %d\n", len(witness.Proof.Decommitments))
	fmt.Printf("  Queried value trees: %d\n", len(witness.Proof.QueriedValues))
	fmt.Printf("  PoW nonce: %d\n", witness.Proof.PowNonce)
	fmt.Printf("  FRI inner layers: %d\n", len(witness.Proof.FriProof.InnerLayers))
	fmt.Printf("  Config: pow_bits=%d, log_blowup=%d, log_last_layer_deg=%d, num_queries=%d\n",
		witness.Config.PowBits,
		witness.Config.LogBlowupFactor,
		witness.Config.LogLastLayerDeg,
		witness.Config.NumQueries)
}
