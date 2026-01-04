package stwo_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stwo "github.com/gnark-stwo/stwo"
)

// TestFullCircuitWithRealData tests the full verifier circuit with real witness data.
func TestFullCircuitWithRealData(t *testing.T) {
	// Load circuit config
	cfg, err := stwo.LoadCircuitConfig("/tmp/witness_out/circuit_config.json")
	if err != nil {
		t.Skipf("No circuit config: %v", err)
	}

	// Load proof witness
	pw, err := stwo.LoadProofWitness("/tmp/witness_out/proof_witness.json")
	if err != nil {
		t.Fatalf("Failed to load proof witness: %v", err)
	}

	// Load public inputs
	pi, err := stwo.LoadPublicInputs("/tmp/witness_out/public_inputs.json")
	if err != nil {
		t.Fatalf("Failed to load public inputs: %v", err)
	}

	// Create circuit placeholder for compilation
	circuit := stwo.CreatePlaceholderFromConfig(cfg)

	t.Log("Compiling circuit...")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	t.Logf("Compiled with %d constraints", ccs.GetNbConstraints())

	// Build witness assignment
	assignment, err := stwo.BuildAssignmentFromSplit(cfg, pw, pi)
	if err != nil {
		t.Fatalf("Failed to build assignment: %v", err)
	}

	// Create witness
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("NewWitness failed: %v", err)
	}

	// Test satisfaction
	t.Log("Testing circuit satisfaction...")
	err = ccs.IsSolved(fullWitness)
	if err != nil {
		t.Errorf("Circuit not satisfied: %v", err)
	} else {
		t.Log("Full circuit satisfied!")
	}
}
