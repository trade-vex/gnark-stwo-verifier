package stwo_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stwo "github.com/gnark-stwo/stwo"
)

// TestStaticLookupsCircuit tests the full circuit with the static_lookups example.
// This example uses LogUp for range checks.
func TestStaticLookupsCircuit(t *testing.T) {
	// Load witness data
	cfg, err := stwo.LoadCircuitConfig("/tmp/witness_out/circuit_config_lookups.json")
	if err != nil {
		t.Skipf("No circuit config: %v", err)
	}

	pw, err := stwo.LoadProofWitness("/tmp/witness_out/proof_witness_lookups.json")
	if err != nil {
		t.Fatalf("Failed to load proof witness: %v", err)
	}

	pi, err := stwo.LoadPublicInputs("/tmp/witness_out/public_inputs_lookups.json")
	if err != nil {
		t.Fatalf("Failed to load public inputs: %v", err)
	}

	t.Logf("Config: %d trees, column log sizes: %v", len(cfg.ColumnLogSizes), cfg.ColumnLogSizes)
	t.Logf("Structure: %d commitments", cfg.Structure.NumCommitments)
	t.Logf("Sampled values shape: %v", cfg.Structure.SampledValuesShape)
	t.Logf("AIR constraints: %v", cfg.AIRConstraints)

	// Create circuit placeholder
	circuit := stwo.CreatePlaceholderFromConfig(cfg)

	// Compile
	t.Log("Compiling circuit...")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	t.Logf("Compiled with %d constraints", ccs.GetNbConstraints())

	// Build witness
	assignment, err := stwo.BuildAssignmentFromSplit(cfg, pw, pi)
	if err != nil {
		t.Fatalf("Failed to build assignment: %v", err)
	}

	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("NewWitness failed: %v", err)
	}

	// Test circuit satisfaction
	t.Log("Testing circuit satisfaction...")
	err = ccs.IsSolved(fullWitness)
	if err != nil {
		t.Fatalf("Circuit not satisfied: %v", err)
	}
	t.Log("Static lookups circuit satisfied!")
}
