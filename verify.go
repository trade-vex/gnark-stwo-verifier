// Package stwo provides Groth16 verification utilities.
package stwo

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

// Verify verifies a Groth16 proof.
func Verify(
	vk groth16.VerifyingKey,
	proof groth16.Proof,
	publicWitness witness.Witness,
) error {
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}
	return nil
}

// VerifyFromFiles loads keys and proof from files and verifies.
func VerifyFromFiles(
	vkPath string,
	proofPath string,
	publicWitnessPath string,
) error {
	// Load verifying key
	vkFile, err := os.Open(vkPath)
	if err != nil {
		return fmt.Errorf("failed to open VK file: %w", err)
	}
	defer vkFile.Close()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(vkFile); err != nil {
		return fmt.Errorf("failed to read VK: %w", err)
	}

	// Load proof
	proof, err := LoadProof(proofPath)
	if err != nil {
		return err
	}

	// Load public witness
	publicWitness, err := LoadPublicWitness(publicWitnessPath)
	if err != nil {
		return err
	}

	return Verify(vk, proof, publicWitness)
}
