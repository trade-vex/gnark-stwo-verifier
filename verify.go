// Package stwo provides Groth16 verification utilities.
package stwo

import (
	"bytes"
	"fmt"
	"os"
	"text/template"

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

// ExportSolidityVerifier generates a Solidity verifier contract.
func ExportSolidityVerifier(vk groth16.VerifyingKey, contractName string) (string, error) {
	// Use gnark's built-in Solidity export
	var buf bytes.Buffer
	if err := vk.ExportSolidity(&buf); err != nil {
		return "", fmt.Errorf("failed to export Solidity verifier: %w", err)
	}

	return buf.String(), nil
}

// SaveSolidityVerifier saves the Solidity verifier to a file.
func SaveSolidityVerifier(vk groth16.VerifyingKey, path string) error {
	solidity, err := ExportSolidityVerifier(vk, "StwoVerifier")
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, []byte(solidity), 0644); err != nil {
		return fmt.Errorf("failed to write Solidity file: %w", err)
	}

	return nil
}

// VerificationResult contains the result of a verification.
type VerificationResult struct {
	Valid   bool
	Message string
}

// BatchVerify verifies multiple proofs efficiently.
func BatchVerify(
	vk groth16.VerifyingKey,
	proofs []groth16.Proof,
	publicWitnesses []witness.Witness,
) ([]VerificationResult, error) {
	if len(proofs) != len(publicWitnesses) {
		return nil, fmt.Errorf("mismatched number of proofs and witnesses")
	}

	results := make([]VerificationResult, len(proofs))
	for i := range proofs {
		if err := Verify(vk, proofs[i], publicWitnesses[i]); err != nil {
			results[i] = VerificationResult{
				Valid:   false,
				Message: err.Error(),
			}
		} else {
			results[i] = VerificationResult{
				Valid:   true,
				Message: "verification successful",
			}
		}
	}

	return results, nil
}

// Solidity template for a wrapper contract that includes public input parsing.
const solidityWrapperTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Groth16Verifier.sol";

/// @title StwoProofVerifier
/// @notice Wrapper contract for verifying stwo proofs wrapped in Groth16
contract StwoProofVerifier {
    Groth16Verifier public immutable groth16Verifier;

    constructor(address _verifier) {
        groth16Verifier = Groth16Verifier(_verifier);
    }

    /// @notice Verify a stwo proof
    /// @param proof The Groth16 proof elements
    /// @param publicInputHash The hash of public inputs from the stwo proof
    /// @return valid True if the proof is valid
    function verifyStwoProof(
        uint256[8] calldata proof,
        uint256 publicInputHash
    ) external view returns (bool valid) {
        uint256[1] memory publicInputs;
        publicInputs[0] = publicInputHash;

        return groth16Verifier.verifyProof(
            [proof[0], proof[1]],      // a
            [[proof[2], proof[3]], [proof[4], proof[5]]], // b
            [proof[6], proof[7]],      // c
            publicInputs
        );
    }

    /// @notice Verify a batch of stwo proofs
    /// @param proofs Array of Groth16 proofs
    /// @param publicInputHashes Array of public input hashes
    /// @return allValid True if all proofs are valid
    function verifyBatch(
        uint256[8][] calldata proofs,
        uint256[] calldata publicInputHashes
    ) external view returns (bool allValid) {
        require(proofs.length == publicInputHashes.length, "Length mismatch");

        for (uint256 i = 0; i < proofs.length; i++) {
            uint256[1] memory publicInputs;
            publicInputs[0] = publicInputHashes[i];

            bool valid = groth16Verifier.verifyProof(
                [proofs[i][0], proofs[i][1]],
                [[proofs[i][2], proofs[i][3]], [proofs[i][4], proofs[i][5]]],
                [proofs[i][6], proofs[i][7]],
                publicInputs
            );

            if (!valid) {
                return false;
            }
        }

        return true;
    }
}
`

// ExportSolidityWrapper generates a wrapper contract for the verifier.
func ExportSolidityWrapper() (string, error) {
	tmpl, err := template.New("wrapper").Parse(solidityWrapperTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, nil); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// SaveSolidityWrapper saves the wrapper contract to a file.
func SaveSolidityWrapper(path string) error {
	wrapper, err := ExportSolidityWrapper()
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, []byte(wrapper), 0644); err != nil {
		return fmt.Errorf("failed to write wrapper file: %w", err)
	}

	return nil
}
