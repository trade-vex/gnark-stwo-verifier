// Package stwo provides Groth16 proving utilities.
package stwo

import (
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/gnark-stwo/stwo/blake2s"
	"github.com/gnark-stwo/stwo/fri"
	"github.com/gnark-stwo/stwo/merkle"
	"github.com/gnark-stwo/stwo/mersenne31"
)

// ProveResult contains the outputs of proving.
type ProveResult struct {
	// The Groth16 proof
	Proof groth16.Proof
	// Public witness for verification
	PublicWitness witness.Witness
}

// convertFriProof converts a FriProofJSON to a FriProof circuit structure.
func convertFriProof(fp *FriProofJSON, upperBound *big.Int) fri.FriProof {
	// Convert first layer
	firstLayer := convertFriLayerProof(&fp.FirstLayer, upperBound)

	// Convert inner layers
	innerLayers := make([]fri.FriLayerProof, len(fp.InnerLayers))
	for i, l := range fp.InnerLayers {
		innerLayers[i] = convertFriLayerProof(&l, upperBound)
	}

	// Convert last layer polynomial
	lastLayerPoly := make([]mersenne31.QM31Variable, len(fp.LastLayerPoly))
	for i, qm := range fp.LastLayerPoly {
		lastLayerPoly[i] = convertQM31(&qm, upperBound)
	}

	return fri.FriProof{
		FirstLayer:    firstLayer,
		InnerLayers:   innerLayers,
		LastLayerPoly: lastLayerPoly,
	}
}

// convertFriLayerProof converts a FriLayerProofJSON to a FriLayerProof circuit structure.
func convertFriLayerProof(lp *FriLayerProofJSON, upperBound *big.Int) fri.FriLayerProof {
	// Convert commitment
	var commitment blake2s.Blake2sHash
	for i := 0; i < 8; i++ {
		commitment.Words[i] = frontend.Variable(lp.Commitment.Words[i])
	}

	// Convert eval values
	evalValues := make([]mersenne31.QM31Variable, len(lp.EvalValues))
	for i, qm := range lp.EvalValues {
		evalValues[i] = convertQM31(&qm, upperBound)
	}

	// Convert decommitment
	hashWitness := make([]blake2s.Blake2sHash, len(lp.Decommitment.HashWitness))
	for i, h := range lp.Decommitment.HashWitness {
		for j := 0; j < 8; j++ {
			hashWitness[i].Words[j] = frontend.Variable(h.Words[j])
		}
	}
	columnWitness := make([]mersenne31.M31Variable, len(lp.Decommitment.ColumnWitness))
	for i, v := range lp.Decommitment.ColumnWitness {
		columnWitness[i] = mersenne31.M31Variable{
			Value:      frontend.Variable(v.Value),
			UpperBound: upperBound,
		}
	}
	decommitment := merkle.MerkleDecommitment{
		HashWitness:   hashWitness,
		ColumnWitness: columnWitness,
	}

	return fri.FriLayerProof{
		Commitment:   commitment,
		EvalValues:   evalValues,
		Decommitment: decommitment,
	}
}

// convertQM31 converts a QM31JSON to a QM31Variable.
func convertQM31(qm *QM31JSON, upperBound *big.Int) mersenne31.QM31Variable {
	return mersenne31.QM31Variable{
		Value: [4]mersenne31.M31Variable{
			{Value: frontend.Variable(qm.Values[0].Value), UpperBound: upperBound},
			{Value: frontend.Variable(qm.Values[1].Value), UpperBound: upperBound},
			{Value: frontend.Variable(qm.Values[2].Value), UpperBound: upperBound},
			{Value: frontend.Variable(qm.Values[3].Value), UpperBound: upperBound},
		},
	}
}

// SaveProof saves a proof to a file.
func SaveProof(proof groth16.Proof, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create proof file: %w", err)
	}
	defer file.Close()

	if _, err := proof.WriteTo(file); err != nil {
		return fmt.Errorf("failed to write proof: %w", err)
	}

	return nil
}

// LoadProof loads a proof from a file.
func LoadProof(path string) (groth16.Proof, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open proof file: %w", err)
	}
	defer file.Close()

	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(file); err != nil {
		return nil, fmt.Errorf("failed to read proof: %w", err)
	}

	return proof, nil
}

// SavePublicWitness saves the public witness to a file.
func SavePublicWitness(w witness.Witness, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create witness file: %w", err)
	}
	defer file.Close()

	if _, err := w.WriteTo(file); err != nil {
		return fmt.Errorf("failed to write witness: %w", err)
	}

	return nil
}

// LoadPublicWitness loads a public witness from a file.
func LoadPublicWitness(path string) (witness.Witness, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open witness file: %w", err)
	}
	defer file.Close()

	w, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	if _, err := w.ReadFrom(file); err != nil {
		return nil, fmt.Errorf("failed to read witness: %w", err)
	}

	return w, nil
}

// ============================================================================
// Split File Functions
// ============================================================================

// BuildAssignmentFromSplit builds a circuit assignment from split witness files.
// This combines the circuit config, proof witness, and public inputs into a single assignment.
func BuildAssignmentFromSplit(
	cfg *CircuitConfigJSON,
	pw *ProofWitnessJSON,
	pi *PublicInputsJSON,
) (*FullStwoVerifierCircuit, error) {
	upperBound := new(big.Int).SetUint64(1 << 31)

	// Convert column log sizes from config
	columnLogSizes := make([][]int, len(cfg.ColumnLogSizes))
	for i, sizes := range cfg.ColumnLogSizes {
		columnLogSizes[i] = make([]int, len(sizes))
		for j, s := range sizes {
			columnLogSizes[i][j] = int(s)
		}
	}

	// Convert commitments from proof witness
	commitments := make([]blake2s.Blake2sHash, len(pw.Proof.Commitments))
	for i, c := range pw.Proof.Commitments {
		for j := 0; j < 8; j++ {
			commitments[i].Words[j] = frontend.Variable(c.Words[j])
		}
	}

	// Convert sampled values from proof witness
	sampledValues := make([]TreeSampledValues, len(pw.Proof.SampledValues))
	for i, tree := range pw.Proof.SampledValues {
		sampledValues[i] = TreeSampledValues{
			Columns: make([]QM31Column, len(tree)),
		}
		for j, col := range tree {
			sampledValues[i].Columns[j] = QM31Column{
				Values: make([]mersenne31.QM31Variable, len(col)),
			}
			for k, qm := range col {
				sampledValues[i].Columns[j].Values[k] = mersenne31.QM31Variable{
					Value: [4]mersenne31.M31Variable{
						{Value: frontend.Variable(qm.Values[0].Value), UpperBound: upperBound},
						{Value: frontend.Variable(qm.Values[1].Value), UpperBound: upperBound},
						{Value: frontend.Variable(qm.Values[2].Value), UpperBound: upperBound},
						{Value: frontend.Variable(qm.Values[3].Value), UpperBound: upperBound},
					},
				}
			}
		}
	}

	// Convert decommitments from proof witness
	decommitments := make([]merkle.MerkleDecommitment, len(pw.Proof.Decommitments))
	for i, d := range pw.Proof.Decommitments {
		hashWitness := make([]blake2s.Blake2sHash, len(d.HashWitness))
		for j, h := range d.HashWitness {
			for k := 0; k < 8; k++ {
				hashWitness[j].Words[k] = frontend.Variable(h.Words[k])
			}
		}
		columnWitness := make([]mersenne31.M31Variable, len(d.ColumnWitness))
		for j, v := range d.ColumnWitness {
			columnWitness[j] = mersenne31.M31Variable{
				Value:      frontend.Variable(v.Value),
				UpperBound: upperBound,
			}
		}
		decommitments[i] = merkle.MerkleDecommitment{
			HashWitness:   hashWitness,
			ColumnWitness: columnWitness,
		}
	}

	// Convert queried values from proof witness
	queriedValues := make([]M31Column, len(pw.Proof.QueriedValues))
	for i, tree := range pw.Proof.QueriedValues {
		queriedValues[i] = M31Column{
			Values: make([]mersenne31.M31Variable, len(tree)),
		}
		for j, v := range tree {
			queriedValues[i].Values[j] = mersenne31.M31Variable{
				Value:      frontend.Variable(v.Value),
				UpperBound: upperBound,
			}
		}
	}

	// Convert FRI proof from proof witness
	friProof := convertFriProof(&pw.Proof.FriProof, upperBound)

	// Convert public input hash from public inputs file
	var publicInputHash blake2s.Blake2sHash
	for i := 0; i < 8; i++ {
		publicInputHash.Words[i] = frontend.Variable(pi.PublicInputHash.Words[i])
	}

	// Convert AIR constraints if present
	var airConstraints *AIRConstraints
	if cfg.AIRConstraints != nil {
		airConstraints = convertAIRConstraintsJSON(cfg.AIRConstraints)
	}

	assignment := &FullStwoVerifierCircuit{
		PublicInputHash: publicInputHash,
		Proof: StwoProof{
			Commitments:   commitments,
			SampledValues: sampledValues,
			Decommitments: decommitments,
			QueriedValues: queriedValues,
			PowNonce:      frontend.Variable(pw.Proof.PowNonce),
			FriProof:      friProof,
		},
		Config: PcsConfig{
			PowBits:         int(cfg.Config.PowBits),
			LogBlowupFactor: int(cfg.Config.LogBlowupFactor),
			LogLastLayerDeg: int(cfg.Config.LogLastLayerDeg),
			NumQueries:      int(cfg.Config.NumQueries),
		},
		ColumnLogSizes: columnLogSizes,
		AIRConstraints: airConstraints,
	}

	return assignment, nil
}

// ProveFromSplit generates a Groth16 proof from split witness files.
func ProveFromSplit(
	cs constraint.ConstraintSystem,
	pk groth16.ProvingKey,
	cfg *CircuitConfigJSON,
	pw *ProofWitnessJSON,
	pi *PublicInputsJSON,
) (*ProveResult, error) {
	assignment, err := BuildAssignmentFromSplit(cfg, pw, pi)
	if err != nil {
		return nil, fmt.Errorf("failed to build assignment from split: %w", err)
	}

	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	proof, err := groth16.Prove(cs, pk, fullWitness)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	publicWitness, err := fullWitness.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to extract public witness: %w", err)
	}

	return &ProveResult{
		Proof:         proof,
		PublicWitness: publicWitness,
	}, nil
}
