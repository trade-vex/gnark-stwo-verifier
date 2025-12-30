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

// Prove generates a Groth16 proof for a stwo proof.
func Prove(
	cs constraint.ConstraintSystem,
	pk groth16.ProvingKey,
	witnessJSON *WitnessJSON,
) (*ProveResult, error) {
	// Build the full circuit witness
	assignment, err := buildFullAssignment(witnessJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to build assignment: %w", err)
	}

	// Create the witness
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	// Generate the proof
	proof, err := groth16.Prove(cs, pk, fullWitness)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	// Extract public witness
	publicWitness, err := fullWitness.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to extract public witness: %w", err)
	}

	return &ProveResult{
		Proof:         proof,
		PublicWitness: publicWitness,
	}, nil
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

// buildFullAssignment converts the JSON witness to FullStwoVerifierCircuit assignment.
func buildFullAssignment(w *WitnessJSON) (*FullStwoVerifierCircuit, error) {
	upperBound := new(big.Int).SetUint64(1 << 31)

	// Convert column log sizes
	columnLogSizes := make([][]int, len(w.ColumnLogSizes))
	for i, sizes := range w.ColumnLogSizes {
		columnLogSizes[i] = make([]int, len(sizes))
		for j, s := range sizes {
			columnLogSizes[i][j] = int(s)
		}
	}

	// Convert commitments
	commitments := make([]blake2s.Blake2sHash, len(w.Proof.Commitments))
	for i, c := range w.Proof.Commitments {
		for j := 0; j < 8; j++ {
			commitments[i].Words[j] = frontend.Variable(c.Words[j])
		}
	}

	// Convert sampled values (using wrapper types to avoid gnark schema bug)
	sampledValues := make([]TreeSampledValues, len(w.Proof.SampledValues))
	for i, tree := range w.Proof.SampledValues {
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

	// Convert decommitments
	decommitments := make([]merkle.MerkleDecommitment, len(w.Proof.Decommitments))
	for i, d := range w.Proof.Decommitments {
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

	// Convert queried values (using wrapper types to avoid gnark schema bug)
	queriedValues := make([]M31Column, len(w.Proof.QueriedValues))
	for i, tree := range w.Proof.QueriedValues {
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

	// Convert FRI proof
	friProof := convertFriProof(&w.Proof.FriProof, upperBound)

	// Compute public input hash
	publicInputHash := frontend.Variable(w.Public.PublicInputHash.Words[0])

	assignment := &FullStwoVerifierCircuit{
		PublicInputHash: publicInputHash,
		Proof: StwoProof{
			Commitments:   commitments,
			SampledValues: sampledValues,
			Decommitments: decommitments,
			QueriedValues: queriedValues,
			PowNonce:      frontend.Variable(w.Proof.PowNonce),
			FriProof:      friProof,
		},
		Config: PcsConfig{
			PowBits:         int(w.Config.PowBits),
			LogBlowupFactor: int(w.Config.LogBlowupFactor),
			LogLastLayerDeg: int(w.Config.LogLastLayerDeg),
			NumQueries:      int(w.Config.NumQueries),
		},
		ColumnLogSizes: columnLogSizes,
	}

	return assignment, nil
}
