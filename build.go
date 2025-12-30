// Package stwo provides circuit building utilities.
package stwo

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/gnark-stwo/stwo/blake2s"
	"github.com/gnark-stwo/stwo/fri"
	"github.com/gnark-stwo/stwo/merkle"
	"github.com/gnark-stwo/stwo/mersenne31"
)

// CompileCircuit compiles the circuit using sizes derived from an actual witness.
// This ensures the compiled circuit matches the witness structure exactly.
// Returns the constraint system (R1CS).
func CompileCircuit(w *WitnessJSON) (constraint.ConstraintSystem, error) {
	// Create a placeholder circuit that matches the witness structure exactly
	circuit := createFullPlaceholderFromWitness(w)

	// Compile the circuit to R1CS
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("failed to compile circuit: %w", err)
	}

	fmt.Printf("Circuit compiled: %d constraints\n", cs.GetNbConstraints())

	return cs, nil
}

// GenerateKeys runs Groth16 setup on a constraint system to generate proving and verifying keys.
func GenerateKeys(cs constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run Groth16 setup: %w", err)
	}

	return pk, vk, nil
}

// SaveCircuit saves the constraint system to a file.
func SaveCircuit(cs constraint.ConstraintSystem, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create circuit file: %w", err)
	}
	defer file.Close()

	if _, err := cs.WriteTo(file); err != nil {
		return fmt.Errorf("failed to write circuit: %w", err)
	}

	return nil
}

// LoadCircuit loads a constraint system from a file.
func LoadCircuit(path string) (constraint.ConstraintSystem, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open circuit file: %w", err)
	}
	defer file.Close()

	cs := groth16.NewCS(ecc.BN254)
	if _, err := cs.ReadFrom(file); err != nil {
		return nil, fmt.Errorf("failed to read circuit: %w", err)
	}

	return cs, nil
}

// SaveProvingKey saves the proving key to a file.
func SaveProvingKey(pk groth16.ProvingKey, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create proving key file: %w", err)
	}
	defer file.Close()

	if _, err := pk.WriteTo(file); err != nil {
		return fmt.Errorf("failed to write proving key: %w", err)
	}

	return nil
}

// LoadProvingKey loads a proving key from a file.
func LoadProvingKey(path string) (groth16.ProvingKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open proving key file: %w", err)
	}
	defer file.Close()

	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(file); err != nil {
		return nil, fmt.Errorf("failed to read proving key: %w", err)
	}

	return pk, nil
}

// SaveVerifyingKey saves the verifying key to a file.
func SaveVerifyingKey(vk groth16.VerifyingKey, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create verifying key file: %w", err)
	}
	defer file.Close()

	if _, err := vk.WriteTo(file); err != nil {
		return fmt.Errorf("failed to write verifying key: %w", err)
	}

	return nil
}

// LoadVerifyingKey loads a verifying key from a file.
func LoadVerifyingKey(path string) (groth16.VerifyingKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open verifying key file: %w", err)
	}
	defer file.Close()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(file); err != nil {
		return nil, fmt.Errorf("failed to read verifying key: %w", err)
	}

	return vk, nil
}

// createPlaceholderFriFromWitness creates a FRI proof placeholder matching a witness.
func createPlaceholderFriFromWitness(fp *FriProofJSON) fri.FriProof {
	// First layer
	firstLayerEvalValues := make([]mersenne31.QM31Variable, len(fp.FirstLayer.EvalValues))
	for i := range firstLayerEvalValues {
		firstLayerEvalValues[i] = createPlaceholderQM31()
	}
	firstLayerHashWitness := make([]blake2s.Blake2sHash, len(fp.FirstLayer.Decommitment.HashWitness))
	firstLayerColWitness := make([]mersenne31.M31Variable, len(fp.FirstLayer.Decommitment.ColumnWitness))
	for i := range firstLayerColWitness {
		firstLayerColWitness[i] = createPlaceholderM31()
	}
	firstLayer := fri.FriLayerProof{
		EvalValues: firstLayerEvalValues,
		Decommitment: merkle.MerkleDecommitment{
			HashWitness:   firstLayerHashWitness,
			ColumnWitness: firstLayerColWitness,
		},
	}

	// Inner layers
	innerLayers := make([]fri.FriLayerProof, len(fp.InnerLayers))
	for i, layer := range fp.InnerLayers {
		evalValues := make([]mersenne31.QM31Variable, len(layer.EvalValues))
		for j := range evalValues {
			evalValues[j] = createPlaceholderQM31()
		}
		hashWitness := make([]blake2s.Blake2sHash, len(layer.Decommitment.HashWitness))
		colWitness := make([]mersenne31.M31Variable, len(layer.Decommitment.ColumnWitness))
		for j := range colWitness {
			colWitness[j] = createPlaceholderM31()
		}
		innerLayers[i] = fri.FriLayerProof{
			EvalValues: evalValues,
			Decommitment: merkle.MerkleDecommitment{
				HashWitness:   hashWitness,
				ColumnWitness: colWitness,
			},
		}
	}

	// Last layer polynomial
	lastLayerPoly := make([]mersenne31.QM31Variable, len(fp.LastLayerPoly))
	for i := range lastLayerPoly {
		lastLayerPoly[i] = createPlaceholderQM31()
	}

	return fri.FriProof{
		FirstLayer:    firstLayer,
		InnerLayers:   innerLayers,
		LastLayerPoly: lastLayerPoly,
	}
}

// createPlaceholderM31 creates a placeholder M31Variable with valid UpperBound.
func createPlaceholderM31() mersenne31.M31Variable {
	return mersenne31.M31Variable{
		Value:      frontend.Variable(0),
		UpperBound: mersenne31.M31Modulus,
	}
}

// createPlaceholderQM31 creates a placeholder QM31Variable with valid UpperBounds.
func createPlaceholderQM31() mersenne31.QM31Variable {
	return mersenne31.QM31Variable{
		Value: [4]mersenne31.M31Variable{
			createPlaceholderM31(),
			createPlaceholderM31(),
			createPlaceholderM31(),
			createPlaceholderM31(),
		},
	}
}


// M31JSON represents an M31 field element in JSON.
type M31JSON struct {
	Value uint32 `json:"value"`
}

// QM31JSON represents a QM31 field element in JSON.
type QM31JSON struct {
	Values [4]M31JSON `json:"values"`
}

// Blake2sHashJSON represents a Blake2s hash in JSON.
type Blake2sHashJSON struct {
	Words [8]uint32 `json:"words"`
}

// MerkleDecommitmentJSON represents a Merkle decommitment in JSON.
type MerkleDecommitmentJSON struct {
	HashWitness   []Blake2sHashJSON `json:"hash_witness"`
	ColumnWitness []M31JSON         `json:"column_witness"`
}

// FriLayerProofJSON represents a FRI layer proof in JSON.
type FriLayerProofJSON struct {
	Commitment   Blake2sHashJSON        `json:"commitment"`
	EvalValues   []QM31JSON             `json:"eval_values"`
	Decommitment MerkleDecommitmentJSON `json:"decommitment"`
}

// FriProofJSON represents a FRI proof in JSON.
type FriProofJSON struct {
	FirstLayer    FriLayerProofJSON   `json:"first_layer"`
	InnerLayers   []FriLayerProofJSON `json:"inner_layers"`
	LastLayerPoly []QM31JSON          `json:"last_layer_poly"`
}

// WitnessJSON represents the witness structure from Rust.
type WitnessJSON struct {
	Public struct {
		PublicInputHash Blake2sHashJSON `json:"public_input_hash"`
	} `json:"public"`
	Proof struct {
		Commitments   []Blake2sHashJSON        `json:"commitments"`
		SampledValues [][][]QM31JSON           `json:"sampled_values"`
		Decommitments []MerkleDecommitmentJSON `json:"decommitments"`
		QueriedValues [][]M31JSON              `json:"queried_values"`
		PowNonce      uint64                   `json:"pow_nonce"`
		FriProof      FriProofJSON             `json:"fri_proof"`
	} `json:"proof"`
	Config struct {
		PowBits         uint32 `json:"pow_bits"`
		LogBlowupFactor uint32 `json:"log_blowup_factor"`
		LogLastLayerDeg uint32 `json:"log_last_layer_deg"`
		NumQueries      uint32 `json:"num_queries"`
	} `json:"config"`
	ColumnLogSizes [][]uint32 `json:"column_log_sizes"`
}

// LoadWitnessFromJSON loads a witness from a JSON file.
func LoadWitnessFromJSON(path string) (*WitnessJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read witness file: %w", err)
	}

	var witness WitnessJSON
	if err := json.Unmarshal(data, &witness); err != nil {
		return nil, fmt.Errorf("failed to parse witness JSON: %w", err)
	}

	return &witness, nil
}

// ParseWitnessJSON parses a witness from a JSON string.
func ParseWitnessJSON(jsonStr string) (*WitnessJSON, error) {
	var witness WitnessJSON
	if err := json.Unmarshal([]byte(jsonStr), &witness); err != nil {
		return nil, fmt.Errorf("failed to parse witness JSON: %w", err)
	}

	return &witness, nil
}

// createFullPlaceholderFromWitness creates a FullStwoVerifierCircuit placeholder.
func createFullPlaceholderFromWitness(w *WitnessJSON) *FullStwoVerifierCircuit {
	// Convert column log sizes
	columnLogSizes := make([][]int, len(w.ColumnLogSizes))
	for i, sizes := range w.ColumnLogSizes {
		columnLogSizes[i] = make([]int, len(sizes))
		for j, s := range sizes {
			columnLogSizes[i][j] = int(s)
		}
	}

	// Create placeholder commitments matching witness size
	commitments := make([]blake2s.Blake2sHash, len(w.Proof.Commitments))

	// Create placeholder sampled values matching witness structure (using wrapper types)
	sampledValues := make([]TreeSampledValues, len(w.Proof.SampledValues))
	for i, tree := range w.Proof.SampledValues {
		sampledValues[i] = TreeSampledValues{
			Columns: make([]QM31Column, len(tree)),
		}
		for j, col := range tree {
			sampledValues[i].Columns[j] = QM31Column{
				Values: make([]mersenne31.QM31Variable, len(col)),
			}
			for k := range col {
				sampledValues[i].Columns[j].Values[k] = createPlaceholderQM31()
			}
		}
	}

	// Create placeholder decommitments matching witness structure
	decommitments := make([]merkle.MerkleDecommitment, len(w.Proof.Decommitments))
	for i, d := range w.Proof.Decommitments {
		hashWitness := make([]blake2s.Blake2sHash, len(d.HashWitness))
		columnWitness := make([]mersenne31.M31Variable, len(d.ColumnWitness))
		for j := range columnWitness {
			columnWitness[j] = createPlaceholderM31()
		}
		decommitments[i] = merkle.MerkleDecommitment{
			HashWitness:   hashWitness,
			ColumnWitness: columnWitness,
		}
	}

	// Create placeholder queried values matching witness structure (using wrapper types)
	queriedValues := make([]M31Column, len(w.Proof.QueriedValues))
	for i, tree := range w.Proof.QueriedValues {
		queriedValues[i] = M31Column{
			Values: make([]mersenne31.M31Variable, len(tree)),
		}
		for j := range tree {
			queriedValues[i].Values[j] = createPlaceholderM31()
		}
	}

	// Create placeholder FRI proof matching witness structure
	friProof := createPlaceholderFriFromWitness(&w.Proof.FriProof)

	return &FullStwoVerifierCircuit{
		Proof: StwoProof{
			Commitments:   commitments,
			SampledValues: sampledValues,
			Decommitments: decommitments,
			QueriedValues: queriedValues,
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
}
