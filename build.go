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

// ============================================================================
// Split Witness File Types
// ============================================================================

// FriLayerStructureJSON represents structure metadata for a FRI layer.
type FriLayerStructureJSON struct {
	EvalCount         int `json:"eval_count"`
	HashWitnessCount  int `json:"hash_witness_count"`
	ColumnWitnessCount int `json:"column_witness_count"`
}

// FriStructureJSON represents structure metadata for the FRI proof.
type FriStructureJSON struct {
	FirstLayerEvalCount         int                     `json:"first_layer_eval_count"`
	FirstLayerHashWitnessCount  int                     `json:"first_layer_hash_witness_count"`
	FirstLayerColumnWitnessCount int                    `json:"first_layer_column_witness_count"`
	InnerLayers                 []FriLayerStructureJSON `json:"inner_layers"`
	LastLayerPolyDegree         int                     `json:"last_layer_poly_degree"`
}

// ProofStructureJSON represents structure metadata for array sizing.
type ProofStructureJSON struct {
	NumCommitments         int         `json:"num_commitments"`
	SampledValuesShape     [][]int     `json:"sampled_values_shape"`
	DecommitmentHashSizes  []int       `json:"decommitment_hash_sizes"`
	DecommitmentColumnSizes []int      `json:"decommitment_column_sizes"`
	QueriedValuesSizes     []int       `json:"queried_values_sizes"`
	FriStructure           FriStructureJSON `json:"fri_structure"`
}

// ConfigJSON represents PCS configuration in JSON.
type ConfigJSON struct {
	PowBits         uint32 `json:"pow_bits"`
	LogBlowupFactor uint32 `json:"log_blowup_factor"`
	LogLastLayerDeg uint32 `json:"log_last_layer_deg"`
	NumQueries      uint32 `json:"num_queries"`
}

// BaseExprJSON represents a base field constraint expression in JSON format.
// Matches Rust's BaseExprJSON from the witness generator.
type BaseExprJSON struct {
	Op string `json:"op"` // "add", "sub", "mul", "neg", "inv", "const", "col", "param"

	// For binary ops (add, sub, mul)
	Left  *BaseExprJSON `json:"left,omitempty"`
	Right *BaseExprJSON `json:"right,omitempty"`

	// For unary ops (neg, inv)
	Child *BaseExprJSON `json:"child,omitempty"`

	// For const op - single base field value
	Value uint32 `json:"value,omitempty"`

	// For col op - column reference
	TreeIdx int `json:"tree_idx,omitempty"`
	ColIdx  int `json:"col_idx,omitempty"`
	RowOff  int `json:"row_off,omitempty"`

	// For param op - named parameter
	Name string `json:"name,omitempty"`
}

// ExtExprJSON represents an extension field constraint expression in JSON format.
// Matches Rust's ExtExprJSON from the witness generator.
type ExtExprJSON struct {
	Op string `json:"op"` // "add", "sub", "mul", "neg", "const", "param", "secure_col", "col"

	// For binary ops (add, sub, mul)
	Left  *ExtExprJSON `json:"left,omitempty"`
	Right *ExtExprJSON `json:"right,omitempty"`

	// For unary ops (neg)
	Child *ExtExprJSON `json:"child,omitempty"`

	// For const op - QM31 values [a, b, c, d] or single value
	Values [4]uint32 `json:"values,omitempty"`
	Value  uint32    `json:"value,omitempty"` // For base field const

	// For param op - named parameter
	Name string `json:"name,omitempty"`

	// For secure_col op - 4 base field expressions
	Parts []*BaseExprJSON `json:"parts,omitempty"`

	// For col op - column reference (also used in circuit_config constraints)
	TreeIdx int `json:"tree_idx,omitempty"`
	ColIdx  int `json:"col_idx,omitempty"`
	RowOff  int `json:"row_off,omitempty"`
}

// ConstraintExprJSON is an alias for ExtExprJSON for compatibility
type ConstraintExprJSON = ExtExprJSON

// AIRConstraintsJSON represents AIR constraint data in JSON format.
type AIRConstraintsJSON struct {
	Constraints               []*ExtExprJSON `json:"constraints"`
	CompositionLogDegreeBound uint32         `json:"composition_log_degree_bound"`
}

// CircuitConfigJSON represents the circuit configuration file (split format).
type CircuitConfigJSON struct {
	Config         ConfigJSON          `json:"config"`
	ColumnLogSizes [][]uint32          `json:"column_log_sizes"`
	Structure      ProofStructureJSON  `json:"structure"`
	AIRConstraints *AIRConstraintsJSON `json:"air_constraints,omitempty"` // Optional AIR constraints
}

// ProofDataJSON represents the proof data portion of a witness.
type ProofDataJSON struct {
	Commitments   []Blake2sHashJSON        `json:"commitments"`
	SampledValues [][][]QM31JSON           `json:"sampled_values"`
	Decommitments []MerkleDecommitmentJSON `json:"decommitments"`
	QueriedValues [][]M31JSON              `json:"queried_values"`
	PowNonce      uint64                   `json:"pow_nonce"`
	FriProof      FriProofJSON             `json:"fri_proof"`
}

// ProofWitnessJSON represents the proof witness file (split format).
type ProofWitnessJSON struct {
	Proof ProofDataJSON `json:"proof"`
}

// PublicInputsJSON represents the public inputs file (split format).
type PublicInputsJSON struct {
	PublicInputHash Blake2sHashJSON `json:"public_input_hash"`
}

// ============================================================================
// Split Witness File Loading Functions
// ============================================================================

// LoadCircuitConfig loads a circuit configuration from a JSON file.
func LoadCircuitConfig(path string) (*CircuitConfigJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read circuit config file: %w", err)
	}

	var cfg CircuitConfigJSON
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse circuit config JSON: %w", err)
	}

	return &cfg, nil
}

// LoadProofWitness loads a proof witness from a JSON file.
func LoadProofWitness(path string) (*ProofWitnessJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read proof witness file: %w", err)
	}

	var pw ProofWitnessJSON
	if err := json.Unmarshal(data, &pw); err != nil {
		return nil, fmt.Errorf("failed to parse proof witness JSON: %w", err)
	}

	return &pw, nil
}

// LoadPublicInputs loads public inputs from a JSON file.
func LoadPublicInputs(path string) (*PublicInputsJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public inputs file: %w", err)
	}

	var pi PublicInputsJSON
	if err := json.Unmarshal(data, &pi); err != nil {
		return nil, fmt.Errorf("failed to parse public inputs JSON: %w", err)
	}

	return &pi, nil
}

// ============================================================================
// JSON to Circuit Constraint Conversion
// ============================================================================

// convertBaseExprJSON converts a base field JSON expression to a QM31 constraint expression.
// The base field value is placed in the first component of QM31 (a + 0*i + 0*j + 0*ij).
func convertBaseExprJSON(jsonExpr *BaseExprJSON) *ConstraintExpr {
	if jsonExpr == nil {
		return nil
	}

	switch jsonExpr.Op {
	case "col":
		// Column reference - treated as base field in first QM31 component
		return &ConstraintExpr{
			Op:      OpCol,
			TreeIdx: jsonExpr.TreeIdx,
			ColIdx:  jsonExpr.ColIdx,
			RowOff:  jsonExpr.RowOff,
		}
	case "const":
		// Base field constant - place in first component
		return &ConstraintExpr{
			Op:       OpConst,
			ConstVal: [4]uint32{jsonExpr.Value, 0, 0, 0},
		}
	case "add":
		left := convertBaseExprJSON(jsonExpr.Left)
		right := convertBaseExprJSON(jsonExpr.Right)
		if left == nil || right == nil {
			return nil
		}
		return &ConstraintExpr{Op: OpAdd, Left: left, Right: right}
	case "sub":
		left := convertBaseExprJSON(jsonExpr.Left)
		right := convertBaseExprJSON(jsonExpr.Right)
		if left == nil || right == nil {
			return nil
		}
		return &ConstraintExpr{Op: OpSub, Left: left, Right: right}
	case "mul":
		left := convertBaseExprJSON(jsonExpr.Left)
		right := convertBaseExprJSON(jsonExpr.Right)
		if left == nil || right == nil {
			return nil
		}
		return &ConstraintExpr{Op: OpMul, Left: left, Right: right}
	case "neg":
		child := convertBaseExprJSON(jsonExpr.Child)
		if child == nil {
			return nil
		}
		return &ConstraintExpr{Op: OpNeg, Child: child}
	case "inv":
		// Inverse operations are used in LogUp fractions.
		// These require field division in circuits which is expensive.
		// Return nil to signal this constraint cannot be evaluated, and the
		// verifier will skip composition polynomial verification.
		return nil
	case "param":
		// Named parameter - used for lookup elements, intermediates, etc.
		// These require values from the Fiat-Shamir transcript.
		// Return nil to signal this constraint cannot be evaluated.
		return nil
	default:
		panic("unknown base expression op: " + jsonExpr.Op)
	}
}

// convertExtExprJSON converts an extension field JSON expression to circuit type.
func convertExtExprJSON(jsonExpr *ExtExprJSON) *ConstraintExpr {
	if jsonExpr == nil {
		return nil
	}

	switch jsonExpr.Op {
	case "secure_col":
		// This is a QM31 value constructed from 4 base field expressions.
		// For simple constraints where non-base parts are zero, we can simplify.
		// Check if parts[1..3] are all zero constants.
		if len(jsonExpr.Parts) == 4 {
			allZeroRest := true
			for i := 1; i < 4; i++ {
				if jsonExpr.Parts[i] != nil && !(jsonExpr.Parts[i].Op == "const" && jsonExpr.Parts[i].Value == 0) {
					allZeroRest = false
					break
				}
			}
			if allZeroRest {
				// Only the base field component is non-zero, use it directly
				return convertBaseExprJSON(jsonExpr.Parts[0])
			}
		}
		// For full QM31 expressions, we'd need to handle all 4 components
		// For now, just use the first component (base field part)
		if len(jsonExpr.Parts) > 0 {
			return convertBaseExprJSON(jsonExpr.Parts[0])
		}
		return nil
	case "const":
		return &ConstraintExpr{
			Op:       OpConst,
			ConstVal: jsonExpr.Values,
		}
	case "add":
		left := convertExtExprJSON(jsonExpr.Left)
		right := convertExtExprJSON(jsonExpr.Right)
		if left == nil || right == nil {
			return nil
		}
		return &ConstraintExpr{Op: OpAdd, Left: left, Right: right}
	case "sub":
		left := convertExtExprJSON(jsonExpr.Left)
		right := convertExtExprJSON(jsonExpr.Right)
		if left == nil || right == nil {
			return nil
		}
		return &ConstraintExpr{Op: OpSub, Left: left, Right: right}
	case "mul":
		left := convertExtExprJSON(jsonExpr.Left)
		right := convertExtExprJSON(jsonExpr.Right)
		if left == nil || right == nil {
			return nil
		}
		return &ConstraintExpr{Op: OpMul, Left: left, Right: right}
	case "neg":
		child := convertExtExprJSON(jsonExpr.Child)
		if child == nil {
			return nil
		}
		return &ConstraintExpr{Op: OpNeg, Child: child}
	case "param":
		// Named parameter - used for lookup elements, intermediates, etc.
		// Return nil to signal this constraint cannot be evaluated.
		return nil
	case "col":
		// Column reference - this is a sampled value at the OOD point
		return &ConstraintExpr{
			Op:      OpCol,
			TreeIdx: jsonExpr.TreeIdx,
			ColIdx:  jsonExpr.ColIdx,
			RowOff:  jsonExpr.RowOff,
		}
	default:
		panic("unknown extension expression op: " + jsonExpr.Op)
	}
}

// convertConstraintExprJSON converts a JSON constraint expression to circuit type.
// This handles both the old format and the new format with secure_col.
func convertConstraintExprJSON(jsonExpr *ConstraintExprJSON) *ConstraintExpr {
	return convertExtExprJSON(jsonExpr)
}

// convertAIRConstraintsJSON converts JSON AIR constraints to circuit type.
// Returns nil if any constraint cannot be fully converted (e.g., contains LogUp operations).
func convertAIRConstraintsJSON(jsonConstraints *AIRConstraintsJSON) *AIRConstraints {
	if jsonConstraints == nil {
		return nil
	}

	constraints := make([]*ConstraintExpr, 0, len(jsonConstraints.Constraints))
	for _, c := range jsonConstraints.Constraints {
		expr := convertConstraintExprJSON(c)
		if expr == nil {
			// This constraint contains unsupported operations (inv, param, etc.)
			// Return nil to signal that composition polynomial verification should be skipped
			return nil
		}
		constraints = append(constraints, expr)
	}

	return &AIRConstraints{
		Constraints:               constraints,
		CompositionLogDegreeBound: jsonConstraints.CompositionLogDegreeBound,
	}
}

// ============================================================================
// Split File Functions
// ============================================================================

// CreatePlaceholderFromConfig creates a placeholder circuit from a circuit config.
// This allows circuit compilation using only the structure metadata, without the actual proof values.
func CreatePlaceholderFromConfig(cfg *CircuitConfigJSON) *FullStwoVerifierCircuit {
	return createPlaceholderFromConfig(cfg)
}

// CompileCircuitFromConfig compiles the circuit using structure metadata from config.
// Returns the constraint system (R1CS).
func CompileCircuitFromConfig(cfg *CircuitConfigJSON) (constraint.ConstraintSystem, error) {
	circuit := createPlaceholderFromConfig(cfg)

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("failed to compile circuit: %w", err)
	}

	fmt.Printf("Circuit compiled: %d constraints\n", cs.GetNbConstraints())

	return cs, nil
}

// createPlaceholderFromConfig creates a FullStwoVerifierCircuit placeholder from config.
func createPlaceholderFromConfig(cfg *CircuitConfigJSON) *FullStwoVerifierCircuit {
	s := &cfg.Structure

	// Convert column log sizes
	columnLogSizes := make([][]int, len(cfg.ColumnLogSizes))
	for i, sizes := range cfg.ColumnLogSizes {
		columnLogSizes[i] = make([]int, len(sizes))
		for j, sz := range sizes {
			columnLogSizes[i][j] = int(sz)
		}
	}

	// Create placeholder commitments
	commitments := make([]blake2s.Blake2sHash, s.NumCommitments)
	for i := range commitments {
		for j := 0; j < 8; j++ {
			commitments[i].Words[j] = frontend.Variable(0)
		}
	}

	// Create placeholder sampled values from shape metadata
	sampledValues := make([]TreeSampledValues, len(s.SampledValuesShape))
	for i, treeCols := range s.SampledValuesShape {
		sampledValues[i] = TreeSampledValues{
			Columns: make([]QM31Column, len(treeCols)),
		}
		for j, count := range treeCols {
			sampledValues[i].Columns[j] = QM31Column{
				Values: make([]mersenne31.QM31Variable, count),
			}
			for k := 0; k < count; k++ {
				sampledValues[i].Columns[j].Values[k] = createPlaceholderQM31()
			}
		}
	}

	// Create placeholder decommitments from size metadata
	decommitments := make([]merkle.MerkleDecommitment, len(s.DecommitmentHashSizes))
	for i := range decommitments {
		hashWitness := make([]blake2s.Blake2sHash, s.DecommitmentHashSizes[i])
		for j := range hashWitness {
			for k := 0; k < 8; k++ {
				hashWitness[j].Words[k] = frontend.Variable(0)
			}
		}
		columnWitness := make([]mersenne31.M31Variable, s.DecommitmentColumnSizes[i])
		for j := range columnWitness {
			columnWitness[j] = createPlaceholderM31()
		}
		decommitments[i] = merkle.MerkleDecommitment{
			HashWitness:   hashWitness,
			ColumnWitness: columnWitness,
		}
	}

	// Create placeholder queried values from size metadata
	queriedValues := make([]M31Column, len(s.QueriedValuesSizes))
	for i, count := range s.QueriedValuesSizes {
		queriedValues[i] = M31Column{
			Values: make([]mersenne31.M31Variable, count),
		}
		for j := 0; j < count; j++ {
			queriedValues[i].Values[j] = createPlaceholderM31()
		}
	}

	// Create placeholder FRI proof from structure metadata
	friProof := createPlaceholderFriFromStructure(&s.FriStructure)

	// Create placeholder public input hash
	var publicInputHash blake2s.Blake2sHash
	for i := 0; i < 8; i++ {
		publicInputHash.Words[i] = frontend.Variable(0)
	}

	// Convert AIR constraints if present
	var airConstraints *AIRConstraints
	if cfg.AIRConstraints != nil {
		airConstraints = convertAIRConstraintsJSON(cfg.AIRConstraints)
	}

	return &FullStwoVerifierCircuit{
		PublicInputHash: publicInputHash,
		Proof: StwoProof{
			Commitments:   commitments,
			SampledValues: sampledValues,
			Decommitments: decommitments,
			QueriedValues: queriedValues,
			PowNonce:      frontend.Variable(0),
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
}

// createPlaceholderFriFromStructure creates a FRI proof placeholder from structure metadata.
func createPlaceholderFriFromStructure(fs *FriStructureJSON) fri.FriProof {
	// First layer
	firstLayerEvalValues := make([]mersenne31.QM31Variable, fs.FirstLayerEvalCount)
	for i := range firstLayerEvalValues {
		firstLayerEvalValues[i] = createPlaceholderQM31()
	}
	firstLayerHashWitness := make([]blake2s.Blake2sHash, fs.FirstLayerHashWitnessCount)
	for i := range firstLayerHashWitness {
		for j := 0; j < 8; j++ {
			firstLayerHashWitness[i].Words[j] = frontend.Variable(0)
		}
	}
	firstLayerColWitness := make([]mersenne31.M31Variable, fs.FirstLayerColumnWitnessCount)
	for i := range firstLayerColWitness {
		firstLayerColWitness[i] = createPlaceholderM31()
	}
	var firstLayerCommitment blake2s.Blake2sHash
	for i := 0; i < 8; i++ {
		firstLayerCommitment.Words[i] = frontend.Variable(0)
	}
	firstLayer := fri.FriLayerProof{
		Commitment: firstLayerCommitment,
		EvalValues: firstLayerEvalValues,
		Decommitment: merkle.MerkleDecommitment{
			HashWitness:   firstLayerHashWitness,
			ColumnWitness: firstLayerColWitness,
		},
	}

	// Inner layers
	innerLayers := make([]fri.FriLayerProof, len(fs.InnerLayers))
	for i, layer := range fs.InnerLayers {
		evalValues := make([]mersenne31.QM31Variable, layer.EvalCount)
		for j := range evalValues {
			evalValues[j] = createPlaceholderQM31()
		}
		hashWitness := make([]blake2s.Blake2sHash, layer.HashWitnessCount)
		for k := range hashWitness {
			for l := 0; l < 8; l++ {
				hashWitness[k].Words[l] = frontend.Variable(0)
			}
		}
		colWitness := make([]mersenne31.M31Variable, layer.ColumnWitnessCount)
		for j := range colWitness {
			colWitness[j] = createPlaceholderM31()
		}
		var innerCommitment blake2s.Blake2sHash
		for j := 0; j < 8; j++ {
			innerCommitment.Words[j] = frontend.Variable(0)
		}
		innerLayers[i] = fri.FriLayerProof{
			Commitment: innerCommitment,
			EvalValues: evalValues,
			Decommitment: merkle.MerkleDecommitment{
				HashWitness:   hashWitness,
				ColumnWitness: colWitness,
			},
		}
	}

	// Last layer polynomial
	lastLayerPoly := make([]mersenne31.QM31Variable, fs.LastLayerPolyDegree)
	for i := range lastLayerPoly {
		lastLayerPoly[i] = createPlaceholderQM31()
	}

	return fri.FriProof{
		FirstLayer:    firstLayer,
		InnerLayers:   innerLayers,
		LastLayerPoly: lastLayerPoly,
	}
}
