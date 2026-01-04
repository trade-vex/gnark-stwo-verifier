// Package stwo provides circuit definition parsing and constraint building.
package stwo

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/consensys/gnark/frontend"
	"github.com/gnark-stwo/stwo/mersenne31"
)

// CircuitDefinition represents the complete circuit definition parsed from Rust.
// This format is designed to capture everything needed to build the constraint
// evaluation circuit in gnark.
type CircuitDefinition struct {
	// Name of the circuit
	Name string `json:"name"`

	// Components that make up the circuit
	Components []ComponentDef `json:"components"`

	// Total composition polynomial log degree bound
	CompositionLogDegreeBound uint32 `json:"composition_log_degree_bound"`
}

// ComponentDef represents a single component (corresponds to FrameworkComponent in Rust).
type ComponentDef struct {
	// Component name
	Name string `json:"name"`

	// Log2 of the trace size
	LogSize uint32 `json:"log_size"`

	// Tree structure: which columns belong to which tree
	Trees TreeStructure `json:"trees"`

	// Mask definition: which columns at which offsets are sampled
	Mask MaskDef `json:"mask"`

	// Relations used by this component (LogUp lookups)
	Relations []RelationDef `json:"relations"`

	// AIR constraints (polynomial constraints that must be zero)
	Constraints []ConstraintDefJSON `json:"constraints"`

	// LogUp accumulation configuration
	Logup *LogupDef `json:"logup,omitempty"`
}

// TreeStructure defines the tree organization.
type TreeStructure struct {
	// Number of trees (commitments)
	NumTrees int `json:"num_trees"`

	// Column log sizes per tree
	ColumnLogSizes [][]uint32 `json:"column_log_sizes"`

	// Preprocessed column indices used by this component
	PreprocessedColumnIndices []int `json:"preprocessed_column_indices"`
}

// MaskDef defines which values are sampled for constraint evaluation.
type MaskDef struct {
	// For each tree, list of mask items
	Samples [][]MaskItem `json:"samples"`
}

// MaskItem represents a single mask entry.
type MaskItem struct {
	ColIdx    int `json:"col_idx"`
	RowOffset int `json:"row_offset"`
}

// RelationDef defines a LogUp lookup relation.
type RelationDef struct {
	// Relation name
	Name string `json:"name"`

	// Number of values combined in this relation
	Size int `json:"size"`

	// When to draw this relation from the channel
	DrawAfterTree int `json:"draw_after_tree"`
}

// ConstraintDefJSON wraps an expression definition.
type ConstraintDefJSON struct {
	Expr ExprDefJSON `json:"expr"`
}

// LogupDef defines LogUp accumulation configuration.
type LogupDef struct {
	// The interaction tree index where LogUp cumsum columns are stored
	InteractionTree int `json:"interaction_tree"`

	// LogUp fractions to be accumulated
	Fractions []FractionDef `json:"fractions"`

	// Finalization mode
	FinalizeMode string `json:"finalize_mode"`

	// For batched finalization, the batch sizes
	BatchSizes []int `json:"batch_sizes,omitempty"`
}

// FractionDef defines a LogUp fraction.
type FractionDef struct {
	Numerator   ExprDefJSON `json:"numerator"`
	Denominator ExprDefJSON `json:"denominator"`
}

// ExprDefJSON represents an expression definition from the Rust side.
// Uses a tagged union format with "type" field.
type ExprDefJSON struct {
	Type string `json:"type"`

	// For const
	Value uint32 `json:"value,omitempty"`

	// For col
	TreeIdx int `json:"tree_idx,omitempty"`
	ColIdx  int `json:"col_idx,omitempty"`
	RowOff  int `json:"row_off,omitempty"`

	// For binary ops (add, sub, mul, ext_add, ext_sub, ext_mul)
	Left  *ExprDefJSON `json:"left,omitempty"`
	Right *ExprDefJSON `json:"right,omitempty"`

	// For unary ops (neg, inv, ext_neg)
	Child *ExprDefJSON `json:"child,omitempty"`

	// For ext_const
	Values [4]uint32 `json:"values,omitempty"`

	// For preprocessed
	ID string `json:"id,omitempty"`

	// For secure_col
	Parts [4]*ExprDefJSON `json:"parts,omitempty"`

	// For relation_combine
	RelationName   string        `json:"relation_name,omitempty"`
	RelationValues []ExprDefJSON `json:"relation_values,omitempty"`
}

// LoadCircuitDefinition loads a circuit definition from a JSON file.
func LoadCircuitDefinition(path string) (*CircuitDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read circuit definition file: %w", err)
	}

	var def CircuitDefinition
	if err := json.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("failed to parse circuit definition: %w", err)
	}

	return &def, nil
}

// ParseCircuitDefinition parses a circuit definition from JSON bytes.
func ParseCircuitDefinition(data []byte) (*CircuitDefinition, error) {
	var def CircuitDefinition
	if err := json.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("failed to parse circuit definition: %w", err)
	}
	return &def, nil
}

// CircuitDefEvaluator evaluates circuit constraints from a CircuitDefinition.
type CircuitDefEvaluator struct {
	api     frontend.API
	m31Chip *mersenne31.M31Chip
	def     *CircuitDefinition
}

// NewCircuitDefEvaluator creates a new evaluator for a circuit definition.
func NewCircuitDefEvaluator(
	api frontend.API,
	m31Chip *mersenne31.M31Chip,
	def *CircuitDefinition,
) *CircuitDefEvaluator {
	return &CircuitDefEvaluator{
		api:     api,
		m31Chip: m31Chip,
		def:     def,
	}
}

// EvaluateExprDef evaluates an expression from the circuit definition.
// sampledValues[tree][col][offset] contains the QM31 value at that position.
// preprocessed maps preprocessed column IDs to their sampled values.
func (e *CircuitDefEvaluator) EvaluateExprDef(
	expr *ExprDefJSON,
	sampledValues [][][]mersenne31.QM31Variable,
	preprocessed map[string]mersenne31.QM31Variable,
) mersenne31.QM31Variable {
	switch expr.Type {
	case "const":
		// Base field constant - promote to extension field
		return mersenne31.QM31Variable{
			Value: [4]mersenne31.M31Variable{
				mersenne31.NewM31Const(fmt.Sprintf("%d", expr.Value)),
				mersenne31.NewM31Const("0"),
				mersenne31.NewM31Const("0"),
				mersenne31.NewM31Const("0"),
			},
		}

	case "ext_const":
		return mersenne31.QM31Variable{
			Value: [4]mersenne31.M31Variable{
				mersenne31.NewM31Const(fmt.Sprintf("%d", expr.Values[0])),
				mersenne31.NewM31Const(fmt.Sprintf("%d", expr.Values[1])),
				mersenne31.NewM31Const(fmt.Sprintf("%d", expr.Values[2])),
				mersenne31.NewM31Const(fmt.Sprintf("%d", expr.Values[3])),
			},
		}

	case "col":
		return e.getColumnValue(expr.TreeIdx, expr.ColIdx, expr.RowOff, sampledValues)

	case "preprocessed":
		if val, ok := preprocessed[expr.ID]; ok {
			return val
		}
		// If not found, return zero (should not happen in well-formed circuits)
		return mersenne31.ZeroQM31()

	case "add", "ext_add":
		left := e.EvaluateExprDef(expr.Left, sampledValues, preprocessed)
		right := e.EvaluateExprDef(expr.Right, sampledValues, preprocessed)
		return e.m31Chip.AddQM31(left, right)

	case "sub", "ext_sub":
		left := e.EvaluateExprDef(expr.Left, sampledValues, preprocessed)
		right := e.EvaluateExprDef(expr.Right, sampledValues, preprocessed)
		return e.m31Chip.SubQM31(left, right)

	case "mul", "ext_mul":
		left := e.EvaluateExprDef(expr.Left, sampledValues, preprocessed)
		right := e.EvaluateExprDef(expr.Right, sampledValues, preprocessed)
		return e.m31Chip.MulQM31(left, right)

	case "neg", "ext_neg":
		child := e.EvaluateExprDef(expr.Child, sampledValues, preprocessed)
		return e.m31Chip.NegQM31(child)

	case "inv":
		child := e.EvaluateExprDef(expr.Child, sampledValues, preprocessed)
		return e.m31Chip.InvQM31(child)

	case "secure_col":
		// Combine 4 base field expressions into extension field
		parts := [4]mersenne31.QM31Variable{}
		for i, part := range expr.Parts {
			if part != nil {
				parts[i] = e.EvaluateExprDef(part, sampledValues, preprocessed)
			}
		}
		// Extract the M31 components from each part
		return mersenne31.QM31Variable{
			Value: [4]mersenne31.M31Variable{
				parts[0].Value[0],
				parts[1].Value[0],
				parts[2].Value[0],
				parts[3].Value[0],
			},
		}

	default:
		panic(fmt.Sprintf("unknown expression type: %s", expr.Type))
	}
}

// getColumnValue retrieves a column value from sampled values.
func (e *CircuitDefEvaluator) getColumnValue(
	treeIdx, colIdx, rowOff int,
	sampledValues [][][]mersenne31.QM31Variable,
) mersenne31.QM31Variable {
	// Bounds check
	if treeIdx >= len(sampledValues) {
		panic(fmt.Sprintf("tree index %d out of bounds (len=%d)", treeIdx, len(sampledValues)))
	}
	if colIdx >= len(sampledValues[treeIdx]) {
		panic(fmt.Sprintf("column index %d out of bounds in tree %d (len=%d)",
			colIdx, treeIdx, len(sampledValues[treeIdx])))
	}

	// For OOD evaluation, offset handling depends on the mask
	// Typically offset 0 is at index 0 for that column
	offIdx := 0
	if rowOff != 0 {
		// For non-zero offsets, they should be stored sequentially
		// The exact mapping depends on how the mask is structured
		offIdx = -rowOff
	}

	colSamples := sampledValues[treeIdx][colIdx]
	if offIdx >= len(colSamples) {
		offIdx = 0
	}

	return colSamples[offIdx]
}

// EvaluateAllConstraints evaluates all constraints in all components.
// Returns the combined constraint evaluation using Horner's rule.
func (e *CircuitDefEvaluator) EvaluateAllConstraints(
	sampledValues [][][]mersenne31.QM31Variable,
	preprocessed map[string]mersenne31.QM31Variable,
	randomCoeff mersenne31.QM31Variable,
	vanishingInv mersenne31.QM31Variable,
) mersenne31.QM31Variable {
	sum := mersenne31.ZeroQM31()

	for _, comp := range e.def.Components {
		for _, constraint := range comp.Constraints {
			// Evaluate the constraint expression
			constraintEval := e.EvaluateExprDef(&constraint.Expr, sampledValues, preprocessed)

			// Compute constraint quotient: constraint_eval * vanishing_inv
			quotient := e.m31Chip.MulQM31(constraintEval, vanishingInv)

			// Horner's rule: sum = sum * randomCoeff + quotient
			sum = e.m31Chip.MulQM31(sum, randomCoeff)
			sum = e.m31Chip.AddQM31(sum, quotient)
		}
	}

	return sum
}

// EvaluateLogupFractions evaluates all LogUp fractions in all components.
// Returns the accumulated sum of all fractions.
func (e *CircuitDefEvaluator) EvaluateLogupFractions(
	sampledValues [][][]mersenne31.QM31Variable,
	preprocessed map[string]mersenne31.QM31Variable,
) mersenne31.QM31Variable {
	sum := mersenne31.ZeroQM31()

	for _, comp := range e.def.Components {
		if comp.Logup == nil {
			continue
		}

		for _, frac := range comp.Logup.Fractions {
			// Evaluate numerator and denominator
			num := e.EvaluateExprDef(&frac.Numerator, sampledValues, preprocessed)
			denom := e.EvaluateExprDef(&frac.Denominator, sampledValues, preprocessed)

			// Compute fraction value: num / denom
			denomInv := e.m31Chip.InvQM31(denom)
			fracVal := e.m31Chip.MulQM31(num, denomInv)

			// Accumulate
			sum = e.m31Chip.AddQM31(sum, fracVal)
		}
	}

	return sum
}
