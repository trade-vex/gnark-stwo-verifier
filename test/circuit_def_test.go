package stwo_test

import (
	"testing"

	stwo "github.com/gnark-stwo/stwo"
)

func TestParseSimpleAirCircuitDef(t *testing.T) {
	// This JSON is from the Rust extraction test
	jsonData := []byte(`{
  "name": "simple_air",
  "components": [
    {
      "name": "simple_air",
      "log_size": 4,
      "trees": {
        "num_trees": 2,
        "column_log_sizes": [
          [],
          [4, 4, 4]
        ],
        "preprocessed_column_indices": []
      },
      "mask": {
        "samples": [
          [],
          [
            {"col_idx": 0, "row_offset": 0},
            {"col_idx": 1, "row_offset": 0},
            {"col_idx": 2, "row_offset": 0}
          ]
        ]
      },
      "relations": [],
      "constraints": [
        {
          "expr": {
            "type": "sub",
            "left": {
              "type": "add",
              "left": {
                "type": "mul",
                "left": {"type": "col", "tree_idx": 1, "col_idx": 0, "row_off": 0},
                "right": {"type": "col", "tree_idx": 1, "col_idx": 1, "row_off": 0}
              },
              "right": {"type": "col", "tree_idx": 1, "col_idx": 0, "row_off": 0}
            },
            "right": {"type": "col", "tree_idx": 1, "col_idx": 2, "row_off": 0}
          }
        }
      ]
    }
  ],
  "composition_log_degree_bound": 5
}`)

	def, err := stwo.ParseCircuitDefinition(jsonData)
	if err != nil {
		t.Fatalf("Failed to parse circuit definition: %v", err)
	}

	// Verify structure
	if def.Name != "simple_air" {
		t.Errorf("Expected name 'simple_air', got '%s'", def.Name)
	}
	if len(def.Components) != 1 {
		t.Fatalf("Expected 1 component, got %d", len(def.Components))
	}

	comp := def.Components[0]
	if comp.Name != "simple_air" {
		t.Errorf("Expected component name 'simple_air', got '%s'", comp.Name)
	}
	if comp.LogSize != 4 {
		t.Errorf("Expected log_size 4, got %d", comp.LogSize)
	}
	if len(comp.Constraints) != 1 {
		t.Errorf("Expected 1 constraint, got %d", len(comp.Constraints))
	}

	// Verify constraint structure: (col[1,0] * col[1,1]) + col[1,0] - col[1,2]
	constraint := comp.Constraints[0].Expr
	if constraint.Type != "sub" {
		t.Errorf("Expected top-level 'sub', got '%s'", constraint.Type)
	}
	if constraint.Left.Type != "add" {
		t.Errorf("Expected left 'add', got '%s'", constraint.Left.Type)
	}
	if constraint.Left.Left.Type != "mul" {
		t.Errorf("Expected left.left 'mul', got '%s'", constraint.Left.Left.Type)
	}
	if constraint.Right.Type != "col" {
		t.Errorf("Expected right 'col', got '%s'", constraint.Right.Type)
	}
	if constraint.Right.ColIdx != 2 {
		t.Errorf("Expected right col_idx 2, got %d", constraint.Right.ColIdx)
	}

	t.Logf("Successfully parsed simple_air circuit definition")
}

func TestParseStaticLookupsCircuitDef(t *testing.T) {
	jsonData := []byte(`{
  "name": "static_lookups",
  "components": [
    {
      "name": "static_lookups",
      "log_size": 4,
      "trees": {
        "num_trees": 2,
        "column_log_sizes": [[], [4, 4, 4]],
        "preprocessed_column_indices": [0]
      },
      "mask": {
        "samples": [[], [{"col_idx": 0, "row_offset": 0}, {"col_idx": 1, "row_offset": 0}, {"col_idx": 2, "row_offset": 0}]]
      },
      "relations": [],
      "constraints": [],
      "logup": {
        "interaction_tree": 2,
        "fractions": [
          {
            "numerator": {"type": "ext_neg", "child": {"type": "col", "tree_idx": 1, "col_idx": 2, "row_off": 0}},
            "denominator": {"type": "ext_sub", "left": {"type": "ext_mul", "left": {"type": "ext_const", "values": [1, 0, 0, 0]}, "right": {"type": "preprocessed", "id": "range_check_4_bits"}}, "right": {"type": "ext_const", "values": [1, 2, 3, 4]}}
          },
          {
            "numerator": {"type": "ext_const", "values": [1, 0, 0, 0]},
            "denominator": {"type": "ext_sub", "left": {"type": "ext_mul", "left": {"type": "ext_const", "values": [1, 0, 0, 0]}, "right": {"type": "col", "tree_idx": 1, "col_idx": 0, "row_off": 0}}, "right": {"type": "ext_const", "values": [1, 2, 3, 4]}}
          },
          {
            "numerator": {"type": "ext_const", "values": [1, 0, 0, 0]},
            "denominator": {"type": "ext_sub", "left": {"type": "ext_mul", "left": {"type": "ext_const", "values": [1, 0, 0, 0]}, "right": {"type": "col", "tree_idx": 1, "col_idx": 1, "row_off": 0}}, "right": {"type": "ext_const", "values": [1, 2, 3, 4]}}
          }
        ],
        "finalize_mode": "batched",
        "batch_sizes": [0, 1, 1]
      }
    }
  ],
  "composition_log_degree_bound": 5
}`)

	def, err := stwo.ParseCircuitDefinition(jsonData)
	if err != nil {
		t.Fatalf("Failed to parse circuit definition: %v", err)
	}

	// Verify structure
	if def.Name != "static_lookups" {
		t.Errorf("Expected name 'static_lookups', got '%s'", def.Name)
	}
	if len(def.Components) != 1 {
		t.Fatalf("Expected 1 component, got %d", len(def.Components))
	}

	comp := def.Components[0]
	if comp.Logup == nil {
		t.Fatal("Expected LogUp configuration")
	}
	if len(comp.Logup.Fractions) != 3 {
		t.Errorf("Expected 3 fractions, got %d", len(comp.Logup.Fractions))
	}
	if comp.Logup.FinalizeMode != "batched" {
		t.Errorf("Expected finalize_mode 'batched', got '%s'", comp.Logup.FinalizeMode)
	}
	if len(comp.Logup.BatchSizes) != 3 {
		t.Errorf("Expected 3 batch sizes, got %d", len(comp.Logup.BatchSizes))
	}

	// Verify first fraction structure
	frac := comp.Logup.Fractions[0]
	if frac.Numerator.Type != "ext_neg" {
		t.Errorf("Expected numerator type 'ext_neg', got '%s'", frac.Numerator.Type)
	}
	if frac.Denominator.Type != "ext_sub" {
		t.Errorf("Expected denominator type 'ext_sub', got '%s'", frac.Denominator.Type)
	}

	t.Logf("Successfully parsed static_lookups circuit definition with %d LogUp fractions",
		len(comp.Logup.Fractions))
}
