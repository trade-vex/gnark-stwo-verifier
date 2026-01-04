// Circuit Definition Format for gnark-stwo
// This module defines an intermediate representation that captures everything
// needed to build the constraint evaluation circuit in gnark.

use serde::{Deserialize, Serialize};

/// Complete circuit definition for constraint evaluation.
/// This format is designed to be:
/// 1. Serializable to JSON for the Go side to parse
/// 2. Complete enough to reconstruct constraint evaluation
/// 3. Generic for any stwo AIR circuit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitDefinition {
    /// Name of the circuit (for identification)
    pub name: String,

    /// Components that make up the circuit
    pub components: Vec<ComponentDef>,

    /// Total composition polynomial log degree bound
    pub composition_log_degree_bound: u32,
}

/// Definition of a single component (corresponds to FrameworkComponent)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentDef {
    /// Component name
    pub name: String,

    /// Log2 of the trace size
    pub log_size: u32,

    /// Tree structure: which columns belong to which tree
    pub trees: TreeStructure,

    /// Mask definition: which columns at which offsets are sampled
    pub mask: MaskDef,

    /// Relations used by this component (LogUp lookups)
    pub relations: Vec<RelationDef>,

    /// AIR constraints (polynomial constraints that must be zero)
    pub constraints: Vec<ConstraintDef>,

    /// LogUp accumulation configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logup: Option<LogupDef>,
}

/// Tree structure definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeStructure {
    /// Number of trees (commitments)
    pub num_trees: usize,

    /// Column log sizes per tree
    pub column_log_sizes: Vec<Vec<u32>>,

    /// Preprocessed column indices used by this component
    pub preprocessed_column_indices: Vec<usize>,
}

/// Mask definition - which values are sampled for constraint evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskDef {
    /// For each tree, list of (column_index, row_offset) pairs
    /// row_offset is relative to the evaluation point
    pub samples: Vec<Vec<MaskItem>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskItem {
    pub col_idx: usize,
    pub row_offset: i32,
}

/// Definition of a relation (LogUp lookup elements)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationDef {
    /// Relation name (e.g., "SmallerThan16Elements")
    pub name: String,

    /// Number of values combined in this relation
    pub size: usize,

    /// When to draw this relation from the channel
    /// (after committing to tree at this index)
    pub draw_after_tree: usize,
}

/// Constraint definition - a polynomial expression that must evaluate to zero
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintDef {
    /// The constraint expression (QM31 polynomial)
    pub expr: ExprDef,
}

/// LogUp configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogupDef {
    /// The interaction tree index where LogUp cumsum columns are stored
    pub interaction_tree: usize,

    /// LogUp fractions to be accumulated
    pub fractions: Vec<FractionDef>,

    /// Finalization mode
    pub finalize_mode: FinalizeMode,

    /// For batched finalization, the batch sizes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_sizes: Option<Vec<usize>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalizeMode {
    /// finalize_logup() - single cumsum column
    Single,
    /// finalize_logup_in_pairs() - pairs of fractions
    Pairs,
    /// finalize_logup_batched(batch_sizes) - batched with given sizes
    Batched,
    /// finalize_last() - special handling for last row
    Last,
}

/// LogUp fraction definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FractionDef {
    /// Numerator expression
    pub numerator: ExprDef,
    /// Denominator expression
    pub denominator: ExprDef,
}

/// Expression definition (either base field or extension field)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ExprDef {
    // Base field operations
    #[serde(rename = "const")]
    Const { value: u32 },

    #[serde(rename = "col")]
    Col {
        tree_idx: usize,
        col_idx: usize,
        row_off: i32,
    },

    #[serde(rename = "add")]
    Add {
        left: Box<ExprDef>,
        right: Box<ExprDef>,
    },

    #[serde(rename = "sub")]
    Sub {
        left: Box<ExprDef>,
        right: Box<ExprDef>,
    },

    #[serde(rename = "mul")]
    Mul {
        left: Box<ExprDef>,
        right: Box<ExprDef>,
    },

    #[serde(rename = "neg")]
    Neg { child: Box<ExprDef> },

    #[serde(rename = "inv")]
    Inv { child: Box<ExprDef> },

    // Extension field operations
    #[serde(rename = "ext_const")]
    ExtConst { values: [u32; 4] },

    #[serde(rename = "ext_add")]
    ExtAdd {
        left: Box<ExprDef>,
        right: Box<ExprDef>,
    },

    #[serde(rename = "ext_sub")]
    ExtSub {
        left: Box<ExprDef>,
        right: Box<ExprDef>,
    },

    #[serde(rename = "ext_mul")]
    ExtMul {
        left: Box<ExprDef>,
        right: Box<ExprDef>,
    },

    #[serde(rename = "ext_neg")]
    ExtNeg { child: Box<ExprDef> },

    // Relation operations (LogUp)
    /// Combine values using a relation's z and alpha
    /// Result: sum(values[i] * alpha^i) - z
    #[serde(rename = "relation_combine")]
    RelationCombine {
        relation_name: String,
        #[serde(rename = "relation_values")]
        values: Vec<ExprDef>,
    },

    /// Reference to a preprocessed column by ID
    #[serde(rename = "preprocessed")]
    Preprocessed { id: String },

    /// Secure column (QM31 from 4 base field parts)
    #[serde(rename = "secure_col")]
    SecureCol { parts: [Box<ExprDef>; 4] },
}

/// QM31 constant value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QM31Def {
    pub values: [u32; 4],
}

impl CircuitDefinition {
    pub fn new(name: &str, composition_log_degree_bound: u32) -> Self {
        Self {
            name: name.to_string(),
            components: Vec::new(),
            composition_log_degree_bound,
        }
    }

    pub fn add_component(&mut self, component: ComponentDef) {
        self.components.push(component);
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Write to file
    pub fn write_to_file(&self, path: &str) -> std::io::Result<()> {
        let json = self.to_json().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })?;
        std::fs::write(path, json)
    }

    /// Load from file
    pub fn load_from_file(path: &str) -> std::io::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        serde_json::from_str(&contents).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })
    }
}

/// Builder for creating CircuitDefinition manually
pub struct CircuitDefBuilder {
    def: CircuitDefinition,
}

impl CircuitDefBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            def: CircuitDefinition::new(name, 0),
        }
    }

    pub fn composition_log_degree_bound(mut self, bound: u32) -> Self {
        self.def.composition_log_degree_bound = bound;
        self
    }

    pub fn add_component(mut self, component: ComponentDef) -> Self {
        self.def.add_component(component);
        self
    }

    pub fn build(self) -> CircuitDefinition {
        self.def
    }
}

/// Builder for creating ComponentDef
pub struct ComponentDefBuilder {
    def: ComponentDef,
}

impl ComponentDefBuilder {
    pub fn new(name: &str, log_size: u32) -> Self {
        Self {
            def: ComponentDef {
                name: name.to_string(),
                log_size,
                trees: TreeStructure {
                    num_trees: 3,
                    column_log_sizes: vec![],
                    preprocessed_column_indices: vec![],
                },
                mask: MaskDef { samples: vec![] },
                relations: vec![],
                constraints: vec![],
                logup: None,
            },
        }
    }

    pub fn trees(mut self, trees: TreeStructure) -> Self {
        self.def.trees = trees;
        self
    }

    pub fn mask(mut self, mask: MaskDef) -> Self {
        self.def.mask = mask;
        self
    }

    pub fn add_relation(mut self, relation: RelationDef) -> Self {
        self.def.relations.push(relation);
        self
    }

    pub fn add_constraint(mut self, constraint: ConstraintDef) -> Self {
        self.def.constraints.push(constraint);
        self
    }

    pub fn logup(mut self, logup: LogupDef) -> Self {
        self.def.logup = Some(logup);
        self
    }

    pub fn build(self) -> ComponentDef {
        self.def
    }
}
