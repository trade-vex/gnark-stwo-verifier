//! Constraint builder for stwo proof verification.
//!
//! This module provides utilities for building constraint representations
//! that can be consumed by the gnark circuit.

use serde::{Deserialize, Serialize};

/// A single constraint in the circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    /// The operation type
    pub op: String,
    /// Input variable names
    pub inputs: Vec<String>,
    /// Output variable name
    pub output: String,
    /// Optional constant value
    pub constant: Option<String>,
}

/// Builder for accumulating constraints.
#[derive(Debug, Default)]
pub struct ConstraintBuilder {
    constraints: Vec<Constraint>,
    var_counter: usize,
}

impl ConstraintBuilder {
    /// Create a new constraint builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a fresh variable name.
    pub fn fresh_var(&mut self) -> String {
        let name = format!("v{}", self.var_counter);
        self.var_counter += 1;
        name
    }

    /// Add a constraint.
    pub fn add_constraint(&mut self, op: &str, inputs: Vec<String>, output: String) {
        self.constraints.push(Constraint {
            op: op.to_string(),
            inputs,
            output,
            constant: None,
        });
    }

    /// Add a constraint with a constant.
    pub fn add_constraint_with_const(
        &mut self,
        op: &str,
        inputs: Vec<String>,
        output: String,
        constant: &str,
    ) {
        self.constraints.push(Constraint {
            op: op.to_string(),
            inputs,
            output,
            constant: Some(constant.to_string()),
        });
    }

    /// Get all constraints.
    pub fn constraints(&self) -> &[Constraint] {
        &self.constraints
    }

    /// Consume the builder and return constraints.
    pub fn into_constraints(self) -> Vec<Constraint> {
        self.constraints
    }
}
