//! Constraint extractor for converting FrameworkEval to CircuitDefinition.
//!
//! This module provides an `EvalAtRow` implementation that captures constraint
//! expressions instead of evaluating them, allowing us to extract the circuit
//! definition from any FrameworkEval.

use std::cell::RefCell;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub};
use std::rc::Rc;

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fields::FieldExpOps;
use stwo::core::Fraction;
use stwo_constraint_framework::{
    logup::LogupAtRow,
    preprocessed_columns::PreProcessedColumnId, EvalAtRow,
    INTERACTION_TRACE_IDX,
};

use crate::circuit_def::{
    CircuitDefinition, ComponentDef, ConstraintDef, ExprDef, FinalizeMode, FractionDef, LogupDef,
    MaskDef, MaskItem, TreeStructure,
};

/// An expression wrapper that builds ExprDef trees.
#[derive(Debug, Clone)]
pub struct Expr {
    inner: ExprDef,
}

impl Expr {
    pub fn new(inner: ExprDef) -> Self {
        Self { inner }
    }

    pub fn into_def(self) -> ExprDef {
        self.inner
    }

    pub fn def(&self) -> &ExprDef {
        &self.inner
    }
}

// Implement Zero for Expr
impl Zero for Expr {
    fn zero() -> Self {
        Expr::new(ExprDef::Const { value: 0 })
    }

    fn is_zero(&self) -> bool {
        matches!(self.inner, ExprDef::Const { value: 0 })
    }
}

impl One for Expr {
    fn one() -> Self {
        Expr::new(ExprDef::Const { value: 1 })
    }
}

// Expr + Expr
impl Add for Expr {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        // Optimize: 0 + x = x
        if self.is_zero() {
            return rhs;
        }
        if rhs.is_zero() {
            return self;
        }
        Expr::new(ExprDef::Add {
            left: Box::new(self.inner),
            right: Box::new(rhs.inner),
        })
    }
}

// Expr - Expr
impl Sub for Expr {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        if rhs.is_zero() {
            return self;
        }
        Expr::new(ExprDef::Sub {
            left: Box::new(self.inner),
            right: Box::new(rhs.inner),
        })
    }
}

// Expr * Expr
impl Mul for Expr {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        // Optimize: 1 * x = x, 0 * x = 0
        if matches!(self.inner, ExprDef::Const { value: 1 }) {
            return rhs;
        }
        if matches!(rhs.inner, ExprDef::Const { value: 1 }) {
            return self;
        }
        if self.is_zero() || rhs.is_zero() {
            return Expr::zero();
        }
        Expr::new(ExprDef::Mul {
            left: Box::new(self.inner),
            right: Box::new(rhs.inner),
        })
    }
}

// -Expr
impl Neg for Expr {
    type Output = Self;

    fn neg(self) -> Self {
        Expr::new(ExprDef::Neg {
            child: Box::new(self.inner),
        })
    }
}

impl AddAssign for Expr {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs;
    }
}

impl AddAssign<BaseField> for Expr {
    fn add_assign(&mut self, rhs: BaseField) {
        *self = self.clone() + Expr::new(ExprDef::Const { value: rhs.0 });
    }
}

impl MulAssign for Expr {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
    }
}

// Expr * BaseField
impl Mul<BaseField> for Expr {
    type Output = Self;

    fn mul(self, rhs: BaseField) -> Self {
        if rhs.0 == 1 {
            return self;
        }
        if rhs.0 == 0 {
            return Expr::zero();
        }
        Expr::new(ExprDef::Mul {
            left: Box::new(self.inner),
            right: Box::new(ExprDef::Const { value: rhs.0 }),
        })
    }
}

impl From<BaseField> for Expr {
    fn from(value: BaseField) -> Self {
        Expr::new(ExprDef::Const { value: value.0 })
    }
}

impl FieldExpOps for Expr {
    fn inverse(&self) -> Self {
        Expr::new(ExprDef::Inv {
            child: Box::new(self.inner.clone()),
        })
    }
}

/// Extension field expression (QM31)
#[derive(Debug, Clone)]
pub struct ExtExpr {
    inner: ExprDef,
}

impl ExtExpr {
    pub fn new(inner: ExprDef) -> Self {
        Self { inner }
    }

    pub fn into_def(self) -> ExprDef {
        self.inner
    }

    pub fn def(&self) -> &ExprDef {
        &self.inner
    }
}

impl Zero for ExtExpr {
    fn zero() -> Self {
        ExtExpr::new(ExprDef::ExtConst {
            values: [0, 0, 0, 0],
        })
    }

    fn is_zero(&self) -> bool {
        matches!(self.inner, ExprDef::ExtConst { values: [0, 0, 0, 0] })
    }
}

impl One for ExtExpr {
    fn one() -> Self {
        ExtExpr::new(ExprDef::ExtConst {
            values: [1, 0, 0, 0],
        })
    }
}

// ExtExpr + ExtExpr
impl Add for ExtExpr {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        if self.is_zero() {
            return rhs;
        }
        if rhs.is_zero() {
            return self;
        }
        ExtExpr::new(ExprDef::ExtAdd {
            left: Box::new(self.inner),
            right: Box::new(rhs.inner),
        })
    }
}

// ExtExpr - ExtExpr
impl Sub for ExtExpr {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        if rhs.is_zero() {
            return self;
        }
        ExtExpr::new(ExprDef::ExtSub {
            left: Box::new(self.inner),
            right: Box::new(rhs.inner),
        })
    }
}

// ExtExpr * ExtExpr
impl Mul for ExtExpr {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        ExtExpr::new(ExprDef::ExtMul {
            left: Box::new(self.inner),
            right: Box::new(rhs.inner),
        })
    }
}

// -ExtExpr
impl Neg for ExtExpr {
    type Output = Self;

    fn neg(self) -> Self {
        ExtExpr::new(ExprDef::ExtNeg {
            child: Box::new(self.inner),
        })
    }
}

impl AddAssign for ExtExpr {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs;
    }
}

// ExtExpr + BaseField
impl Add<BaseField> for ExtExpr {
    type Output = Self;

    fn add(self, rhs: BaseField) -> Self {
        ExtExpr::new(ExprDef::ExtAdd {
            left: Box::new(self.inner),
            right: Box::new(ExprDef::Const { value: rhs.0 }),
        })
    }
}

// ExtExpr * BaseField
impl Mul<BaseField> for ExtExpr {
    type Output = Self;

    fn mul(self, rhs: BaseField) -> Self {
        ExtExpr::new(ExprDef::ExtMul {
            left: Box::new(self.inner),
            right: Box::new(ExprDef::Const { value: rhs.0 }),
        })
    }
}

// ExtExpr + SecureField
impl Add<SecureField> for ExtExpr {
    type Output = Self;

    fn add(self, rhs: SecureField) -> Self {
        let values = [rhs.0 .0 .0, rhs.0 .1 .0, rhs.1 .0 .0, rhs.1 .1 .0];
        ExtExpr::new(ExprDef::ExtAdd {
            left: Box::new(self.inner),
            right: Box::new(ExprDef::ExtConst { values }),
        })
    }
}

// ExtExpr - SecureField
impl Sub<SecureField> for ExtExpr {
    type Output = Self;

    fn sub(self, rhs: SecureField) -> Self {
        let values = [rhs.0 .0 .0, rhs.0 .1 .0, rhs.1 .0 .0, rhs.1 .1 .0];
        ExtExpr::new(ExprDef::ExtSub {
            left: Box::new(self.inner),
            right: Box::new(ExprDef::ExtConst { values }),
        })
    }
}

// ExtExpr * SecureField
impl Mul<SecureField> for ExtExpr {
    type Output = Self;

    fn mul(self, rhs: SecureField) -> Self {
        let values = [rhs.0 .0 .0, rhs.0 .1 .0, rhs.1 .0 .0, rhs.1 .1 .0];
        ExtExpr::new(ExprDef::ExtMul {
            left: Box::new(self.inner),
            right: Box::new(ExprDef::ExtConst { values }),
        })
    }
}

// ExtExpr + Expr (base field promotion)
impl Add<Expr> for ExtExpr {
    type Output = Self;

    fn add(self, rhs: Expr) -> Self {
        ExtExpr::new(ExprDef::ExtAdd {
            left: Box::new(self.inner),
            right: Box::new(rhs.inner),
        })
    }
}

// ExtExpr * Expr (base field promotion)
impl Mul<Expr> for ExtExpr {
    type Output = Self;

    fn mul(self, rhs: Expr) -> Self {
        ExtExpr::new(ExprDef::ExtMul {
            left: Box::new(self.inner),
            right: Box::new(rhs.inner),
        })
    }
}

impl From<SecureField> for ExtExpr {
    fn from(value: SecureField) -> Self {
        let values = [value.0 .0 .0, value.0 .1 .0, value.1 .0 .0, value.1 .1 .0];
        ExtExpr::new(ExprDef::ExtConst { values })
    }
}

impl From<Expr> for ExtExpr {
    fn from(value: Expr) -> Self {
        // Promote base field expression to extension field
        ExtExpr::new(value.inner)
    }
}

// Expr + SecureField -> ExtExpr
impl Add<SecureField> for Expr {
    type Output = ExtExpr;

    fn add(self, rhs: SecureField) -> ExtExpr {
        ExtExpr::from(self) + rhs
    }
}

// Expr * SecureField -> ExtExpr
impl Mul<SecureField> for Expr {
    type Output = ExtExpr;

    fn mul(self, rhs: SecureField) -> ExtExpr {
        ExtExpr::from(self) * rhs
    }
}

/// State shared between expression extraction.
struct ExtractorState {
    /// Mask offsets per tree
    mask_offsets: Vec<Vec<Vec<isize>>>,
    /// Column index per tree
    col_indices: Vec<usize>,
    /// Preprocessed columns used
    preprocessed_columns: Vec<PreProcessedColumnId>,
    /// Constraints collected
    constraints: Vec<ConstraintDef>,
    /// LogUp fractions
    logup_fracs: Vec<FractionDef>,
    /// Finalization mode
    finalize_mode: Option<FinalizeMode>,
    /// Batch sizes for batched finalization
    batch_sizes: Option<Vec<usize>>,
}

/// Constraint extractor that implements EvalAtRow to capture expressions.
pub struct ConstraintExtractor {
    state: Rc<RefCell<ExtractorState>>,
    logup: LogupAtRow<Self>,
}

impl ConstraintExtractor {
    pub fn new(log_size: u32, claimed_sum: SecureField) -> Self {
        Self {
            state: Rc::new(RefCell::new(ExtractorState {
                mask_offsets: Vec::new(),
                col_indices: Vec::new(),
                preprocessed_columns: Vec::new(),
                constraints: Vec::new(),
                logup_fracs: Vec::new(),
                finalize_mode: None,
                batch_sizes: None,
            })),
            logup: LogupAtRow::new(INTERACTION_TRACE_IDX, claimed_sum, log_size),
        }
    }

    /// Extract circuit definition from the collected state.
    pub fn into_component_def(self, name: &str, log_size: u32) -> ComponentDef {
        // Ensure logup is finalized
        drop(self.logup);

        let state = self.state.borrow();

        // Build mask
        let mask = MaskDef {
            samples: state
                .mask_offsets
                .iter()
                .map(|tree_offsets| {
                    tree_offsets
                        .iter()
                        .enumerate()
                        .flat_map(|(col_idx, offsets)| {
                            offsets.iter().map(move |&row_offset| MaskItem {
                                col_idx,
                                row_offset: row_offset as i32,
                            })
                        })
                        .collect()
                })
                .collect(),
        };

        // Build tree structure
        let trees = TreeStructure {
            num_trees: state.mask_offsets.len(),
            column_log_sizes: state
                .mask_offsets
                .iter()
                .map(|tree| vec![log_size; tree.len()])
                .collect(),
            preprocessed_column_indices: (0..state.preprocessed_columns.len()).collect(),
        };

        // Build logup config if we have fractions
        let logup = if !state.logup_fracs.is_empty() {
            Some(LogupDef {
                interaction_tree: INTERACTION_TRACE_IDX,
                fractions: state.logup_fracs.clone(),
                finalize_mode: state.finalize_mode.clone().unwrap_or(FinalizeMode::Single),
                batch_sizes: state.batch_sizes.clone(),
            })
        } else {
            None
        };

        ComponentDef {
            name: name.to_string(),
            log_size,
            trees,
            mask,
            relations: vec![], // Relations are captured in the expression tree
            constraints: state.constraints.clone(),
            logup,
        }
    }
}

impl EvalAtRow for ConstraintExtractor {
    type F = Expr;
    type EF = ExtExpr;

    fn next_interaction_mask<const N: usize>(
        &mut self,
        interaction: usize,
        offsets: [isize; N],
    ) -> [Self::F; N] {
        let mut state = self.state.borrow_mut();

        // Extend mask_offsets if needed
        while state.mask_offsets.len() <= interaction {
            state.mask_offsets.push(Vec::new());
            state.col_indices.push(0);
        }

        let col_idx = state.col_indices[interaction];
        state.col_indices[interaction] += 1;
        state.mask_offsets[interaction].push(offsets.to_vec());

        // Return column expressions
        std::array::from_fn(|i| {
            Expr::new(ExprDef::Col {
                tree_idx: interaction,
                col_idx,
                row_off: offsets[i] as i32,
            })
        })
    }

    fn get_preprocessed_column(&mut self, column: PreProcessedColumnId) -> Self::F {
        let mut state = self.state.borrow_mut();
        let id = column.id.clone();
        state.preprocessed_columns.push(column);

        Expr::new(ExprDef::Preprocessed { id })
    }

    fn add_constraint<G>(&mut self, constraint: G)
    where
        Self::EF: Mul<G, Output = Self::EF> + From<G>,
    {
        // Convert constraint to ExtExpr
        let ext_constraint = Self::EF::from(constraint);
        let mut state = self.state.borrow_mut();
        state.constraints.push(ConstraintDef {
            expr: ext_constraint.into_def(),
        });
    }

    fn combine_ef(values: [Self::F; 4]) -> Self::EF {
        // Combine 4 base field values into extension field
        ExtExpr::new(ExprDef::SecureCol {
            parts: [
                Box::new(values[0].clone().into_def()),
                Box::new(values[1].clone().into_def()),
                Box::new(values[2].clone().into_def()),
                Box::new(values[3].clone().into_def()),
            ],
        })
    }

    // Use default add_to_relation which calls write_logup_frac
    // We can't access RelationEntry fields from outside the crate

    fn write_logup_frac(&mut self, fraction: Fraction<Self::EF, Self::EF>) {
        // Capture the fraction definition
        {
            let mut state = self.state.borrow_mut();
            state.logup_fracs.push(FractionDef {
                numerator: fraction.numerator.clone().into_def(),
                denominator: fraction.denominator.clone().into_def(),
            });
        }

        if self.logup.fracs.is_empty() {
            self.logup.is_finalized = false;
        }
        self.logup.fracs.push(fraction);
    }

    fn finalize_logup_batched(&mut self, batching: &Vec<usize>) {
        // Record the finalization mode
        {
            let mut state = self.state.borrow_mut();
            state.finalize_mode = Some(FinalizeMode::Batched);
            state.batch_sizes = Some(batching.clone());
        }

        // We need to finalize the logup properly
        assert!(!self.logup.is_finalized, "LogupAtRow was already finalized");
        assert_eq!(
            batching.len(),
            self.logup.fracs.len(),
            "Batching must be of the same length as the number of entries"
        );

        self.logup.is_finalized = true;
    }

    fn finalize_logup(&mut self) {
        {
            let mut state = self.state.borrow_mut();
            state.finalize_mode = Some(FinalizeMode::Single);
        }
        let batches: Vec<usize> = (0..self.logup.fracs.len()).collect();
        self.finalize_logup_batched(&batches);
    }

    fn finalize_logup_in_pairs(&mut self) {
        {
            let mut state = self.state.borrow_mut();
            state.finalize_mode = Some(FinalizeMode::Pairs);
        }
        let batches: Vec<usize> = (0..self.logup.fracs.len()).map(|n| n / 2).collect();
        self.finalize_logup_batched(&batches);
    }
}

/// Extract component definition from a FrameworkEval.
pub fn extract_component_def<E: stwo_constraint_framework::FrameworkEval>(
    name: &str,
    eval: &E,
    claimed_sum: SecureField,
) -> ComponentDef {
    let log_size = eval.log_size();
    let extractor = ConstraintExtractor::new(log_size, claimed_sum);

    // Run the evaluation to capture constraints - evaluate returns the modified extractor
    let extractor = eval.evaluate(extractor);

    // Extract the component definition
    extractor.into_component_def(name, log_size)
}

/// Extract full circuit definition from multiple FrameworkEvals.
pub fn extract_circuit_def(
    name: &str,
    components: Vec<ComponentDef>,
    composition_log_degree_bound: u32,
) -> CircuitDefinition {
    CircuitDefinition {
        name: name.to_string(),
        components,
        composition_log_degree_bound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expr_arithmetic() {
        let a = Expr::new(ExprDef::Col {
            tree_idx: 1,
            col_idx: 0,
            row_off: 0,
        });
        let b = Expr::new(ExprDef::Col {
            tree_idx: 1,
            col_idx: 1,
            row_off: 0,
        });

        let sum = a.clone() + b.clone();
        let prod = a.clone() * b.clone();
        let neg = -a.clone();

        assert!(matches!(sum.def(), ExprDef::Add { .. }));
        assert!(matches!(prod.def(), ExprDef::Mul { .. }));
        assert!(matches!(neg.def(), ExprDef::Neg { .. }));
    }

    #[test]
    fn test_expr_zero_optimization() {
        let zero = Expr::zero();
        let one = Expr::new(ExprDef::Const { value: 1 });

        // 0 + x = x
        let sum = zero.clone() + one.clone();
        assert!(matches!(sum.def(), ExprDef::Const { value: 1 }));

        // x + 0 = x
        let sum = one.clone() + zero.clone();
        assert!(matches!(sum.def(), ExprDef::Const { value: 1 }));
    }
}
