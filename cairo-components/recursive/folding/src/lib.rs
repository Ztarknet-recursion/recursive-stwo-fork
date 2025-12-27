use cairo_plonk_dsl_hints::folding::SinglePairMerkleProof;
use circle_plonk_dsl_constraint_system::ConstraintSystemRef;
use circle_plonk_dsl_primitives::{HashVar, QM31Var};
use stwo::core::pcs::quotients::IndexMap;

pub struct PaddedSinglePairMerkleProofVar {
    pub cs: ConstraintSystemRef,
    pub value: SinglePairMerkleProof,
    pub sibling_hashes: Vec<HashVar>,
    pub self_columns: IndexMap<usize, QM31Var>,
    pub siblings_columns: IndexMap<usize, QM31Var>,
}
