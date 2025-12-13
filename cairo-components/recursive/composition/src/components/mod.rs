use circle_plonk_dsl_primitives::fields::WrappedQM31Var;
use stwo_constraint_framework::EvalAtRow;

pub mod subroutines;

pub mod blake;
pub mod memory_address_to_id;
pub mod memory_id_to_big;
pub mod opcodes;
pub mod range_check_builtin_bits_128;
pub mod range_checks;
pub mod verify_bitwise;
pub mod verify_instruction;

pub trait ComponentVar {
    fn evaluate<E: EvalAtRow<F = WrappedQM31Var, EF = WrappedQM31Var>>(&self, eval: E) -> E;
}

pub mod prelude {
    pub use crate::components::ComponentVar;
    pub use cairo_plonk_dsl_data_structures::lookup::*;
    pub use circle_plonk_dsl_primitives::fields::WrappedQM31Var;
    pub use num_traits::One;
    pub use serde::{Deserialize, Serialize};
    pub use stwo::core::fields::m31::M31;
    pub use stwo_cairo_common::preprocessed_columns::bitwise_xor::BitwiseXor;
    pub use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedColumn;
    pub use stwo_cairo_common::preprocessed_columns::preprocessed_trace::Seq;
    pub use stwo_cairo_serialize::CairoDeserialize;
    pub use stwo_cairo_serialize::CairoSerialize;
    pub use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
    pub use stwo_constraint_framework::EvalAtRow;
    pub use stwo_constraint_framework::RelationEntry;
}
