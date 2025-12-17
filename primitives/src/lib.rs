// Main lib.rs for unified primitives crate

// Fields module (base module)
pub mod m31;
pub use m31::*;

pub mod cm31;
pub use cm31::*;

pub mod qm31;
pub use qm31::*;

// Other modules
pub mod bits;
pub mod channel;
pub mod circle;
pub mod fields;
pub mod line;
pub mod merkle;
pub mod option;
pub mod query;

// Poseidon31 module
pub mod poseidon31;

// Re-export commonly used types for convenience
pub use bits::{BitVar, BitsVar};
pub use channel::{ChannelVar, HashVar};
pub use circle::{CirclePointM31Var, CirclePointQM31Var};
pub use line::LinePolyVar;
pub use merkle::Poseidon31MerkleHasherVar;
pub use poseidon31::Poseidon2HalfVar;
pub use query::{PointCarryingQueryVar, QueryPositionsPerLogSizeVar};

// Oblivious data structures
pub mod oblivious_map;
