# TODO

## Decommitment Merkle Tree in Constraint System

### 1. Allocate Merkle Tree Structure in Constraint System
**Location**: `cairo-components/recursive/decommitment`

**Context**: 
- The Merkle tree structure is already implemented in `cairo-components/hints/src/decommitment.rs` as `QueryDecommitmentProof` and `QueryDecommitmentNode`
- The structure contains nodes with optional children (for leaf nodes) and column values
- Some bottom layers may be "optional" (nodes may not exist for all columns)

**Tasks**:
- [ ] Create `QueryDecommitmentProofVar` and `QueryDecommitmentNodeVar` structs that mirror the hint structures
- [ ] Implement `AllocVar` trait for these Var types to allocate them in the constraint system
- [ ] Handle optional bottom layers: design a mechanism to conditionally allocate nodes based on whether columns exist
  - Consider using `Option<Poseidon2HalfVar>` for children when they may not exist
  - Ensure the constraint system can handle sparse Merkle trees where not all leaf nodes are present
- [ ] Map the layer structure from hints (organized by `log_size`) to the constraint system representation
- [ ] Ensure proper variable allocation for:
  - Node hashes (`Poseidon2HalfVar`)
  - Column values (`Vec<M31Var>`)
  - Optional children hashes

**Reference**: See `QueryDecommitmentProof::from_stwo_proof` in `cairo-components/hints/src/decommitment.rs` for the structure and logic

### 2. Complete Merkle Tree Root Computation
**Location**: `cairo-components/recursive/decommitment`

**Context**:
- `PreprocessedTraceQueryResultVar::compute_column_hashes()` already computes column hashes (leaf layer)
- Need to compute intermediate layers and root hash using the Merkle tree structure

**Tasks**:
- [ ] Implement function to compute intermediate Merkle tree layers from column hashes
  - Start with column hashes (already computed)
  - For each layer, compute parent nodes by hashing pairs of children
  - Handle cases where a node has only one child (odd number of nodes in layer)
- [ ] Implement root hash computation that traverses from column hashes to root
  - Use `Poseidon31MerkleHasherVar::hash_tree` or similar methods for parent node computation
  - Follow the same layer-by-layer approach as in `QueryDecommitmentProof::from_stwo_proof`
- [ ] Ensure the computation matches the structure from hints:
  - Layers organized by `log_size` (from max to 0)
  - Each node's hash computed using `Poseidon31MerkleHasherVar::hash_node` equivalent
  - Final root should match the commitment root from the proof
- [ ] Add verification that computed root matches expected root hash
- [ ] Consider edge cases:
  - Sparse trees with missing nodes
  - Layers with odd number of nodes
  - Empty or single-node layers

**Reference**: 
- See `QueryDecommitmentNode::hash()` in `cairo-components/hints/src/decommitment.rs` for hash computation
- See `Poseidon31MerkleHasherVar` in `primitives/src/merkle.rs` for available hashing methods
