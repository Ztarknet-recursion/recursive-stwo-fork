# TODO

## First Layer Separation and Refactoring

### Overview
Separate the first layer from the rest of the layers. The first layer will have pairs of elements (left and right pairs in each layer). The pairs may or may not each carry a QM31 in that layer.

### Tasks

1. **Refactor First Layer Structure in Fiat-Shamir**
   - [ ] Refactor the first layer structure in `cairo-components/recursive/fiat_shamir/src/lib.rs`
   - [ ] Update `FriProofVar` to separate first layer from inner layers
   - [ ] Modify data structures to handle pairs (left and right) in the first layer
   - [ ] Ensure pairs can optionally carry QM31 values

2. **Implement Parent Folding for First Layer**
   - [ ] Deduce folded result for the parent of each pair in the first layer
   - [ ] Implement folding logic for first layer pairs
   - [ ] Handle cases where pairs may or may not carry QM31 values

3. **Hints Side Implementation**
   - [ ] Recreate how first layer data is being verified in hints
   - [ ] Extract sibling evaluations from the proof
   - [ ] Add debug printing to examine one proof structure
   - [ ] Verify the extraction matches the expected structure

4. **Integration and Testing**
   - [ ] Ensure first layer pairs work correctly with the rest of the system
   - [ ] Test with proofs that have pairs with and without QM31 values
   - [ ] Verify parent folding results are correct

### Related Files
- `cairo-components/recursive/fiat_shamir/src/lib.rs` - Fiat-Shamir implementation
- `cairo-components/recursive/data_structures/src/stark_proof.rs` - FRI proof structures
- `cairo-components/hints/src/folding.rs` - First layer hints (currently empty)
- `components/hints/src/folding.rs` - Reference implementation for first layer hints
- `components/recursive/folding/src/lib.rs` - Folding results computation
