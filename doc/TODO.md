# TODO

## Data Structures

### 1. SampleVar Data Structure
- [ ] Create a `SampleVar` data structure that arranges samples in a structural format mirrored with `Query`
  - [ ] Study the `QueryPositionsPerLogSizeVar` and `PointCarryingQueryVar` structure in `primitives/src/query.rs`
  - [ ] Design `SampleVar` to mirror the hierarchical organization of queries (per log size, with points)
  - [ ] Ensure `SampleVar` maintains the same structural relationships as `Query` for consistency
  - [ ] Implement in appropriate location (likely `components/recursive/answer/src/data_structures.rs` or similar)

## Constraint System Implementation

### 3. Masked Point Computation
- [ ] Implement code that computes the masked point (by -1) in the constraint system
  - [ ] Review existing masked point logic (e.g., `conditional_negate` in `primitives/src/circle.rs`)
  - [ ] Implement masked point computation using -1 multiplication in constraint system
  - [ ] Add consistency checks to compare computed masked points with expected values
  - [ ] Ensure proper constraint generation for masked point verification

## Algorithm Study and Documentation

### 4. Accumulator Implementation Study
- [ ] Study the accumulator code to determine the best implementation order
  - [ ] Review `HashAccumulatorVar` in `cairo-components/recursive/decommitment/src/utils.rs`
  - [ ] Review `PointEvaluationAccumulatorVar` in `components/recursive/composition/src/data_structures.rs`
  - [ ] Analyze the order of operations in existing accumulator implementations
  - [ ] Document findings on optimal ordering for accumulator operations
  - [ ] Determine if order matters for correctness and efficiency

Note that the accumulation would start with the unmasked (oods point) evaluation for all four rounds. 
After that, it would start processing the accumulation on the -1 point, for each log size.

Each one being inserted gets another "alpha" in it, so the data structure may benefit from having a "cur_multiplier" thing
nearby. This might not be the most ideal solution, but the current implementation desires so.

what is being added (assuming a -2j has been taking care of):

c * queried_value - a * queried_pointed.y - b

where 

a = sampled_value.img
b = sampled_point.y.img
c = sampled.value.real * sampled_point.y.img - sampled_value.img * sampled_point.y.real

divided by 
        let prx = sample_batch.point.x.0;
        let pry = sample_batch.point.y.0;
        let pix = sample_batch.point.x.1;
        let piy = sample_batch.point.y.1;
        denominators.push((prx - domain_point.x) * piy - (pry - domain_point.y) * pix);

### 5. Algorithm Documentation
- [ ] Settle down the algorithm in a standalone format in a note
  - [ ] Create a comprehensive algorithm description document
  - [ ] Include step-by-step procedure for the recursive proof verification
  - [ ] Document data flow and transformations
  - [ ] Include examples and edge cases
  - [ ] Make it self-contained and understandable without code context

## Integration and Comparison

### 6. Query Points Implementation
- [ ] Use the previous implementation that obtains query points
  - [ ] Review `QueryPositionsPerLogSizeVar::new()` in `primitives/src/query.rs`
  - [ ] Integrate query point computation into the recursive verification flow
  - [ ] Ensure compatibility with existing FRI answer computation
  - [ ] Test query point generation matches expected format

### 7. FRI Answers Comparison
- [ ] Compare the FRI answers result
  - [ ] Review FRI answer computation in `components/recursive/answer/src/lib.rs`
  - [ ] Review comparison logic in `components/recursive/folding/src/lib.rs` (lines 35-54)
  - [ ] Implement or verify FRI answer comparison between computed and expected values
  - [ ] Ensure proper constraint system checks for FRI answer equality
  - [ ] Add tests to validate FRI answer consistency
