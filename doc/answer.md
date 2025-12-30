## Answer calculation

This document describes how FRI answers are computed in the Cairo-to-Plonk verifier. The answer calculation computes the values of the FRI polynomial at the queried points, which are later used to verify the FRI opening.

### Precomputation of domain points and denominator inverses

Before computing answers, the code precomputes domain points and denominator inverses for efficient lookup during answer calculation.

#### Domain points

For each log size from `LOG_N_LANES + 1` to `MAX_SEQUENCE_LOG_SIZE + 1`, the code computes the domain points for each query. These are the points on the circle where the FRI polynomial will be evaluated. The domain points are computed from the query positions using `get_next_point()` to advance to the next point in the coset.

```rust
let domain_points: IndexMap<u32, Vec<CirclePointM31Var>> = query_positions_var
    .points
    .iter()
    .map(|(k, v)| {
        let v = v.iter().map(|v| v.get_next_point()).collect_vec();
        (*k, v)
    })
    .collect();
```

#### Denominator inverses

For each domain point, the code precomputes the denominator inverse used in the FRI answer formula. The denominator inverse is computed as:

```
inv((prx - v.x) * piy - (pry - v.y) * pix)
```

where `(prx, pry)` and `(pix, piy)` are the real and imaginary parts of the OODS point, and `(v.x, v.y)` is the domain point. This precomputation avoids redundant calculations during answer accumulation.

```rust
let denominator_inverses_with_oods_point: IndexMap<u32, Vec<CM31Var>> = {
    domain_points
        .iter()
        .map(|(k, v)| {
            let v = v
                .iter()
                .map(|v| (&(&(&prx - &v.x) * &piy) - &(&(&pry - &v.y) * &pix)).inv())
                .collect_vec();
            (*k, v)
        })
        .collect()
};
```

These precomputed values are stored in maps indexed by log size, allowing efficient oblivious lookup during answer accumulation.

### Order of answer accumulator updates

The answer accumulators are updated in a specific order to follow the original Stwo protocol, where shift points are processed after the original OODS point evaluations:

1. **Preprocessed trace answers** - Computes answers for preprocessed trace columns at the OODS point
2. **Trace answers** - Computes answers for trace columns at the OODS point
3. **Interaction answers (without shift)** - Computes answers for interaction columns at the OODS point, but excludes the shifted point contributions
4. **Composition answers** - Computes answers for composition polynomial at the OODS point
5. **Interaction answers (shift only)** - Computes answers for interaction columns at the shifted points

This ordering ensures that all evaluations at the original OODS point are completed before processing the shifted points, which matches the original Stwo protocol structure.

### AnswerAccumulator design

`AnswerAccumulator` is designed to obliviously accumulate FRI answers for components with variable log sizes. It maintains a map of `(answer, multiplier)` pairs, one for each possible log size from `LOG_N_LANES` to `MAX_SEQUENCE_LOG_SIZE`.

#### Structure

Each entry in the map contains:
- **`answer: QM31Var`** - The accumulated answer value for that log size
- **`multiplier: QM31Var`** - A multiplier that tracks how many column results have been added (initialized to a special constant, then multiplied by `random_coeff` for each result)

#### Oblivious update

The `update` method takes a `LogSizeVar` and a list of column results, and obliviously updates only the accumulator for the actual log size:

1. Uses `log_size.bitmap` to obliviously select the current `(answer, multiplier)` pair from the map
2. For each column result, accumulates it into the answer: `answer = answer + result * multiplier`
3. Updates the multiplier: `multiplier = multiplier * random_coeff`
4. Obliviously writes the updated values back to the map (only the correct log size entry is updated)

This design allows a single component (which has one log size) to contribute multiple column results to the answer, while keeping the circuit oblivious to which log size is being used.

#### Handling multiple results per log size

Since each component has one log size but may have multiple columns (e.g., a component might have 5 trace columns), the accumulator processes all column results for a component in sequence. Each result is multiplied by the current multiplier and added to the answer, then the multiplier is advanced. 

#### Finalization

The `finalize` method determines which log sizes actually received results by checking if the multiplier has changed from its initial value:

```rust
let is_some = multiplier
    .is_eq(&QM31Var::new_constant(
        &answer.cs,
        &QM31::from_m31(M31::zero(), M31::zero(), M31::from(2).neg(), M31::zero()),
    ))
    .neg();
```

The initial multiplier is set to a special constant `(0, 0, -2, 0)` in QM31 representation. If the multiplier equals this initial value, it means no results were added for that log size, so `is_some = false`. Otherwise, `is_some = true` and the answer is returned as `Some(answer)`.

This approach allows the circuit to obliviously determine which log sizes have answers without revealing the actual log size values used.
