## Description of ConditionalChannelMixer

`ConditionalChannelMixer`, implemented in [channel.rs](../primitives/src/channel.rs), is a primitive that conditionally and obliviously mixes QM31 elements into the channel. It allows the circuit to conditionally include or skip values in the channel hash computation without revealing which values were skipped, making the Fiat-Shamir transform independent of whether some "Seq" preprocessed trace columns are used.

### Algorithm overview

The `mix` method takes:
- `felt: &[QM31Var]` - an array of values to potentially mix
- `bits: &[BitVar]` - a corresponding array of condition bits (true = include, false = skip), which are expected to be shorter than `felt`

The algorithm uses three input buffers to accumulate values and performs Poseidon2 permutations every two iterations:

1. **Main loop** (processes `felt` and `bits` in parallel):
   - Maintains three input buffers: `input_1`, `input_2`, and `input_3`
   - Tracks occupancy of each buffer with `is_input_1_occupied`, `is_input_2_occupied`, and `is_input_3_occupied`
   - Maintains a `count` that increments for each processed value
   - For each `(felt, bit)` pair:
     - If `bit` is false: skip this value (no operation)
     - If `bit` is true:
       - Writes `felt` to the first unoccupied buffer (priority: `input_1` → `input_2` → `input_3`)
       - Updates the corresponding occupancy flag
   - Every 2 iterations (when `count % 2 == 0`):
     - If `input_2` is occupied, performs a Poseidon2 permutation with `input_1` and `input_2`
     - Moves `input_3` to `input_1` and clears `input_2` and `input_3` if a permutation occurred

2. **Remaining values** (when `felt.len() > bits.len()`):
   - Processes any extra `felt` values that don't have corresponding `bits`
   - Uses the same three-buffer strategy, writing to the first unoccupied buffer
   - Continues to perform permutations every 2 iterations

3. **Final flush**:
   - If `input_1` is occupied, performs a final permutation with `input_1` and `input_2_or_default`, where `input_2_or_default` is `input_2` if `input_2` is occupied, otherwise zero