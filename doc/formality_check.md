# Cairo proof formality checks

The `check_claim` function in the Cairo-to-Plonk verifier performs the following formality checks on the Cairo proof claim. 

Note that, however, it does not perform the check that the program must have [certain entries](https://github.com/Ztarknet-recursion/stwo-cairo-fork/blob/main/stwo_cairo_prover/crates/cairo-air/src/verifier.rs#L200) because the program has already been treated as a known, hardcoded, and trusted constant in the circuit.

```rust
    // First instruction: add_app_immediate (n_builtins).
    let n_builtins = public_segments.present_segments().len() as u32;
    assert_eq!(program[0].1, [0x7fff7fff, 0x4078001, 0, 0, 0, 0, 0, 0]); // add_ap_imm.
    assert_eq!(program[1].1, [n_builtins, 0, 0, 0, 0, 0, 0, 0]); // Imm.

    // Safe call.
    assert_eq!(program[2].1, [0x80018000, 0x11048001, 0, 0, 0, 0, 0, 0]); // Instruction: call rel ?
    assert_eq!(program[4].1, [0x7fff7fff, 0x1078001, 0, 0, 0, 0, 0, 0]); // Instruction: jmp rel 0.
    assert_eq!(program[5].1, [0, 0, 0, 0, 0, 0, 0, 0]); // Imm of last instruction (jmp rel 0).
```

### Builtin segments

The only optional builtin that we used is range_check_128, and the remaining builtins are not used. Their segments are empty (start_ptr = end_ptr): `pedersen`, `ecdsa`, `bitwise`, `ec_op`, `keccak`, `poseidon`, `range_check_96`, `add_mod`, `mul_mod`.

### Output builtin segment

The memory segment range must be sensible: start_ptr <= stop_ptr.

### Range check 128 builtin segment

- **Segment start consistency**: `start_ptr == range_check_builtin_segment_start`
- **Segment validity**: `start_ptr <= stop_ptr`
- **Segment bounds**: `stop_ptr <= segment_end` where `segment_end = segment_start + 2^range_check_128_builtin_log_size`

### Initial state checks

- **Initial program counter**: `initial_pc == 1`
- **Initial allocation pointer**: `initial_ap >= 4` (ensures `initial_pc + 2 < initial_ap`)
- **Frame pointer consistency**: `initial_fp == final_fp` (frame pointer must remain constant)
- **Frame pointer initialization**: `initial_fp == initial_ap` (frame pointer equals allocation pointer at start)

### Final state checks

- **Final program counter**: `final_pc == 5`
- **Memory growth**: `initial_ap <= final_ap` (allocation pointer can only grow, never shrink)

### Memory and relation checks

- **Relation uses**: Accumulates all relation uses from the claim and, *during this process*, checks that the relation uses do not overflow the field prime by using [add_assert_no_overflow](primitives/src/m31.rs)
- **Memory ID overflow**: Ensures that the largest memory ID `(2^big_log_size - 1) + LARGE_MEMORY_VALUE_ID_BASE` does not overflow the field prime
