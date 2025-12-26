## Progress (ongoing)

This document tracks **current progress and assumptions** for the work in `cairo-components/`.

## Scope

- **Primary focus**: `cairo-components/` (Cairo-focused components + recursive verifier work).
- **In particular**: `cairo-components/hints/` as an executable “reference verifier” that derives deterministic values used by the Cairo/recursive side.

## Key assumptions (current, intentionally restrictive)

This project currently targets a *narrow* Cairo proof shape. Many checks are enforced as hard assertions, and the code often indexes `[0]` into component arrays, so these constraints are not “nice-to-have”; they are required for correctness with the current implementation.

### AIR/component inventory assumptions (which Cairo components exist, and how many)

In `cairo-components/hints/src/fiat_shamir.rs`, `CairoFiatShamirHints::verify_claim()` enforces:

- **Builtins**
  - `range_check_128` is the **only builtin we expect to be active** (present and non-empty segment), and the claim must contain `range_check_128_builtin`.
  - Other builtins (pedersen, bitwise, poseidon, range_check_96, add_mod, mul_mod) are treated as **not implemented / must not appear in the claim**, even though their segment ranges are expected to exist and be empty.
  - Concretely, the code asserts:
    - `segment_ranges.*.is_some()` for many builtins, but also `segment_ranges.*.is_empty()` for all of them except `range_check_128`.
    - `claim.builtins.range_check_128_builtin.is_some()`.
    - `claim.builtins.{pedersen,bitwise,poseidon,range_check_96,add_mod,mul_mod}_builtin.is_none()`.

- **Opcodes (cardinality)**
  - The code forces a **specific opcode “shape”** with exact counts, e.g.:
    - `claim.opcodes.add.len() == 1`
    - `claim.opcodes.generic.len() == 0`
    - (and similar `== 1` / `== 0` constraints for many opcode categories)
  - This matches how later code is written: downstream logic often uses `component_generator.opcodes.<opcode>[0]`, which implicitly assumes **exactly one** component instance for each enabled opcode type (see `cairo-components/hints/src/composition.rs`).

### Proof/PCS/FRI shape assumptions

In `cairo-components/hints/src/fiat_shamir.rs`, `CairoFiatShamirHints::new()` enforces:

- **FRI last layer**
  - `last_layer_poly` must be a single constant:
    - `proof.stark_proof.fri_proof.last_layer_poly.coeffs.len() == 1`
    - `log_last_layer_degree_bound == 0`
- **FRI blowup**
  - `log_blowup_factor == 1`
- **PoW**
  - `pow_bits == 26` (and interaction PoW checked with `INTERACTION_POW_BITS`)

These constraints are currently “baked in” to match the recursive verifier work-in-progress, and will need to be relaxed for general Cairo proofs.

### Commitment tree ordering assumptions

Across the hints code, the proof is treated as having **four commitment trees** in a fixed order:

- `commitments[0]`: preprocessed
- `commitments[1]`: original trace
- `commitments[2]`: interaction trace
- `commitments[3]` (aka `commitments.last()`): composition polynomial

Related assumptions:

- A **preprocessed trace exists** at `PREPROCESSED_TRACE_IDX` and is currently fixed to:
  - `PreProcessedTraceVariant::CanonicalWithoutPedersen`
- `n_preprocessed_columns` is derived from the verifier’s preprocessed commitment tree:
  - `commitment_scheme_verifier.trees[PREPROCESSED_TRACE_IDX].column_log_sizes.len()`

### “Components” (STWO `Components`) construction assumptions

The hints code constructs a STWO `Components` object from Cairo AIR components:

- `component_generator.components()` is used as the canonical list of AIR components.
- `Components { components: ..., n_preprocessed_columns }` is then used to:
  - Derive `composition_log_size` (via `composition_log_degree_bound()`).
  - Derive mask sample points (via `mask_points(oods_point)`), with an extra final “composition mask” layer appended manually.

## Main challenge: supporting multiple log sizes in a single circuit

In production, different Cairo components (and different proof instances) may have different `log_size`s. The goal is a **single recursive circuit** that can verify proofs across that variability, rather than compiling one circuit per shape.

The key constraint is that the circuit must work for `log_size` in a known range:

- **Lower bound**: `LOG_N_LANES` (SIMD lane lower bound).
- **Upper bound**: `MAX_SEQUENCE_LOG_SIZE` (upper bound baked into the preprocessed trace).

The core technique used throughout `cairo-components/recursive/` is:

- Allocate for the **maximum** shape (up to `MAX_SEQUENCE_LOG_SIZE`), then
- Use **oblivious / conditional selection** (bit-controlled muxes) to “activate” only the parts that are semantically present for the current proof instance.

### Common patterns used in `cairo-components/recursive/`

- **`LogSizeVar` + one-hot/bitmap selection**
  - A runtime `log_size` is represented as a variable plus a bitmap so the circuit can iterate over a fixed range and select the correct branch with `*_Var::select(...)`.
  - Example usage: `cairo-components/recursive/decommitment/src/utils.rs` (`ColumnsHasherVar::update`) selects the active per-log-size accumulator using `log_size.bitmap`.
- **Oblivious map selection (`ObliviousMapVar`)**
  - Used to select precomputed constants/points keyed by log size without branching.
  - Example: `cairo-components/recursive/answer/src/lib.rs` builds shifted points for all `i in LOG_N_LANES..=MAX_SEQUENCE_LOG_SIZE` and selects via `ObliviousMapVar::select(...)`.
- **Optional values (`OptionVar`)**
  - Used when some values may not exist for smaller log sizes (presence is carried by a bit, value is still allocated).
  - Example: preprocessed trace sampled-values are exposed via `OptionVar<QM31Var>` in `cairo-components/recursive/answer/src/data_structures/preprocessed.rs`.

### Fiat–Shamir impact: skipping absent sampled values / commitments

Two concrete issues that require “variable-log-size aware” Fiat–Shamir:

- **Preprocessed sampled values may not be present**
  - `StarkProofVar` encodes the preprocessed round (`sampled_values[0]`) so that each column is either:
    - A single evaluation (present), or
    - An empty column (absent), represented by a dummy zero plus a `false` presence bit.
  - See: `cairo-components/recursive/data_structures/src/stark_proof.rs` (`is_preprocessed_trace_present`).
  - The recursive Fiat–Shamir then hashes sampled values into the channel using a conditional mixer:
    - See: `cairo-components/recursive/fiat_shamir/src/lib.rs` (`ConditionalChannelMixer::mix(..., is_preprocessed_trace_present)`).

- **FRI inner layers depend on the maximal log size**
  - The recursive Fiat–Shamir loops over all possible inner layers up to `MAX_SEQUENCE_LOG_SIZE`, but conditionally “skips” layers above the current `max_log_size` by restoring the previous digest using `QM31Var::select`.
  - See: `cairo-components/recursive/fiat_shamir/src/lib.rs` (the `num_layers_to_skip` / `skip` logic).

Additionally, query generation is made shape-stable by masking query bits above the effective `query_log_size`:

- See: `cairo-components/recursive/fiat_shamir/src/lib.rs` (builds a `mask: Vec<BitVar>` and ANDs it into query bit-vectors).

### Decommitment impact: computing column hashes without fixing component log sizes

Merkle decommitment verification needs per-layer hashing that depends on whether a “column hash” exists at that layer. Because log sizes vary, the circuit can’t hardcode a single per-layer “has column” schedule.

Two key building blocks are used:

- **Oblivious per-log-size column hashing**
  - `cairo-components/recursive/decommitment/src/utils.rs` defines `ColumnsHasherVar` / `ColumnsHasherQM31Var`, which maintain a hash accumulator for every candidate log size in `[LOG_N_LANES..=MAX_SEQUENCE_LOG_SIZE]`.
  - The circuit selects which accumulator to update using `log_size.bitmap`, updates it, and writes it back with conditional selection—so the constraint system doesn’t depend on the actual `log_size`.
  - Finalization returns `IndexMap<usize, OptionVar<Poseidon2HalfVar>>`, i.e. each candidate hash is accompanied by an `is_some` bit.

- **Conditional incorporation of column hashes during Merkle path verification**
  - `QueryDecommitmentProofVar::verify` (`cairo-components/recursive/decommitment/src/data_structures.rs`) computes `expected_hash` bottom-up, and conditionally chooses:
    - “hash-without-column” vs “hash-with-column” using `OptionVar.is_some`, and
    - Whether a layer is constrained at all using `max_tree_log_size` / `max_included_log_size` comparisons.

This is the same overarching principle as Fiat–Shamir’s “skip absent sampled values”: allocate the maximum structure, then use bits to ensure only the semantically-present parts constrain the proof.

## What’s implemented (high level)

- **Fiat–Shamir transcript replay for Cairo proofs**: `cairo-components/hints/src/fiat_shamir.rs`
  - Replays transcript mixing of claim/public memory + commitments, draws interaction elements, commits interaction trace, commits composition, samples OODS, derives mask points and FRI query positions.
- **Composition OODS evaluation cross-check**: `cairo-components/hints/src/composition.rs`
  - Evaluates constraint quotients for the selected component set and checks it matches `Components::eval_composition_polynomial_at_point(...)`.

## Open items / next steps

- Relax “component inventory” assumptions (builtins/opcodes) to support more general Cairo proofs.
- Remove debug prints from hints (`println!`) once stabilized, or gate them behind a feature flag.
- Implement/port folding + decommitment logic for Cairo proofs on the hints side (see `doc/TODO.md`).

