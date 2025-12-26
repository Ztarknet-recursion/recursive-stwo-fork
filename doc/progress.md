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

## What’s implemented (high level)

- **Fiat–Shamir transcript replay for Cairo proofs**: `cairo-components/hints/src/fiat_shamir.rs`
  - Replays transcript mixing of claim/public memory + commitments, draws interaction elements, commits interaction trace, commits composition, samples OODS, derives mask points and FRI query positions.
- **Composition OODS evaluation cross-check**: `cairo-components/hints/src/composition.rs`
  - Evaluates constraint quotients for the selected component set and checks it matches `Components::eval_composition_polynomial_at_point(...)`.

## Open items / next steps

- Relax “component inventory” assumptions (builtins/opcodes) to support more general Cairo proofs.
- Remove debug prints from hints (`println!`) once stabilized, or gate them behind a feature flag.
- Implement/port folding + decommitment logic for Cairo proofs on the hints side (see `doc/TODO.md`).

