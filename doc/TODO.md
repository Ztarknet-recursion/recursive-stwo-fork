# TODO

## Incomplete Implementations

### check_claim in cairo-components/recursive/fiat_shamir/src/lib.rs
The `check_claim` implementation is not complete and needs to be finished.

### CairoInteractionClaimVar in progress
`CairoInteractionClaimVar` is in progress. Adding things from `CairoInteractionClaim`, starting with `OpcodeInteractionClaim` in `air.rs` (lines 637-638).

### Lookup sum for public memory
To finish the lookup sum for public memory, need to start with a function that calculates the sum and sum them up, starting with the program, and then the rest.

### Consistency test for claim.mix_into(channel)
Add a consistency test for `claim.mix_into(channel)` that is currently expanded out in the code at `cairo-components/hints/src/fiat_shamir.rs` (lines 155-222).

### Output compression
Experiment and get output compression to work.

## Breaking Changes Needed

### Poseidon31MerkleHasher breaking change
A breaking change is needed to `Poseidon31MerkleHasher` to make it easy to handle the merkle tree proof. Need to regenerate proofs after implementing this change.

