# TODO

## FRI Verifier - Degree Bounds

### Check degree bounds
- [ ] Get the degree bounds and check what the degree bounds are
  - This impacts whether we need to implement `FriVerifier` in a way that works with multiple degree bounds
  - Need to understand if different parts of the proof use different degree bounds
  - Determine if a single-degree or multi-degree FRI verifier implementation is required

## Cairo Components Analysis

### Analyze log_size dependencies
- [ ] Analyze how many cairo components may be dependent on log_size and make a list
  - Components that use log_size in generating constraints:
    - [x] `blake_compress_opcode` (as `pub blake: Vec<blake_compress_opcode::Component>`)
    - [x] `memory_address_to_id`
    - [x] `memory_id_to_big` (big)
    - [x] `memory_id_to_big` (small)
    - [x] `range_check_128_builtin`

### LogupAtRowVar log_size refactoring
- [ ] Change `LogupAtRowVar` to use a variable for `log_size` instead of a constant (`u32`)
  - Currently `log_size` is a constant parameter, but this would not work for Cairo
  - Need to refactor to use a variable type instead

