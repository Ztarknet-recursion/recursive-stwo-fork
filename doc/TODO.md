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

### Preprocessed column indices
- [ ] Study the preprocessed column indices for Cairo components
  - Need to understand how `preprocessed_column_indices()` works for different components
  - Investigate what these indices represent and how they're used in the constraint evaluation

preprocessed columns:

blake_compress_opcode (1)
- Seq self.log_size()

memory_address_to_id (1)
- Seq self.log_size()

memory_id_to_big big (1)
- Seq self.log_size()   

memory_id_to_big small (1)
- Seq self.log_size()

blake_round_sigma (17)
- Seq4
- blake sigma 0-15 

range_check_3_3_3_3_3 (5)
- range_check_3_3_3_3_3_column_0-4

range_check_3_6_6_3 (4)
- range_check_3_6_6_3_column_0-3

range_check_4_3 (2)
- range_check_4_3_column_0-1

range_check_4_4_4_4 (4)
- range_check_4_4_4_4_column_0-3

range_check_4_4 (2)
- range_check_4_4_column_0-1

range_check_5_4 (2)
- range_check_5_4_column_0-1

range_check_6 (1)
- seq6

range_check_7_2_5 (3)
- range_check_7_2_5_column_0-2

range_check_8 (1)
- seq8

range_check_9_9 (2)
- range_check_9_9_column_0-1

range_check_9_9_b (2)
- range_check_9_9_b_column_0-1

range_check_9_9_c (2)
- range_check_9_9_c_column_0-1

range_check_9_9_d (2)
- range_check_9_9_d_column_0-1

range_check_9_9_e (2)
- range_check_9_9_e_column_0-1

range_check_9_9_f (2)
- range_check_9_9_f_column_0-1

range_check_9_9_g (2)
- range_check_9_9_g_column_0-1

range_check_9_9_h (2)
- range_check_9_9_h_column_0-1

range_check_11 (1)
- seq11

range_check_12 (1)
- seq12

range_check_18 (1)
- seq18

range_check_18_b (1)
- seq18

range_check_20 (4)
- seq20

range_check_20_b (4)
- seq20

range_check_20_c (4)
- seq20

range_check_20_d (4)
- seq20

range_check_20_e (4)
- seq20

range_check_20_f (4)
- seq20

range_check_20_g (4)
- seq20

range_check_20_h (4)
- seq20

range_check_builtin_bits_128 (1)
- seq self.log_size()

verify_bitwise_xor_4(3) 
- bitwise_xor_4_0-2

verify_bitwise_xor_7(3)
- bitwise_xor_7_0-2

verify_bitwise_xor_8(3)
- bitwise_xor_8_0-2

verify_bitwise_xor_8_b(3)
- bitwise_xor_8_b_0-2

verify_bitwise_xor_9(3)
- bitwise_xor_9_0-26

verify_bitwise_xor_12(3)
- bitwise_xor_12_0-2
