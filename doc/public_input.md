### Public input in a Cairo proof

The Cairo-to-Plonk verifier treats certain memory entries as public inputs by including them in the logup sum calculation, which ensures that the same values shown in the claim are used in the Cairo VM. 

To include public inputs, for each input, the code creates  memory address-to-id and id-to-value lookup entries for specific memory locations and adding their inverses to a logup sum. The final logup sum is computed as, which should be zero.

```
public_data.logup_sum() = public_memory.logup_sum() - initial_state.logup_sum() + final_state.logup_sum()
```

#### Public memory entries

The `public_memory.logup_sum()` function creates lookup entries for the following memory sections:

1. **Program constants** (addresses 1, 2, 3, ...):
   - Creates `memory_address_to_id` entries: `(address, id)` for each program constant
   - Creates `memory_id_to_value` entries: `(id, value)` where value is split into M31 limbs
   - Addresses start at 1 and increment by 1 for each constant

2. **Output section** (addresses starting at `final_ap`):
   - Creates `memory_address_to_id` entries: `(final_ap + offset, id)` for each output value
   - Creates `memory_id_to_value` entries: `(id, value)` where value is split into M31 limbs
   - The output section contains the Cairo program's return values

3. **Safe call IDs** (addresses `initial_ap - 2` and `initial_ap - 1`):
   - Creates `memory_address_to_id` entries for two special memory locations
   - At `initial_ap - 2`: stores `initial_ap` value (split into 4 M31 limbs) with `safe_call_ids[0]`
   - At `initial_ap - 1`: stores a single M31 value with `safe_call_ids[1]`

4. **Public segment ranges** (addresses `initial_ap + i` and `final_ap - (10 - i)` for each builtin):
   - For each of the 10 builtin segments (output, pedersen, range_check_128, ecdsa, bitwise, ec_op, keccak, poseidon, range_check_96, add_mod, mul_mod):
     - Creates `memory_address_to_id` entries for `start_ptr` and `stop_ptr` at computed addresses
     - Creates `memory_id_to_value` entries for `start_ptr` and `stop_ptr` values (each split into 4 M31 limbs)
   - These segment ranges define the memory boundaries for each builtin

#### Initial and final state entries

- **Initial state**: Creates an opcodes lookup entry `(initial_pc, initial_ap, initial_fp)` that is **subtracted** from the sum
- **Final state**: Creates an opcodes lookup entry `(final_pc, final_ap, final_fp)` that is **added** to the sum

