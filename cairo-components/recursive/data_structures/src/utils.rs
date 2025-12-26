use circle_plonk_dsl_primitives::{BitVar, BitsVar, M31Var};
use stwo_cairo_common::memory::N_M31_IN_FELT252;

use crate::BitIntVar;

pub fn split_f252_memory_var(value: &[BitIntVar<32>; 8]) -> [M31Var; N_M31_IN_FELT252] {
    let bits = value
        .iter()
        .flat_map(|v| v.bits.0.clone())
        .collect::<Vec<BitVar>>();

    let res: [M31Var; N_M31_IN_FELT252] = std::array::from_fn(|i| {
        let collection = BitsVar(bits[i * 9..(i + 1) * 9].to_vec());
        collection.compose()
    });

    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use circle_plonk_dsl_constraint_system::{var::AllocVar, ConstraintSystemRef};
    use circle_plonk_dsl_primitives::M31Var;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use stwo_cairo_common::prover_types::felt::split_f252;

    #[test]
    fn test_split_f252_memory_var_random() {
        let mut rng = ChaCha20Rng::seed_from_u64(0);

        let mut random_u32s = [0u32; 8];
        for val in random_u32s.iter_mut() {
            *val = rng.next_u32();
        }

        let cs = ConstraintSystemRef::new();
        let value_vars: [BitIntVar<32>; 8] =
            std::array::from_fn(|i| BitIntVar::<32>::new_witness(&cs, &(random_u32s[i] as u64)));

        let expected_result = split_f252(random_u32s);
        let result_vars = split_f252_memory_var(&value_vars);

        for (expected, result_var) in expected_result.iter().zip(result_vars.iter()) {
            result_var.equalverify(&M31Var::new_constant(&cs, expected));
        }

        cs.pad();
        cs.check_arithmetics();
    }
}
