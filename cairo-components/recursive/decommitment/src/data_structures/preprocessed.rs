use cairo_plonk_dsl_hints::PreprocessedTraceQueryResult;
use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::{
    option::OptionVar, M31Var, Poseidon2HalfVar, Poseidon31MerkleHasherVar,
};
use indexmap::IndexMap;

pub struct PreprocessedTraceQueryResultVar {
    pub cs: ConstraintSystemRef,
    pub seq_25: M31Var,
    pub seq_24: M31Var,
    pub seq_23: M31Var,
    pub seq_22: M31Var,
    pub seq_21: M31Var,
    pub seq_20: M31Var, /* used by range check 20, 20b, 20c, 20d, 20e, 20f, 20g, 20h */
    pub bitwise_xor_10_0: M31Var,
    pub bitwise_xor_10_1: M31Var,
    pub bitwise_xor_10_2: M31Var,
    pub seq_19: M31Var,
    pub seq_18: M31Var, /* used by range check 18, 18b */
    pub bitwise_xor_9_0: M31Var,
    pub bitwise_xor_9_1: M31Var,
    pub bitwise_xor_9_2: M31Var,
    pub range_check_9_9_column_0: M31Var,
    pub range_check_9_9_column_1: M31Var,
    pub range_check_3_6_6_3_column_0: M31Var,
    pub range_check_3_6_6_3_column_1: M31Var,
    pub range_check_3_6_6_3_column_2: M31Var,
    pub range_check_3_6_6_3_column_3: M31Var,
    pub seq_17: M31Var,
    pub seq_16: M31Var,
    pub bitwise_xor_8_0: M31Var,
    pub bitwise_xor_8_1: M31Var,
    pub bitwise_xor_8_2: M31Var,
    pub range_check_4_4_4_4_column_0: M31Var,
    pub range_check_4_4_4_4_column_1: M31Var,
    pub range_check_4_4_4_4_column_2: M31Var,
    pub range_check_4_4_4_4_column_3: M31Var,
    pub seq_15: M31Var,
    pub range_check_3_3_3_3_3_column_0: M31Var,
    pub range_check_3_3_3_3_3_column_1: M31Var,
    pub range_check_3_3_3_3_3_column_2: M31Var,
    pub range_check_3_3_3_3_3_column_3: M31Var,
    pub range_check_3_3_3_3_3_column_4: M31Var,
    pub seq_14: M31Var,
    pub bitwise_xor_7_0: M31Var,
    pub bitwise_xor_7_1: M31Var,
    pub bitwise_xor_7_2: M31Var,
    pub range_check_7_2_5_column_0: M31Var,
    pub range_check_7_2_5_column_1: M31Var,
    pub range_check_7_2_5_column_2: M31Var,
    pub seq_13: M31Var,
    pub seq_12: M31Var, /* used by range check 12 */
    pub seq_11: M31Var, /* used by range check 11 */
    pub seq_10: M31Var,
    pub seq_9: M31Var,
    pub range_check_5_4_column_0: M31Var,
    pub range_check_5_4_column_1: M31Var,
    pub seq_8: M31Var, /* used by range check 8 */
    pub bitwise_xor_4_0: M31Var,
    pub bitwise_xor_4_1: M31Var,
    pub bitwise_xor_4_2: M31Var,
    pub range_check_4_4_column_0: M31Var,
    pub range_check_4_4_column_1: M31Var,
    pub seq_7: M31Var,
    pub range_check_4_3_column_0: M31Var,
    pub range_check_4_3_column_1: M31Var,
    pub seq_6: M31Var, /* used by range check 6 */
    pub poseidon_round_keys_0: M31Var,
    pub poseidon_round_keys_1: M31Var,
    pub poseidon_round_keys_2: M31Var,
    pub poseidon_round_keys_3: M31Var,
    pub poseidon_round_keys_4: M31Var,
    pub poseidon_round_keys_5: M31Var,
    pub poseidon_round_keys_6: M31Var,
    pub poseidon_round_keys_7: M31Var,
    pub poseidon_round_keys_8: M31Var,
    pub poseidon_round_keys_9: M31Var,
    pub poseidon_round_keys_10: M31Var,
    pub poseidon_round_keys_11: M31Var,
    pub poseidon_round_keys_12: M31Var,
    pub poseidon_round_keys_13: M31Var,
    pub poseidon_round_keys_14: M31Var,
    pub poseidon_round_keys_15: M31Var,
    pub poseidon_round_keys_16: M31Var,
    pub poseidon_round_keys_17: M31Var,
    pub poseidon_round_keys_18: M31Var,
    pub poseidon_round_keys_19: M31Var,
    pub poseidon_round_keys_20: M31Var,
    pub poseidon_round_keys_21: M31Var,
    pub poseidon_round_keys_22: M31Var,
    pub poseidon_round_keys_23: M31Var,
    pub poseidon_round_keys_24: M31Var,
    pub poseidon_round_keys_25: M31Var,
    pub poseidon_round_keys_26: M31Var,
    pub poseidon_round_keys_27: M31Var,
    pub poseidon_round_keys_28: M31Var,
    pub poseidon_round_keys_29: M31Var,
    pub seq_5: M31Var,
    pub seq_4: M31Var, /* used by blake_round_sigma */
    pub blake_sigma_0: M31Var,
    pub blake_sigma_1: M31Var,
    pub blake_sigma_2: M31Var,
    pub blake_sigma_3: M31Var,
    pub blake_sigma_4: M31Var,
    pub blake_sigma_5: M31Var,
    pub blake_sigma_6: M31Var,
    pub blake_sigma_7: M31Var,
    pub blake_sigma_8: M31Var,
    pub blake_sigma_9: M31Var,
    pub blake_sigma_10: M31Var,
    pub blake_sigma_11: M31Var,
    pub blake_sigma_12: M31Var,
    pub blake_sigma_13: M31Var,
    pub blake_sigma_14: M31Var,
    pub blake_sigma_15: M31Var,
}

impl Var for PreprocessedTraceQueryResultVar {
    type Value = PreprocessedTraceQueryResult;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for PreprocessedTraceQueryResultVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let seq_25 = M31Var::new_variables(cs, &value.seq_25, mode);
        let seq_24 = M31Var::new_variables(cs, &value.seq_24, mode);
        let seq_23 = M31Var::new_variables(cs, &value.seq_23, mode);
        let seq_22 = M31Var::new_variables(cs, &value.seq_22, mode);
        let seq_21 = M31Var::new_variables(cs, &value.seq_21, mode);
        let seq_20 = M31Var::new_variables(cs, &value.seq_20, mode);
        let bitwise_xor_10_0 = M31Var::new_variables(cs, &value.bitwise_xor_10_0, mode);
        let bitwise_xor_10_1 = M31Var::new_variables(cs, &value.bitwise_xor_10_1, mode);
        let bitwise_xor_10_2 = M31Var::new_variables(cs, &value.bitwise_xor_10_2, mode);
        let seq_19 = M31Var::new_variables(cs, &value.seq_19, mode);
        let seq_18 = M31Var::new_variables(cs, &value.seq_18, mode);
        let bitwise_xor_9_0 = M31Var::new_variables(cs, &value.bitwise_xor_9_0, mode);
        let bitwise_xor_9_1 = M31Var::new_variables(cs, &value.bitwise_xor_9_1, mode);
        let bitwise_xor_9_2 = M31Var::new_variables(cs, &value.bitwise_xor_9_2, mode);
        let range_check_9_9_column_0 =
            M31Var::new_variables(cs, &value.range_check_9_9_column_0, mode);
        let range_check_9_9_column_1 =
            M31Var::new_variables(cs, &value.range_check_9_9_column_1, mode);
        let range_check_3_6_6_3_column_0 =
            M31Var::new_variables(cs, &value.range_check_3_6_6_3_column_0, mode);
        let range_check_3_6_6_3_column_1 =
            M31Var::new_variables(cs, &value.range_check_3_6_6_3_column_1, mode);
        let range_check_3_6_6_3_column_2 =
            M31Var::new_variables(cs, &value.range_check_3_6_6_3_column_2, mode);
        let range_check_3_6_6_3_column_3 =
            M31Var::new_variables(cs, &value.range_check_3_6_6_3_column_3, mode);
        let seq_17 = M31Var::new_variables(cs, &value.seq_17, mode);
        let seq_16 = M31Var::new_variables(cs, &value.seq_16, mode);
        let bitwise_xor_8_0 = M31Var::new_variables(cs, &value.bitwise_xor_8_0, mode);
        let bitwise_xor_8_1 = M31Var::new_variables(cs, &value.bitwise_xor_8_1, mode);
        let bitwise_xor_8_2 = M31Var::new_variables(cs, &value.bitwise_xor_8_2, mode);
        let range_check_4_4_4_4_column_0 =
            M31Var::new_variables(cs, &value.range_check_4_4_4_4_column_0, mode);
        let range_check_4_4_4_4_column_1 =
            M31Var::new_variables(cs, &value.range_check_4_4_4_4_column_1, mode);
        let range_check_4_4_4_4_column_2 =
            M31Var::new_variables(cs, &value.range_check_4_4_4_4_column_2, mode);
        let range_check_4_4_4_4_column_3 =
            M31Var::new_variables(cs, &value.range_check_4_4_4_4_column_3, mode);
        let seq_15 = M31Var::new_variables(cs, &value.seq_15, mode);
        let range_check_3_3_3_3_3_column_0 =
            M31Var::new_variables(cs, &value.range_check_3_3_3_3_3_column_0, mode);
        let range_check_3_3_3_3_3_column_1 =
            M31Var::new_variables(cs, &value.range_check_3_3_3_3_3_column_1, mode);
        let range_check_3_3_3_3_3_column_2 =
            M31Var::new_variables(cs, &value.range_check_3_3_3_3_3_column_2, mode);
        let range_check_3_3_3_3_3_column_3 =
            M31Var::new_variables(cs, &value.range_check_3_3_3_3_3_column_3, mode);
        let range_check_3_3_3_3_3_column_4 =
            M31Var::new_variables(cs, &value.range_check_3_3_3_3_3_column_4, mode);
        let seq_14 = M31Var::new_variables(cs, &value.seq_14, mode);
        let bitwise_xor_7_0 = M31Var::new_variables(cs, &value.bitwise_xor_7_0, mode);
        let bitwise_xor_7_1 = M31Var::new_variables(cs, &value.bitwise_xor_7_1, mode);
        let bitwise_xor_7_2 = M31Var::new_variables(cs, &value.bitwise_xor_7_2, mode);
        let range_check_7_2_5_column_0 =
            M31Var::new_variables(cs, &value.range_check_7_2_5_column_0, mode);
        let range_check_7_2_5_column_1 =
            M31Var::new_variables(cs, &value.range_check_7_2_5_column_1, mode);
        let range_check_7_2_5_column_2 =
            M31Var::new_variables(cs, &value.range_check_7_2_5_column_2, mode);
        let seq_13 = M31Var::new_variables(cs, &value.seq_13, mode);
        let seq_12 = M31Var::new_variables(cs, &value.seq_12, mode);
        let seq_11 = M31Var::new_variables(cs, &value.seq_11, mode);
        let seq_10 = M31Var::new_variables(cs, &value.seq_10, mode);
        let seq_9 = M31Var::new_variables(cs, &value.seq_9, mode);
        let range_check_5_4_column_0 =
            M31Var::new_variables(cs, &value.range_check_5_4_column_0, mode);
        let range_check_5_4_column_1 =
            M31Var::new_variables(cs, &value.range_check_5_4_column_1, mode);
        let seq_8 = M31Var::new_variables(cs, &value.seq_8, mode);
        let bitwise_xor_4_0 = M31Var::new_variables(cs, &value.bitwise_xor_4_0, mode);
        let bitwise_xor_4_1 = M31Var::new_variables(cs, &value.bitwise_xor_4_1, mode);
        let bitwise_xor_4_2 = M31Var::new_variables(cs, &value.bitwise_xor_4_2, mode);
        let range_check_4_4_column_0 =
            M31Var::new_variables(cs, &value.range_check_4_4_column_0, mode);
        let range_check_4_4_column_1 =
            M31Var::new_variables(cs, &value.range_check_4_4_column_1, mode);
        let seq_7 = M31Var::new_variables(cs, &value.seq_7, mode);
        let range_check_4_3_column_0 =
            M31Var::new_variables(cs, &value.range_check_4_3_column_0, mode);
        let range_check_4_3_column_1 =
            M31Var::new_variables(cs, &value.range_check_4_3_column_1, mode);
        let seq_6 = M31Var::new_variables(cs, &value.seq_6, mode);
        let poseidon_round_keys_0 = M31Var::new_variables(cs, &value.poseidon_round_keys_0, mode);
        let poseidon_round_keys_1 = M31Var::new_variables(cs, &value.poseidon_round_keys_1, mode);
        let poseidon_round_keys_2 = M31Var::new_variables(cs, &value.poseidon_round_keys_2, mode);
        let poseidon_round_keys_3 = M31Var::new_variables(cs, &value.poseidon_round_keys_3, mode);
        let poseidon_round_keys_4 = M31Var::new_variables(cs, &value.poseidon_round_keys_4, mode);
        let poseidon_round_keys_5 = M31Var::new_variables(cs, &value.poseidon_round_keys_5, mode);
        let poseidon_round_keys_6 = M31Var::new_variables(cs, &value.poseidon_round_keys_6, mode);
        let poseidon_round_keys_7 = M31Var::new_variables(cs, &value.poseidon_round_keys_7, mode);
        let poseidon_round_keys_8 = M31Var::new_variables(cs, &value.poseidon_round_keys_8, mode);
        let poseidon_round_keys_9 = M31Var::new_variables(cs, &value.poseidon_round_keys_9, mode);
        let poseidon_round_keys_10 = M31Var::new_variables(cs, &value.poseidon_round_keys_10, mode);
        let poseidon_round_keys_11 = M31Var::new_variables(cs, &value.poseidon_round_keys_11, mode);
        let poseidon_round_keys_12 = M31Var::new_variables(cs, &value.poseidon_round_keys_12, mode);
        let poseidon_round_keys_13 = M31Var::new_variables(cs, &value.poseidon_round_keys_13, mode);
        let poseidon_round_keys_14 = M31Var::new_variables(cs, &value.poseidon_round_keys_14, mode);
        let poseidon_round_keys_15 = M31Var::new_variables(cs, &value.poseidon_round_keys_15, mode);
        let poseidon_round_keys_16 = M31Var::new_variables(cs, &value.poseidon_round_keys_16, mode);
        let poseidon_round_keys_17 = M31Var::new_variables(cs, &value.poseidon_round_keys_17, mode);
        let poseidon_round_keys_18 = M31Var::new_variables(cs, &value.poseidon_round_keys_18, mode);
        let poseidon_round_keys_19 = M31Var::new_variables(cs, &value.poseidon_round_keys_19, mode);
        let poseidon_round_keys_20 = M31Var::new_variables(cs, &value.poseidon_round_keys_20, mode);
        let poseidon_round_keys_21 = M31Var::new_variables(cs, &value.poseidon_round_keys_21, mode);
        let poseidon_round_keys_22 = M31Var::new_variables(cs, &value.poseidon_round_keys_22, mode);
        let poseidon_round_keys_23 = M31Var::new_variables(cs, &value.poseidon_round_keys_23, mode);
        let poseidon_round_keys_24 = M31Var::new_variables(cs, &value.poseidon_round_keys_24, mode);
        let poseidon_round_keys_25 = M31Var::new_variables(cs, &value.poseidon_round_keys_25, mode);
        let poseidon_round_keys_26 = M31Var::new_variables(cs, &value.poseidon_round_keys_26, mode);
        let poseidon_round_keys_27 = M31Var::new_variables(cs, &value.poseidon_round_keys_27, mode);
        let poseidon_round_keys_28 = M31Var::new_variables(cs, &value.poseidon_round_keys_28, mode);
        let poseidon_round_keys_29 = M31Var::new_variables(cs, &value.poseidon_round_keys_29, mode);
        let seq_5 = M31Var::new_variables(cs, &value.seq_5, mode);
        let seq_4 = M31Var::new_variables(cs, &value.seq_4, mode);
        let blake_sigma_0 = M31Var::new_variables(cs, &value.blake_sigma_0, mode);
        let blake_sigma_1 = M31Var::new_variables(cs, &value.blake_sigma_1, mode);
        let blake_sigma_2 = M31Var::new_variables(cs, &value.blake_sigma_2, mode);
        let blake_sigma_3 = M31Var::new_variables(cs, &value.blake_sigma_3, mode);
        let blake_sigma_4 = M31Var::new_variables(cs, &value.blake_sigma_4, mode);
        let blake_sigma_5 = M31Var::new_variables(cs, &value.blake_sigma_5, mode);
        let blake_sigma_6 = M31Var::new_variables(cs, &value.blake_sigma_6, mode);
        let blake_sigma_7 = M31Var::new_variables(cs, &value.blake_sigma_7, mode);
        let blake_sigma_8 = M31Var::new_variables(cs, &value.blake_sigma_8, mode);
        let blake_sigma_9 = M31Var::new_variables(cs, &value.blake_sigma_9, mode);
        let blake_sigma_10 = M31Var::new_variables(cs, &value.blake_sigma_10, mode);
        let blake_sigma_11 = M31Var::new_variables(cs, &value.blake_sigma_11, mode);
        let blake_sigma_12 = M31Var::new_variables(cs, &value.blake_sigma_12, mode);
        let blake_sigma_13 = M31Var::new_variables(cs, &value.blake_sigma_13, mode);
        let blake_sigma_14 = M31Var::new_variables(cs, &value.blake_sigma_14, mode);
        let blake_sigma_15 = M31Var::new_variables(cs, &value.blake_sigma_15, mode);

        Self {
            cs: cs.clone(),
            seq_25,
            seq_24,
            seq_23,
            seq_22,
            seq_21,
            seq_20,
            bitwise_xor_10_0,
            bitwise_xor_10_1,
            bitwise_xor_10_2,
            seq_19,
            seq_18,
            bitwise_xor_9_0,
            bitwise_xor_9_1,
            bitwise_xor_9_2,
            range_check_9_9_column_0,
            range_check_9_9_column_1,
            range_check_3_6_6_3_column_0,
            range_check_3_6_6_3_column_1,
            range_check_3_6_6_3_column_2,
            range_check_3_6_6_3_column_3,
            seq_17,
            seq_16,
            bitwise_xor_8_0,
            bitwise_xor_8_1,
            bitwise_xor_8_2,
            range_check_4_4_4_4_column_0,
            range_check_4_4_4_4_column_1,
            range_check_4_4_4_4_column_2,
            range_check_4_4_4_4_column_3,
            seq_15,
            range_check_3_3_3_3_3_column_0,
            range_check_3_3_3_3_3_column_1,
            range_check_3_3_3_3_3_column_2,
            range_check_3_3_3_3_3_column_3,
            range_check_3_3_3_3_3_column_4,
            seq_14,
            bitwise_xor_7_0,
            bitwise_xor_7_1,
            bitwise_xor_7_2,
            range_check_7_2_5_column_0,
            range_check_7_2_5_column_1,
            range_check_7_2_5_column_2,
            seq_13,
            seq_12,
            seq_11,
            seq_10,
            seq_9,
            range_check_5_4_column_0,
            range_check_5_4_column_1,
            seq_8,
            bitwise_xor_4_0,
            bitwise_xor_4_1,
            bitwise_xor_4_2,
            range_check_4_4_column_0,
            range_check_4_4_column_1,
            seq_7,
            range_check_4_3_column_0,
            range_check_4_3_column_1,
            seq_6,
            poseidon_round_keys_0,
            poseidon_round_keys_1,
            poseidon_round_keys_2,
            poseidon_round_keys_3,
            poseidon_round_keys_4,
            poseidon_round_keys_5,
            poseidon_round_keys_6,
            poseidon_round_keys_7,
            poseidon_round_keys_8,
            poseidon_round_keys_9,
            poseidon_round_keys_10,
            poseidon_round_keys_11,
            poseidon_round_keys_12,
            poseidon_round_keys_13,
            poseidon_round_keys_14,
            poseidon_round_keys_15,
            poseidon_round_keys_16,
            poseidon_round_keys_17,
            poseidon_round_keys_18,
            poseidon_round_keys_19,
            poseidon_round_keys_20,
            poseidon_round_keys_21,
            poseidon_round_keys_22,
            poseidon_round_keys_23,
            poseidon_round_keys_24,
            poseidon_round_keys_25,
            poseidon_round_keys_26,
            poseidon_round_keys_27,
            poseidon_round_keys_28,
            poseidon_round_keys_29,
            seq_5,
            seq_4,
            blake_sigma_0,
            blake_sigma_1,
            blake_sigma_2,
            blake_sigma_3,
            blake_sigma_4,
            blake_sigma_5,
            blake_sigma_6,
            blake_sigma_7,
            blake_sigma_8,
            blake_sigma_9,
            blake_sigma_10,
            blake_sigma_11,
            blake_sigma_12,
            blake_sigma_13,
            blake_sigma_14,
            blake_sigma_15,
        }
    }
}

impl PreprocessedTraceQueryResultVar {
    pub fn compute_column_hashes(&self) -> IndexMap<usize, OptionVar<Poseidon2HalfVar>> {
        let mut map = IndexMap::new();
        map.insert(
            25,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[self.seq_25.clone()]),
        );
        map.insert(
            24,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[self.seq_24.clone()]),
        );
        map.insert(
            23,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[self.seq_23.clone()]),
        );
        map.insert(
            22,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[self.seq_22.clone()]),
        );
        map.insert(
            21,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[self.seq_21.clone()]),
        );
        map.insert(
            20,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[
                self.seq_20.clone(),
                self.bitwise_xor_10_0.clone(),
                self.bitwise_xor_10_1.clone(),
                self.bitwise_xor_10_2.clone(),
            ]),
        );
        map.insert(
            19,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[self.seq_19.clone()]),
        );
        map.insert(
            18,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[
                self.seq_18.clone(),
                self.bitwise_xor_9_0.clone(),
                self.bitwise_xor_9_1.clone(),
                self.bitwise_xor_9_2.clone(),
                self.range_check_9_9_column_0.clone(),
                self.range_check_9_9_column_1.clone(),
                self.range_check_3_6_6_3_column_0.clone(),
                self.range_check_3_6_6_3_column_1.clone(),
                self.range_check_3_6_6_3_column_2.clone(),
                self.range_check_3_6_6_3_column_3.clone(),
            ]),
        );
        map.insert(
            17,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[self.seq_17.clone()]),
        );
        map.insert(
            16,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[
                self.seq_16.clone(),
                self.bitwise_xor_8_0.clone(),
                self.bitwise_xor_8_1.clone(),
                self.bitwise_xor_8_2.clone(),
                self.range_check_4_4_4_4_column_0.clone(),
                self.range_check_4_4_4_4_column_1.clone(),
                self.range_check_4_4_4_4_column_2.clone(),
                self.range_check_4_4_4_4_column_3.clone(),
            ]),
        );
        map.insert(
            15,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[
                self.seq_15.clone(),
                self.range_check_3_3_3_3_3_column_0.clone(),
                self.range_check_3_3_3_3_3_column_1.clone(),
                self.range_check_3_3_3_3_3_column_2.clone(),
                self.range_check_3_3_3_3_3_column_3.clone(),
                self.range_check_3_3_3_3_3_column_4.clone(),
            ]),
        );
        map.insert(
            14,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[
                self.seq_14.clone(),
                self.bitwise_xor_7_0.clone(),
                self.bitwise_xor_7_1.clone(),
                self.bitwise_xor_7_2.clone(),
                self.range_check_7_2_5_column_0.clone(),
                self.range_check_7_2_5_column_1.clone(),
                self.range_check_7_2_5_column_2.clone(),
            ]),
        );
        map.insert(
            13,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[self.seq_13.clone()]),
        );
        map.insert(
            12,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[self.seq_12.clone()]),
        );
        map.insert(
            11,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[self.seq_11.clone()]),
        );
        map.insert(
            10,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[self.seq_10.clone()]),
        );
        map.insert(
            9,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[
                self.seq_9.clone(),
                self.range_check_5_4_column_0.clone(),
                self.range_check_5_4_column_1.clone(),
            ]),
        );
        map.insert(
            8,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[
                self.seq_8.clone(),
                self.bitwise_xor_4_0.clone(),
                self.bitwise_xor_4_1.clone(),
                self.bitwise_xor_4_2.clone(),
                self.range_check_4_4_column_0.clone(),
                self.range_check_4_4_column_1.clone(),
            ]),
        );
        map.insert(
            7,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[
                self.seq_7.clone(),
                self.range_check_4_3_column_0.clone(),
                self.range_check_4_3_column_1.clone(),
            ]),
        );
        map.insert(
            6,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[
                self.seq_6.clone(),
                self.poseidon_round_keys_0.clone(),
                self.poseidon_round_keys_1.clone(),
                self.poseidon_round_keys_2.clone(),
                self.poseidon_round_keys_3.clone(),
                self.poseidon_round_keys_4.clone(),
                self.poseidon_round_keys_5.clone(),
                self.poseidon_round_keys_6.clone(),
                self.poseidon_round_keys_7.clone(),
                self.poseidon_round_keys_8.clone(),
                self.poseidon_round_keys_9.clone(),
                self.poseidon_round_keys_10.clone(),
                self.poseidon_round_keys_11.clone(),
                self.poseidon_round_keys_12.clone(),
                self.poseidon_round_keys_13.clone(),
                self.poseidon_round_keys_14.clone(),
                self.poseidon_round_keys_15.clone(),
                self.poseidon_round_keys_16.clone(),
                self.poseidon_round_keys_17.clone(),
                self.poseidon_round_keys_18.clone(),
                self.poseidon_round_keys_19.clone(),
                self.poseidon_round_keys_20.clone(),
                self.poseidon_round_keys_21.clone(),
                self.poseidon_round_keys_22.clone(),
                self.poseidon_round_keys_23.clone(),
                self.poseidon_round_keys_24.clone(),
                self.poseidon_round_keys_25.clone(),
                self.poseidon_round_keys_26.clone(),
                self.poseidon_round_keys_27.clone(),
                self.poseidon_round_keys_28.clone(),
                self.poseidon_round_keys_29.clone(),
            ]),
        );
        map.insert(
            5,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[self.seq_5.clone()]),
        );
        map.insert(
            4,
            Poseidon31MerkleHasherVar::hash_m31_columns_get_capacity(&[
                self.seq_4.clone(),
                self.blake_sigma_0.clone(),
                self.blake_sigma_1.clone(),
                self.blake_sigma_2.clone(),
                self.blake_sigma_3.clone(),
                self.blake_sigma_4.clone(),
                self.blake_sigma_5.clone(),
                self.blake_sigma_6.clone(),
                self.blake_sigma_7.clone(),
                self.blake_sigma_8.clone(),
                self.blake_sigma_9.clone(),
                self.blake_sigma_10.clone(),
                self.blake_sigma_11.clone(),
                self.blake_sigma_12.clone(),
                self.blake_sigma_13.clone(),
                self.blake_sigma_14.clone(),
                self.blake_sigma_15.clone(),
            ]),
        );

        let cs = self.cs();
        let map = map
            .into_iter()
            .map(|(k, v)| (k, OptionVar::some(&cs, v)))
            .collect();
        map
    }
}
