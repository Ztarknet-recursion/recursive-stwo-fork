use circle_plonk_dsl_channel::ChannelVar;
use circle_plonk_dsl_constraint_system::{ConstraintSystemRef, var::Var};
use circle_plonk_dsl_fields::QM31Var;
use stwo_constraint_framework::logup::LookupElements;

#[derive(Debug, Clone)]
pub struct LookupElementsVar<const N: usize> {
    pub z: QM31Var,
    pub alpha: QM31Var,
    pub alpha_powers: [QM31Var; N],
}

impl<const N: usize> Var for LookupElementsVar<N> {
    type Value = LookupElements<N>;

    fn cs(&self) -> ConstraintSystemRef {
        self.z.cs().and(&self.alpha.cs())
    }
}

impl<const N: usize> LookupElementsVar<N> {
    pub fn draw(channel: &mut ChannelVar) -> Self {
        let [z, alpha] = channel.draw_felts();
        Self::from_z_and_alpha(z, alpha)
    }

    pub fn from_z_and_alpha(z: QM31Var, alpha: QM31Var) -> Self {
        let cs = z.cs().and(&alpha.cs());

        let mut alpha_powers = Vec::with_capacity(N);
        alpha_powers.push(QM31Var::one(&cs));
        if N > 1 {
            alpha_powers.push(alpha.clone());
        }

        let mut cur = alpha.clone();
        for _ in 2..N {
            cur = &cur * &alpha;
            alpha_powers.push(cur.clone());
        }

        let alpha_powers: [QM31Var; N] = alpha_powers.try_into().unwrap();

        Self {
            z,
            alpha,
            alpha_powers,
        }
    }
}

// Macro to generate lookup element structs with draw method
macro_rules! lookup_element_var {
    ($name:ident, $n:expr) => {
        pub struct $name(pub LookupElementsVar<$n>);

        impl $name {
            pub fn draw(channel: &mut ChannelVar) -> Self {
                Self(LookupElementsVar::<$n>::draw(channel))
            }
        }
    };
}

lookup_element_var!(BlakeGVar, 20);
lookup_element_var!(BlakeRoundVar, 35);
lookup_element_var!(BlakeRoundSigmaVar, 17);
lookup_element_var!(Cube252Var, 20);
lookup_element_var!(MemoryAddressToIdVar, 2);
lookup_element_var!(MemoryIdToBigVar, 29);
lookup_element_var!(OpcodesVar, 3);
lookup_element_var!(PedersenAggregatorVar, 3);
lookup_element_var!(PartialEcMulVar, 73);
lookup_element_var!(PedersenPointsTableVar, 57);
lookup_element_var!(PoseidonAggregatorVar, 6);
lookup_element_var!(Poseidon3PartialRoundsChainVar, 42);
lookup_element_var!(PoseidonFullRoundChainVar, 32);
lookup_element_var!(PoseidonRoundKeysVar, 31);
lookup_element_var!(RangeCheck11Var, 1);
lookup_element_var!(RangeCheck12Var, 1);
lookup_element_var!(RangeCheck18Var, 1);
lookup_element_var!(RangeCheck18BVar, 1);
lookup_element_var!(RangeCheck20Var, 1);
lookup_element_var!(RangeCheck20BVar, 1);
lookup_element_var!(RangeCheck20CVar, 1);
lookup_element_var!(RangeCheck20DVar, 1);
lookup_element_var!(RangeCheck20EVar, 1);
lookup_element_var!(RangeCheck20FVar, 1);
lookup_element_var!(RangeCheck20GVar, 1);
lookup_element_var!(RangeCheck20HVar, 1);
lookup_element_var!(RangeCheck33333Var, 5);
lookup_element_var!(RangeCheck3663Var, 4);
lookup_element_var!(RangeCheck43Var, 2);
lookup_element_var!(RangeCheck4444Var, 4);
lookup_element_var!(RangeCheck44Var, 2);
lookup_element_var!(RangeCheck54Var, 2);
lookup_element_var!(RangeCheck6Var, 1);
lookup_element_var!(RangeCheck725Var, 3);
lookup_element_var!(RangeCheck8Var, 1);
lookup_element_var!(RangeCheck99Var, 2);
lookup_element_var!(RangeCheck99BVar, 2);
lookup_element_var!(RangeCheck99CVar, 2);
lookup_element_var!(RangeCheck99DVar, 2);
lookup_element_var!(RangeCheck99EVar, 2);
lookup_element_var!(RangeCheck99FVar, 2);
lookup_element_var!(RangeCheck99GVar, 2);
lookup_element_var!(RangeCheck99HVar, 2);
lookup_element_var!(RangeCheck252Width27Var, 10);
lookup_element_var!(TripleXor32Var, 8);
lookup_element_var!(VerifyBitwiseXor12Var, 3);
lookup_element_var!(VerifyBitwiseXor4Var, 3);
lookup_element_var!(VerifyBitwiseXor7Var, 3);
lookup_element_var!(VerifyBitwiseXor8Var, 3);
lookup_element_var!(VerifyBitwiseXor8BVar, 3);
lookup_element_var!(VerifyBitwiseXor9Var, 3);
lookup_element_var!(VerifyInstructionVar, 7);

pub struct CairoInteractionElementsVar {
    pub opcodes: OpcodesVar,
    pub verify_instruction: VerifyInstructionVar,
    pub blake_round: BlakeRoundVar,
    pub blake_g: BlakeGVar,
    pub blake_sigma: BlakeRoundSigmaVar,
    pub triple_xor_32: TripleXor32Var,
    pub poseidon_aggregator: PoseidonAggregatorVar,
    pub poseidon_3_partial_rounds_chain: Poseidon3PartialRoundsChainVar,
    pub poseidon_full_round_chain: PoseidonFullRoundChainVar,
    pub cube_252: Cube252Var,
    pub poseidon_round_keys: PoseidonRoundKeysVar,
    pub range_check_252_width_27: RangeCheck252Width27Var,
    pub pedersen_aggregator: PedersenAggregatorVar,
    pub partial_ec_mul: PartialEcMulVar,
    pub pedersen_points_table: PedersenPointsTableVar,
    pub memory_address_to_id: MemoryAddressToIdVar,
    pub memory_id_to_value: MemoryIdToBigVar,
    pub range_checks: RangeChecksInteractionElementsVar,
    pub verify_bitwise_xor_4: VerifyBitwiseXor4Var,
    pub verify_bitwise_xor_7: VerifyBitwiseXor7Var,
    pub verify_bitwise_xor_8: VerifyBitwiseXor8Var,
    pub verify_bitwise_xor_8_b: VerifyBitwiseXor8BVar,
    pub verify_bitwise_xor_9: VerifyBitwiseXor9Var,
    pub verify_bitwise_xor_12: VerifyBitwiseXor12Var,
}

impl CairoInteractionElementsVar {
    pub fn draw(channel: &mut ChannelVar) -> Self {
        Self {
            opcodes: OpcodesVar::draw(channel),
            verify_instruction: VerifyInstructionVar::draw(channel),
            blake_round: BlakeRoundVar::draw(channel),
            blake_g: BlakeGVar::draw(channel),
            blake_sigma: BlakeRoundSigmaVar::draw(channel),
            triple_xor_32: TripleXor32Var::draw(channel),
            poseidon_aggregator: PoseidonAggregatorVar::draw(channel),
            poseidon_3_partial_rounds_chain: Poseidon3PartialRoundsChainVar::draw(channel),
               poseidon_full_round_chain: PoseidonFullRoundChainVar::draw(channel),
            cube_252: Cube252Var::draw(channel),
            poseidon_round_keys: PoseidonRoundKeysVar::draw(channel),
            range_check_252_width_27: RangeCheck252Width27Var::draw(channel),
            pedersen_aggregator: PedersenAggregatorVar::draw(channel),
            partial_ec_mul: PartialEcMulVar::draw(channel),
            pedersen_points_table: PedersenPointsTableVar::draw(channel),
            memory_address_to_id: MemoryAddressToIdVar::draw(channel),
            memory_id_to_value: MemoryIdToBigVar::draw(channel),
            range_checks: RangeChecksInteractionElementsVar::draw(channel),
            verify_bitwise_xor_4: VerifyBitwiseXor4Var::draw(channel),
            verify_bitwise_xor_7: VerifyBitwiseXor7Var::draw(channel),
            verify_bitwise_xor_8: VerifyBitwiseXor8Var::draw(channel),
            verify_bitwise_xor_8_b: VerifyBitwiseXor8BVar::draw(channel),
            verify_bitwise_xor_9: VerifyBitwiseXor9Var::draw(channel),
            verify_bitwise_xor_12: VerifyBitwiseXor12Var::draw(channel),
        }
    }
}

pub struct RangeChecksInteractionElementsVar {
    pub rc_6: RangeCheck6Var,
    pub rc_8: RangeCheck8Var,
    pub rc_11: RangeCheck11Var,
    pub rc_12: RangeCheck12Var,
    pub rc_18: RangeCheck18Var,
    pub rc_18_b: RangeCheck18BVar,
    pub rc_20: RangeCheck20Var,
    pub rc_20_b: RangeCheck20BVar,
    pub rc_20_c: RangeCheck20CVar,
    pub rc_20_d: RangeCheck20DVar,
    pub rc_20_e: RangeCheck20EVar,
    pub rc_20_f: RangeCheck20FVar,
    pub rc_20_g: RangeCheck20GVar,
    pub rc_20_h: RangeCheck20HVar,
    pub rc_4_3: RangeCheck43Var,
    pub rc_4_4: RangeCheck44Var,
    pub rc_5_4: RangeCheck54Var,
    pub rc_9_9: RangeCheck99Var,
    pub rc_9_9_b: RangeCheck99BVar,
    pub rc_9_9_c: RangeCheck99CVar,
    pub rc_9_9_d: RangeCheck99DVar,
    pub rc_9_9_e: RangeCheck99EVar,
    pub rc_9_9_f: RangeCheck99FVar,
    pub rc_9_9_g: RangeCheck99GVar,
    pub rc_9_9_h: RangeCheck99HVar,
    pub rc_7_2_5: RangeCheck725Var,
    pub rc_3_6_6_3: RangeCheck3663Var,
    pub rc_4_4_4_4: RangeCheck4444Var,
    pub rc_3_3_3_3_3: RangeCheck33333Var,
}

impl RangeChecksInteractionElementsVar {
    pub fn draw(channel: &mut ChannelVar) -> Self {
        RangeChecksInteractionElementsVar {
            rc_6: RangeCheck6Var::draw(channel),
            rc_8: RangeCheck8Var::draw(channel),
            rc_11: RangeCheck11Var::draw(channel),
            rc_12: RangeCheck12Var::draw(channel),
            rc_18: RangeCheck18Var::draw(channel),
            rc_18_b: RangeCheck18BVar::draw(channel),
            rc_20: RangeCheck20Var::draw(channel),
            rc_20_b: RangeCheck20BVar::draw(channel),
            rc_20_c: RangeCheck20CVar::draw(channel),
            rc_20_d: RangeCheck20DVar::draw(channel),
            rc_20_e: RangeCheck20EVar::draw(channel),
            rc_20_f: RangeCheck20FVar::draw(channel),
            rc_20_g: RangeCheck20GVar::draw(channel),
            rc_20_h: RangeCheck20HVar::draw(channel),
            rc_4_3: RangeCheck43Var::draw(channel),
            rc_4_4: RangeCheck44Var::draw(channel),
            rc_5_4: RangeCheck54Var::draw(channel),
            rc_9_9: RangeCheck99Var::draw(channel),
            rc_9_9_b: RangeCheck99BVar::draw(channel),
            rc_9_9_c: RangeCheck99CVar::draw(channel),
            rc_9_9_d: RangeCheck99DVar::draw(channel),
            rc_9_9_e: RangeCheck99EVar::draw(channel),
            rc_9_9_f: RangeCheck99FVar::draw(channel),
            rc_9_9_g: RangeCheck99GVar::draw(channel),
            rc_9_9_h: RangeCheck99HVar::draw(channel),
            rc_7_2_5: RangeCheck725Var::draw(channel),
            rc_3_6_6_3: RangeCheck3663Var::draw(channel),
            rc_4_4_4_4: RangeCheck4444Var::draw(channel),
            rc_3_3_3_3_3: RangeCheck33333Var::draw(channel),
        }
    }
}