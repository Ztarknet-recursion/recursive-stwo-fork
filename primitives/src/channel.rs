use crate::poseidon31::Poseidon2HalfVar;
use crate::{BitVar, M31Var, QM31Var};
use circle_plonk_dsl_constraint_system::var::{AllocVar, Var};
use circle_plonk_dsl_constraint_system::ConstraintSystemRef;
use std::ops::Neg;
use stwo::core::fields::m31::M31;

pub type HashVar = Poseidon2HalfVar;

#[derive(Clone)]
pub struct ChannelVar {
    pub n_sent: usize,
    pub digest: Poseidon2HalfVar,
}

impl Var for ChannelVar {
    type Value = [M31; 16];

    fn cs(&self) -> ConstraintSystemRef {
        self.digest.cs()
    }
}

impl ChannelVar {
    pub fn default(cs: &ConstraintSystemRef) -> Self {
        let n_sent = 0;
        let digest = Poseidon2HalfVar::zero(cs);
        Self { n_sent, digest }
    }

    pub fn mix_root(&mut self, root: &HashVar) {
        self.digest = Poseidon2HalfVar::permute_get_capacity(root, &self.digest);
        self.n_sent = 0;
    }

    pub fn draw_felts(&mut self) -> [QM31Var; 2] {
        let cs = self.cs();

        let n_sent = M31Var::new_constant(&cs, &M31::from(self.n_sent as u32));
        self.n_sent += 1;

        let n_sent = QM31Var::from(&n_sent);

        let left = Poseidon2HalfVar::from_qm31(&n_sent, &QM31Var::zero(&cs));
        Poseidon2HalfVar::permute_get_rate(&left, &self.digest).to_qm31()
    }

    pub fn mix_one_felt(&mut self, felt: &QM31Var) {
        let cs = self.cs();
        let left = Poseidon2HalfVar::from_qm31(felt, &QM31Var::zero(&cs));
        self.digest = Poseidon2HalfVar::permute_get_capacity(&left, &self.digest);
        self.n_sent = 0;
    }

    pub fn mix_two_felts(&mut self, felt1: &QM31Var, felt2: &QM31Var) {
        let left = Poseidon2HalfVar::from_qm31(felt1, felt2);
        self.digest = Poseidon2HalfVar::permute_get_capacity(&left, &self.digest);
        self.n_sent = 0;
    }
}

pub struct ConditionalChannelMixer {
    pub channel: ChannelVar,
}

impl ConditionalChannelMixer {
    pub fn new(channel: ChannelVar) -> Self {
        Self { channel }
    }

    pub fn mix(mut self, felt: &[QM31Var], bits: &[BitVar]) -> ChannelVar {
        let cs = self.channel.cs();
        let mut count = 0;

        let mut input_1 = QM31Var::zero(&cs);
        let mut input_2 = QM31Var::zero(&cs);
        let mut input_3 = QM31Var::zero(&cs);

        let mut is_input_1_occupied: BitVar = BitVar::new_false(&cs);
        let mut is_input_2_occupied = BitVar::new_false(&cs);
        let mut is_input_3_occupied = BitVar::new_false(&cs);

        for (felt, bit) in felt.iter().zip(bits.iter()) {
            let should_write_to_input_1 = &is_input_1_occupied.neg() & bit;
            let should_write_to_input_2 =
                &(&is_input_1_occupied & &is_input_2_occupied.neg()) & bit;
            let should_write_to_input_3 = &is_input_2_occupied & bit;

            input_1 = QM31Var::select(&input_1, felt, &should_write_to_input_1);
            input_2 = QM31Var::select(&input_2, felt, &should_write_to_input_2);
            input_3 = QM31Var::select(&input_3, felt, &should_write_to_input_3);

            is_input_1_occupied = &is_input_1_occupied | &should_write_to_input_1;
            is_input_2_occupied = &is_input_2_occupied | &should_write_to_input_2;
            is_input_3_occupied = &is_input_3_occupied | &should_write_to_input_3;

            count += 1;

            if count % 2 == 0 {
                let should_permute = is_input_2_occupied.clone();

                let left = Poseidon2HalfVar::from_qm31(&input_1, &input_2);
                let existing_digest = self.channel.digest.to_qm31();
                let candidate_digest =
                    Poseidon2HalfVar::permute_get_capacity(&left, &self.channel.digest).to_qm31();

                let new_digest_left =
                    QM31Var::select(&existing_digest[0], &candidate_digest[0], &should_permute);
                let new_digest_right =
                    QM31Var::select(&existing_digest[1], &candidate_digest[1], &should_permute);

                input_1 = QM31Var::select(&input_1, &input_3, &should_permute);
                is_input_1_occupied = &(&is_input_1_occupied & &should_permute.neg())
                    | &(&is_input_3_occupied & &should_permute);
                is_input_2_occupied = &is_input_2_occupied & &should_permute.neg();
                is_input_3_occupied = &is_input_3_occupied & &should_permute.neg();

                self.channel.digest =
                    Poseidon2HalfVar::from_qm31(&new_digest_left, &new_digest_right);
            }
        }

        for felt in felt.iter().skip(bits.len()) {
            let should_write_to_input_1 = is_input_1_occupied.neg();
            let should_write_to_input_2 = &is_input_1_occupied & &is_input_2_occupied.neg();
            let should_write_to_input_3 = is_input_2_occupied.clone();

            input_1 = QM31Var::select(&input_1, felt, &should_write_to_input_1);
            input_2 = QM31Var::select(&input_2, felt, &should_write_to_input_2);
            input_3 = QM31Var::select(&input_3, felt, &should_write_to_input_3);

            is_input_1_occupied = &is_input_1_occupied | &should_write_to_input_1;
            is_input_2_occupied = &is_input_2_occupied | &should_write_to_input_2;
            is_input_3_occupied = &is_input_3_occupied | &should_write_to_input_3;

            count += 1;

            if count % 2 == 0 {
                let should_permute = is_input_2_occupied.clone();

                let left = Poseidon2HalfVar::from_qm31(&input_1, &input_2);
                let existing_digest = self.channel.digest.to_qm31();
                let candidate_digest =
                    Poseidon2HalfVar::permute_get_capacity(&left, &self.channel.digest).to_qm31();

                let new_digest_left =
                    QM31Var::select(&existing_digest[0], &candidate_digest[0], &should_permute);
                let new_digest_right =
                    QM31Var::select(&existing_digest[1], &candidate_digest[1], &should_permute);

                input_1 = QM31Var::select(&input_1, &input_3, &should_permute);
                is_input_1_occupied = &(&is_input_1_occupied & &should_permute.neg())
                    | &(&is_input_3_occupied & &should_permute);
                is_input_2_occupied = &is_input_2_occupied & &should_permute.neg();
                is_input_3_occupied = &is_input_3_occupied & &should_permute.neg();

                self.channel.digest =
                    Poseidon2HalfVar::from_qm31(&new_digest_left, &new_digest_right);
            }
        }

        let should_permute = is_input_1_occupied.clone();
        let input_2_or_default = &input_2 * &is_input_2_occupied.0;

        let left = Poseidon2HalfVar::from_qm31(&input_1, &input_2_or_default);
        let existing_digest = self.channel.digest.to_qm31();
        let candidate_digest =
            Poseidon2HalfVar::permute_get_capacity(&left, &self.channel.digest).to_qm31();

        let new_digest_left =
            QM31Var::select(&existing_digest[0], &candidate_digest[0], &should_permute);
        let new_digest_right =
            QM31Var::select(&existing_digest[1], &candidate_digest[1], &should_permute);

        self.channel.digest = Poseidon2HalfVar::from_qm31(&new_digest_left, &new_digest_right);

        self.channel.n_sent = 0;
        self.channel
    }
}
