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
        let left = Poseidon2HalfVar::from_qm31(&felt, &QM31Var::zero(&cs));
        self.digest = Poseidon2HalfVar::permute_get_capacity(&left, &self.digest);
        self.n_sent = 0;
    }

    pub fn mix_two_felts(&mut self, felt1: &QM31Var, felt2: &QM31Var) {
        let left = Poseidon2HalfVar::from_qm31(&felt1, &felt2);
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
        let mut input_1 = QM31Var::zero(&self.channel.cs());
        let mut input_2 = QM31Var::zero(&self.channel.cs());

        let mut is_input_1_occupied = BitVar::new_false(&self.channel.cs());
        for (felt, bit) in felt.iter().zip(bits.iter()) {
            // if bit is false, do nothing this time

            // otherwise,
            // - if input_1 is occupied, write input_2 = felt
            // - if input_1 is not occupied, write input_1 = felt

            let should_write_to_input_1 = &is_input_1_occupied.neg() & bit;
            let should_write_to_input_2 = &is_input_1_occupied & bit;

            input_1 = QM31Var::select(&input_1, felt, &should_write_to_input_1);
            input_2 = QM31Var::select(&input_2, felt, &should_write_to_input_2);

            // is_input_1_occupied should be:
            // - if bit is false, unchanged
            // - otherwise, change to should_write_to_input_1 (which is true only if bit is true)
            is_input_1_occupied = &(&bit.neg() & &is_input_1_occupied) | &should_write_to_input_1;

            // permutation should happen if "should_write_to_input_2"
            let should_permute = &should_write_to_input_2;

            let left = Poseidon2HalfVar::from_qm31(&input_1, &input_2);
            let existing_digest = self.channel.digest.to_qm31();
            let candidate_digest =
                Poseidon2HalfVar::permute_get_capacity(&left, &self.channel.digest).to_qm31();

            let new_digest_left =
                QM31Var::select(&existing_digest[0], &candidate_digest[0], &should_permute);
            let new_digest_right =
                QM31Var::select(&existing_digest[1], &candidate_digest[1], &should_permute);

            self.channel.digest = Poseidon2HalfVar::from_qm31(&new_digest_left, &new_digest_right);
        }

        for felt in felt.iter().skip(bits.len()) {
            input_1 = QM31Var::select(&felt, &input_1, &is_input_1_occupied);
            input_2 = QM31Var::select(&input_2, felt, &is_input_1_occupied);

            let should_permute = &is_input_1_occupied;

            let left = Poseidon2HalfVar::from_qm31(&input_1, &input_2);
            let existing_digest = self.channel.digest.to_qm31();
            let candidate_digest =
                Poseidon2HalfVar::permute_get_capacity(&left, &self.channel.digest).to_qm31();

            let new_digest_left =
                QM31Var::select(&existing_digest[0], &candidate_digest[0], &should_permute);
            let new_digest_right =
                QM31Var::select(&existing_digest[1], &candidate_digest[1], &should_permute);

            self.channel.digest = Poseidon2HalfVar::from_qm31(&new_digest_left, &new_digest_right);

            is_input_1_occupied = is_input_1_occupied.neg();
        }

        // deal with the case where is_input_1_occupied is true
        let should_permute = &is_input_1_occupied;
        let left = Poseidon2HalfVar::from_qm31(&input_1, &QM31Var::zero(&self.channel.cs()));
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
