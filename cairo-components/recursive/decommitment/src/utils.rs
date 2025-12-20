use circle_plonk_dsl_constraint_system::var::Var;
use circle_plonk_dsl_constraint_system::{var::AllocVar, ConstraintSystemRef};
use circle_plonk_dsl_primitives::{BitVar, M31Var, Poseidon2HalfVar, QM31Var};
use std::ops::Neg;
use stwo::core::fields::{m31::M31, qm31::QM31};

#[derive(Clone)]
pub struct HashAccumulatorVar {
    pub cs: ConstraintSystemRef,
    pub refresh_counter: usize,
    pub size: [BitVar; 16],
    pub digest: [QM31Var; 2],
    pub buffer: [M31Var; 16],
}

impl HashAccumulatorVar {
    pub fn new(cs: &ConstraintSystemRef) -> Self {
        let size = std::array::from_fn(|i| {
            if i == 0 {
                BitVar::new_true(cs)
            } else {
                BitVar::new_false(cs)
            }
        });

        let buffer = std::array::from_fn(|_| M31Var::zero(cs));

        Self {
            cs: cs.clone(),
            refresh_counter: 0,
            size,
            digest: [QM31Var::zero(cs), QM31Var::zero(cs)],
            buffer,
        }
    }

    pub fn update(&mut self, data: &[M31Var]) {
        for elem in data.iter() {
            for i in 0..16 {
                self.buffer[i] = M31Var::select(&self.buffer[i], elem, &self.size[i]);
            }
            self.size.rotate_right(1);
            self.refresh_counter += 1;

            if self.refresh_counter == 8 {
                self.refresh();
            }
        }
    }

    pub fn refresh(&mut self) {
        let mut has_at_least_8_elements = self.size[8].clone();
        for i in 9..16 {
            has_at_least_8_elements = &has_at_least_8_elements | &self.size[i];
        }

        let left = Poseidon2HalfVar::from_m31(&self.buffer[0..8]);
        let right = Poseidon2HalfVar::from_qm31(&self.digest[0], &self.digest[1]);
        let new_digest = Poseidon2HalfVar::permute_get_capacity(&left, &right).to_qm31();

        let mut new_size = self.size.clone();
        new_size.rotate_left(8);

        self.digest = [
            QM31Var::select(&self.digest[0], &new_digest[0], &has_at_least_8_elements),
            QM31Var::select(&self.digest[1], &new_digest[1], &has_at_least_8_elements),
        ];
        self.refresh_counter = 0;
        for i in 0..16 {
            self.size[i] = BitVar::select(&self.size[i], &new_size[i], &has_at_least_8_elements);
        }
    }

    pub fn finalize(&self) -> [QM31Var; 2] {
        let has_at_least_1_element = self.size[0].neg();

        let mut buffer = self.buffer.clone();
        let mut clear = BitVar::new_false(&self.cs);
        let zero = M31Var::zero(&self.cs);
        for i in 1..16 {
            clear = &clear | &self.size[i];
            buffer[i] = M31Var::select(&buffer[i], &zero, &clear);
        }

        let left = Poseidon2HalfVar::from_m31(&buffer[0..8]);
        let right = Poseidon2HalfVar::from_qm31(&self.digest[0], &self.digest[1]);
        let new_digest = Poseidon2HalfVar::permute_get_capacity(&left, &right).to_qm31();

        [
            QM31Var::select(&self.digest[0], &new_digest[0], &has_at_least_1_element),
            QM31Var::select(&self.digest[1], &new_digest[1], &has_at_least_1_element),
        ]
    }

    pub fn compress(&mut self) -> HashAccumulatorCompressedVar {
        if self.refresh_counter != 0 {
            self.refresh();
        }

        let mut size_var = M31Var::zero(&self.cs);
        for i in 1..=7 {
            size_var = &size_var + &self.size[i].0.mul_constant(M31::from(i as u32));
        }
        let size = size_var.value.0 as u32;
        let digest = [self.digest[0].value(), self.digest[1].value()];
        let buffer = std::array::from_fn(|i| self.buffer[i].value);

        let mut state = self.buffer[0..7].to_vec();
        state.push(size_var);

        let left = Poseidon2HalfVar::from_m31(&state);
        let right = Poseidon2HalfVar::from_qm31(&self.digest[0], &self.digest[1]);
        let compressed_digest = Poseidon2HalfVar::permute_get_capacity(&left, &right).to_qm31();

        HashAccumulatorCompressedVar {
            size,
            digest,
            buffer,
            compressed_digest,
        }
    }

    pub fn equalverify(&self, rhs: &HashAccumulatorVar) {
        let mut ignore = BitVar::new_false(&self.cs);
        for i in 0..16 {
            ignore = &ignore | &self.size[i];
            let test = M31Var::select(&self.buffer[i], &rhs.buffer[i], &ignore);
            rhs.buffer[i].equalverify(&test);
        }
        self.digest[0].equalverify(&rhs.digest[0]);
        self.digest[1].equalverify(&rhs.digest[1]);
        for i in 0..16 {
            self.size[i].0.equalverify(&rhs.size[i].0);
        }
    }
}

pub struct HashAccumulatorCompressedVar {
    pub size: u32,
    pub digest: [QM31; 2],
    pub buffer: [M31; 7],
    pub compressed_digest: [QM31Var; 2],
}

impl HashAccumulatorCompressedVar {
    pub fn cs(&self) -> ConstraintSystemRef {
        self.compressed_digest[0].cs()
    }

    pub fn select(
        a: &HashAccumulatorCompressedVar,
        b: &HashAccumulatorCompressedVar,
        bit: &BitVar,
    ) -> HashAccumulatorCompressedVar {
        let pick_b = bit.value();
        let size = if pick_b { b.size } else { a.size };
        let digest = if pick_b { b.digest } else { a.digest };
        let buffer = if pick_b { b.buffer } else { a.buffer };

        let compressed_digest = [
            QM31Var::select(&a.compressed_digest[0], &b.compressed_digest[0], bit),
            QM31Var::select(&a.compressed_digest[1], &b.compressed_digest[1], bit),
        ];

        HashAccumulatorCompressedVar {
            size,
            digest,
            buffer,
            compressed_digest,
        }
    }

    pub fn decompress(&self) -> HashAccumulatorVar {
        let cs = self.compressed_digest[0].cs();

        let size = std::array::from_fn(|i| {
            if i <= 7 {
                BitVar::new_witness(&cs, &(self.size == i as u32))
            } else {
                BitVar::new_false(&cs)
            }
        });

        let mut one_hot = size[0].0.clone();
        for i in 1..=7 {
            one_hot = &one_hot + &size[i].0;
        }
        one_hot.equalverify(&M31Var::one(&cs));

        let mut size_var = M31Var::zero(&cs);
        for i in 1..=7 {
            size_var = &size_var + &size[i].0.mul_constant(M31::from(i as u32));
        }

        let digest = [
            QM31Var::new_witness(&cs, &(self.digest[0])),
            QM31Var::new_witness(&cs, &(self.digest[1])),
        ];

        let buffer = std::array::from_fn(|i| {
            if i < 7 {
                M31Var::new_witness(&cs, &(self.buffer[i]))
            } else {
                M31Var::zero(&cs)
            }
        });

        let mut state = buffer[0..7].to_vec();
        state.push(size_var);

        let left = Poseidon2HalfVar::from_m31(&state);
        let right = Poseidon2HalfVar::from_qm31(&digest[0], &digest[1]);
        let expected_digest = Poseidon2HalfVar::permute_get_capacity(&left, &right).to_qm31();
        for i in 0..2 {
            self.compressed_digest[i].equalverify(&expected_digest[i]);
        }

        HashAccumulatorVar {
            cs,
            refresh_counter: 0,
            size,
            digest,
            buffer,
        }
    }
}

#[derive(Clone)]
pub struct HashAccumulatorQM31Var {
    pub cs: ConstraintSystemRef,
    pub refresh_counter: usize,
    pub size: [BitVar; 4],
    pub digest: [QM31Var; 2],
    pub buffer: [QM31Var; 4],
}

impl HashAccumulatorQM31Var {
    pub fn new(cs: &ConstraintSystemRef) -> Self {
        let size = std::array::from_fn(|i| {
            if i == 0 {
                BitVar::new_true(cs)
            } else {
                BitVar::new_false(cs)
            }
        });

        let buffer = std::array::from_fn(|_| QM31Var::zero(cs));

        Self {
            cs: cs.clone(),
            refresh_counter: 0,
            size,
            digest: [QM31Var::zero(cs), QM31Var::zero(cs)],
            buffer,
        }
    }

    pub fn update(&mut self, data: &[QM31Var]) {
        for elem in data.iter() {
            for i in 0..4 {
                self.buffer[i] = QM31Var::select(&self.buffer[i], elem, &self.size[i]);
            }
            self.size.rotate_right(1);
            self.refresh_counter += 1;

            if self.refresh_counter == 2 {
                self.refresh();
            }
        }
    }

    pub fn refresh(&mut self) {
        let mut has_at_least_2_elements = self.size[2].clone();
        for i in 3..4 {
            has_at_least_2_elements = &has_at_least_2_elements | &self.size[i];
        }

        let left = Poseidon2HalfVar::from_qm31(&self.buffer[0], &self.buffer[1]);
        let right = Poseidon2HalfVar::from_qm31(&self.digest[0], &self.digest[1]);
        let new_digest = Poseidon2HalfVar::permute_get_capacity(&left, &right).to_qm31();

        let mut new_size = self.size.clone();
        new_size.rotate_left(2);

        self.digest = [
            QM31Var::select(&self.digest[0], &new_digest[0], &has_at_least_2_elements),
            QM31Var::select(&self.digest[1], &new_digest[1], &has_at_least_2_elements),
        ];
        self.refresh_counter = 0;
        for i in 0..4 {
            self.size[i] = BitVar::select(&self.size[i], &new_size[i], &has_at_least_2_elements);
        }
    }

    pub fn finalize(&self) -> [QM31Var; 2] {
        let has_at_least_1_element = self.size[0].neg();

        let mut buffer = self.buffer.clone();
        let mut clear = BitVar::new_false(&self.cs);
        let zero = QM31Var::zero(&self.cs);
        for i in 1..4 {
            clear = &clear | &self.size[i];
            buffer[i] = QM31Var::select(&buffer[i], &zero, &clear);
        }

        let left = Poseidon2HalfVar::from_qm31(&buffer[0], &buffer[1]);
        let right = Poseidon2HalfVar::from_qm31(&self.digest[0], &self.digest[1]);
        let new_digest = Poseidon2HalfVar::permute_get_capacity(&left, &right).to_qm31();

        [
            QM31Var::select(&self.digest[0], &new_digest[0], &has_at_least_1_element),
            QM31Var::select(&self.digest[1], &new_digest[1], &has_at_least_1_element),
        ]
    }

    pub fn compress(&mut self) -> HashAccumulatorQM31CompressedVar {
        if self.refresh_counter != 0 {
            self.refresh();
        }

        let size_var = self.size[1].0.clone();
        let size = size_var.value.0 as u32;
        let digest = [self.digest[0].value(), self.digest[1].value()];
        let buffer = std::array::from_fn(|i| self.buffer[i].value);

        let left = Poseidon2HalfVar::from_qm31(&self.buffer[0], &QM31Var::from(&size_var));
        let right = Poseidon2HalfVar::from_qm31(&self.digest[0], &self.digest[1]);
        let compressed_digest = Poseidon2HalfVar::permute_get_capacity(&left, &right).to_qm31();

        HashAccumulatorQM31CompressedVar {
            size,
            digest,
            buffer,
            compressed_digest,
        }
    }

    pub fn equalverify(&self, rhs: &HashAccumulatorQM31Var) {
        let mut ignore = BitVar::new_false(&self.cs);
        for i in 0..4 {
            ignore = &ignore | &self.size[i];
            let test = QM31Var::select(&self.buffer[i], &rhs.buffer[i], &ignore);
            rhs.buffer[i].equalverify(&test);
        }
        self.digest[0].equalverify(&rhs.digest[0]);
        self.digest[1].equalverify(&rhs.digest[1]);
        for i in 0..4 {
            self.size[i].0.equalverify(&rhs.size[i].0);
        }
    }
}

pub struct HashAccumulatorQM31CompressedVar {
    pub size: u32,
    pub digest: [QM31; 2],
    pub buffer: [QM31; 1],
    pub compressed_digest: [QM31Var; 2],
}

impl HashAccumulatorQM31CompressedVar {
    pub fn cs(&self) -> ConstraintSystemRef {
        self.compressed_digest[0].cs()
    }

    pub fn select(
        a: &HashAccumulatorQM31CompressedVar,
        b: &HashAccumulatorQM31CompressedVar,
        bit: &BitVar,
    ) -> HashAccumulatorQM31CompressedVar {
        let pick_b = bit.value();
        let size = if pick_b { b.size } else { a.size };
        let digest = if pick_b { b.digest } else { a.digest };
        let buffer = if pick_b { b.buffer } else { a.buffer };

        let compressed_digest = [
            QM31Var::select(&a.compressed_digest[0], &b.compressed_digest[0], bit),
            QM31Var::select(&a.compressed_digest[1], &b.compressed_digest[1], bit),
        ];

        HashAccumulatorQM31CompressedVar {
            size,
            digest,
            buffer,
            compressed_digest,
        }
    }

    pub fn decompress(&self) -> HashAccumulatorQM31Var {
        let cs = self.compressed_digest[0].cs();

        let size = std::array::from_fn(|i| {
            if i <= 1 {
                BitVar::new_witness(&cs, &(self.size == i as u32))
            } else {
                BitVar::new_false(&cs)
            }
        });

        let one_hot = &size[0].0 + &size[1].0;
        one_hot.equalverify(&M31Var::one(&cs));

        let size_var = size[1].0.clone();
        let digest = [
            QM31Var::new_witness(&cs, &(self.digest[0])),
            QM31Var::new_witness(&cs, &(self.digest[1])),
        ];
        let buffer = std::array::from_fn(|i| {
            if i < 1 {
                QM31Var::new_witness(&cs, &(self.buffer[i]))
            } else {
                QM31Var::zero(&cs)
            }
        });

        let left = Poseidon2HalfVar::from_qm31(&buffer[0], &QM31Var::from(&size_var));
        let right = Poseidon2HalfVar::from_qm31(&digest[0], &digest[1]);
        let expected_digest = Poseidon2HalfVar::permute_get_capacity(&left, &right).to_qm31();
        for i in 0..2 {
            self.compressed_digest[i].equalverify(&expected_digest[i]);
        }

        HashAccumulatorQM31Var {
            cs,
            refresh_counter: 0,
            size,
            digest,
            buffer,
        }
    }
}

#[cfg(test)]
mod tests {
    use cairo_plonk_dsl_hints::utils::{HashAccumulator, HashAccumulatorQM31};
    use circle_plonk_dsl_constraint_system::var::AllocVar;
    use rand::{Rng, SeedableRng};
    use stwo::core::fields::{m31::M31, qm31::QM31};

    use super::*;

    #[test]
    fn test_hash_accumulator_var() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0);

        let mut test = Vec::new();
        for _ in 0..103 {
            test.push(M31::from(rng.gen::<u32>()));
        }

        let mut hash_accumulator = HashAccumulator::new();
        hash_accumulator.update(&test);
        let expected = hash_accumulator.finalize();

        let cs = ConstraintSystemRef::new();
        let mut hash_accumulator = HashAccumulatorVar::new(&cs);
        let mut test_vars = Vec::new();
        for elem in test.iter() {
            test_vars.push(M31Var::new_witness(&cs, &elem));
        }
        hash_accumulator.update(&test_vars);
        let result = hash_accumulator.finalize();
        for i in 0..2 {
            let expected_qm31 = QM31::from_m31(
                expected[i * 4],
                expected[i * 4 + 1],
                expected[i * 4 + 2],
                expected[i * 4 + 3],
            );
            result[i].equalverify(&QM31Var::new_constant(&cs, &expected_qm31));
        }

        let hash_accumulator_var_old = hash_accumulator.clone();
        let compressed = hash_accumulator.compress();
        let decompressed = compressed.decompress();
        decompressed.equalverify(&hash_accumulator);

        hash_accumulator.update(&test_vars);
        let mut hash_accumulator_var_new = hash_accumulator.clone();

        let compressed_2 = hash_accumulator_var_new.compress();

        let pick_old = HashAccumulatorCompressedVar::select(
            &compressed,
            &compressed_2,
            &BitVar::new_false(&cs),
        );
        let decompressed = pick_old.decompress();
        decompressed.equalverify(&hash_accumulator_var_old);

        let pick_new = HashAccumulatorCompressedVar::select(
            &compressed,
            &compressed_2,
            &BitVar::new_true(&cs),
        );
        let decompressed = pick_new.decompress();
        decompressed.equalverify(&hash_accumulator_var_new);

        cs.pad();
        cs.check_arithmetics();
        cs.populate_logup_arguments();
        cs.check_poseidon_invocations();
    }

    #[test]
    fn test_hash_accumulator_qm31_var() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0);

        let mut test = Vec::new();
        for _ in 0..101 {
            test.push(QM31::from_m31(
                rng.gen::<M31>(),
                rng.gen::<M31>(),
                rng.gen::<M31>(),
                rng.gen::<M31>(),
            ));
        }

        let mut hash_accumulator = HashAccumulatorQM31::new();
        hash_accumulator.update(&test);
        let expected = hash_accumulator.finalize();

        let cs = ConstraintSystemRef::new();
        let mut hash_accumulator = HashAccumulatorQM31Var::new(&cs);
        let mut test_vars = Vec::new();
        for elem in test.iter() {
            test_vars.push(QM31Var::new_witness(&cs, &elem));
        }
        hash_accumulator.update(&test_vars);
        let result = hash_accumulator.finalize();
        for i in 0..2 {
            let expected_qm31 = QM31::from_m31(
                expected[i * 4],
                expected[i * 4 + 1],
                expected[i * 4 + 2],
                expected[i * 4 + 3],
            );
            result[i].equalverify(&QM31Var::new_constant(&cs, &expected_qm31));
        }

        let hash_accumulator_var_old = hash_accumulator.clone();
        let compressed = hash_accumulator.compress();
        let decompressed = compressed.decompress();
        decompressed.equalverify(&hash_accumulator);

        hash_accumulator.update(&test_vars);
        let mut hash_accumulator_var_new = hash_accumulator.clone();

        let compressed_2 = hash_accumulator_var_new.compress();

        let pick_old = HashAccumulatorQM31CompressedVar::select(
            &compressed,
            &compressed_2,
            &BitVar::new_false(&cs),
        );
        let decompressed = pick_old.decompress();
        decompressed.equalverify(&hash_accumulator_var_old);

        let pick_new = HashAccumulatorQM31CompressedVar::select(
            &compressed,
            &compressed_2,
            &BitVar::new_true(&cs),
        );
        let decompressed = pick_new.decompress();
        decompressed.equalverify(&hash_accumulator_var_new);

        cs.pad();
        cs.check_arithmetics();
        cs.populate_logup_arguments();
        cs.check_poseidon_invocations();
    }
}
