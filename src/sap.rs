// implementation of SAP scheme as described in
// [Approximate Distance-Comparison-Preserving Symmetric Encryption](https://eprint.iacr.org/2021/1666.pdf)
use rand::{Rng, rng};
use rand_distr::{Distribution, Normal, Uniform};
use std::collections::HashMap;

/// BinaryString in SAP scheme as key for the psuedorandom function PRF to ensure
/// it produce values in a deterministic manner
pub type BinaryString = Vec<bool>;

pub trait Sample {
    fn sample(length: usize) -> Self;
}

impl Sample for BinaryString {
    /// Sample a value from {0,1} to the power of l where l belong to N.
    /// In other words, generate a binary string vector of the length l by random.
    fn sample(length: usize) -> Vec<bool> {
        let mut rng = rng();
        let t = (0..length).map(|_| rng.random_bool(0.5)).collect();
        t
    }
}

/// TapeGenPRF is psuedorandom function described in
/// [Order-Preserving Symmetric Encryption](https://eprint.iacr.org/2012/624.pdf)
/// it maintains a ```state_d``` using a binary string to ensure its deterministic nature.
///
/// TapeGenPRF enable SAP's decryption of encrypted value by
/// deterministically regenerate random binary string using an BinaryString provided in ```EncryptionSeed```
pub struct BinaryStringTapeGenPRF {
    state_d: HashMap<Vec<bool>, BinaryString>,
}

impl BinaryStringTapeGenPRF {
    pub fn new() -> Self {
        BinaryStringTapeGenPRF {
            state_d: HashMap::new(),
        }
    }

    /// Generate a binary string using a seed binary string and a variable l.
    /// Because the ambiguity of the original psuedo code we make one assumption about it implementation:
    /// * If x is not available in state D, we initialize it with the value r <- {0,1}<sup>l</sup>
    pub fn generate(&mut self, x: Vec<bool>, l: usize) -> BinaryString {
        let dx: Vec<bool> = match self.state_d.get(&x) {
            None => {
                let r = BinaryString::sample(l);
                let _ = self.state_d.insert(x, r.clone());
                r
            }
            Some(dx) => {
                if dx.len() < l {
                    let r = BinaryString::sample(l - dx.len());
                    self.state_d
                        .get_mut(&x)
                        .map(|x| x.extend(r.into_iter()))
                        .unwrap_or(());
                    self.state_d.get(&x).unwrap().to_vec()
                } else {
                    dx.to_vec()
                }
            }
        };

        dx.clone().into_iter().take(l).collect()
    }
}

/// Stateful multivariate normal PRF for generating element in a deterministic manner using
/// the state mechanic of TapeGenPRF.
///
/// Similar to TapeGenPRF, the MVNStatePRF enable SAP's decryption of encrypted value by
/// deterministically regenerate random f32 vector from a binary string generated from ```EncryptionSeed``` value.
pub struct MVNStatefulPRF {
    state: HashMap<BinaryString, Vec<f32>>,
}
impl MVNStatefulPRF {
    pub fn new() -> Self {
        MVNStatefulPRF {
            state: HashMap::new(),
        }
    }

    fn multivariate_normal_vec(d: usize) -> Vec<f32> {
        let normal = Normal::new(0.0, 1.0).unwrap();
        let mut rng = rng();
        let mut v: Vec<f32> = vec![];
        for _ in 0..d {
            v.push(normal.sample(&mut rng));
        }
        v
    }

    pub fn generate(&mut self, length: usize, key: BinaryString) -> Vec<f32> {
        match self.state.get(&key) {
            Some(value) => value.clone(),
            None => {
                let value = MVNStatefulPRF::multivariate_normal_vec(length);
                self.state.insert(key, value.clone());
                value
            }
        }
    }
}

/// UniformDistributionStatefulPRF for generating element in a deterministic manner using
/// the state mechanic of TapeGenPRF. Its value generation is injected during construction.
pub struct UniformDistributionStatefulPRF {
    state: HashMap<BinaryString, f32>,
}
impl UniformDistributionStatefulPRF {
    pub fn new() -> Self {
        UniformDistributionStatefulPRF {
            state: HashMap::new(),
        }
    }

    pub fn generate(&mut self, min: f32, max: f32, key: BinaryString) -> f32 {
        match self.state.get(&key) {
            Some(value) => *value,
            None => {
                let uniform = Uniform::new(min, max).unwrap();
                let mut rng = rng();
                let value = uniform.sample(&mut rng);
                self.state.insert(key, value);
                value
            }
        }
    }
}

/// Encryption seed hold a secret scale factor to scale the plain text vector
/// and a seed_key value to generate pertubation factor to perturb
#[derive(Clone, Debug)]
pub struct EncryptionSeed {
    scale_factor: f32,
    seed_key: Vec<bool>,
}

impl EncryptionSeed {
    pub fn new(scale_factor: f32, seed_length: usize) -> Self {
        EncryptionSeed {
            scale_factor,
            seed_key: BinaryString::sample(seed_length),
        }
    }
}

pub struct EncryptedValue {
    value: Vec<f32>,
    original_dimension_count: usize,
    n: Vec<bool>,
}

/// Scale and Perturb (SAP) scheme is a beta distance-comparison-preserving encryption
/// as described in
/// [Approximate Distance Preserving Encryption](https://eprint.iacr.org/2021/1666.pdf)
pub struct SAP {
    beta: f32,
    binary_string_prf: BinaryStringTapeGenPRF,
    mvn_vec_prf: MVNStatefulPRF,
    u_f32_prf: UniformDistributionStatefulPRF,
}

impl SAP {
    /// Construct a SAP scheme.
    /// SAP is implemented as an object to ensure the our psuedorandom function (PRF) are stateful
    /// * `beta`: represent the beta in beta-dpc (beta distance preserving comparision) its value should be tuned for different range of plain text input.
    pub fn new(beta: f32) -> Self {
        SAP {
            beta,
            binary_string_prf: BinaryStringTapeGenPRF::new(),
            mvn_vec_prf: MVNStatefulPRF::new(),
            u_f32_prf: UniformDistributionStatefulPRF::new(),
        }
    }

    pub fn encrypt(&mut self, seed: EncryptionSeed, m: Vec<f32>) -> EncryptedValue {
        let dimension_count = m.len();
        let n = BinaryString::sample(dimension_count);
        let coins_1 = self
            .binary_string_prf
            .generate(seed.seed_key.clone(), seed.seed_key.len());

        let coins_2 = self.binary_string_prf.generate(n.clone(), n.len());

        let u = self.mvn_vec_prf.generate(dimension_count, coins_1);
        let x_prime = self.u_f32_prf.generate(0., 1., coins_2);

        let x = x_prime.powf(1.0 / dimension_count as f32) * seed.scale_factor * self.beta / 4.0;

        let u_length = u.len() as f32;
        let lambda_m = crate::math::multiply(u, x / u_length);
        let scaled_vector = crate::math::multiply(m, seed.scale_factor);
        let c = crate::math::sum(scaled_vector, lambda_m);

        EncryptedValue {
            value: c,
            original_dimension_count: dimension_count,
            n,
        }
    }

    pub fn decrypt(&mut self, seed: EncryptionSeed, encrypted_value: EncryptedValue) -> Vec<f32> {
        let coins_1 = self
            .binary_string_prf
            .generate(seed.seed_key.clone(), seed.seed_key.len());
        let coins_2 = self
            .binary_string_prf
            .generate(encrypted_value.n.clone(), encrypted_value.n.len());

        let u = self
            .mvn_vec_prf
            .generate(encrypted_value.original_dimension_count, coins_1);
        let x_prime = self.u_f32_prf.generate(0., 1., coins_2);
        let x = x_prime.powf(1.0 / encrypted_value.original_dimension_count as f32)
            * seed.scale_factor
            * self.beta
            / 4.0;
        let lambda_m = crate::math::multiply(crate::math::normalise(u), x);
        let m = crate::math::multiply(
            crate::math::minus(encrypted_value.value, lambda_m),
            1.0 / seed.scale_factor,
        );
        m
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

    fn dot_distance(a: &Vec<f32>, b: &Vec<f32>) -> f32 {
        assert_eq!(
            a.len(),
            b.len(),
            "Can't calculate the 2d norm if the number of a and b components doesn't match"
        );
        a.par_iter().zip(b.par_iter()).map(|(a, b)| (a * b)).sum()
    }

    fn create_random_vector(length: usize) -> Vec<f32> {
        let mut rng = rand::rng();
        (0..length).map(|_| rng.random_range(-1.0..1.0)).collect()
    }

    fn is_approximately_equal(a: Vec<f32>, b: Vec<f32>) -> bool {
        let epsilon = 1e-8;
        let mut error = false;
        for (x, y) in a.into_iter().zip(b.into_iter()) {
            if (x - y).abs() > epsilon {
                error = true;
                break;
            }
        }

        return error;
    }

    #[test]
    pub fn encrypt_decrypt_round_trip() {
        let value = create_random_vector(10);
        let seed = EncryptionSeed::new(5.0, 8);
        let mut sap = SAP::new(0.5);
        let ciphered = sap.encrypt(seed.clone(), value.clone());
        let deciphered = sap.decrypt(seed, ciphered);

        let is_equal = is_approximately_equal(value.clone(), deciphered.clone());
        assert!(
            is_equal,
            "Expect value equal deciphered. However got\nx: {:?}\ny: {:?}",
            value, deciphered
        )
    }

    #[test]
    /// Beta preserve distance comparison property is defined as
    /// dist(x,y) < dist(x,z) - beta => dist(encrypt(x), encrypt(y)) < dist(encrypted(x), encrypted(z))
    pub fn beta_preserve_distance() {
        let x = create_random_vector(4);
        let y = create_random_vector(4);
        let z = create_random_vector(4);

        let dist_xy = dot_distance(&x, &y);
        let dist_xz = dot_distance(&x, &z);

        let seed = EncryptionSeed::new(5.0, 8);

        let delta = dist_xz - dist_xy;
        let t = delta.abs();
        let beta = t * 0.9;

        let mut sap = SAP::new(beta);
        let fx = sap.encrypt(seed.clone(), x.clone());
        let fy = sap.encrypt(seed.clone(), y.clone());
        let fz = sap.encrypt(seed.clone(), z.clone());

        let dist_fxy = dot_distance(&fx.value, &fy.value);
        let dist_fxz = dot_distance(&fx.value, &fz.value);

        if dist_xz > dist_xy {
            assert!(dist_fxz > dist_fxy);
        } else {
            assert!(dist_fxz < dist_fxy);
        }
    }
}
