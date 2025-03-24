# SSAP
Stateless SAP (scale and perturbation) is rust library for a one way vector encryption based on SAP scheme as as described in [Approximate Distance-Comparision Preserving Symmetric Encryption](https://eprint.iacr.org/2021/1666). 

SSAP deviates from SAP in that the use of a psuedorandom function (PRF) is removed.
1. Rather than using a key ``K`` to generate a psuedorandom vector from a *multivariate normal distribution* for pertubation, we store a normalised vector as a key to remove the reliance on PRF. 
1. Rather than storing a random factor ``n`` to generate a psuderandom scale factor ``x'`` the pertubation vector, we ommit to store it and generate ``x'`` at random. Since ``x'`` is a ``f32`` randomly sampled from 0 to 1 which means there's a one in 16.7 million chance it can be guessed. 

Included in this library is an implementation of the original SAP scheme as described in Approximate Distance Comparison Preserving Symmetric Encryption. 

## Usage
### SAP
```rust
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
```

## SSAP

```rust
pub fn encrypt_with_key(){
    let plain_text = vec![0.02132726, -0.06046767, 0.018071115, 0.016465398];
    let seed = HashKey::new(4, 0.05, 2.0);
    let ciphert_text = hash(&seed, x);
    assert!(plain_text != cipher_text);
}

```