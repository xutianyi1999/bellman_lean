#![feature(slice_flatten)]

use bellman::groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    Parameters,
};
use bellman::{Circuit, ConstraintSystem, SynthesisError, Variable};
use bls12_381::{Bls12, Scalar};
use pairing::group::ff::PrimeField;
use rand::thread_rng;

#[derive(Clone)]
struct XORCipher<Fr: PrimeField> {
    plaintext: Vec<[Fr; 8]>,
    ciphertext: Vec<[Fr; 8]>,
    key: [[Fr; 8]; 16],
}

fn constraint_0_or_1<Fr: PrimeField, CS: ConstraintSystem<Fr>>(v: Variable, cs: &mut CS) {
    cs.enforce(
        || "constraint_0_or_1",
        |lc| lc + v - CS::one(),
        |lc| lc + v,
        |lc| lc + (Fr::from(0), CS::one()),
    )
}

// 2a * b = a + b - c
fn xor<Fr: PrimeField, CS: ConstraintSystem<Fr>>(
    a: Variable,
    b: Variable,
    key: Variable,
    cs: &mut CS,
) {
    cs.enforce(
        || "constraint_xor",
        |lc| lc + a + a,
        |lc| lc + key,
        |lc| lc + a + key - b,
    )
}

fn alloc_privates<Fr: PrimeField, CS: ConstraintSystem<Fr>>(
    list: &[[Fr; 8]],
    cs: &mut CS,
) -> Result<Vec<[Variable; 8]>, SynthesisError> {
    let mut res = Vec::with_capacity(list.len());

    for v in list {
        let arr = [
            cs.alloc(|| "alloc_privates", || Ok(v[0]))?,
            cs.alloc(|| "alloc_privates", || Ok(v[1]))?,
            cs.alloc(|| "alloc_privates", || Ok(v[2]))?,
            cs.alloc(|| "alloc_privates", || Ok(v[3]))?,
            cs.alloc(|| "alloc_privates", || Ok(v[4]))?,
            cs.alloc(|| "alloc_privates", || Ok(v[5]))?,
            cs.alloc(|| "alloc_privates", || Ok(v[6]))?,
            cs.alloc(|| "alloc_privates", || Ok(v[7]))?,
        ];
        res.push(arr)
    }
    Ok(res)
}

fn alloc_inputs<Fr: PrimeField, CS: ConstraintSystem<Fr>>(
    list: &[[Fr; 8]],
    cs: &mut CS,
) -> Result<Vec<[Variable; 8]>, SynthesisError> {
    let mut res = Vec::with_capacity(list.len());

    for v in list {
        let arr = [
            cs.alloc_input(|| "alloc_inputs", || Ok(v[0]))?,
            cs.alloc_input(|| "alloc_inputs", || Ok(v[1]))?,
            cs.alloc_input(|| "alloc_inputs", || Ok(v[2]))?,
            cs.alloc_input(|| "alloc_inputs", || Ok(v[3]))?,
            cs.alloc_input(|| "alloc_inputs", || Ok(v[4]))?,
            cs.alloc_input(|| "alloc_inputs", || Ok(v[5]))?,
            cs.alloc_input(|| "alloc_inputs", || Ok(v[6]))?,
            cs.alloc_input(|| "alloc_inputs", || Ok(v[7]))?,
        ];
        res.push(arr)
    }
    Ok(res)
}

impl<Fr: PrimeField> Circuit<Fr> for XORCipher<Fr> {
    fn synthesize<CS: ConstraintSystem<Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        assert_eq!(self.ciphertext.len(), self.plaintext.len());

        let plaintext = alloc_inputs(&self.plaintext, cs)?;
        let ciphertext = alloc_inputs(&self.ciphertext, cs)?;
        let key = alloc_privates(&self.key, cs)?;

        for a in &plaintext {
            for b in a {
                constraint_0_or_1(*b, cs)
            }
        }

        for a in &ciphertext {
            for b in a {
                constraint_0_or_1(*b, cs)
            }
        }

        for a in &key {
            for b in a {
                constraint_0_or_1(*b, cs)
            }
        }

        for i in 0..plaintext.len() {
            let p = plaintext[i];
            let c = ciphertext[i];
            let k = key[i % 16];

            for x in 0..8 {
                xor(p[x], c[x], k[x], cs);
            }
        }

        Ok(())
    }
}

fn convert<Fr: PrimeField>(buff: &[u8]) -> Vec<[Fr; 8]> {
    buff.iter()
        .map(|v| {
            [
                Fr::from((v >> 0 & 1) as u64),
                Fr::from((v >> 1 & 1) as u64),
                Fr::from((v >> 2 & 1) as u64),
                Fr::from((v >> 3 & 1) as u64),
                Fr::from((v >> 4 & 1) as u64),
                Fr::from((v >> 5 & 1) as u64),
                Fr::from((v >> 6 & 1) as u64),
                Fr::from((v >> 7 & 1) as u64),
            ]
        })
        .collect()
}

fn xor_encode(buff: &mut [u8], key: &[u8; 16]) {
    for i in 0..buff.len() {
        buff[i] ^= key[i % 16];
    }
}

fn main() {
    let rng = &mut thread_rng();

    let p = b"abc";
    let k: [u8; 16] = 13245435u128.to_le_bytes();
    let mut c = p.to_vec();
    let c = &mut *c;

    xor_encode(c, &k);

    let circuit = XORCipher::<Scalar> {
        plaintext: convert(p),
        ciphertext: convert(c),
        key: [[Scalar::zero(); 8]; 16],
    };

    let params: Parameters<Bls12> = generate_random_parameters(circuit, rng).unwrap();
    let pvk = prepare_verifying_key(&params.vk);

    let mut key = [[Scalar::zero(); 8]; 16];
    key.copy_from_slice(&convert(&k));

    let circuit = XORCipher::<Scalar> {
        plaintext: convert(p),
        ciphertext: convert(c),
        key,
    };
    let proof = create_random_proof(circuit, &params, rng).unwrap();

    let mut pub_inputs: Vec<[Scalar; 8]> = convert(p);
    pub_inputs.append(&mut convert(c));
    let pub_inputs = pub_inputs.flatten();

    verify_proof(&pvk, &proof, pub_inputs).unwrap()
}
