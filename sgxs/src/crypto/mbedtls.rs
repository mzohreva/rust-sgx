use super::*;

use mbedtls::Error as MbedtlsError;
use mbedtls::bignum::Mpi;
use mbedtls::hash::{Md, Type as MdType};
use mbedtls::pk::{Pk};
use mbedtls::rng::Rdrand;
use std::cell::RefCell;
use std::ops::{Sub, Div, Mul};

impl SgxHashOps for Md {
    fn new() -> Self {
        Md::new(MdType::Sha256).expect("failed to create mbedtls md")
    }

    fn update(&mut self, data: &[u8]) {
        self.update(data).expect("failed to update mbedtls md");
    }

    fn finish(self) -> Hash {
        let mut hash = [0u8; 32];
        self.finish(&mut hash).expect("failed to finish mbedtls md");
        hash
    }
}

pub struct PrivateKey(RefCell<Pk>);

impl PrivateKey {
    pub fn new(pk: Pk) -> Self {
        PrivateKey(RefCell::new(pk))
    }
}

impl SgxRsaOps for PrivateKey {
    type Error = MbedtlsError;

    fn len(&self) -> usize {
        self.0.borrow().len()
    }

    fn sign_sha256_pkcs1v1_5_with_q1_q2<H: AsRef<[u8]>>(
        &self,
        hash: H,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Self::Error> {
        let mut s_vec = vec![0; (self.0.borrow().len() + 7) / 8];
        let mut rng = Rdrand;
        let len = self.0.borrow_mut().sign(
            MdType::Sha256,
            hash.as_ref(),
            &mut s_vec,
            &mut rng
        )?;
        s_vec.truncate(len);

        // Compute Q1 and Q2
        let s = Mpi::from_binary(&s_vec)?;
        let n = self.0.borrow().rsa_public_modulus().expect("failed to get mbedtls rsa public modulus");
        let s_2 = s.mul(&s)?;
        let q1 = s_2.div(&n)?;

        let s_3 = s_2.mul(&s)?;
        let tmp1 = q1.mul(&s)?;
        let tmp2 = tmp1.mul(&n)?;
        let tmp3 = s_3.sub(&tmp2)?;
        let q2 = tmp3.div(&n)?;
        let mut q1 = q1.to_binary()?;
        let mut q2 = q2.to_binary()?;

        // Return in little-endian format
        q1.reverse();
        q2.reverse();
        s_vec.reverse();
        Ok((s_vec, q1, q2))
    }

    fn verify_sha256_pkcs1v1_5<S: AsRef<[u8]>, H: AsRef<[u8]>>(
        &self,
        sig: S,
        hash: H,
    ) -> Result<(), Self::Error> {
        // Convert to big-endian format
        let mut sig = sig.as_ref().to_owned();
        sig.reverse();

        self.0.borrow_mut().verify(MdType::Sha256, hash.as_ref(), &sig)
    }

    fn e(&self) -> Vec<u8> {
        let e = self.0.borrow().rsa_public_exponent().expect("failed to get mbedtls rsa public exponent");
        let mut e = Mpi::new(e as _).expect("failed to create mbedtls mpi")
            .to_binary().expect("failed to convert mbedtls rsa public exponent");
        e.reverse();
        e
    }

    fn n(&self) -> Vec<u8> {
        let n = self.0.borrow().rsa_public_modulus().expect("failed to get mbedtls rsa public modulus");
        let mut n = n.to_binary().expect("failed to convert mbedtls rsa public modulus");
        n.reverse();
        n
    }
}
