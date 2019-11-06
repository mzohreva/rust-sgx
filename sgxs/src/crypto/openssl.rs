use super::*;

use foreign_types::ForeignTypeRef;
use openssl::bn::{BigNum, BigNumContext};
use openssl::error::ErrorStack as SslError;
use openssl::hash::{Hasher, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, Private, Public};
use openssl::rsa::RsaRef;
use openssl_sys as ffi;

impl SgxHashOps for Hasher {
    fn new() -> Self {
        Hasher::new(MessageDigest::sha256()).expect("failed to create openssl hasher")
    }

    fn update(&mut self, data: &[u8]) {
        self.update(data).expect("failed to update openssl hasher");
    }

    fn finish(mut self) -> Hash {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(
            &Hasher::finish(&mut self).expect("failed to finish openssl hasher"),
        );
        hash
    }
}

pub trait MaybePrivate: Sized {
    fn as_private(rsa: &RsaRef<Self>) -> &RsaRef<Private>;
}

impl MaybePrivate for Private {
    fn as_private(rsa: &RsaRef<Self>) -> &RsaRef<Private> {
        rsa
    }
}

impl MaybePrivate for Public {
    fn as_private(_rsa: &RsaRef<Self>) -> &RsaRef<Private> {
        panic!("Requires private key!")
    }
}

impl<T: HasPublic + MaybePrivate> SgxRsaOps for RsaRef<T> {
    type Error = SslError;

    fn len(&self) -> usize {
        self.n().num_bits() as _
    }

    fn sign_sha256_pkcs1v1_5_with_q1_q2<H: AsRef<[u8]>>(
        &self,
        hash: H,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Self::Error> {
        // The following `unsafe` block was copied from `fn sign_with_hash`
        // https://github.com/sfackler/rust-openssl/tree/7515272692ea30ee320667563027f75508f1dc60.
        let mut s_vec = unsafe {
            // OpenSSL wrapper does not expose a function to sign hashes,
            // only unhashed data.
            // man RSA_sign: "sigret must point to RSA_size(rsa) bytes of memory."
            let mut r = vec![0; self.size() as _];

            let mut len = 0;
            let rv = ffi::RSA_sign(
                Nid::SHA256.as_raw(),
                hash.as_ref().as_ptr(),
                hash.as_ref().len() as _,
                r.as_mut_ptr(),
                &mut len,
                self.as_ptr(),
            );

            if rv < 0 {
                return Err(SslError::get());
            } else {
                r.truncate(len as _);
                r
            }
        };

        // Compute Q1 and Q2
        let mut s_2 = BigNum::new()?;
        let mut s_3 = BigNum::new()?;
        let mut q1 = BigNum::new()?;
        let mut tmp1 = BigNum::new()?;
        let mut tmp2 = BigNum::new()?;
        let mut tmp3 = BigNum::new()?;
        let mut q2 = BigNum::new()?;

        let mut ctx = BigNumContext::new()?;
        let s = BigNum::from_slice(&s_vec)?;
        let n = self.n();
        s_2.sqr(&s, &mut ctx)?;
        q1.checked_div(&s_2, &n, &mut ctx)?;

        s_3.checked_mul(&s_2, &s, &mut ctx)?;
        tmp1.checked_mul(&q1, &s, &mut ctx)?;
        tmp2.checked_mul(&tmp1, &n, &mut ctx)?;
        tmp3.checked_sub(&s_3, &tmp2)?;
        q2.checked_div(&tmp3, &n, &mut ctx)?;
        let mut q1 = q1.to_vec();
        let mut q2 = q2.to_vec();

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

        let ret = unsafe {
            // OpenSSL wrapper does not expose a function to verify hashes,
            // only unhashed data.
            ffi::RSA_verify(
                Nid::SHA256.as_raw(),
                hash.as_ref().as_ptr(),
                hash.as_ref().len() as _,
                sig.as_mut_ptr(),
                sig.len() as _,
                self.as_ptr(),
            )
        };

        if ret == 1 {
            Ok(())
        } else {
            Err(SslError::get())
        }
    }

    fn e(&self) -> Vec<u8> {
        let mut v = self.e().to_vec();
        v.reverse();
        v
    }

    fn n(&self) -> Vec<u8> {
        let mut v = self.n().to_vec();
        v.reverse();
        v
    }
}
