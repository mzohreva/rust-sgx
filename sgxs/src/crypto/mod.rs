/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub type Hash = [u8; 32];

pub trait SgxHashOps {
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finish(self) -> Hash;
}

pub trait SgxRsaOps {
    type Error: ::std::error::Error;

    /// Return the number of bits in the RSA key
    fn len(&self) -> usize;

    /// Generate an RSASSA-PKCS1-v1_5 signature over a SHA256 hash. Also
    /// compute
    /// - `q1 = s^2 / n`
    /// - `q2 = (s^3 - q1*s*n) / n`
    /// where `/` is integer division.
    ///
    /// Returns `(s, q1, q2)` in little-endian format.
    ///
    /// ### Panics
    /// May panic if the input length is not 32, or if the key does not contain
    /// the private component.
    fn sign_sha256_pkcs1v1_5_with_q1_q2<H: AsRef<[u8]>>(
        &self,
        hash: H,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Self::Error>;

    /// Verify an RSASSA-PKCS1-v1_5 signature `s` over a SHA256 hash.
    ///
    /// Supply `s` in little-endian format.
    ///
    /// ### Panics
    /// May panic if the hash input length is not 32.
    fn verify_sha256_pkcs1v1_5<S: AsRef<[u8]>, H: AsRef<[u8]>>(
        &self,
        sig: S,
        hash: H,
    ) -> Result<(), Self::Error>;

    /// Retrieve the public key in little-endian format
    fn e(&self) -> Vec<u8>;

    /// Retrieve the modulus in little-endian format
    fn n(&self) -> Vec<u8>;
}

#[cfg(feature = "crypto-openssl")]
mod openssl;

#[cfg(feature = "crypto-mbedtls")]
pub mod mbedtls;

#[cfg(feature = "crypto-external")]
pub mod external;

#[cfg(all(test))]
mod tests;
