// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
mod negotiated;
#[macro_use]
mod header_key;

mod aead;
mod cipher_suite;
mod iv;

#[cfg(not(target_os = "windows"))]
use aws_lc_rs as ring;

#[doc(hidden)]
pub use ring::{
    aead as bla_ring_aead,
    aead::{Algorithm as BlaAlgorithm, MAX_TAG_LEN},
    constant_time as bla_constant_time,
    hkdf as bla_hkdf,
    hkdf::Prk as BlaPrk,
};
pub use ring::{
    constant_time as nope_constant_time, digest as nope_digest,
    hmac as nope_hmac,
};

#[derive(Clone)]
pub struct SecretPair {
    pub server: BlaPrk,
    pub client: BlaPrk,
}

pub mod handshake;
pub mod initial;
pub mod one_rtt;
pub mod retry;
pub mod zero_rtt;

#[derive(Clone, Copy, Debug, Default)]
pub struct Suite;

impl s2n_quic_core::crypto::CryptoSuite for Suite {
    type HandshakeKey = handshake::HandshakeKey;
    type HandshakeHeaderKey = handshake::HandshakeHeaderKey;
    type InitialKey = initial::InitialKey;
    type InitialHeaderKey = initial::InitialHeaderKey;
    type OneRttKey = one_rtt::OneRttKey;
    type OneRttHeaderKey = one_rtt::OneRttHeaderKey;
    type ZeroRttKey = zero_rtt::ZeroRttKey;
    type ZeroRttHeaderKey = zero_rtt::ZeroRttHeaderKey;
    type RetryKey = retry::RetryKey;
}
