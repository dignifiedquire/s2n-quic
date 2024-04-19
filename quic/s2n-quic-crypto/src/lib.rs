// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// audit
// D: no audit needed
// A: needs audit
//
// D- impl core::crypto::CryptoSuite for Suite {handshake, initial, onertt, zerortt, retry}
//   - handshake, initial,onertt... none expose private fields so we can simply audit the code in those modules
// D- SecretPair {pub server: Prk, pub client: Prk}
//   - exposes pub server and client so we need to audit those usage
// D- SecretPair::server - only used for constucting SecretPair
// D- SecretPair::client - only used for constucting SecretPair
//
// D- ring::aead::MAX_TAG_LEN - this is just a constant
// D- ring::constant_time - not an algo and also not used for encryption
// D- ring::aead::Algorithm - not used publically.. moved to private
// - TODO ring::aead as ring_aead
//   - aead.rs
//      - aead::Aad::from()
//      - LessSafeKey::seal_in_place_separate_tag()
//      - LessSafeKey::seal_in_place_scatter()
//      - LessSafeKey::open_in_place()
//      - Nonce::assume_unique_for_key()
//   - retry.rs
//      - UnboundKey::new
//      - Nonce::assume_unique_for_key()
//      - LessSafeKey::seal_in_place_separate_tag()
//   - header_key.rs
//      - HeaderProtectionKey::new_mask()
// - ring::hkdf
//   - crate/initial.rs
//      - hkdf::Salt.extract()
//      - hkdf::Prk.expand()
//   - crate/header_key.rs
//      - hkdf::Prk.expand()
//      - hkdf::Okm.fill()
// - ring::hkdf::Prk
//   - tls/callback.rs - called when tls generates a new secret and passes it to quic
//      - Prk::new_less_safe(prk_algo, secret)
//   - crate/iv.rs
//      - hkdf::Prk.expand()
//      - hkdf::Okm.fill()
//   - crate/cipher_suite.rs
//      - hkdf::Prk.expand()
//      - hkdf::Okm.fill()
// - cipher_suite module



#[macro_use]
mod negotiated;
#[macro_use]
mod header_key;

mod aead;
mod cipher_suite;
mod iv;

#[cfg(not(target_os = "windows"))]
use aws_lc_rs as ring;

// PUBLIC
#[doc(hidden)]
pub use ring::{
    aead as good_ring_aead,
    aead::{MAX_TAG_LEN},
    constant_time as good_constant_time,
    hkdf as good_hkdf,
    hkdf::Prk as AuditPrk,
};

// PRIVATE
use ring::aead::{Algorithm as GoodAlgorithm};
use ring::hkdf::Prk as GoodPrk;
use ring::hkdf::Prk as AuditInternalPrk;
use ring::hkdf as good_internal_hkdf;
use ring::hkdf as audit_internal_hkdf;
// TODO see if all these need audit
use ring::aead as bla_internal_aead;
use ring::aead as audit_internal_aead;
use ring::aead as good_internal_aead;

// NOT used for encryption
pub use ring::{
    constant_time as nope_constant_time, digest as nope_digest,
    hmac as nope_hmac,
};

#[derive(Clone)]
pub struct GoodSecretPair {
    good_server: GoodPrk,
    good_client: GoodPrk,
}

impl GoodSecretPair {
    pub fn new(good_server: GoodPrk, good_client: GoodPrk) -> Self {
        GoodSecretPair {
            good_server,
            good_client
        }
    }
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
