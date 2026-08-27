//! The **mint digest** the `Pevm` committee signs — the bridge between a finalized Beldex
//! deposit and a wBDX `mint`. It must equal, byte-for-byte, both the signer's
//! `watch.rs::MintEvent::mint_preimage` (the preimage members agree on) and the digest the
//! contract recomputes in `mint(...)` before `ecrecover`. This module lets an operator
//! compute it locally and feed it to the signer's `sign` subcommand
//! (`BRIDGE_SIGNER_SIGN_DIGEST`), closing the manual mint loop.
//!
//! ```text
//!   preimage = abi.encode(MINT_TAG, chainId, wBDX, keyEpoch, to, amount,
//!                         beldexTxid, outputIndex)                           // 8 words
//!   digest   = keccak256(preimage)
//! ```
//! where `MINT_TAG = keccak256("BELDEX_BRIDGE_MINT_V2")` — the same value the signer hardcodes
//! and the contract computes.

use crate::abi::{word_address, word_u256};
use sha3::{Digest, Keccak256};

/// The wBDX mint domain tag string (hashed to form `MINT_TAG`).
pub const MINT_TAG_STRING: &[u8] = b"BELDEX_BRIDGE_MINT_V2";

/// `MINT_TAG = keccak256("BELDEX_BRIDGE_MINT_V2")`.
pub fn mint_tag() -> [u8; 32] {
    Keccak256::digest(MINT_TAG_STRING).into()
}

/// The exact V2 mint preimage enforced by `WrappedBDX` (8 × 32-byte words).
pub fn mint_preimage(
    chain_id: u64,
    contract: [u8; 20],
    key_epoch: u64,
    to: [u8; 20],
    amount: u128,
    beldex_txid: [u8; 32],
    output_index: u32,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 * 8);
    v.extend_from_slice(&mint_tag());
    v.extend_from_slice(&word_u256(chain_id as u128));
    v.extend_from_slice(&word_address(contract));
    v.extend_from_slice(&word_u256(key_epoch as u128));
    v.extend_from_slice(&word_address(to));
    v.extend_from_slice(&word_u256(amount));
    v.extend_from_slice(&beldex_txid);
    v.extend_from_slice(&word_u256(output_index as u128));
    v
}

/// `keccak256(mint_preimage(...))` — the 32-byte digest the committee signs and the contract
/// `ecrecover`s.
pub fn mint_digest(
    chain_id: u64,
    contract: [u8; 20],
    key_epoch: u64,
    to: [u8; 20],
    amount: u128,
    beldex_txid: [u8; 32],
    output_index: u32,
) -> [u8; 32] {
    Keccak256::digest(mint_preimage(
        chain_id, contract, key_epoch, to, amount, beldex_txid, output_index,
    ))
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_tag_is_keccak_of_the_domain_string() {
        // Same value the signer hardcodes (watch.rs::MINT_TAG) and the contract computes.
        assert_eq!(
            mint_tag(),
            [
                0x26, 0xd4, 0x8d, 0x33, 0xd4, 0x13, 0xc4, 0x4f, 0xc6, 0xf4, 0x27, 0x94, 0x83, 0xab, 0x40, 0xc9,
                0x93, 0x1a, 0xec, 0xbd, 0x2d, 0x2b, 0x35, 0x5f, 0x50, 0x3e, 0x48, 0xd6, 0x9e, 0x40, 0xdb, 0xf1,
            ]
        );
    }

    #[test]
    fn preimage_is_eight_abi_words_in_order() {
        let contract = [0x22u8; 20];
        let to = [0x11u8; 20];
        let txid = [0xcdu8; 32];
        let p = mint_preimage(1, contract, 7, to, 1000, txid, 9);
        assert_eq!(p.len(), 32 * 8);
        assert_eq!(&p[0..32], &mint_tag());            // MINT_TAG
        assert_eq!(p[32 + 31], 1);                     // chainId in the low byte
        assert_eq!(&p[64 + 12..96], &contract);        // wBDX (right-aligned)
        assert_eq!(p[96 + 31], 7);                     // keyEpoch
        assert_eq!(&p[128 + 12..160], &to);            // to (right-aligned)
        assert_eq!(&p[160 + 16..192], &1000u128.to_be_bytes()); // amount low 16 bytes
        assert_eq!(&p[192..224], &txid);               // beldexTxid verbatim
        assert_eq!(p[224 + 31], 9);                    // outputIndex
    }

    #[test]
    fn digest_is_deterministic_and_field_sensitive() {
        let c = [0x22u8; 20];
        let to = [0x11u8; 20];
        let txid = [0xcdu8; 32];
        let base = mint_digest(1, c, 7, to, 1000, txid, 9);
        assert_eq!(base, mint_digest(1, c, 7, to, 1000, txid, 9));
        // Any field change moves the digest (no accidental cross-binding).
        assert_ne!(base, mint_digest(2, c, 7, to, 1000, txid, 9));
        assert_ne!(base, mint_digest(1, [0x23; 20], 7, to, 1000, txid, 9));
        assert_ne!(base, mint_digest(1, c, 8, to, 1000, txid, 9));
        assert_ne!(base, mint_digest(1, c, 7, [0x12; 20], 1000, txid, 9));
        assert_ne!(base, mint_digest(1, c, 7, to, 1001, txid, 9));
        assert_ne!(base, mint_digest(1, c, 7, to, 1000, [0xce; 32], 9));
        assert_ne!(base, mint_digest(1, c, 7, to, 1000, txid, 10));
        assert_eq!(
            base,
            [
                0x34, 0x20, 0xcc, 0xd3, 0xb8, 0x9e, 0xd0, 0xc0, 0x0a, 0x28, 0x24, 0x0f,
                0xdb, 0x5a, 0xe0, 0xbc, 0xac, 0xd7, 0x64, 0x87, 0x84, 0x8a, 0x96, 0x67,
                0x73, 0x3c, 0xfb, 0x6f, 0x62, 0xa1, 0x8c, 0x21,
            ],
            "must match keccak256(Solidity abi.encode V2 vector)"
        );
    }
}
