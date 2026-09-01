//! Watchers (**Phase E**): each committee member independently observes **both**
//! chains and only lets a signing session start on events it has itself confirmed —
//! no shared oracle (whitepaper §3.1, §6). This module is the **std-only core**:
//!
//!   * **E.1/E.2 normalized events** — [`MintEvent`] (a finalized Beldex gateway
//!     deposit → an EVM wBDX mint) and [`ReleaseEvent`] (a confirmed EVM wBDX burn →
//!     an L1 BDX release), each reduced to a **canonical, deterministic byte
//!     encoding**. Honest members watching divergent RPCs derive the *same* bytes
//!     for the same on-chain fact; any tampering changes the bytes (→ a NACK, never
//!     a silent accept).
//!   * **S9 reorg-safe finality** — [`FinalityGate`] / [`Tracker`]: an event is
//!     actionable only after enough confirmations *and* while its inclusion block is
//!     still canonical; an event that reorgs away before finality is **dropped** and
//!     never triggers signing.
//!   * **E.4 independent agreement** — [`MemberWatch`]: this member's set of
//!     independently-finalized canonical ids. `verify_proposal` answers the session
//!     engine's Consensus stage — ACK a leader proposal only if *this* member
//!     observed exactly it, else NACK (feeds S4).
//!
//! The mint canonical bytes are the **`abi.encode` preimage the wBDX contract
//! keccak-hashes** (Phase H), so the digest members agree on is exactly the one
//! `ecrecover` checks. The actual RPC clients (Beldex `gateway_get_history`, EVM
//! JSON-RPC) are the I/O layer and a feature-gated follow-on; this core is driven by
//! plain data so it is fully testable without a network.

use crate::chain_registry::ChainId;
use crate::session::NackReason;
use std::collections::BTreeSet;

/// Domain tag for the L1 gateway release signature (matches
/// `config::GW_INPUT_SIG`, with genesis binding — S6).
pub const GW_INPUT_SIG: &[u8] = b"gateway_input_sig";

/// The wBDX mint domain tag: **`keccak256("BELDEX_BRIDGE_MINT_V2")`** — matching the
/// contract's `bytes32 constant MINT_TAG = keccak256("BELDEX_BRIDGE_MINT_V2")`, so the
/// digests coincide. Hardcoded as the precomputed hash (this module is std-only core;
/// `sha3` is a feature-gated dep, so we do not hash at runtime here). The
/// `mint_tag_is_keccak_of_the_domain_string` test re-derives it wherever a keccak is
/// available, guarding against drift.
pub const MINT_TAG: [u8; 32] = [
    0x26, 0xd4, 0x8d, 0x33, 0xd4, 0x13, 0xc4, 0x4f, 0xc6, 0xf4, 0x27, 0x94, 0x83, 0xab, 0x40, 0xc9,
    0x93, 0x1a, 0xec, 0xbd, 0x2d, 0x2b, 0x35, 0x5f, 0x50, 0x3e, 0x48, 0xd6, 0x9e, 0x40, 0xdb, 0xf1,
];

/// `keccak256("BELDEX_BRIDGE_MINT_V2")`. See [`MINT_TAG`].
pub fn mint_tag() -> [u8; 32] {
    MINT_TAG
}

/// A `uint256` big-endian encoding of a `u128` (left-padded to 32 bytes).
fn u256_be(x: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&x.to_be_bytes());
    out
}

/// A Solidity `address` encoded as `abi.encode` does — left-padded to 32 bytes.
fn addr32(a: [u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&a);
    out
}

/// A finalized Beldex gateway **deposit**, normalized to a mint intent (E.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintEvent {
    /// The L1 deposit tx id.
    pub beldex_txid: [u8; 32],
    /// Index of this deposit's gateway output within `beldex_txid`. Together with the
    /// tx id this is the replay nonce the contract dedupes on: consensus permits up to
    /// `GATEWAY_TX_MAX_OUTPUTS` gateway outputs per tx, each its own deposit (H-2).
    pub output_index: u32,
    /// Destination EVM chain (from the Phase A.5 routing memo / pid registry).
    pub dst_chain: ChainId,
    /// Active wBDX signer generation. V2 binds this into the signature so a
    /// signature produced before a rotation cannot be replayed after it.
    pub key_epoch: u64,
    /// Destination EVM recipient.
    pub to: [u8; 20],
    /// Amount in atomic units.
    pub amount: u128,
}

impl MintEvent {
    /// The `abi.encode(MINT_TAG, chainid, wBDX, keyEpoch, to, amount,
    /// beldexTxid, outputIndex)` preimage the
    /// wBDX contract keccak-hashes and `ecrecover`s (`Pevm` signs `keccak256` of
    /// this), where `MINT_TAG = keccak256("BELDEX_BRIDGE_MINT_V2")`. Binding the
    /// contract address + chain id makes a mint non-replayable across chains/contracts;
    /// `beldex_txid` makes it single-use.
    pub fn mint_preimage(&self, contract: [u8; 20]) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 * 8);
        v.extend_from_slice(&mint_tag());
        v.extend_from_slice(&u256_be(self.dst_chain.0 as u128));
        v.extend_from_slice(&addr32(contract));
        v.extend_from_slice(&u256_be(self.key_epoch as u128));
        v.extend_from_slice(&addr32(self.to));
        v.extend_from_slice(&u256_be(self.amount));
        v.extend_from_slice(&self.beldex_txid);
        v.extend_from_slice(&u256_be(self.output_index as u128));
        v
    }

    /// The canonical id members agree on (E.4) = the exact mint preimage, so
    /// agreement is on the precise thing to be signed.
    pub fn canonical_id(&self, contract: [u8; 20]) -> Vec<u8> {
        self.mint_preimage(contract)
    }
}

/// A confirmed EVM wBDX **burn**, normalized to a release intent (E.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseEvent {
    /// The EVM burn tx id.
    pub evm_txid: [u8; 32],
    /// Index of this burn's log within `evm_txid`. Together with `evm_txid` this is
    /// the L1-side replay nonce: a single transaction may carry several burns, so the
    /// tx id alone does not identify one (H-1).
    pub log_index: u32,
    /// Source EVM chain.
    pub chain: ChainId,
    /// Amount in atomic units.
    pub amount: u128,
    /// The L1 BDX recipient (opaque bytes — an address or integrated address).
    pub beldex_recipient: Vec<u8>,
}

impl ReleaseEvent {
    /// The canonical **release intent** bytes members agree on (E.4), domain-
    /// separated and **genesis-bound** (S6/S14). The concrete `Pgw` signing digest
    /// `H(GW_INPUT_SIG ‖ genesis ‖ tx_prefix)` is derived when the release tx is
    /// built downstream (deterministically from this intent), so agreeing on the
    /// intent fixes what gets signed.
    pub fn canonical_id(&self, genesis: [u8; 32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(
            GW_INPUT_SIG.len() + 32 + 32 + 4 + 8 + 16 + self.beldex_recipient.len(),
        );
        v.extend_from_slice(GW_INPUT_SIG);
        v.extend_from_slice(&genesis);
        v.extend_from_slice(&self.evm_txid);
        v.extend_from_slice(&self.log_index.to_be_bytes());
        v.extend_from_slice(&self.chain.0.to_be_bytes());
        v.extend_from_slice(&self.amount.to_be_bytes());
        v.extend_from_slice(&(self.beldex_recipient.len() as u32).to_be_bytes());
        v.extend_from_slice(&self.beldex_recipient);
        v
    }
}

/// Finality classification of an observed event (S9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finality {
    /// Seen, but not yet deep enough — do not act.
    Pending,
    /// Deep enough and still canonical — actionable.
    Final,
    /// Its inclusion block reorged away before finality — never act.
    Dropped,
}

/// One observation of an event at a specific block (the reorg anchor).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation<E> {
    pub event: E,
    /// Height of the block that included the event.
    pub inclusion_height: u64,
    /// Hash of that block (to detect a reorg replacing it).
    pub block_hash: [u8; 32],
}

/// Pure finality decision. `confirmations` counts blocks built **on top of** the
/// inclusion block (depth): an event `required_confs` deep is [`Finality::Final`],
/// unless its block is no longer canonical (→ [`Finality::Dropped`]).
pub struct FinalityGate;

impl FinalityGate {
    pub fn classify(
        inclusion_height: u64,
        still_canonical: bool,
        tip_height: u64,
        required_confs: u64,
    ) -> Finality {
        if !still_canonical {
            return Finality::Dropped;
        }
        let depth = tip_height.saturating_sub(inclusion_height);
        if depth >= required_confs {
            Finality::Final
        } else {
            Finality::Pending
        }
    }
}

/// Result of advancing a [`Tracker`] to a new tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerUpdate<E> {
    /// Events that just became final (actionable this poll).
    pub finalized: Vec<E>,
    /// Observations dropped because their block reorged away before finality.
    pub dropped: Vec<Observation<E>>,
}

/// A reorg-aware finalizer for one chain's observations (S9). Holds pending
/// observations and, each time the tip advances, moves them to *finalized* (deep +
/// canonical) or *dropped* (reorged away), leaving the rest pending.
#[derive(Debug, Clone, Default)]
pub struct Tracker<E> {
    pending: Vec<Observation<E>>,
    required_confs: u64,
}

impl<E: Clone> Tracker<E> {
    pub fn new(required_confs: u64) -> Tracker<E> {
        Tracker {
            pending: Vec::new(),
            required_confs,
        }
    }

    /// Record a freshly-seen observation (idempotence is the caller's concern).
    pub fn observe(&mut self, obs: Observation<E>) {
        self.pending.push(obs);
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// The observations awaiting finality — the caller reads their inclusion
    /// heights to fetch current block hashes before [`poll`](Self::poll).
    pub fn pending(&self) -> &[Observation<E>] {
        &self.pending
    }

    /// Advance to `tip_height`. `is_canonical(inclusion_height, &block_hash)` must
    /// report whether that exact block is still on the canonical chain (the RPC
    /// layer answers this; in tests it's a closure). Returns what finalized and what
    /// dropped this step; both are removed from the pending set.
    pub fn poll<F>(&mut self, tip_height: u64, mut is_canonical: F) -> TrackerUpdate<E>
    where
        F: FnMut(u64, &[u8; 32]) -> bool,
    {
        let mut finalized = Vec::new();
        let mut dropped = Vec::new();
        let mut still_pending = Vec::new();

        for obs in self.pending.drain(..) {
            let canonical = is_canonical(obs.inclusion_height, &obs.block_hash);
            match FinalityGate::classify(
                obs.inclusion_height,
                canonical,
                tip_height,
                self.required_confs,
            ) {
                Finality::Final => finalized.push(obs.event),
                Finality::Dropped => dropped.push(obs),
                Finality::Pending => still_pending.push(obs),
            }
        }
        self.pending = still_pending;
        TrackerUpdate { finalized, dropped }
    }
}

/// This member's independent view for **E.4 agreement**: the set of canonical event
/// ids it has itself finalized. Drives the session's ACK/NACK — a leader proposal is
/// accepted only if this member observed exactly it.
#[derive(Debug, Clone, Default)]
pub struct MemberWatch {
    finalized_ids: BTreeSet<Vec<u8>>,
}

impl MemberWatch {
    pub fn new() -> MemberWatch {
        MemberWatch {
            finalized_ids: BTreeSet::new(),
        }
    }

    /// Mark a canonical id as independently finalized by this member.
    pub fn mark_final(&mut self, canonical_id: Vec<u8>) {
        self.finalized_ids.insert(canonical_id);
    }

    /// E.4: does this member's own watcher support the proposed event? ACK ⇔ true.
    pub fn verify_proposal(&self, canonical_id: &[u8]) -> bool {
        self.finalized_ids.contains(canonical_id)
    }

    /// The Consensus-stage decision this member yields for a leader's proposal
    /// (the proposal payload **is** the canonical event id): ACK only what this
    /// member independently finalized, else NACK `EventNotObserved` (E.4 → S4).
    pub fn decide(&self, proposed_canonical_id: &[u8]) -> ProposalDecision {
        if self.verify_proposal(proposed_canonical_id) {
            ProposalDecision::Ack
        } else {
            ProposalDecision::Nack(NackReason::EventNotObserved)
        }
    }

    pub fn finalized_count(&self) -> usize {
        self.finalized_ids.len()
    }
}

/// A member's Consensus-stage response to a leader proposal, produced by its own
/// watcher — fed straight into [`crate::session::Session::on_ack`] /
/// [`on_nack`](crate::session::Session::on_nack).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalDecision {
    Ack,
    Nack(NackReason),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mint(amount: u128) -> MintEvent {
        MintEvent {
            beldex_txid: [0xab; 32],
            output_index: 0,
            dst_chain: ChainId(1),
            key_epoch: 1,
            to: [0x11; 20],
            amount,
        }
    }

    #[test]
    fn mint_preimage_is_deterministic_and_abi_shaped() {
        let contract = [0x22u8; 20];
        let a = mint(1000).mint_preimage(contract);
        let b = mint(1000).mint_preimage(contract);
        assert_eq!(a, b, "same event → same bytes (honest members converge)");
        assert_eq!(a.len(), 32 * 8, "V2 abi.encode has 8 words");
        assert_eq!(&a[..32], &mint_tag(), "leads with MINT_TAG");
        // amount lives in the 6th word, big-endian in the low 16 bytes.
        assert_eq!(&a[32 * 5 + 16..32 * 6], &1000u128.to_be_bytes());
        // output_index is the 8th and last word (H-2): the deposit's gateway output.
        assert_eq!(&a[32 * 7 + 28..32 * 8], &0u32.to_be_bytes());

        // A different output of the SAME tx must produce different signed bytes,
        // otherwise one signature would authorize another deposit.
        let mut other = mint(1000);
        other.output_index = 1;
        assert_ne!(a, other.mint_preimage(contract), "output_index is bound in");
    }

    #[cfg(any(feature = "evm-watcher", feature = "tss-integration"))]
    #[test]
    fn mint_v2_digest_matches_solidity_abi_vector() {
        use sha3::{Digest, Keccak256};
        let ev = MintEvent {
            beldex_txid: [0xcd; 32],
            output_index: 9,
            dst_chain: ChainId(1),
            key_epoch: 7,
            to: [0x11; 20],
            amount: 1000,
        };
        let digest: [u8; 32] = Keccak256::digest(ev.mint_preimage([0x22; 20])).into();
        assert_eq!(
            digest,
            [
                0x34, 0x20, 0xcc, 0xd3, 0xb8, 0x9e, 0xd0, 0xc0, 0x0a, 0x28, 0x24, 0x0f, 0xdb, 0x5a,
                0xe0, 0xbc, 0xac, 0xd7, 0x64, 0x87, 0x84, 0x8a, 0x96, 0x67, 0x73, 0x3c, 0xfb, 0x6f,
                0x62, 0xa1, 0x8c, 0x21,
            ]
        );
    }

    /// Drift guard: the hardcoded [`MINT_TAG`] must equal `keccak256("BELDEX_BRIDGE_MINT_V2")`
    /// — the same value the contract computes. Runs wherever a keccak is available
    /// (`sha3` is feature-gated; this module's core is std-only, hence the hardcode).
    #[cfg(any(feature = "evm-watcher", feature = "tss-integration"))]
    #[test]
    fn mint_tag_is_keccak_of_the_domain_string() {
        use sha3::{Digest, Keccak256};
        let expected: [u8; 32] = Keccak256::digest(b"BELDEX_BRIDGE_MINT_V2").into();
        assert_eq!(
            MINT_TAG, expected,
            "MINT_TAG must be keccak256 of the domain string"
        );
    }

    #[test]
    fn tampering_any_field_changes_the_canonical_id() {
        let c = [0x22u8; 20];
        let base = mint(1000).canonical_id(c);
        assert_ne!(base, mint(1001).canonical_id(c), "amount");
        let mut other_to = mint(1000);
        other_to.to = [0x33; 20];
        assert_ne!(base, other_to.canonical_id(c), "recipient");
        assert_ne!(base, mint(1000).canonical_id([0x99; 20]), "contract");
    }

    #[test]
    fn release_canonical_is_genesis_bound() {
        let e = ReleaseEvent {
            evm_txid: [0x01; 32],
            log_index: 0,
            chain: ChainId(1),
            amount: 500,
            beldex_recipient: b"bxRecipient".to_vec(),
        };
        let g1 = e.canonical_id([0xaa; 32]);
        let g2 = e.canonical_id([0xbb; 32]);
        assert_ne!(
            g1, g2,
            "different genesis → different id (S6/S14, no cross-net replay)"
        );
        assert!(g1.starts_with(GW_INPUT_SIG));
    }

    #[test]
    fn finality_gate_pending_final_dropped() {
        // required 12 confs, included at height 100.
        assert_eq!(
            FinalityGate::classify(100, true, 105, 12),
            Finality::Pending
        );
        assert_eq!(FinalityGate::classify(100, true, 112, 12), Finality::Final);
        // reorged away (not canonical) → dropped, even if deep enough.
        assert_eq!(
            FinalityGate::classify(100, false, 200, 12),
            Finality::Dropped
        );
    }

    #[test]
    fn tracker_finalizes_deep_and_drops_reorged() {
        let mut t: Tracker<MintEvent> = Tracker::new(12);
        t.observe(Observation {
            event: mint(1),
            inclusion_height: 100,
            block_hash: [1; 32],
        });
        t.observe(Observation {
            event: mint(2),
            inclusion_height: 100,
            block_hash: [2; 32],
        });

        // Tip at 105: nothing deep enough yet.
        let u = t.poll(105, |_, _| true);
        assert!(u.finalized.is_empty() && u.dropped.is_empty());
        assert_eq!(t.pending_len(), 2);

        // Tip at 120: block [1;32] still canonical → final; block [2;32] reorged → dropped.
        let u = t.poll(120, |_h, hash| *hash == [1u8; 32]);
        assert_eq!(u.finalized, vec![mint(1)]);
        assert_eq!(u.dropped.len(), 1);
        assert_eq!(u.dropped[0].event, mint(2));
        assert_eq!(t.pending_len(), 0, "both resolved");
    }

    #[test]
    fn member_agreement_acks_only_what_it_finalized() {
        let c = [0x22u8; 20];
        let mut m = MemberWatch::new();
        let good = mint(1000).canonical_id(c);
        m.mark_final(good.clone());

        assert!(m.verify_proposal(&good), "ACK: independently observed");
        // A leader proposing a different amount → not in our view → NACK.
        assert!(!m.verify_proposal(&mint(9999).canonical_id(c)));
        // A reorg'd-away event we never finalized → NACK.
        assert!(!m.verify_proposal(&mint(1000).canonical_id([0x33; 20])));
    }

    // ---- E.4 → S4: the watcher decision drives the real session engine --------
    use crate::committee::CommitteeView;
    use crate::session::{Session, Stage};
    use crate::transport::Leg;

    fn committee(n: usize, t: usize) -> CommitteeView {
        CommitteeView {
            epoch: 2,
            height: 240,
            members: (0..n).map(|i| [i as u8; 32]).collect(),
            signer_keys: Vec::new(),
            member_ips: Vec::new(),
            member_x25519: Vec::new(),
            daemon_self_index: None,
            threshold: t,
        }
    }

    /// The leader proposes a finalized mint; each member's *own* watcher decides.
    /// Honest members that independently finalized it ACK and the session advances
    /// to Sign; a member that didn't observe it NACKs `EventNotObserved` without
    /// blocking the honest quorum.
    #[test]
    fn watcher_decision_drives_session_consensus() {
        let (n, t) = (6usize, 4usize);
        let contract = [0x22u8; 20];
        let proposal = mint(1000).canonical_id(contract); // the payload the leader proposes

        // Members 0..4 independently finalized it; members 4,5 did not.
        let mut members: Vec<MemberWatch> = (0..n).map(|_| MemberWatch::new()).collect();
        for m in members.iter_mut().take(4) {
            m.mark_final(proposal.clone());
        }

        // One member's local session view (member 0), driven by every member's
        // watcher decision (as their Ack/Nack frames arrive).
        let mut session =
            Session::start(&committee(n, t), Leg::Pevm, proposal.clone(), [9u8; 32], 0).unwrap();
        assert_eq!(session.stage(), Stage::Consensus);

        // Feed each member's decision; once the quorum advances past Consensus,
        // later frames are benign drops (as the real dispatcher treats them).
        let mut acks = 0;
        for (idx, m) in members.iter().enumerate() {
            match m.decide(&proposal) {
                ProposalDecision::Ack => {
                    let _ = session.on_ack(idx);
                    acks += 1;
                }
                ProposalDecision::Nack(reason) => {
                    assert_eq!(reason, NackReason::EventNotObserved);
                    let _ = session.on_nack(idx, reason);
                }
            }
        }
        assert_eq!(acks, 4, "the four honest observers ACK");
        assert_eq!(
            session.stage(),
            Stage::Sign,
            "honest t ACKs → advance to Sign"
        );
    }

    /// If a leader proposes an event too few members observed (e.g. fabricated or
    /// reorg'd away), the honest majority NACKs and the session never signs it.
    #[test]
    fn fabricated_proposal_never_reaches_sign() {
        let (n, t) = (6usize, 4usize);
        let contract = [0x22u8; 20];
        let real = mint(1000).canonical_id(contract);
        let fabricated = mint(9_999_999).canonical_id(contract);

        // Everyone finalized the real event; nobody finalized the fabricated one.
        let mut members: Vec<MemberWatch> = (0..n).map(|_| MemberWatch::new()).collect();
        for m in members.iter_mut() {
            m.mark_final(real.clone());
        }

        let mut session = Session::start(
            &committee(n, t),
            Leg::Pevm,
            fabricated.clone(),
            [9u8; 32],
            0,
        )
        .unwrap();
        for (idx, m) in members.iter().enumerate() {
            let _ = match m.decide(&fabricated) {
                ProposalDecision::Ack => session.on_ack(idx),
                ProposalDecision::Nack(r) => session.on_nack(idx, r),
            };
        }
        assert_ne!(
            session.stage(),
            Stage::Sign,
            "a fabricated payload is never signed"
        );
    }
}
