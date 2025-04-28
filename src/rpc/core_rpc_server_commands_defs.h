// Copyright (c) 2018-2020, The Beldex Project
// Copyright (c) 2014-2019, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

// vim help for nicely wrapping/formatting comments in here:
// Global options for wrapping and indenting lists within comments with gq:
//
//     set formatoptions+=n
//     set formatlistpat=^\\s*\\d\\+[\\]:.)}\\t\ ]\\s\\+\\\\|^\\s*[-+*]\\s\\+
//
// cpp-specific options to properly recognize `///` as a comment when wrapping, to go in
// ~/.vim/after/ftplugin/cpp.vim:
//
//     setlocal comments-=://
//     setlocal comments+=:///
//     setlocal comments+=://

#include "crypto/crypto.h"
#include "epee/string_tools.h"

#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/verification_context.h"
#include "cryptonote_basic/difficulty.h"
#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "cryptonote_core/master_node_voting.h"
#include "cryptonote_core/master_node_list.h"
#include "common/varint.h"
#include "common/perf_timer.h"
#include "common/meta.h"
#include "common/hex.h"
#include "checkpoints/checkpoints.h"

#include "cryptonote_core/master_node_quorum_cop.h"
#include "cryptonote_core/master_node_list.h"
#include "common/beldex.h"

#include "rpc_binary.h"
#include <nlohmann/json.hpp>
#include <oxenc/bt_serialize.h>
#include <type_traits>
#include <unordered_set>

namespace cryptonote {
  void to_json(nlohmann::json& j, const checkpoint_t& c);
}

namespace master_nodes {
  void to_json(nlohmann::json& j, const key_image_blacklist_entry& b);
  void to_json(nlohmann::json& j, const quorum_signature& s);
}

/// Namespace for core RPC commands.  Every RPC commands gets defined here (including its name(s),
/// access, and data type), and added to `core_rpc_types` list at the bottom of the file.
namespace cryptonote::rpc {

  using version_t = std::pair<uint16_t, uint16_t>;

// When making *any* change here, bump minor
// If the change is incompatible, then bump major and set minor to 0
// This ensures rpc::VERSION always increases, that every change
// has its own version, and that clients can just test major to see
// whether they can talk to a given daemon without having to know in
// advance which version they will stop working with
  constexpr version_t VERSION = {4, 1};

  /// Makes a version array from a packed 32-bit integer version
  constexpr version_t make_version(uint32_t version)
  {
    return {static_cast<uint16_t>(version >> 16), static_cast<uint16_t>(version & 0xffff)};
  }
  /// Packs a version array into a packed 32-bit integer version
  constexpr uint32_t pack_version(version_t version)
  {
    return (uint32_t(version.first) << 16) | version.second;
  }

  const static std::string
    STATUS_OK = "OK",
    STATUS_FAILED = "FAILED",
    STATUS_BUSY = "BUSY",
    STATUS_NOT_MINING = "NOT MINING",
    STATUS_TX_LONG_POLL_TIMED_OUT = "Long polling client timed out before txpool had an update";


  namespace {
    /// Returns a constexpr std::array of string_views from an arbitrary list of string literals
    /// Used to specify RPC names as:
    /// static constexpr auto names() { return NAMES("primary_name", "some_alias"); }
    template <size_t... N>
    constexpr std::array<std::string_view, sizeof...(N)> NAMES(const char (&...names)[N]) {
      static_assert(sizeof...(N) > 0, "RPC command must have at least one name");
      return {std::string_view{names, N-1}...};
    }
  }

  /// Base class that all RPC commands must inherit from (either directly or via one or more of the
  /// below tags).  Inheriting from this (and no others) gives you a private, json, non-legacy RPC
  /// command.  For LMQ RPC the command will be available at `admin.whatever`; for HTTP RPC it'll be
  /// at `whatever`.  This base class is also where response objects are stored.
  struct RPC_COMMAND {
    private:
      bool bt = false;
    public:
      /// Indicates whether this response is to be bt (true) or json (false) encoded.  Do not set.
      bool is_bt() const { return bt; }

      /// Called early in the request to indicate that this request is a bt-encoded one.
      void set_bt();

      /// The response data.  For bt-encoded responses we convert this on the fly, with the
      /// following notes:
      /// - boolean values become 0 or 1
      /// - key-value pairs with null values are omitted from the object
      /// - other null values are not permitted at all: an exception will be raised if the json
      /// contains such a value.
      /// - double values are not permitted; if a double is absolutely needed then check `is_bt`
      /// and, when bt, encode it in some documented, endpoint-specific way.
      /// - binary values in strings *are* permitted, but the caller must take care because they
      /// will not be permitted for actual json responses (json serialization will fail): the caller
      /// is expected to do something like:
      ///
      ///     std::string binary = some_binary_data();
      ///     cmd.response["binary_value"] = is_bt ? binary : oxenc::to_hex(binary);
      ///
      /// or, more conveniently, using the shortcut interface:
      ///
      ///      cmd.response_hex["binary_value"] = some_binary_data();
      nlohmann::json response;

      /// Proxy object that is used to set binary data in `response`, encoding it as hex if this
      /// data is being returned as json.  If this response is to be bt-encoded then the binary
      /// value is left as-is (which isn't valid for json, but can be transported inside the json
      /// value as we never dump() when going to bt-encoded).
      ///
      /// Usage:
      ///   std::string data = "abc";
      ///   rpc.response_hex["foo"]["bar"] = data; // json: "616263", bt: "abc"
      json_binary_proxy response_hex{response, json_binary_proxy::fmt::hex};

      /// Proxy object that encodes binary data as base64 for json, leaving it as binary for
      /// bt-encoded responses.
      ///
      /// Usage:
      ///   std::string data = "abc";
      ///   rpc.response_b64["foo"]["bar"] = data; // json: "YWJj", bt: "abc"
      json_binary_proxy response_b64{response, json_binary_proxy::fmt::base64};
  };

  /// Tag types that are used (via inheritance) to set rpc endpoint properties

  /// Specifies that the RPC call is public (i.e. available through restricted rpc).  If this is
  /// *not* inherited from then the command is restricted (i.e. only available to admins).  For LMQ,
  /// PUBLIC commands are available at `rpc.command` (versus non-PUBLIC ones at `admin.command`).
  struct PUBLIC : virtual RPC_COMMAND {};

  /// Specifies that the RPC call takes no input arguments.  (A dictionary of parameters may still
  /// be passed, but will be ignored).
  struct NO_ARGS : virtual RPC_COMMAND {};

  /// Specifies a "legacy" JSON RPC command, available via HTTP JSON at /whatever (in addition to
  /// json_rpc as "whatever").  When accessed via legacy mode the result is just the .result element
  /// of the JSON RPC response.  (Only applies to the HTTP RPC interface, and does nothing if BINARY
  /// if specified).
  struct LEGACY : virtual RPC_COMMAND {};


  /// (Not a tag). Generic, serializable, no-argument request type, use as `struct request : EMPTY {};`
  struct EMPTY { KV_MAP_SERIALIZABLE };

  /// (Not a tag). Generic response which contains only a status string; use as `struct response : STATUS {};`
  struct STATUS
  {
    std::string status; // General RPC error code. "OK" means everything looks good.

    KV_MAP_SERIALIZABLE
  };

  
  /// Get the node's current height.
  ///
  /// Inputs: none.
  ///
  /// Outputs:
  ///
  /// - \p height -- The current blockchain height according to the queried daemon.
  /// - \p status -- Generic RPC error code. "OK" is the success value.
  /// - \p untrusted -- If the result is obtained using bootstrap mode then this will be set to true, otherwise will be omitted.
  /// - \p hash -- Hash of the block at the current height
  /// - \p immutable_height -- The latest height in the blockchain that cannot be reorganized because of a hardcoded checkpoint or 2 MN checkpoints.  Omitted if not available.
  /// - \p immutable_hash -- Hash of the highest block in the chain that cannot be reorganized.
  struct GET_HEIGHT : PUBLIC, LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_height", "getheight"); }
  };

  /// Look up one or more transactions by hash.
  ///
  /// Outputs:
  ///
  /// - \p status -- Generic RPC error code. "OK" is the success value.
  /// - \p untrusted -- If the result is obtained using bootstrap mode then this will be set to
  /// - \p missed_tx -- set of transaction hashes that were not found.  If all were found then this
  ///   field is omitted.  There is no particular ordering of hashes in this list.
  /// - \p txs -- list of transaction details; each element is a dict containing:
  ///   - \p tx_hash -- Transaction hash.
  ///   - \p size -- Size of the transaction, in bytes. Note that if the transaction has been pruned
  ///     this is the post-pruning size, not the original size.
  ///   - \p in_pool -- Will be set to true if the transaction is in the transaction pool (`true`)
  ///     and omitted if mined into a block.
  ///   - \p flash -- True if this is an approved, flash transaction; this information is generally
  ///     only available for approved in-pool transactions and txes in very recent blocks.
  ///   - \p fee -- the transaction fee (in atomic BELDEX) incurred in this transaction (not including
  ///     any burned amount).
  ///   - \p burned -- the amount of BELDEX (in atomic units) burned by this transaction.
  ///   - \p block_height -- Block height including the transaction.  Omitted for tx pool
  ///     transactions.
  ///   - \p block_timestamp -- Unix time at which the block has been added to the blockchain.
  ///     Omitted for tx pool transactions.
  ///   - \p output_indices -- List of transaction indexes.  Omitted for tx pool transactions.
  ///   - \p relayed -- For `in_pool` transactions this field will be set to indicate whether the
  ///     transaction has been relayed to the network.
  ///   - \p double_spend_seen -- Will be set to true for tx pool transactions that are
  ///     double-spends (and thus cannot be added to the blockchain).  Omitted for mined
  ///     transactions.
  ///   - \p received_timestamp -- Timestamp transaction was received in the pool.  Omitted for
  ///     mined blocks.
    ///   - \p max_used_block -- the hash of the highest block referenced by this transaction; only
  ///     for mempool transactions.
  ///   - \p max_used_height -- the height of the highest block referenced by this transaction; only
  ///     for mempool transactions.
  ///   - \p last_failed_block -- the hash of the last block where this transaction was attempted to
  ///     be mined (but failed).
  ///   - \p max_used_height -- the height of the last block where this transaction failed to be
  ///     acceptable for a block.
  ///   - \p weight -- the transaction "weight" which is the size of the transaction with padding
  ///     removed.  Only included for mempool transactions (for mined transactions the size and
  ///     weight at the same and so only `size` is included).
  ///   - \p kept_by_block will be present and true if this is a mempool transaction that was added
  ///     to the mempool after being popped off a block (e.g. because of a blockchain
  ///     reorganization).
  ///   - \p last_relayed_time indicates the last time this block was relayed to the network; only
  ///     for mempool transactions.
  ///   - \p do_not_relay -- set to true for mempool blocks that are marked "do not relay"
  ///   - \p double_spend_seen -- set to true if one or more outputs in this mempool transaction
  ///     have already been spent (and thus the tx cannot currently be added to the blockchain).
  ///   - \p data -- Full, unpruned transaction data.  For a json request this is hex-encoded; for a
  ///     bt-encoded request this is raw bytes.  This field is omitted if any of `decode_as_json`,
  ///     `split`, or `prune` is requested; or if the transaction has been pruned in the database.
  ///   - \p pruned -- The non-prunable part of the transaction, encoded as hex (for json requests).
  ///     Always included if `split` or `prune` are specified; without those options it will be
  ///     included instead of `data` if the transaction has been pruned.
  ///   - \p prunable -- The prunable part of the transaction.  Only included when `split` is
  ///     specified, the transaction is prunable, and the tx has not been pruned from the database.
  ///   - \p prunable_hash -- The hash of the prunable part of the transaction.  Will be provided if
  ///     either: the tx has been pruned; or the tx is prunable and either of `prune` or `split` are
  ///     specified.
  ///   - \p extra -- Parsed "extra" transaction information; omitted unless specifically requested
  ///     (via the `tx_extra` request parameter).  This is a dict containing one or more of the
  ///     following keys.
  ///     - \p pubkey -- The tx extra public key
  ///     - \p burn_amount -- The amount of BELDEX that this transaction burns, if any.
  ///     - \p extra_nonce -- Optional extra nonce value (in hex); will be empty if nonce is
  ///       recognized as a payment id
  ///     - \p payment_id -- The payment ID, if present. This is either a 16 hex character (8-byte)
  ///       encrypted payment id, or a 64 hex character (32-byte) deprecated, unencrypted payment ID
  ///     - \p mm_depth -- (Merge-mining) the merge-mined depth
  ///     - \p mm_root -- (Merge-mining) the merge mining merkle root hash
  ///     - \p additional_pubkeys -- Additional public keys
  ///     - \p mn_winner -- Master node block reward winner public key
  ///     - \p mn_pubkey -- Master node public key (e.g. for registrations, stakes, unlocks)
  ///     - \p mn_contributor -- Master node contributor wallet address (for stakes)
  ///     - \p tx_secret_key -- The transaction secret key, included in registrations/stakes to
  ///       decrypt transaction amounts and recipients
  ///     - \p locked_key_images -- Key image(s) locked by the transaction (for registrations,
  ///       stakes)
  ///     - \p key_image_unlock -- A key image being unlocked in a stake unlock request (an unlock
  ///       will be started for *all* key images locked in the same MN contributions).
  ///     - \p mn_registration -- Master node registration details; this is a dict containing:
  ///       - \p fee the operator fee expressed in millionths (i.e. 234567 == 23.4567%)
  ///       - \p expiry the unix timestamp at which the registration signature expires
  ///       - \p contributors: dict of (wallet => portion) pairs indicating the staking portions
  ///         reserved for the operator and any reserved contribution spots in the registration.
  ///         Portion is expressed in millionths (i.e. 250000 = 25% staking portion).
  ///     - \p mn_state_change -- Information for a "state change" transaction such as a
  ///       deregistration, decommission, recommission, or ip change reset transaction.  This is a
  ///       dict containing:
  ///       - \p old_dereg will be set to true if this is an "old" deregistration transaction
  ///         (before the BDX 4 hardfork), omitted for more modern state change txes.
  ///       - \p type string indicating the state change type: "dereg", "decomm", "recomm", or "ip"
  ///         for a deregistration, decommission, recommission, or ip change penalty transaction.
  ///       - \p height the voting block height for the changing master node and voting master
  ///         nodes that produced this state change transaction.
  ///       - \p index the position of the affected node in the random list of tested nodes for this
  ///         `height`.
  ///       - \p voters the positions of validators in the testing quorum for this `height` who
  ///         tested and voted for this state change.  This typically contains the first 7 voters
  ///         who voted for the state change (out of a possible set of 10).
  ///       - \p reasons list of reported reasons for a decommission or deregistration as reported
  ///         by the voting quorum.  This contains any reasons that all 7+ voters agreed on, and
  ///         contains one or more of:
  ///         - \p "uptime" -- the master node was missing uptime proofs
  ///         - \p "checkpoints" -- the master node missed too many recent checkpoint votes
  ///         - \p "pos" -- the master node missed too many recent pos votes
  ///         - \p "storage" -- the master node's storage server was unreachable for too long
  ///         - \p "belnet" -- the master node's belnet router was unreachable for too long
  ///         - \p "timecheck" -- the master node's beldexd was not reachable for too many recent
  ///           time synchronization checks.  (This generally means beldexd's quorumnet port is not
  ///           reachable).
  ///         - \p "timesync" -- the master node's clock was too far out of sync
  ///         The list is omitted entirely if there are no reasons at all or if there are no reasons
  ///         that were agreed upon by all voting master nodes.
  ///       - \p reasons_maybe list of reported reasons that some but not all master nodes provided
  ///         for the deregistration/decommission.  Possible values are identical to the above.
  ///         This list is omitted entirely if it would be empty (i.e. there are no reasons at all,
  ///         or all voting master nodes agreed on all given reasons).
  ///     - \p bns -- BNS registration or update transaction details.  This contains keys:
  ///       - \p buy -- set to true if this is an BNS buy record; omitted otherwise.
  ///       - \p update -- set to true if this is an BNS record update; omitted otherwise.
  ///       - \p renew -- set to true if this is an BNS renewal; omitted otherwise.
  ///       - \p bchat_value -- the BNS request type string.  For registrations: "bchat",
  ///          for a record update: "update".
  ///       - \p wallet_value -- the BNS request type string.  For registrations: "wallet",
  ///          for a record update: "update".
  ///       - \p belnet_value -- the BNS request type string.  For registrations: "belnet",
  ///          for a record update: "update".
  ///       - \p blocks -- The registration length in blocks; omitted for registrations (such as
  ///         Session/Wallets) that do not expire.
  ///       - \p name_hash -- The hashed name of the record being purchased/updated.  Encoded in hex
  ///         for json requests.  Note that the actual name is not provided on the blockchain.
  ///       - \p prev_txid -- For an update this field is set to the txid of the previous BNS update
  ///         or registration (i.e. the most recent transaction that this record is updating).
  ///       - \p value -- The encrypted value of the record (in hex for json requests) being
  ///         set/updated.  \see ONS_RESOLVE for details on encryption/decryption.
  ///       - \p owner -- the owner of this record being set in a registration or update; this can
  ///         be a primary wallet address, wallet subaddress, or a plain public key.
  ///       - \p backup_owner -- an optional backup owner who also has permission to edit the
  ///         record.
  ///   - \p stake_amount -- Set to the calculated transaction stake amount (only applicable if the
  ///     transaction is a master node registration or stake).
  /// - \p mempool_key_images -- dict of spent key images of mempool transactions.  Only included
  ///   when `memory_pool` is set to true.  Each key is the key image (in hex, for json requests)
  ///   and each value is a list of transaction hashes that spend that key image (typically just
  ///   one, but in the case of conflicting transactions there can be multiple).
  struct GET_TRANSACTIONS : PUBLIC, LEGACY
  {
    static constexpr auto names() { return NAMES("get_transactions", "gettransactions"); }
    struct request_parameters
    {
      /// List of transaction hashes to look up.  (Will also be accepted as json input key
      /// "txs_hashes" for backwards compatibility).  Exclusive of `memory_pool`.
      std::vector<crypto::hash> tx_hashes;
      /// If true then return all transactions and spent key images currently in the memory pool.
      /// This field is exclusive of `tx_hashes`.
      bool memory_pool = false;
      /// If set to true then parse and return tx-extra information
      bool tx_extra = false;
      /// Controls whether the `data` (or `pruned`, if pruned) field containing raw tx data is
      /// included: if explicitly specified then the raw data will be included if true.  Otherwise
      /// the raw data is included only when neither of `split` nor `prune` are set to true.
      bool data = true;
      /// If set to true then always split transactions into non-prunable and prunable parts in the
      /// response.
      bool split = false;
      /// Like `split`, but also omits the prunable part of transactions from the response details.
      bool prune = false;
    } request;

  };

  /// Queries whether outputs have been spent using the key image associated with the output.
  ///
  /// Inputs:
  ///
  /// - \p key_images list of key images to check.  For json requests these must be hex or
  ///   base64-encoded; for bt-requests they can be hex/base64 or raw bytes.
  ///
  /// Outputs
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p untrusted States if the result is obtained using the bootstrap mode, and is therefore
  /// - \p spent_status array of status codes returned in the same order as the `key_images` input.
  ///   Each value is one of:
  ///   - \p 0 the key image is unspent
  ///   - \p 1 the key image is spent in a mined block
  ///   - \p 2 the key image is spent in a transaction currently in the mempool
  struct IS_KEY_IMAGE_SPENT : PUBLIC, LEGACY
  {
    static constexpr auto names() { return NAMES("is_key_image_spent"); }

    enum class SPENT : uint8_t {
      UNSPENT = 0,
      BLOCKCHAIN = 1,
      POOL = 2,
    };

    struct request_parameters {
      std::vector<crypto::key_image> key_images;
    } request;
  };

  //-----------------------------------------------
  /// Retrieve outputs
  ///
  /// Inputs:
  ///
  /// - \p outputs Array of output indices.  For backwards compatibility these may also be passed as
  ///   an array of {"amount":0,"index":n} dicts.
  /// - \p get_txid Request the TXID (i.e. hash) of the transaction as well.
  /// - \p as_tuple Requests the returned outs variable as a tuple of values rather than a dict.
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p untrusted States if the result is obtained using the bootstrap mode, and is therefore
  /// - \p outs List of outkey information; if `as_tuple` is not set then these are dicts containing
  ///   keys:
  ///   - \p key The public key of the output.
  ///   - \p mask
  ///   - \p unlocked States if output is locked (`false`) or not (`true`).
  ///   - \p height Block height of the output.
  ///   - \p txid Transaction id; only present if requested via the `get_txid` parameter.
  ///   Otherwise, when `as_tuple` is set, these are 4- or 5-element arrays (depending on whether
  ///   `get_txid` is desired) containing the values in the order listed above.
  struct GET_OUTPUTS : PUBLIC, LEGACY
  {
    static constexpr auto names() { return NAMES("get_outs"); }

    /// Maximum outputs that may be requested in a single request (unless admin)
    static constexpr size_t MAX_COUNT = 5000;

    struct request_parameters
    {
      bool get_txid = false;  // If true the request will return the TXID/hash of the transaction as well.
      bool as_tuple = false;
      std::vector<uint64_t> output_indices;
    } request;
  };

   /// Submit a transaction to be broadcast to the network.
  ///
  /// Inputs:
  ///
  /// - \p tx the full transaction data itself.  Can be hex- or base64-encoded for json requests;
  ///   can also be those or raw bytes for bt-encoded requests.  For backwards compatibility,
  ///   hex-encoded data can also be passed in a json request via the parameter \p tx_as_hex but
  ///   that is deprecated and will eventually be removed.
  /// - \p flash Should be set to true if this transaction is a flash transaction that should be
  ///   submitted to a flash quorum rather than distributed through the mempool.
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p untrusted States if the result is obtained using the bootstrap mode, and is therefore
  /// - \p reason String containing additional information on why a transaction failed.
  /// - \p flash_status Set to the result of submitting this transaction to the flash quorum.  1
  ///   means the quorum rejected the transaction; 2 means the quorum accepted it; 3 means there was
  ///   a timeout connecting to or waiting for a response from the flash quorum.  Note that a
  ///   timeout response does *not* necessarily mean the transaction has not made it to the network.
  /// - \p not_relayed will be set to true if some problem with the transactions prevents it from
  ///   being relayed to the network, omitted otherwise.
  /// - \p reason_codes If the transaction was rejected this will be set to a set of reason string
  ///   codes indicating why the transaction failed:
  ///   - \c "failed" -- general "bad transaction" code
  ///   - \c "altchain" -- the transaction is spending outputs that exist on an altchain.
  ///   - \c "mixin" -- the transaction has the wrong number of decoys
  ///   - \c "double_spend" -- the transaction is spending outputs that are already spent
  ///   - \c "invalid_input" -- one or more inputs in the transaction are invalid
  ///   - \c "invalid_output" -- out or more outputs in the transaction are invalid
  ///   - \c "too_few_outputs" -- the transaction does not create enough outputs (at least two are
  ///     required, currently).
  ///   - \c "too_big" -- the transaction is too large
  ///   - \c "overspend" -- the transaction spends (via outputs + fees) more than the inputs
  ///   - \c "fee_too_low" -- the transaction fee is insufficient
  ///   - \c "invalid_version" -- the transaction version is invalid (the wallet likely needs an
  ///     update).
  ///   - \c "invalid_type" -- the transaction type is invalid
  ///   - \c "mnode_locked" -- one or more outputs are currently staked to a registred master node
  ///     and thus are not currently spendable on the blockchain.
  ///   - \c "blacklisted" -- the outputs are currently blacklisted (from being in the 30-day
  ///     penalty period following a master node deregistration).
  ///   - \c "flash" -- the flash transaction failed (see `flash_status`)
  struct SUBMIT_TRANSACTION : PUBLIC, LEGACY
  {
    static constexpr auto names() { return NAMES("submit_transaction", "send_raw_transaction", "sendrawtransaction"); }

    struct request_parameters
    {
      std::string tx;
      bool flash = false;
    } request;

  };

  //-----------------------------------------------
  /// Start mining on the daemon
  ///
  /// Inputs:
  ///
  /// - \p miner_address Account address to mine to.
  /// - \p threads_count Number of mining threads to run. Defaults to 1 thread if omitted or 0.
  /// - \p num_blocks Mine until the blockchain has this many new blocks, then stop (no limit if 0, the default).
  /// - \p slow_mining Do slow mining (i.e. don't allocate RandomX cache); primarily intended for testing.
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  struct START_MINING : LEGACY
  {
    static constexpr auto names() { return NAMES("start_mining"); }
    
    struct request_parameters {
      std::string miner_address;
      int threads_count = 1;
      int num_blocks = 0;
      bool slow_mining = false;
    } request;
  };

  //-----------------------------------------------
  /// Stop mining on the daemon.
  ///
  /// Inputs: none
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  struct STOP_MINING : LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("stop_mining"); }
  };

  //-----------------------------------------------
  /// Get the mining status of the daemon.
  ///
  /// Inputs: none
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p active States if mining is enabled (`true`) or disabled (`false`).
  /// - \p speed Mining power in hashes per seconds.
  /// - \p threads_count Number of running mining threads.
  /// - \p address Account address daemon is mining to. Empty if not mining.
  /// - \p pow_algorithm Current hashing algorithm name
  /// - \p block_target The expected time to solve per block, i.e. TARGET_BLOCK_TIME
  /// - \p block_reward Block reward for the current block being mined.
  /// - \p difficulty The difficulty for the current block being mined.
  struct MINING_STATUS : LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("mining_status"); }
  };

  /// Retrieve general information about the state of the node and the network.
  ///
  /// Inputs: none.
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p height Current length of longest chain known to daemon.
  /// - \p target_height The height of the next block in the chain.
  /// - \p immutable_height The latest height in the blockchain that can not be reorganized (i.e.
  ///   is backed by at least 2 Master Node, or 1 hardcoded checkpoint, 0 if N/A).  Omitted if it
  ///   cannot be determined (typically because the node is still syncing).
  /// - \p POS will be true if the next expected block is a POS block, false otherwise.
  /// - \p POS_ideal_timestamp For POS blocks this is the ideal timestamp of the next block,
  ///   that is, the timestamp if the network was operating with perfect 2-minute blocks since the
  ///   POS hard fork.
  /// - \p POS_target_timestamp For POS blocks this is the target timestamp of the next block,
  ///   which targets 2 minutes after the previous block but will be slightly faster/slower if the
  ///   previous block is behind/ahead of the ideal timestamp.
  /// - \p difficulty Network mining difficulty; omitted when the network is expecting a POS
  ///   block.
  /// - \p target Current target for next proof of work.
  /// - \p tx_count Total number of non-coinbase transaction in the chain.
  /// - \p tx_pool_size Number of transactions that have been broadcast but not included in a block.
  /// - \p mainnet Indicates whether the node is on the main network (`true`) or not (`false`).
  /// - \p testnet Indicates that the node is on the test network (`true`). Will be omitted for
  ///   non-testnet.
  /// - \p devnet Indicates that the node is on the dev network (`true`). Will be omitted for
  ///   non-devnet.
  /// - \p fakechain States that the node is running in "fakechain" mode (`true`).  Omitted
  ///   otherwise.
  /// - \p nettype String value of the network type (mainnet, testnet, devnet, or fakechain).
  /// - \p top_block_hash Hash of the highest block in the chain.  Will be hex for JSON requests,
  ///   32-byte binary value for bt requests.
  /// - \p immutable_block_hash Hash of the highest block in the chain that can not be reorganized.
  ///   Hex string for json, bytes for bt.
  /// - \p cumulative_difficulty Cumulative difficulty of all blocks in the blockchain.
  /// - \p block_size_limit Maximum allowed block size.
  /// - \p block_size_median Median block size of latest 100 blocks.
  /// - \p bns_counts BNS registration counts.
  /// - \p offline Indicates that the node is offline, if true.  Omitted for online nodes.
  /// - \p untrusted Indicates that the result was obtained using a bootstrap mode, and is therefore
  /// - \p database_size Current size of Blockchain data.  Over public RPC this is rounded up to the
  ///   next-largest GB value.
  /// - \p version Current version of this daemon, as a string.  For a public node this will just be
  ///   the major and minor version (e.g. "9"); for an admin rpc endpoint this will return the full
  ///   version (e.g. "9.2.1").
  /// - \p status_line A short one-line summary string of the node (requires an admin/unrestricted
  ///   connection for most details)
  ///
  /// If the endpoint is a restricted (i.e. admin) endpoint then the following fields are also
  /// included:
  ///
  /// - \p alt_blocks_count Number of alternative blocks to main chain.
  /// - \p outgoing_connections_count Number of peers that you are connected to and getting
  ///   information from.
  /// - \p incoming_connections_count Number of peers connected to and pulling from your node.
  /// - \p white_peerlist_size White Peerlist Size
  /// - \p grey_peerlist_size Grey Peerlist Size
  /// - \p master_node Will be true if the node is running in --master-node mode.
  /// - \p start_time Start time of the daemon, as UNIX time.
  /// - \p last_storage_server_ping Last ping time of the storage server (0 if never or not running
  ///   as a master node)
  /// - \p last_belnet_ping Last ping time of belnet (0 if never or not running as a master node)
  /// - \p free_space Available disk space on the node.
  /// - \p bootstrap_daemon_address Bootstrap node to give immediate usability to wallets while
  ///   syncing by proxying RPC to it. (Note: the replies may be untrustworthy).
  /// - \p height_without_bootstrap Current length of the local chain of the daemon.  Only included
  ///   if a bootstrap daemon is configured.
  /// - \p was_bootstrap_ever_used States if the bootstrap node has ever been used since the daemon
  struct GET_INFO : PUBLIC, LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_info", "getinfo"); }
  };

  //-----------------------------------------------
  /// Retrieve general information about the state of the network.
  ///
  /// Inputs: none.
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p start_time something.
  /// - \p total_packets_in something.
  /// - \p total_bytes_in something.
  /// - \p total_packets_out something.
  /// - \p total_bytes_out something.
  struct GET_NET_STATS : LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_net_stats"); }
  };


  //-----------------------------------------------
  /// Save the blockchain. The blockchain does not need saving and is always saved when modified,
  /// however it does a sync to flush the filesystem cache onto the disk for safety purposes,
  /// against Operating System or Hardware crashes.
  ///
  /// Inputs: none
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  struct SAVE_BC : LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("save_bc"); }
  };

  //-----------------------------------------------
  /// Look up how many blocks are in the longest chain known to the node.
  ///
  /// Inputs: none
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p count Number of blocks in logest chain seen by the node.
  struct GET_BLOCK_COUNT : PUBLIC, NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_block_count", "getblockcount"); }
  };

  /// Look up one or more blocks' hashes by their height.
  ///
  /// Inputs:
  /// - heights array of block heights of which to look up the block hashes.  Accepts at most 1000
  ///   heights per request.
  ///
  /// Output values are pairs of heights as keys to block hashes as values:
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p height the current blockchain height of this node
  /// - \p <height> the block hash of the block with the given height.  Note that each height key is
  ///   the stringified integer value, e.g. "3456" rather than 3456.
  struct GET_BLOCK_HASH : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_block_hash", "on_get_block_hash", "on_getblockhash"); }
    static constexpr size_t MAX_HEIGHTS = 1000;
    struct request_parameters {
      std::vector<uint64_t> heights;
    } request;          // Block hash (string).
  };

  BELDEX_RPC_DOC_INTROSPECT
  struct block_header_response
  {
      uint8_t major_version;                  // The major version of the beldex protocol at this block height.
      uint8_t minor_version;                  // The minor version of the beldex protocol at this block height.
      uint64_t timestamp;                     // The unix time at which the block was recorded into the blockchain.
      std::string prev_hash;                  // The hash of the block immediately preceding this block in the chain.
      uint32_t nonce;                         // A cryptographic random one-time number used in mining a Beldex block.
      bool orphan_status;                     // Usually `false`. If `true`, this block is not part of the longest chain.
      uint64_t height;                        // The number of blocks preceding this block on the blockchain.
      uint64_t depth;                         // The number of blocks succeeding this block on the blockchain. A larger number means an older block.
      std::string hash;                       // The hash of this block.
      difficulty_type difficulty;             // The strength of the Beldex network based on mining power.
      difficulty_type cumulative_difficulty;  // The cumulative strength of the Beldex network based on mining power.
      uint64_t reward;                        // The amount of new generated in this block and rewarded to the miner, foundation and master Nodes. Note: 1 BELDEX = 1e9 atomic units.
      uint64_t miner_reward;                  // The amount of new generated in this block and rewarded to the miner. Note: 1 BELDEX = 1e9 atomic units.
      uint64_t block_size;                    // The block size in bytes.
      uint64_t block_weight;                  // The block weight in bytes.
      uint64_t num_txes;                      // Number of transactions in the block, not counting the coinbase tx.
      std::optional<std::string> pow_hash;    // The hash of the block's proof of work (requires `fill_pow_hash`)
      uint64_t long_term_weight;              // Long term weight of the block.
      std::string miner_tx_hash;              // The TX hash of the miner transaction
      std::vector<std::string> tx_hashes;     // The TX hashes of all non-coinbase transactions (requires `get_tx_hashes`)
      std::string master_node_winner;        // Master node that received a reward for this block

      KV_MAP_SERIALIZABLE
  };

  void to_json(nlohmann::json& j, const block_header_response& h);
  void from_json(const nlohmann::json& j, block_header_response& h);

  /// Block header information for the most recent block is easily retrieved with this method. No inputs are needed.
  ///
  /// Inputs:
  /// - \p fill_pow_hash Tell the daemon if it should fill out pow_hash field.
  /// - \p get_tx_hashes If true (default false) then include the hashes of non-coinbase transactions
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p block_header A structure containing block header information.
  struct GET_LAST_BLOCK_HEADER : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_last_block_header", "getlastblockheader"); }

    struct request_parameters
    {
      bool fill_pow_hash; 
      bool get_tx_hashes;
    } request;
  };

  /// Block header information can be retrieved using either a block's hash or height. This method includes a block's hash as an input parameter to retrieve basic information about the block.
  ///
  /// Inputs:
  /// - \p hash The block's SHA256 hash.
  /// - \p hashes Request multiple blocks via an array of hashes
  /// - \p fill_pow_hash Tell the daemon if it should fill out pow_hash field.
  /// - \p get_tx_hashes If true (default false) then include the hashes of non-coinbase transactions
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p block_header Block header information for the requested `hash` block
  /// - \p block_headers Block header information for the requested `hashes` blocks
  struct GET_BLOCK_HEADER_BY_HASH : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_block_header_by_hash", "getblockheaderbyhash"); }

    struct request_parameters
    {
      std::string hash;   // The block's SHA256 hash.
      std::vector<std::string> hashes; // Request multiple blocks via an array of hashes
      bool fill_pow_hash; // Tell the daemon if it should fill out pow_hash field.
      bool get_tx_hashes; // If true (default false) then include the hashes of non-coinbase transactions
    } request;
  };

  /// Similar to get_block_header_by_hash above, this method includes a block's height as an input parameter to retrieve basic information about the block.
  ///
  /// Inputs:
  ///
  /// - \p height A block height to look up; returned in `block_header`
  /// - \p heights Block heights to retrieve; returned in `block_headers`
  /// - \p fill_pow_hash Tell the daemon if it should fill out pow_hash field.
  /// - \p get_tx_hashes If true (default false) then include the hashes of non-coinbase transactions
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p block_header Block header information for the requested `height` block
  /// - \p block_headers Block header information for the requested `heights` blocks
  struct GET_BLOCK_HEADER_BY_HEIGHT : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_block_header_by_height", "getblockheaderbyheight"); }

    struct request_parameters
    {
      std::optional<uint64_t> height; // A block height to look up; returned in `block_header`
      std::vector<uint64_t> heights;  // Block heights to retrieve; returned in `block_headers`
      bool fill_pow_hash; // Tell the daemon if it should fill out pow_hash field.
      bool get_tx_hashes; // If true (default false) then include the hashes of non-coinbase transactions
    } request;
  };

  /// Full block information can be retrieved by either block height or hash, like with the above block header calls.
  /// For full block information, both lookups use the same method, but with different input parameters.
  ///
  /// Inputs:
  ///
  /// - \p hash The block's hash.
  /// - \p height A block height to look up; returned in `block_header`
  /// - \p fill_pow_hash Tell the daemon if it should fill out pow_hash field.
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p block_header Block header information for the requested `height` block
  /// - \p tx_hashes List of hashes of non-coinbase transactions in the block. If there are no other transactions, this will be an empty list.
  /// - \p blob Hexadecimal blob of block information.
  /// - \p json JSON formatted block details.
  struct GET_BLOCK : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_block", "getblock"); }

    struct request_parameters
    {
      std::string hash;   // The block's hash.
      uint64_t height;    // The block's height.
      bool fill_pow_hash; // Tell the daemon if it should fill out pow_hash field.
    } request;
  };

  /// Get the list of current network peers known to this node.
  ///
  /// Inputs: none
  ///
  /// Output values (requires a restricted/admin RPC endpoint):
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p white_list list of "whitelist" peers (see below), that is, peers that were recorded
  ///   reachable the last time this node connected to them.  Peers that are unreachable or not
  ///   synchronized with the network are moved to the graylist.
  /// - \p gray_list list of peers (see below) that this node knows of but has not (recently) tried
  ///   to connect to.
  ///
  /// Each peer list is an array of dicts containing the following fields:
  /// - \p id a unique integer locally identifying the peer
  /// - \p host the peer's IP address (as a string)
  /// - \p port the port on which the peer is reachable
  /// - \p last_seen unix timestamp when this node last connected to the peer.  Will be omitted if
  ///   never connected (e.g. for a peer we received from another node but haven't yet tried).
  struct GET_PEER_LIST : LEGACY
  {
    static constexpr auto names() { return NAMES("get_peer_list"); }

    struct request_parameters
    {
      bool public_only = false; // Hidden option: can be set to false to also include non-public-zone peers (Tor, I2P), but since Beldex currently only really exists in public zones, we don't put this in the RPC docs.
    } request;

  };

  /// Set the daemon log level. By default, log level is set to `0`.  For more fine-tuned logging
  /// control set the set_log_categories command instead.
  ///
  /// Inputs:
  /// - \p level Daemon log level to set from `0` (less verbose) to `4` (most verbose)
  ///
  /// Output values (requires a restricted/admin RPC endpoint):
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  struct SET_LOG_LEVEL : LEGACY
  {
    static constexpr auto names() { return NAMES("set_log_level"); }

    struct request_parameters
    {
      int8_t level; // Daemon log level to set from `0` (less verbose) to `4` (most verbose)
    } request;

  };

  /// Set the daemon log categories. Categories are represented as a comma separated list of
  /// `<Category>:<level>` (similarly to syslog standard `<Facility>:<Severity-level>`), where:
  /// Category is one of the following: * (all facilities), default, net, net.http, net.p2p,
  /// logging, net.trottle, blockchain.db, blockchain.db.lmdb, bcutil, checkpoints, net.dns, net.dl,
  /// i18n, perf,stacktrace, updates, account, cn ,difficulty, hardfork, miner, blockchain, txpool,
  /// cn.block_queue, net.cn, daemon, debugtools.deserialize, debugtools.objectsizes, device.ledger,
  /// wallet.gen_multisig, multisig, bulletproofs, ringct, daemon.rpc, wallet.simplewallet,
  /// WalletAPI, wallet.ringdb, wallet.wallet2, wallet.rpc, tests.core.
  ///
  /// Level is one of the following: FATAL - higher level, ERROR, WARNING, INFO, DEBUG, TRACE.
  /// Lower level A level automatically includes higher level. By default, categories are set to:
  /// `*:WARNING,net:FATAL,net.p2p:FATAL,net.cn:FATAL,global:INFO,verify:FATAL,stacktrace:INFO,logging:INFO,msgwriter:INFO`
  /// Setting the categories to "" prevent any logs to be outputed.
  ///
  /// You can append to the current the log level for updating just one or more categories while
  /// leaving other log levels unchanged by specifying one or more "<category>:<level>" pairs
  /// preceded by a "+", for example "+difficulty:DEBUG,net:WARNING".
  ///
  /// Inputs:
  /// - \p categories Optional, daemon log categores to enable
  ///
  /// Output values (requires a restricted/admin RPC endpoint):
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p categories Daemon log enabled categories
  struct SET_LOG_CATEGORIES : LEGACY
  {
    static constexpr auto names() { return NAMES("set_log_categories"); }

    struct request_parameters
    {
      std::string categories; // Optional, daemon log categories to enable
    } request;

  };


  //-----------------------------------------------
  /// Get hashes from transaction pool.
  ///
  /// Inputs: none
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p tx_hashes List of transaction hashes,
  /// - \p untrusted States if the result is obtained using the bootstrap mode, and is therefore not
  struct GET_TRANSACTION_POOL_HASHES : PUBLIC, LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_transaction_pool_hashes"); }
  };

  BELDEX_RPC_DOC_INTROSPECT
  struct txpool_histo
  {
    uint32_t txs;   // Number of transactions.
    uint64_t bytes; // Size in bytes.

    KV_MAP_SERIALIZABLE
  };

  //-----------------------------------------------
  /// Get the transaction pool statistics.
  ///
  /// Inputs: none
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p pool_stats Dict of pool statistics:
  ///   - \p bytes_total the total size (in bytes) of the transactions in the transaction pool.
  ///   - \p bytes_min the size of the smallest transaction in the tx pool.
  ///   - \p bytes_max the size of the largest transaction in the pool.
  ///   - \p bytes_med the median transaction size in the pool.
  ///   - \p fee_total the total fees of all transactions in the transaction pool.
  ///   - \p txs_total the total number of transactions in the transaction pool
  ///   - \p num_failing the number of failing transactions: that is, transactions that are in the
  ///     mempool but are not currently eligible to be added to the blockchain.
  ///   - \p num_10m the number of transactions received within the last ten minutes
  ///   - \p num_not_relayed the number of transactions which are not being relayed to the
  ///     network.  Only included when the \p include_unrelayed request parameter is set to true.
  ///   - \p num_double_spends the number of transactions in the mempool that are marked as
  ///     double-spends of existing blockchain transactions.
  ///   - \p oldest the unix timestamp of the oldest transaction in the pool.
  ///   - \p histo pairs of [# txes, size of bytes] that form a histogram of transactions in the
  ///     mempool, if there are at least two transactions in the mempool (and omitted entirely
  ///     otherwise).  When present, this field will contain 10 pairs:
  ///     - When `histo_max` is given then `histo` consists of 10 equally-spaced bins from
  ///       newest to oldest where the newest bin begins at age 0 and the oldest bin ends at age `\p
  ///       histo_max`.  For example, bin `[3]` contains statistics for transactions with ages
  ///       between `3*histo_max/10` and `4*histo_max/10`.
  ///     - Otherwise `histo_98pc` will be present in which case `histo` contains 9 equally spaced
  ///       bins from newest to oldest where the newest bin begins at age 0 and the oldest bin ends
  ///       at age `histo_98pc`, and at least 98% of the mempool transactions will fall in these 9
  ///       bins.  The 10th bin contains statistics for all transactions with ages greater than
  ///       `histo_98pc`.
  ///   - \p histo_98pc See `histo` for details.
  ///   - \p histo_max See `histo` for details.
  /// - \p untrusted States if the result is obtained using the bootstrap mode, and is therefore not
  struct GET_TRANSACTION_POOL_STATS : PUBLIC, LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_transaction_pool_stats"); }

    struct request_parameters {
      /// Whether to include transactions marked "do not relay" in the returned statistics.  False
      /// by default: since they are not relayed, they do not form part of the global network
      /// transaction pool.
      bool include_unrelayed = false;
    } request;
  };

  /// Retrieve information about incoming and outgoing P2P connections to your node.
  ///
  /// Inputs: none
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p connections List of all connections and their info; each element is a dict containing:
  ///   - \p incoming bool of whether this connection was established by the remote to us (true) or
  ///     by us to the remove (false).
  ///   - \p ip address of the remote peer
  ///   - \p port the remote port of the peer connection
  ///   - \p address_type - 1/2/3/4 for ipv4/ipv6/i2p/tor, respectively.
  ///   - \p peer_id a string that uniquely identifies a peer node
  ///   - \p recv_count number of bytes of data received from this peer
  ///   - \p recv_idle_ms number of milliseconds since we last received data from this peer
  ///   - \p send_count number of bytes of data send to this peer
  ///   - \p send_idle_ms number of milliseconds since we last sent data to this peer
  ///   - \p state returns the current state of the connection with this peer as a string, one of:
  ///     - \c before_handshake - the connection is still being established/negotiated
  ///     - \c synchronizing - we are synchronizing the blockchain with this peer
  ///     - \c standby - the peer is available for synchronizing but we are not currently using it
  ///     - \c normal - this is a regular, synchronized peer
  ///   - \p live_ms - number of milliseconds since this connection was initiated
  ///   - \p avg_download - the average download speed from this peer in bytes per second
  ///   - \p current_download - the current (i.e. average over a very recent period) download speed
  ///     from this peer in bytes per second.
  ///   - \p avg_upload - the average upload speed to this peer in bytes per second
  ///   - \p current_upload - the current upload speed to this peer in bytes per second
  ///   - \p connection_id - a unique random string identifying this connection
  ///   - \p height - the height of the peer
  ///   - \p host - the hostname for this peer; only included if != \p ip
  ///   - \p localhost - set to true if the peer is a localhost connection; omitted otherwise.
  ///   - \p local_ip - set to true if the peer is a non-public, local network connection; omitted
  ///     otherwise.
  struct GET_CONNECTIONS : NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_connections"); }
  };

  /// Similar to get_block_header_by_height above, but for a range of blocks.
  /// This method includes a starting block height and an ending block height as
  /// parameters to retrieve basic information about the range of blocks.
  ///
  /// Inputs:
  ///
  /// - \p start_height The starting block's height.
  /// - \p end_height The ending block's height.
  /// - \p fill_pow_hash Tell the daemon if it should fill out pow_hash field.
  /// - \p get_tx_hashes If true (default false) then include the hashes of non-coinbase transactions
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p headers Array of block_header (a structure containing block header information. See get_last_block_header).
  struct GET_BLOCK_HEADERS_RANGE : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_block_headers_range", "getblockheadersrange"); }

    struct request_parameters
    {
      uint64_t start_height; // The starting block's height.
      uint64_t end_height;   // The ending block's height.
      bool fill_pow_hash;    // Tell the daemon if it should fill out pow_hash field.
      bool get_tx_hashes;    // If true (default false) then include the hashes or txes in the block details
    } request;
  };

  // BELDEX_RPC_DOC_INTROSPECT
  // // Set the bootstrap daemon to use for data on the blockchain whilst syncing the chain.
  // struct SET_BOOTSTRAP_DAEMON : RPC_COMMAND
  // {
  //   static constexpr auto names() { return NAMES("set_bootstrap_daemon"); }
  //   struct request
  //   {

  //     std::string address;
  //     std::string username;
  //     std::string password;

  //     KV_MAP_SERIALIZABLE
  //   };

  //   struct response : STATUS {};
  // };

  //-----------------------------------------------
  /// Stop the daemon.
  ///
  /// Inputs: none
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  struct STOP_DAEMON : LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("stop_daemon"); }
  };

  /// Get daemon p2p bandwidth limits.
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p limit_up Upload limit in kiB/s
  /// - \p limit_down Download limit in kiB/s
  struct GET_LIMIT : LEGACY, NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_limit"); }
  };

  /// Set daemon p2p bandwidth limits.
  ///
  /// Inputs:
  ///
  /// - \p limit_down Download limit in kBytes per second.  -1 means reset to default; 0 (or
  ///   omitted) means don't change the current limit
  /// - \p limit_up Upload limit in kBytes per second.  -1 means reset to default; 0 (or omitted)
  ///   means don't change the current limit
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p limit_up The new (or existing, if unchanged) upload limit in kiB/s
  /// - \p limit_down The new (or existing, if unchanged) download limit in kiB/s
  struct SET_LIMIT : LEGACY
  {
    static constexpr auto names() { return NAMES("set_limit"); }

    struct request_parameters {
      int64_t limit_down = 0;
      int64_t limit_up = 0;
    } request;
  };

  /// Limit number of Outgoing peers.
  ///
  /// Inputs:
  ///
  /// - \p set If true, set the number of outgoing peers, otherwise the response returns the current
  ///   limit of outgoing peers. (Defaults to true)
  /// - \p out_peers Max number of outgoing peers
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p out_peers The current limit set for outgoing peers.
  struct OUT_PEERS : LEGACY
  {
    static constexpr auto names() { return NAMES("out_peers"); }

    struct request_parameters
    {
      bool set;
      uint32_t out_peers;
    } request;
  };

  /// Limit number of Incoming peers.
  ///
  /// Inputs:
  ///
  /// - \p set If true, set the number of incoming peers, otherwise the response returns the current
  ///   limit of incoming peers. (Defaults to true)
  /// - \p in_peers Max number of incoming peers
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p in_peers The current limit set for incoming peers.
  struct IN_PEERS : LEGACY
  {
    static constexpr auto names() { return NAMES("in_peers"); }

    struct request_parameters
    {
      bool set;
      uint32_t in_peers;
    } request;
  };

  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p untrusted States if the result is obtained using the bootstrap mode, and is therefore
  /// - \p version The major block version for the fork.
  /// - \p enabled Indicates whether the hard fork is enforced on the blockchain (that is, whether
  ///   the blockchain height is at or above the requested hardfork).
  /// - \p earliest_height Block height at which the hard fork will become enabled.
  /// - \p last_height The last block height at which this hard fork will be active; will be omitted
  ///   if this beldexd is not aware of any following hard fork.
  struct HARD_FORK_INFO : PUBLIC
  {
    static constexpr auto names() { return NAMES("hard_fork_info"); }

    struct request_parameters {
      /// If specified, this is the hard fork (i.e. major block) version for the fork.  Only one of
      /// `version` and `height` may be given; returns the current hard fork info if neither is
      /// given.
      uint8_t version = 0;
      /// Request hard fork info by querying a particular height.  Only one of `version` and
      /// `height` may be given.
      uint64_t height = 0;
    } request;
  };

  /// Get list of banned IPs.
  ///
  /// Inputs: None
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p bans List of banned nodes
  struct GETBANS : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_bans"); }
  };

  struct ban
  {
    std::string host; // Banned host (IP in A.B.C.D form).
    uint32_t ip;      // Banned IP address, in Int format.
    uint32_t seconds; // Local Unix time that IP is banned until
  };
  inline void to_json(nlohmann::json& j, const ban& b) { j = nlohmann::json{{"host", b.host}, {"ip", b.ip}, {"seconds", b.seconds} }; };

  /// Ban another node by IP.
  ///
  /// Inputs: 
  /// - \p host Banned host (IP in A.B.C.D form).
  /// - \p ip Banned IP address, in Int format.
  /// - \p seconds Local Unix time that IP is banned until, or Number of seconds to ban node
  /// - \p ban Set true to ban.
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  struct SETBANS : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("set_bans"); }

    struct request_parameters
    {
      std::string host; // Banned host (IP in A.B.C.D form).
      uint32_t ip;      // Banned IP address, in Int format.
      uint32_t seconds; // Local Unix time that IP is banned until, or Number of seconds to ban node
      bool ban;         // Set true to ban.
    } request;
  };

  /// Determine whether a given IP address is banned
  ///
  /// Inputs:
  /// - \p address The IP address to check.
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p banned True if the given address is banned, false otherwise.
  /// - \p seconds The number of seconds remaining in the ban.
  struct BANNED : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("banned"); }

    struct request_parameters
    {
      std::string address; // The IP address to check
    } request;
  };

  /// Flush tx ids from transaction pool..
  ///
  /// Inputs:
  /// - \p txids Optional, list of transactions IDs to flosh from pool (all tx ids flushed if empty)
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  struct FLUSH_TRANSACTION_POOL : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("flush_txpool"); }

    struct request_parameters
    {
      std::vector<std::string> txids;
    } request;
  };

  /// Get a histogram of output amounts. For all amounts (possibly filtered by parameters),
  /// gives the number of outputs on the chain for that amount. RingCT outputs counts as 0 amount.
  ///
  /// Inputs: 
  ///
  /// - \p amounts list of amounts in Atomic Units.
  /// - \p min_count The minimum amounts you are requesting.
  /// - \p max_count The maximum amounts you are requesting.
  /// - \p unlocked Look for locked only.
  /// - \p recent_cutoff
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p histogram List of histogram entries. Each element is structured as follows:
  ///   - \p uint64_t amount Output amount in atomic units.
  ///   - \p uint64_t total_instances
  ///   - \p uint64_t unlocked_instances
  ///   - \p uint64_t recent_instances
  struct GET_OUTPUT_HISTOGRAM : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_output_histogram"); }

    struct request_parameters
    {
      std::vector<uint64_t> amounts; // list of amounts in Atomic Units.
      uint64_t min_count;            // The minimum amounts you are requesting.
      uint64_t max_count;            // The maximum amounts you are requesting.
      bool unlocked;                 // Look for locked only.
      uint64_t recent_cutoff;
    } request;

    struct entry
    {
      uint64_t amount;            // Output amount in atomic units.
      uint64_t total_instances;
      uint64_t unlocked_instances;
      uint64_t recent_instances;
    };
  };
  void to_json(nlohmann::json& j, const GET_OUTPUT_HISTOGRAM::entry& c);
  void from_json(const nlohmann::json& j, GET_OUTPUT_HISTOGRAM::entry& c);

  /// Get current RPC protocol version.
  ///
  /// Inputs: None
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p version RPC current version.
  /// - \p untrusted States if the result is obtained using the bootstrap mode, and is therefore not
  struct GET_VERSION : PUBLIC, NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_version"); }

    struct request : EMPTY {};
  };

  /// Get the coinbase amount and the fees amount for n last blocks starting at particular height.
  ///
  /// Inputs:
  ///
  /// - \p height Block height from which getting the amounts.
  /// - \p count Number of blocks to include in the sum.
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p emission_amount Amount of coinbase reward in atomic units.
  /// - \p fee_amount Amount of fees in atomic units.
  /// - \p burn_amount Amount of burnt beldex.
  struct GET_COINBASE_TX_SUM : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_coinbase_tx_sum"); }

    struct request_parameters
    {
      uint64_t height;
      uint64_t count;
    } request;

  };

    /// Gives an estimation of per-output + per-byte fees
  ///
  /// Inputs:
  ///
  /// - \p grace_blocks Optional.
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p emission_amount Amount of coinbase reward in atomic units.
  /// - \p fee_amount Amount of fees in atomic units.
  /// - \p burn_amount Amount of burnt beldex.
  /// - \p fee_per_byte Amount of fees estimated per byte in atomic units
  /// - \p fee_per_output Amount of fees per output generated by the tx (adds to the `fee_per_byte` per-byte value)
  /// - \p flash_fee_per_byte Value for sending a flash. The portion of the overall flash fee above the overall base fee is burned.
  /// - \p flash_fee_per_output Value for sending a flash. The portion of the overall flash fee above the overall base fee is burned.
  /// - \p flash_fee_fixed Fixed flash fee in addition to the per-output and per-byte amounts. The portion of the overall flash fee above the overall base fee is burned.
  /// - \p quantization_mask
  /// - \p untrusted States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).
  struct GET_BASE_FEE_ESTIMATE : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_fee_estimate"); }

    struct request_parameters
    {
      uint64_t grace_blocks;
    } request;

  };

  /// Display alternative chains seen by the node.
  ///
  /// Inputs: None
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p chains Array of Chains. Each element is contains the following keys:
  ///   - \p block_hash The block hash of the first diverging block of this alternative chain.
  ///   - \p height The block height of the first diverging block of this alternative chain.
  ///   - \p length The length in blocks of this alternative chain, after divergence.
  ///   - \p difficulty The cumulative difficulty of all blocks in the alternative chain.
  ///   - \p block_hashes List containing hex block hashes
  ///   - \p main_chain_parent_block
  struct GET_ALTERNATE_CHAINS : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_alternative_chains"); }

    struct chain_info
    {
      std::string block_hash;                // The block hash of the first diverging block of this alternative chain.
      uint64_t height;                       // The block height of the first diverging block of this alternative chain.
      uint64_t length;                       // The length in blocks of this alternative chain, after divergence.
      uint64_t difficulty;                   // The cumulative difficulty of all blocks in the alternative chain.
      std::vector<std::string> block_hashes;
      std::string main_chain_parent_block;
    };
  };
  void to_json(nlohmann::json& j, const GET_ALTERNATE_CHAINS::chain_info& c);
  void from_json(const nlohmann::json& j, GET_ALTERNATE_CHAINS::chain_info& c);

  /// Relay a list of transaction IDs.
  ///
  /// Inputs: 
  ///
  /// - \p txids List of transactions IDs to relay from pool.
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  struct RELAY_TX : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("relay_tx"); }

    struct request_parameters
    {
      std::vector<std::string> txids; // List of transactions IDs to relay from pool.
    } request;

    struct response : STATUS {};
  };

  /// Get node synchronisation information.  This returns information on the node's syncing "spans"
  /// which are block segments being downloaded from peers while syncing; spans are generally
  /// downloaded out of order from multiple peers, and so these spans reflect in-progress downloaded
  /// blocks that have not yet been added to the block chain: typically because the spans is not yet
  /// complete, or because the span is for future blocks that are dependent on intermediate blocks
  /// (likely in another span) being added to the chain first.
  ///
  /// Inputs: none
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p height Current block height
  /// - \p target_height If the node is currently syncing then this is the target height the node
  ///   wants to reach.  If fully synced then this field is omitted.
  /// - \p peers dict of connection information about peers.  The key is the peer connection_id; the
  ///   value is identical to the values of the \p connections field of GET_CONNECTIONS.  \sa
  ///   GET_CONNECTIONS.
  /// - \p span array of span information of current in progress synchronization.  Element element
  ///   contains:
  ///   - \p start_block_height Block height of the first block in the span
  ///   - \p nblocks the number of blocks in the span
  ///   - \p connection_id the connection_id of the connection from which we are downloading the span
  ///   - \p rate the most recent connection speed measurement
  ///   - \p speed the average connection speed over recent downloaded blocks
  ///   - \p size total number of block and transaction data stored in the span
  /// - \p overview a string containing a one-line ascii-art depiction of the current sync status
  struct SYNC_INFO : NO_ARGS
  {
    static constexpr auto names() { return NAMES("sync_info"); }
  };

  struct output_distribution_data
  {
    std::vector<std::uint64_t> distribution;
    std::uint64_t start_height;
    std::uint64_t base;
  };


  BELDEX_RPC_DOC_INTROSPECT
  struct GET_OUTPUT_DISTRIBUTION : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_output_distribution"); }

    struct request
    {
      std::vector<uint64_t> amounts; // Amounts to look for in atomic units.
      uint64_t from_height;          // (optional, default is 0) starting height to check from.
      uint64_t to_height;            // (optional, default is 0) ending height to check up to.
      bool cumulative;               // (optional, default is false) States if the result should be cumulative (true) or not (false).
      bool binary;
      bool compress;

      KV_MAP_SERIALIZABLE
    };

    struct distribution
    {
      rpc::output_distribution_data data;
      uint64_t amount;
      std::string compressed_data;
      bool binary;
      bool compress;

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;                      // General RPC error code. "OK" means everything looks good.
      std::vector<distribution> distributions; //
      // bool untrusted;                          // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  /// Pop blocks off the main chain
  ///
  /// Inputs:
  ///
  /// - \p nblocks Number of blocks in that span.
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p height Height of the blockchain after blocks have been popped.
  struct POP_BLOCKS : LEGACY
  {
    static constexpr auto names() { return NAMES("pop_blocks"); }

    struct request_parameters
    {
      uint64_t nblocks; // Number of blocks in that span.
    } request;
  };

  /// Pruning is the process of removing non-critical blockchain information from local storage. 
  /// Full nodes keep an entire copy of everything that is stored on the blockchain, including data
  /// that is not very useful anymore. Pruned nodes remove much of this less relevant information 
  /// to have a lighter footprint. Of course, running a full node is always better; however, pruned 
  /// nodes have most of the important information and can still support the network.
  ///
  /// Inputs:
  ///
  /// - \p check Instead of running check if the blockchain has already been pruned.
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p pruned Bool returning whether the blockchain was pruned or not.
  /// - \p pruning_seed The seed that determined how the blockchain was to be pruned.
  struct PRUNE_BLOCKCHAIN : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("prune_blockchain"); }

    struct request_parameters
    {
      bool check;
    } request;
  };


  /// Accesses the list of public keys of the nodes who are participating or being tested in a quorum.
  ///
  /// Inputs:
  ///
  /// - \p start_height (Optional): Start height, omit both start and end height to request the latest quorum. Note that "latest" means different heights for different types of quorums as not all quorums exist at every block heights.
  /// - \p end_height (Optional): End height, omit both start and end height to request the latest quorum
  /// - \p quorum_type (Optional): Set value to request a specific quorum, 0 = Obligation, 1 = Checkpointing, 2 = Flash, 3 = POS, 255 = all quorums, default is all quorums. For POS quorums, requesting the blockchain height (or latest) returns the primary POS quorum responsible for the next block; for heights with blocks this returns the actual quorum, which may be a backup quorum if the primary quorum did not produce in time.
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p quorums An array of quorums associated with the requested height. Each element is structured with the following keys:
  ///   - \p master_node_pubkey The public key of the Master Node, in hex (json) or binary (bt).
  ///   - \p height The height the quorums are relevant for
  ///   - \p quorum_type The quorum type
  ///   - \p quorum Quorum of Master Nodes. Each element is structured with the following keys:
  ///     - \p validators List of master node public keys in the quorum. For obligations quorums these are the testing nodes; for checkpoint and Flash these are the participating nodes (there are no workers); for POS Flash quorums these are the block signers. This is hex encoded, even for bt-encoded requests.
  ///     - \p workers Public key of the quorum workers. For obligations quorums these are the nodes being tested; for POS quorums this is the block producer. Checkpoint and Flash quorums do not populate this field. This is hex encoded, even for bt-encoded requests.
  struct GET_QUORUM_STATE : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_quorum_state"); }

    static constexpr size_t MAX_COUNT = 256;
    static constexpr uint64_t HEIGHT_SENTINEL_VALUE = UINT64_MAX;
    static constexpr uint8_t ALL_QUORUMS_SENTINEL_VALUE = 255;
    struct request_parameters
    {
      uint64_t start_height; // (Optional): Start height, omit both start and end height to request the latest quorum. Note that "latest" means different heights for different types of quorums as not all quorums exist at every block heights.
      uint64_t end_height;   // (Optional): End height, omit both start and end height to request the latest quorum
      uint8_t  quorum_type;  // (Optional): Set value to request a specific quorum, 0 = Obligation, 1 = Checkpointing, 2 = Flash, 3 = POS, 255 = all quorums, default is all quorums. For POS quorums, requesting the blockchain height (or latest) returns the primary POS quorum responsible for the next block; for heights with blocks this returns the actual quorum, which may be a backup quorum if the primary quorum did not produce in time.
    } request;

    struct quorum_t
    {
      std::vector<std::string> validators; // List of master node public keys in the quorum. For obligations quorums these are the testing nodes; for checkpoint and flash these are the participating nodes (there are no workers); for POS flash quorums these are the block signers.
      std::vector<std::string> workers; // Public key of the quorum workers. For obligations quorums these are the nodes being tested; for POS quorums this is the block producer. Checkpoint and Flash quorums do not populate this field.
    };

    struct quorum_for_height
    {
      uint64_t height;          // The height the quorums are relevant for
      uint8_t  quorum_type;     // The quorum type
      quorum_t quorum;          // Quorum of Master Nodes
    };
  };
  void to_json(nlohmann::json& j, const GET_QUORUM_STATE::quorum_t& q);
  void to_json(nlohmann::json& j, const GET_QUORUM_STATE::quorum_for_height& q);

  /// Returns the command that should be run to prepare a master node, includes correct parameters 
  /// and master node ids formatted ready for cut and paste into daemon console.
  ///
  /// Inputs:
  ///
  /// - \p check Instead of running check if the blockchain has already been pruned.
  /// - \p args (Developer) The list of arguments used in raw registration, i.e. portions
  /// - \p make_friendly Provide information about how to use the command in the result.
  /// - \p staking_requirement The staking requirement to become a Master Node the registration command will be generated upon
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p registration_cmd The command to execute in the wallet CLI to register the queried daemon as a Master Node.
  struct GET_MASTER_NODE_REGISTRATION_CMD_RAW : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_master_node_registration_cmd_raw"); }

    struct request_parameters
    {
      std::vector<std::string> args; 
      bool make_friendly;
      uint64_t staking_requirement;
    } request;
  };

  BELDEX_RPC_DOC_INTROSPECT
  struct GET_MASTER_NODE_REGISTRATION_CMD : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_master_node_registration_cmd"); }

    struct request_parameters
    {
      std::string operator_cut;                  // The percentage of cut per reward the operator receives expressed as a string, i.e. "1.1%"
      std::vector<std::string> contributor_addresses;
      std::vector<uint64_t> contributor_amounts;
      uint64_t staking_requirement;              // The staking requirement to become a Master Node the registration command will be generated upon
    } request;
  };

  /// Get the master public keys of the queried daemon, encoded in hex.  All three keys are used
  /// when running as a master node; when running as a regular node only the x25519 key is regularly
  /// used for some RPC and and node-to-MN communication requests.
  ///
  /// Inputs: None
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p master_node_pubkey The queried daemon's master node public key.  Will be empty if not running as a master node.
  /// - \p master_node_ed25519_pubkey The daemon's ed25519 auxiliary public key.
  /// - \p master_node_x25519_pubkey The daemon's x25519 auxiliary public key.
  struct GET_MASTER_KEYS : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_master_keys", "get_master_node_key"); }
  };

  /// Get the master private keys of the queried daemon, encoded in hex.  Do not ever share
  /// these keys: they would allow someone to impersonate your master node.  All three keys are used
  /// when running as a master node; when running as a regular node only the x25519 key is regularly
  /// used for some RPC and and node-to-MN communication requests.
  ///
  /// Inputs: None
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status General RPC status string. `"OK"` means everything looks good.
  /// - \p master_node_privkey The queried daemon's master node private key.  Will be empty if not running as a master node.
  /// - \p master_node_ed25519_privkey The daemon's ed25519 private key (note that this is in sodium's format, which consists of the private and public keys concatenated together)
  /// - \p master_node_x25519_privkey The daemon's x25519 private key.
  struct GET_MASTER_PRIVKEYS : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_master_privkeys", "get_master_node_privkey"); }
  };

  /// Get information on some, all, or a random subset of Master Nodes.
  ///
  /// Output variables available are as follows (you can request which parameters are returned; see
  /// the request parameters description).  Note that BDX values are returned in atomic BDX units,
  /// which are nano-BDX (i.e. 1.000000000 BDX will be returned as 1000000000).
  ///
  /// - \p height the height of the current top block.  (Note that this is one less than the
  ///   "blockchain height" as would be returned by the \c get_info endpoint).
  /// - \p target_height the target height of the blockchain; will be greater than height+1 if this
  ///   node is still syncing the chain.
  /// - \p block_hash the hash of the most recent block
  /// - \p hardfork the current hardfork version of the daemon
  /// - \p mnode_revision the current mnode revision for non-hardfork, but mandatory, master node
  ///   updates.
  /// - \p status generic RPC error code; "OK" means the request was successful.
  /// - \p unchanged when using poll_block_hash, this value is set to true and results are omitted
  ///   if the current block hash has not changed from the requested polling block hash.  If block
  ///   hash has changed this is set to false (and results included).  When not polling this value
  ///   is omitted entirely.
  /// - \p master_node_states list of information about all known master nodes; each element is a
  ///   dict containing the following keys (which fields are included/omitted can be controlled via
  ///   the "fields" input parameter):
  ///   - \p master_node_pubkey The public key of the Master Node, in hex (json) or binary (bt).
  ///   - \p registration_height The height at which the registration for the Master Node arrived
  ///     on the blockchain.
  ///   - \p registration_hf_version The current hard fork at which the registration for the Master
  ///     Node arrived on the blockchain.
  ///   - \p requested_unlock_height If an unlock has been requested for this MN, this field
  ///     contains the height at which the Master Node registration expires and contributions will
  ///     be released.
  ///   - \p last_reward_block_height The height that determines when this master node will next
  ///     receive a reward.  This field is somewhat misnamed for historic reasons: it is updated
  ///     when receiving a reward, but is also updated when a MN is activated, recommissioned, or
  ///     has an IP change position reset, and so does not strictly indicate when a reward was
  ///     received.
  ///   - \p last_reward_transaction_index When multiple Master Nodes register (or become
  ///     active/reactivated) at the same height (i.e. have the same last_reward_block_height), this
  ///     field contains the activating transaction position in the block which is used to break
  ///     ties in determining which MN is next in the reward list.
  ///   - \p active True if fully funded and not currently decommissioned (and so `funded &&
  ///     !active` implicitly defines decommissioned).
  ///   - \p funded True if the required stakes have been submitted to activate this Master Node.
  ///   - \p state_height Indicates the height at which the master node entered its current state:
  ///     - If \p active: this is the height at which the master node last became active (i.e.
  ///       became fully staked, or was last recommissioned);
  ///     - If decommissioned (i.e. \p funded but not \p active): the decommissioning height;
  ///     - If awaiting contributions (i.e. not \p funded): the height at which the last
  ///       contribution (or registration) was processed.
  ///   - \p decommission_count The number of times the Master Node has been decommissioned since
  ///     registration
  ///   - \p last_decommission_reason_consensus_all The reason for the last decommission as voted by
  ///     the testing quorum MNs that decommissioned the node.  This is a numeric bitfield made up
  ///     of the sum of given reasons (multiple reasons may be given for a decommission).  Values
  ///     are included here if *all* quorum members agreed on the reasons:
  ///     - \c 0x01 - Missing uptime proofs
  ///     - \c 0x02 - Missed too many checkpoint votes
  ///     - \c 0x04 - Missed too many POS blocks
  ///     - \c 0x08 - Storage server unreachable
  ///     - \c 0x10 - Beldexd quorumnet unreachable for timesync checks
  ///     - \c 0x20 - Beldexd system clock is too far off
  ///     - \c 0x40 - Belnet unreachable
  ///     - \c 0x50 - Multi_mn_accept_range_not_met
  ///     - other bit values are reserved for future use.
  ///   - \p last_decommission_reason_consensus_any The reason for the last decommission as voted by
  ///     *any* MNs.  Reasons are set here if *any* quorum member gave a reason, even if not all
  ///     quorum members agreed.  Bit values are the same as \p
  ///     last_decommission_reason_consensus_all.
  ///   - \p decomm_reasons - a gentler version of the last_decommission_reason_consensus_all/_any
  ///     values: this is returned as a dict with two keys, \c "all" and \c "some", containing a
  ///     list of short string identifiers of the reasons.  \c "all" contains reasons that are
  ///     agreed upon by all voting nodes; \c "some" contains reasons that were provided by some but
  ///     not all nodes (and is included only if there are at least one such value).  Note that,
  ///     unlike \p last_decommission_reason_consensus_any, the \c "some" field only includes
  ///     reasons that are *not* included in \c "all".  Returned values in the lists are:
  ///     - \p "uptime"
  ///     - \p "checkpoints"
  ///     - \p "POS"
  ///     - \p "storage"
  ///     - \p "timecheck"
  ///     - \p "timesync"
  ///     - \p "belnet"
  ///     - \p "multi-mn"
  ///     - other values are reserved for future use.
  ///   - \p earned_downtime_blocks The number of blocks earned towards decommissioning (if
  ///     currently active), or the number of blocks remaining until the master node is eligible
  ///     for deregistration (if currently decommissioned).
  ///   - \p master_node_version The three-element numeric version of the Master Node (as received
  ///     in the last uptime proof).  Omitted if we have never received a proof.
  ///   - \p belnet_version The major, minor, patch version of the Master Node's belnet router
  ///     (as received in the last uptime proof).  Omitted if we have never received a proof.
  ///   - \p storage_server_version The major, minor, patch version of the Master Node's storage
  ///     server (as received in the last uptime proof).  Omitted if we have never received a proof.
  ///   - \p contributors Array of contributors, contributing to this Master Node.  Each element is
  ///     a dict containing:
  ///     - \p amount The total amount of BDX staked by this contributor into
  ///       this Master Node.
  ///     - \p reserved The amount of BDX reserved by this contributor for this Master Node; this
  ///       field will be included only if the contributor has unfilled, reserved space in the
  ///       master node.
  ///     - \p address The wallet address of this contributor to which rewards are sent and from
  ///       which contributions were made.
  ///     - \p locked_contributions Array of contributions from this contributor; this field (unlike
  ///       the other fields inside \p contributors) is controlled by the "fields" input parameter.
  ///       Each element contains:
  ///       - \p key_image The contribution's key image which is locked on the network.
  ///       - \p key_image_pub_key The contribution's key image, public key component.
  ///       - \p amount The amount of BDX that is locked in this contribution.
  ///
  ///   - \p total_contributed The total amount of BDX contributed to this Master Node.
  ///   - \p total_reserved The total amount of BDX contributed or reserved for this Master Node.
  ///     Only included in the response if there are still unfilled reservations (i.e. if it is
  ///     greater than total_contributed).
  ///   - \p staking_requirement The total BDX staking requirement in that is/was required to be
  ///     contributed for this Master Node.
  ///   - \p portions_for_operator The operator fee to take from the master node reward, as a
  ///     fraction of 18446744073709551612 (2^64 - 4) (that is, this number corresponds to 100%).
  ///     Note that some JSON parsers may silently change this value while parsing as typical values
  ///     do not fit into a double without loss of precision.
  ///   - \p operator_fee The operator fee expressed as thousandths of a percent (and rounded to the
  ///     nearest integer value).  That is, 100000 corresponds to a 100% fee, 5456 corresponds to a
  ///     5.456% fee.  Note that this number is for human consumption; the actual value that matters
  ///     for the blockchain is the precise \p portions_for_operator value.
  ///   - \p swarm_id The numeric identifier of the Master Node's current swarm.  Note that
  ///     returned values can exceed the precision available in a double value, which can result in
  ///     (changed) incorrect values by some JSON parsers.  Consider using \p swarm instead if you
  ///     are not sure your JSON parser supports 64-bit values.
  ///   - \p swarm The swarm id, expressed in hexadecimal, such as \c "f4ffffffffffffff".
  ///   - \p operator_address The wallet address of the Master Node operator.
  ///   - \p public_ip The public ip address of the master node; omitted if we have not yet
  ///     received a network proof containing this information from the master node.
  ///   - \p storage_port The port number associated with the storage server; omitted if we have no
  ///     uptime proof yet.
  ///   - \p storage_lmq_port The port number associated with the storage server (oxenmq interface);
  ///     omitted if we have no uptime proof yet.
  ///   - \p quorumnet_port The port for direct MN-to-MN beldexd communication (oxenmq interface).
  ///     Omitted if we have no uptime proof yet.
  ///   - \p pubkey_ed25519 The master node's ed25519 public key for auxiliary services. Omitted if
  ///     we have no uptime proof yet.  Note that for newer registrations this will be the same as
  ///     the \p master_node_pubkey.
  ///   - \p pubkey_x25519 The master node's x25519 public key for auxiliary services (mainly used
  ///     for \p quorumnet_port and the \p storage_lmq_port OxenMQ encrypted connections).
  ///   - \p last_uptime_proof The last time we received an uptime proof for this master node from
  ///     the network, in unix epoch time.  0 if we have never received one.
  ///   - \p storage_server_reachable True if this storage server is currently passing tests for the
  ///     purposes of MN node testing: true if the last test passed, or if it has been unreachable
  ///     for less than an hour; false if it has been failing tests for more than an hour (and thus
  ///     is considered unreachable).  This field is omitted if the queried beldexd is not a master
  ///     node.
  ///   - \p storage_server_first_unreachable If the last test we received was a failure, this field
  ///     contains the timestamp when failures started.  Will be 0 if the last result was a success,
  ///     and will be omitted if the node has not yet been tested since this beldexd last restarted.
  ///   - \p storage_server_last_unreachable The last time this master node's storage server failed
  ///     a ping test (regardless of whether or not it is currently failing). Will be omitted if it
  ///     has never failed a test since startup.
  ///   - \p storage_server_last_reachable The last time we received a successful ping response for
  ///     this storage server (whether or not it is currently failing). Will be omitted if we have
  ///     never received a successful ping response since startup.
  ///   - \p belnet_reachable Same as \p storage_server_reachable, but for belnet router testing.
  ///   - \p belnet_first_unreachable Same as \p storage_server_first_unreachable, but for belnet
  ///     router testing.
  ///   - \p belnet_last_unreachable Same as \p storage_server_last_unreachable, but for belnet
  ///     router testing.
  ///   - \p belnet_last_reachable Same as \p storage_server_last_reachable, but for belnet router
  ///     testing.
  ///   - \p checkpoint_votes dict containing recent received checkpoint voting information for this
  ///     master node.  Master node tests will fail if too many recent POS blocks are missed.
  ///     Contains keys:
  ///     - \p voted list of blocks heights at which a required vote was received from this
  ///       master node
  ///     - \p missed list of block heights at which a vote from this master node was required
  ///       but not received.
  ///   - \p POS_votes dict containing recent POS blocks in which this master node was supposed
  ///     to have participated.  Master node testing will fail if too many recent POS blocks are
  ///     missed.  Contains keys:
  ///     - \p voted list of [HEIGHT,ROUND] pairs in which an expected POS participation was
  ///       recorded for this node.  ROUND starts at 0 and increments for backup POS quorums if a
  ///       previous round does not broadcast a POS block for the given height in time.
  ///     - \p missed list of [HEIGHT,ROUND] pairs in which POS participation by this master node
  ///       was expected but did not occur.
  ///   - \p quorumnet_tests array containing the results of recent attempts to connect to the
  ///     remote node's quorumnet port (while conducting timesync checks).  The array contains two
  ///     values: [SUCCESSES,FAILURES], where SUCCESSES is the number of recent successful
  ///     connections and FAILURES is the number of recent connection and/or request timeouts.  If
  ///     there are two many failures then the master node will fail testing.
  ///   - \p timesync_tests array containing the results of recent time synchronization checks of
  ///     this master node.  Contains [SUCCESSES,FAILURES] counts where SUCCESSES is the number of
  ///     recent checks where the system clock was relatively close and FAILURES is the number of
  ///     recent checks where we received a significantly out-of-sync timestamp response from the
  ///     master node.  A master node fails tests if there are too many recent out-of-sync
  ///     responses.
  struct GET_MASTER_NODES : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_master_nodes", "get_n_master_nodes", "get_all_master_nodes"); }

    struct request_parameters {
      /// Set of fields to return; listed fields apply to both the top level (such as \p "height" or
      /// - \p "block_hash") and to keys inside \p master_node_states.  Fields should be provided as
      /// a list of field names to include.  For backwards compatibility when making a json request
      /// field names can also be provided as a dictionary of {"field_name": true} pairs, but this
      /// usage is deprecated (and not supported for bt-encoded requests).
      ///
      /// The special field name "all" can be used to request all available fields; this is the
      /// default when no fields key are provided at all.  Be careful when requesting all fields:
      /// the response can be very large.
      ///
      /// When providing a list you may prefix a field name with a \c - to remove the field from the
      /// list; this is mainly useful when following "all" to remove some fields from the returned
      /// results.  (There is no equivalent mode when using the deprecated dict value).
      std::unordered_set<std::string> fields;

      /// Array of public keys of registered master nodes to request information about.  Omit to
      /// query all master nodes.  For a JSON request pubkeys must be specified in hex; for a
      /// bt-encoded request pubkeys can be hex or bytes.
      std::vector<crypto::public_key> master_node_pubkeys;

      /// If true then only return active master nodes.
      bool active_only = false;

      /// If specified and non-zero then only return a random selection of this number of master
      /// nodes (in random order) from the result.  If negative then no limiting is performed but
      /// the returned result is still shuffled.
      int limit = 0;

      /// If specified then only return results if the current top block hash is different than the
      /// hash given here.  This is intended to allow quick polling of results without needing to do
      /// anything if the block (and thus MN registrations) have not changed since the last request.
      crypto::hash poll_block_hash = crypto::hash::null();
    } request;

  };

  /// Retrieves information on the current daemon's Master Node state.  The returned information is
  /// the same as what would be returned by "get_master_nodes" when passed this master node's
  /// public key.
  ///
  /// Inputs: none.
  ///
  /// Outputs:
  /// - \p master_node_state - if this is a registered master node then all available fields for
  ///   this master node.  \sa GET_MASTER_NODES for the list of fields.  Note that some fields
  ///   (such as remote testing results) will not be available (through this call or \p
  ///   "get_master_nodes") because a master node is incapable of testing itself for remote
  ///   connectivity.  If this daemon is running in master node mode but not registered then only
  ///   MN pubkey, ip, and port fields are returned.
  /// - \p height current top block height at the time of the request (note that this is generally
  ///   one less than the "blockchain height").
  /// - \p block_hash current top block hash at the time of the request
  /// - \p status generic RPC error code; "OK" means the request was successful.
  struct GET_MASTER_NODE_STATUS : NO_ARGS
  {
    static constexpr auto names() { return NAMES("get_master_node_status"); }
  };

  /// Endpoint to receive an uptime ping from the connected storage server. This is used
  /// to record whether the storage server is ready before the master node starts
  /// sending uptime proofs. This is usually called internally from the storage server
  /// and this endpoint is mostly available for testing purposes.
  ///
  /// Inputs:
  ///
  /// - \p version Storage server version
  /// - \p https_port Storage server https port to include in uptime proofs.
  /// - \p omq_port Storage server oxenmq port to include in uptime proofs.
  /// - \p pubkey_ed25519 Master node Ed25519 pubkey for verifying that storage server is using the right one
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status generic RPC error code; "OK" means the request was successful.
  struct STORAGE_SERVER_PING : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("storage_server_ping"); }

    struct request_parameters
    {
      std::array<uint16_t, 3> version; // Storage server version
      uint16_t https_port; // Storage server https port to include in uptime proofs
      uint16_t omq_port; // Storage Server oxenmq port to include in uptime proofs
      std::string pubkey_ed25519; // Master node Ed25519 pubkey for verifying that storage server is using the right one
    } request;
  };

  /// Endpoint to receive an uptime ping from the connected belnet server. This is used 
  /// to record whether belnet is ready before the master node starts sending uptime proofs.
  /// This is usually called internally from belnet and this endpoint is mostly
  /// available for testing purposes.
  ///
  /// Inputs:
  ///
  /// - \p version Belnet version
  /// - \p pubkey_ed25519 // Master node Ed25519 pubkey for verifying that belnet is using the right one
  ///
  /// Output values available from a restricted/admin RPC endpoint:
  ///
  /// - \p status generic RPC error code; "OK" means the request was successful.
  struct BELNET_PING : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("belnet_ping"); }

    struct request_parameters
    {
      std::array<uint16_t, 3> version; // Belnet version
      std::string pubkey_ed25519; // Master node Ed25519 pubkey for verifying that belnet is using the right one
    } request;

  };

  /// Get the required amount of BDX to become a Master Node at the queried height.
  /// For devnet and testnet values, ensure the daemon is started with the
  /// `--devnet` or `--testnet` flags respectively.
  ///
  /// Inputs:
  ///
  /// - \p height The height to query the staking requirement for.  0 (or omitting) means current height.
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status generic RPC error code; "OK" means the request was successful.
  /// - \p staking_requirement The staking requirement in Oxen, in atomic units.
  /// - \p height The height requested (or current height if 0 was requested)
  struct GET_STAKING_REQUIREMENT : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_staking_requirement"); }

    struct request_parameters
    {
      uint64_t height; // The height to query the staking requirement for.  0 (or omitting) means current height.
    } request;

  };

  /// Get information on blacklisted Master Node key images.
  ///
  /// Inputs: None
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status generic RPC error code; "OK" means the request was successful.
  /// - \p blacklist Array of blacklisted key images, i.e. unspendable transactions. Each entry contains
  ///   - \p key_image The key image of the transaction that is blacklisted on the network.
  ///   - \p unlock_height The height at which the key image is removed from the blacklist and becomes spendable.
  ///   - \p amount The total amount of locked Beldex in atomic units in this blacklisted stake.
  struct GET_MASTER_NODE_BLACKLISTED_KEY_IMAGES : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_master_node_blacklisted_key_images"); }
  };

  /// Query hardcoded/master node checkpoints stored for the blockchain. Omit all arguments to retrieve the latest "count" checkpoints.
  ///
  /// Inputs:
  ///
  /// - \p start_height Optional: Get the first count checkpoints starting from this height. Specify both start and end to get the checkpoints inbetween.
  /// - \p end_height Optional: Get the first count checkpoints before end height. Specify both start and end to get the checkpoints inbetween.
  /// - \p count Optional: Number of checkpoints to query.
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status generic RPC error code; "OK" means the request was successful.
  /// - \p checkpoints Array of requested checkpoints
  struct GET_CHECKPOINTS : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_checkpoints"); }

    static constexpr size_t MAX_COUNT = 256;
    static constexpr uint32_t NUM_CHECKPOINTS_TO_QUERY_BY_DEFAULT = 60;
    static constexpr uint64_t HEIGHT_SENTINEL_VALUE               = std::numeric_limits<uint64_t>::max() - 1;
    struct request_parameters
    {
      uint64_t start_height; // Optional: Get the first count checkpoints starting from this height. Specify both start and end to get the checkpoints inbetween.
      uint64_t end_height;   // Optional: Get the first count checkpoints before end height. Specify both start and end to get the checkpoints inbetween.
      uint32_t count;        // Optional: Number of checkpoints to query.
    } request;
  };

  /// Query hardcoded/master node checkpoints stored for the blockchain. Omit all arguments to retrieve the latest "count" checkpoints.
  ///
  /// Inputs:
  /// 
  /// - \p start_height The starting block's height.
  /// - \p end_height The ending block's height.
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status Generic RPC error code. "OK" is the success value.
  /// - \p untrusted If the result is obtained using bootstrap mode then this will be set to true, otherwise will be omitted.
  /// - \p total_deregister
  /// - \p total_ip_change_penalty
  /// - \p total_decommission
  /// - \p total_recommission
  /// - \p total_unlock
  /// - \p start_height
  /// - \p end_height
  struct GET_MN_STATE_CHANGES : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_master_nodes_state_changes"); }

    static constexpr uint64_t HEIGHT_SENTINEL_VALUE = std::numeric_limits<uint64_t>::max() - 1;
    struct request_parameters
    {
      uint64_t start_height;
      uint64_t end_height;   // Optional: If omitted, the tally runs until the current block
    } request;
  };


  /// Reports master node peer status (success/fail) from belnet and storage server.
  ///
  /// Inputs:
  /// 
  /// - \p type test type; currently supported are: "storage" and "belnet" for storage server and belnet tests, respectively.
  /// - \p pubkey master node pubkey
  /// - \p passed whether node is passing the test
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status Generic RPC error code. "OK" is the success value.
  struct REPORT_PEER_STATUS : RPC_COMMAND
  {
    // TODO: remove the `report_peer_storage_server_status` once we require a storage server version
    // that stops using the old name.
    static constexpr auto names() { return NAMES("report_peer_status", "report_peer_storage_server_status"); }

    struct request_parameters
    {
      std::string type; // test type; currently supported are: "storage" and "belnet" for storage server and belnet tests, respectively.
      std::string pubkey; // master node pubkey
      bool passed; // whether the node is passing the test
    } request;
  };

  /// Deliberately undocumented; this RPC call is really only useful for testing purposes to reset
  /// the resync idle timer (which normally fires every 60s) for the test suite.
  ///
  /// Inputs: none
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status Generic RPC error code. "OK" is the success value.
  struct TEST_TRIGGER_P2P_RESYNC : NO_ARGS
  {
    static constexpr auto names() { return NAMES("test_trigger_p2p_resync"); }
  };

  /// Deliberately undocumented; this RPC call is really only useful for testing purposes to
  /// force send an uptime proof. NOT available on mainnet
  ///
  /// Inputs: none
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status Generic RPC error code. "OK" is the success value.
  struct TEST_TRIGGER_UPTIME_PROOF : NO_ARGS
  {
    static constexpr auto names() { return NAMES("test_trigger_uptime_proof"); }
  };

  BELDEX_RPC_DOC_INTROSPECT
  // Get the name mapping for a Beldex Name Service entry. Beldex currently supports mappings
  // for Bchat and Belnet.
  struct BNS_NAMES_TO_OWNERS : PUBLIC
  {
    static constexpr auto names() { return NAMES("bns_names_to_owners", "lns_names_to_owners"); }

    static constexpr size_t MAX_REQUEST_ENTRIES      = 256;
    struct request
    {
      std::vector<std::string> entries; // Entries to look up
      bool include_expired;               // Optional: if provided and true, include entries in the results even if they are expired

      KV_MAP_SERIALIZABLE
    };

    struct response_entry
    {
      uint64_t entry_index;                     // The index in request_entry's `entries` array that was resolved via Beldex Name Service.
      std::string name_hash;                    // The hash of the name that was queried, in base64
      std::string owner;                        // The public key that purchased the Beldex Name Service entry.
      std::optional<std::string> backup_owner;  // The backup public key that the owner specified when purchasing the Beldex Name Service entry. Omitted if no backup owner.
      std::string encrypted_bchat_value;        // The encrypted value that the name maps to. See the `BNS_RESOLVE` description for information on how this value can be decrypted.
      std::string encrypted_wallet_value;       // The encrypted value that the name maps to. See the `BNS_RESOLVE` description for information on how this value can be decrypted.
      std::string encrypted_belnet_value;       // The encrypted value that the name maps to. See the `BNS_RESOLVE` description for information on how this value can be decrypted.
      std::string encrypted_eth_addr_value;     // The encrypted value that the name maps to. See the `BNS_RESOLVE` description for information on how this value can be decrypted.
      uint64_t update_height;                   // The last height that this Beldex Name Service entry was updated on the Blockchain.
      std::optional<uint64_t> expiration_height;// For records that expire, this will be set to the expiration block height.
      std::string txid;                         // The txid of the mapping's most recent update or purchase.
      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::vector<response_entry> entries;
      std::string status; // Generic RPC error code. "OK" is the success value.

      KV_MAP_SERIALIZABLE
    };
  };

  BELDEX_RPC_DOC_INTROSPECT
  // Get the name mapping for a Beldex Name Service entry. Beldex currently supports mappings
  // for Bchat and Belnet and wallet.
  struct BNS_LOOKUP : PUBLIC
  {
    static constexpr auto names() { return NAMES("bns_lookup"); }

    static constexpr size_t MAX_REQUEST_ENTRIES      = 256;
    struct request
    {
      std::string name; // Entries to look up
      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string name_hash;                    // The hash of the name that was queried, in base64
      std::string owner;                        // The public key that purchased the Beldex Name Service entry.
      std::optional<std::string> backup_owner;  // The backup public key that the owner specified when purchasing the Beldex Name Service entry. Omitted if no backup owner.
      std::optional<std::string> bchat_value;   // The encrypted value that the name maps to. See the `BNS_RESOLVE` description for information on how this value can be decrypted.
      std::optional<std::string> wallet_value;  // The encrypted value that the name maps to. See the `BNS_RESOLVE` description for information on how this value can be decrypted.
      std::optional<std::string> belnet_value;  // The encrypted value that the name maps to. See the `BNS_RESOLVE` description for information on how this value can be decrypted.
      std::optional<std::string> eth_addr_value;  // The encrypted value that the name maps to. See the `BNS_RESOLVE` description for information on how this value can be decrypted.
      uint64_t update_height;                   // The last height that this Beldex Name Service entry was updated on the Blockchain.
      std::optional<uint64_t> expiration_height;// For records that expire, this will be set to the expiration block height.
      std::string txid;                         // The txid of the mapping's most recent update or purchase.
      
      std::string status; // Generic RPC error code. "OK" is the success value.

      KV_MAP_SERIALIZABLE
    };
  };

  /// Get all the name mappings for the queried owner. The owner can be either a ed25519 public key or Monero style
  /// public key; by default purchases are owned by the spend public key of the purchasing wallet.
  ///
  /// Inputs:
  /// 
  /// - \p entries List of owner's public keys to find all Oxen Name Service entries for.
  /// - \p include_expired Optional: if provided and true, include entries in the results even if they are expired
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status Generic RPC error code. "OK" is the success value.
  /// - \p entries List of BNS names. Each element is structured as follows:
  ///   - \p request_index (Deprecated) The index in request's `entries` array that was resolved via Beldex Name Service.
  ///   - \p type The category the Beldex Name Service entry belongs to; currently 0 for Bchat, 1 for Wallet, 2 for Belnet and 3 Eth Address .
  ///   - \p name_hash The hash of the name that the owner purchased via Beldex Name Service in base64
  ///   - \p owner The backup public key specified by the owner that purchased the Beldex Name Service entry.
  ///   - \p backup_owner The backup public key specified by the owner that purchased the Beldex Name Service entry. Omitted if no backup owner.
  ///   - \p encrypted_bchat_value The encrypted Bchat value that the name maps to, in hex. This value is encrypted using the name (not the hash) as the secret.
  ///   - \p encrypted_wallet_value The encrypted Wallet value that the name maps to, in hex. This value is encrypted using the name (not the hash) as the secret.
  ///   - \p encrypted_belnet_value The encrypted Belnet value that the name maps to, in hex. This value is encrypted using the name (not the hash) as the secret.
  ///   - \p encrypted_eth_addr_value The encrypted Eth Address value that the name maps to, in hex. This value is encrypted using the name (not the hash) as the secret.
  ///   - \p update_height The last height that this Beldex Name Service entry was updated on the Blockchain.
  ///   - \p expiration_height For records that expire, this will be set to the expiration block height.
  ///   - \p txid The txid of the mapping's most recent update or purchase.
  struct BNS_OWNERS_TO_NAMES : PUBLIC
  {
    static constexpr auto names() { return NAMES("bns_owners_to_names", "lns_owners_to_names"); }

    static constexpr size_t MAX_REQUEST_ENTRIES = 256;
    struct request_parameters
    {
      std::vector<std::string> entries; // The owner's public key to find all Beldex Name Service entries for.
      bool include_expired;             // Optional: if provided and true, include entries in the results even if they are expired
    } request;

    struct response_entry
    {
      uint64_t    request_index;                // (Deprecated) The index in request's `entries` array that was resolved via Beldex Name Service.
      std::string name_hash;                    // The hash of the name that the owner purchased via Beldex Name Service in base64
      std::string owner;                        // The backup public key specified by the owner that purchased the Beldex Name Service entry.
      std::optional<std::string> backup_owner;  // The backup public key specified by the owner that purchased the Beldex Name Service entry. Omitted if no backup owner.
      std::string encrypted_bchat_value;        // The bchat encrypted value that the name maps to, in hex. This value of bchat is encrypted using the name (not the hash) as the secret.
      std::string encrypted_wallet_value;       // The wallet encrypted value that the name maps to, in hex. This value of wallet is encrypted using the name (not the hash) as the secret.
      std::string encrypted_belnet_value;       // The belnet encrypted value that the name maps to, in hex. This value of belnet is encrypted using the name (not the hash) as the secret.
      std::string encrypted_eth_addr_value;     // The eth_address encrypted value that the name maps to, in hex. This value of eth_address is encrypted using the name (not the hash) as the secret.
      uint64_t    update_height;                // The last height that this Beldex Name Service entry was updated on the Blockchain.
      std::optional<uint64_t> expiration_height;// For records that expire, this will be set to the expiration block height.
      std::string txid;                         // The txid of the mapping's most recent update or purchase.
    };
  };
  void to_json(nlohmann::json& j, const BNS_OWNERS_TO_NAMES::response_entry& r);

  /// Performs a simple BNS lookup of a BLAKE2b-hashed name.  This RPC method is meant for simple,
  /// single-value resolutions that do not care about registration details, etc.; if you need more
  /// information use BNS_NAMES_TO_OWNERS instead.
  ///
  /// Returned values:
  ///
  /// - \p encrypted_value The encrypted BNS value, in hex.  Will be omitted from the response if
  ///   the given name_hash is not registered.
  /// - \p nonce The nonce value used for encryption, in hex.  Will be omitted if the given name is
  ///   not registered.
  ///
  /// Technical details: the returned value is encrypted using the name itself so that neither this
  /// beldexd responding to the RPC request nor any other blockchain observers can (easily) obtain the
  /// name of registered addresses or the registration details.  Thus, from a client's point of view,
  /// resolving an BNS record involves:
  ///
  /// 1. Lower-case the name.
  /// 2. Calculate the name hash as a null-key, 32-byte BLAKE2b hash of the lower-case name.
  /// 3. Obtain the encrypted value and the nonce from this RPC call (or BNS_NAMES_TO_OWNERS); when
  ///    using json encode the name hash using either hex or base64.
  /// 4. Calculate the decryption key as a 32-byte BLAKE2b *keyed* hash of the name using the
  ///    (unkeyed) name hash calculated above (in step 2) as the hash key.
  /// 5. Decrypt (and verify) using XChaCha20-Poly1305 (for example libsodium's
  ///    crypto_aead_xchacha20poly1305_ietf_decrypt) using the above decryption key and using the
  ///    first 24 bytes of the name hash as the public nonce.
  struct BNS_RESOLVE : PUBLIC
  {
    static constexpr auto names() { return NAMES("bns_resolve", "lns_resolve"); }

    struct request_parameters {
      int type = -1;         ///< The BNS type (mandatory); currently supported values are: 0 = bchat, 1 = wallet, 2 = belnet, 6=eth_addr.
      std::string name_hash; ///< The 32-byte BLAKE2b hash of the name to look up, encoded as 64 hex digits or 44/43 base64 characters (with/without padding).  For bt-encoded requests this can also be the raw 32 bytes.
    } request;
  };

  BELDEX_RPC_DOC_INTROSPECT
  // Takes a BNS encrypted value and decrypts the mapping value using the BNS name.
  struct BNS_VALUE_DECRYPT : PUBLIC
  {
    static constexpr auto names() { return NAMES("bns_value_decrypt"); }

    struct request
    {
      std::string name;            // The BNS name of the given encrypted value.
      std::string type;            // The mapping type: "bchat" or "belnet" or "wallet".
      std::string encrypted_value; // The encrypted value represented in hex.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string value; // The value decrypted

      KV_MAP_SERIALIZABLE
    };
  };
  
  /// Clear TXs from the daemon cache, currently only the cache storing TX hashes that were previously verified bad by the daemon.
  ///
  /// Inputs:
  ///
  /// - \p bad_txs Clear the cache storing TXs that failed verification.
  /// - \p bad_blocks Clear the cache storing blocks that failed verfication.
  ///
  /// Output values available from a public RPC endpoint:
  ///
  /// - \p status Generic RPC error code. "OK" is the success value.
  struct FLUSH_CACHE : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("flush_cache"); }
    struct request_parameter
    {
      bool bad_txs; // Clear the cache storing TXs that failed verification.
      bool bad_blocks; // Clear the cache storing blocks that failed verfication.
    } request;

    struct response : STATUS { };
  };

  /// List of all supported rpc command structs to allow compile-time enumeration of all supported
  /// RPC types.  Every type added above that has an RPC endpoint needs to be added here, and needs
  /// a core_rpc_server::invoke() overload that takes a <TYPE>::request and returns a
  /// <TYPE>::response.  The <TYPE>::request has to be unique (for overload resolution);
  /// <TYPE>::response does not.
  using core_rpc_types = tools::type_list<
    GET_CONNECTIONS,
    GET_HEIGHT,
    GET_INFO,
    BNS_RESOLVE,
    GET_OUTPUTS,
    GET_LIMIT,
    SET_LIMIT,
    HARD_FORK_INFO,
    START_MINING,
    STOP_MINING,
    SAVE_BC,
    STOP_DAEMON,
    SYNC_INFO,
    GET_BLOCK_COUNT,
    MINING_STATUS,
    GET_TRANSACTION_POOL_HASHES,
    GET_TRANSACTION_POOL_STATS,
    GET_TRANSACTIONS,
    IS_KEY_IMAGE_SPENT,
    GET_MASTER_NODES,
    GET_MASTER_NODE_STATUS,
    SUBMIT_TRANSACTION,
    GET_BLOCK_HASH,
    GET_PEER_LIST,
    GET_MASTER_NODE_REGISTRATION_CMD_RAW,
    GET_MASTER_NODE_REGISTRATION_CMD,
    SET_LOG_LEVEL,
    SET_LOG_CATEGORIES,
    BANNED,
    FLUSH_TRANSACTION_POOL,
    GET_VERSION,
    GET_COINBASE_TX_SUM,
    GET_BASE_FEE_ESTIMATE,
    OUT_PEERS,
    IN_PEERS,
    POP_BLOCKS,
    STORAGE_SERVER_PING,
    BELNET_PING,
    PRUNE_BLOCKCHAIN,
    TEST_TRIGGER_P2P_RESYNC,
    TEST_TRIGGER_UPTIME_PROOF,
    REPORT_PEER_STATUS,
    GET_MN_STATE_CHANGES,
    FLUSH_CACHE
  >;
  using FIXME_old_rpc_types = tools::type_list<
    GET_NET_STATS,
    GET_LAST_BLOCK_HEADER,
    GET_BLOCK_HEADER_BY_HASH,
    GET_BLOCK_HEADER_BY_HEIGHT,
    GET_BLOCK,
    GET_BLOCK_HEADERS_RANGE,
    // SET_BOOTSTRAP_DAEMON,
    GETBANS,
    SETBANS,
    GET_OUTPUT_HISTOGRAM,
    GET_ALTERNATE_CHAINS,
    RELAY_TX,
    GET_OUTPUT_DISTRIBUTION,
    GET_QUORUM_STATE,
    GET_MASTER_KEYS,
    GET_MASTER_PRIVKEYS,
    GET_STAKING_REQUIREMENT,
    GET_MASTER_NODE_BLACKLISTED_KEY_IMAGES,
    GET_CHECKPOINTS,
    BNS_NAMES_TO_OWNERS,
    BNS_LOOKUP,
    BNS_OWNERS_TO_NAMES,
    BNS_VALUE_DECRYPT
  >;

} // namespace cryptonote::rpc
