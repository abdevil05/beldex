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

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/preprocessor/stringize.hpp>
#include <algorithm>
#include <cstring>
#include <iterator>
#include <type_traits>
#include <variant>
#include <oxenc/base64.h>
#include <oxenc/endian.h>
#include "epee/net/network_throttle.hpp"
#include "common/string_util.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/hardfork.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_config.h"
#include "cryptonote_core/beldex_name_system.h"
#include "cryptonote_core/pos.h"
#include "beldex_economy.h"
#include "epee/string_tools.h"
#include "core_rpc_server.h"
#include "core_rpc_server_command_parser.h"
#include "bootstrap_daemon.h"
#include "rpc_args.h"
#include "core_rpc_server_error_codes.h"
#include "common/command_line.h"
#include "common/beldex.h"
#include "common/sha256sum.h"
#include "common/perf_timer.h"
#include "common/random.h"
#include "common/hex.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_core/uptime_proof.h"
#include "net/parse.h"
#include "crypto/hash.h"
#include "p2p/net_node.h"
#include "version.h"
#include <fmt/core.h>

#undef BELDEX_DEFAULT_LOG_CATEGORY
#define BELDEX_DEFAULT_LOG_CATEGORY "daemon.rpc"


namespace cryptonote::rpc {

  using nlohmann::json;
  namespace {

    oxenc::bt_value json_to_bt(json&& j) {
      using namespace oxenmq;
      if (j.is_object()) {
        oxenc::bt_dict res;
        for (auto& [k, v] : j.items()) {
          if (v.is_null())
            continue; // skip k-v pairs with a null v (for other nulls we fail).
            res[k] = json_to_bt(std::move(v));
        }
        return res;
      }
      if (j.is_array()) {
        oxenc::bt_list res;
        for (auto& v : j)
          res.push_back(json_to_bt(std::move(v)));
        return res;
      }
      if (j.is_string()) {
        return std::move(j.get_ref<std::string&>());
      }
      if (j.is_boolean())
        return j.get<bool>() ? 1 : 0;
      if (j.is_number_unsigned())
        return j.get<uint64_t>();
      if (j.is_number_integer())
        return j.get<int64_t>();
      throw std::domain_error{"internal error: encountered some unhandled/invalid type in json-to-bt translation"};
    }
    
    template <typename RPC, std::enable_if_t<std::is_base_of_v<RPC_COMMAND, RPC>, int> = 0>
    void register_rpc_command(std::unordered_map<std::string, std::shared_ptr<const rpc_command>>& regs)
    {
      auto cmd = std::make_shared<rpc_command>();
      cmd->is_public = std::is_base_of_v<PUBLIC, RPC>;
      cmd->is_binary = std::is_base_of_v<BINARY, RPC>;
      cmd->is_legacy = std::is_base_of_v<LEGACY, RPC>;
      if constexpr (!std::is_base_of_v<BINARY, RPC>) {
        static_assert(!FIXME_has_nested_response_v<RPC>);
        cmd->invoke = [](rpc_request&& request, core_rpc_server& server) -> rpc_command::result_type {
          RPC rpc{};
          try {
            if (auto body = request.body_view()) {
              if (body->front() == 'd') { // Looks like a bt dict
                rpc.set_bt();
                parse_request(rpc, oxenc::bt_dict_consumer{*body});
              }
              else
                parse_request(rpc, json::parse(*body));
            } else if (auto* j = std::get_if<json>(&request.body)) {
              parse_request(rpc, std::move(*j));
            } else {
              assert(std::holds_alternative<std::monostate>(request.body));
              parse_request(rpc, std::monostate{});
            }
          } catch (const std::exception& e) {
            throw parse_error{"Failed to parse request parameters: "s + e.what()};
          }

          server.invoke(rpc, std::move(request.context));

          if (rpc.response.is_null())
            rpc.response = json::object();

          if (rpc.is_bt())
            return json_to_bt(std::move(rpc.response));
          else
            return std::move(rpc.response);
        };
      } else {
        // Legacy binary request; these still use epee serialization, and should be considered
        // deprecated (tentatively to be removed in Oxen 11).
        cmd->invoke = [](rpc_request&& request, core_rpc_server& server) -> rpc_command::result_type {
          typename RPC::request req{};
          std::string_view data;
          if (auto body = request.body_view())
            data = *body;
          else
            throw std::runtime_error{"Internal error: can't load binary a RPC command with non-string body"};
          if (!epee::serialization::load_t_from_binary(req, data))
            throw parse_error{"Failed to parse binary data parameters"};

          auto res = server.invoke(std::move(req), std::move(request.context));

          std::string response;
          epee::serialization::store_t_to_binary(res, response);
          return response;
        };
      }

      for (const auto& name : RPC::names())
        regs.emplace(name, cmd);
    }

    template <typename... RPC>
    std::unordered_map<std::string, std::shared_ptr<const rpc_command>> register_rpc_commands(tools::type_list<RPC...>) {
      std::unordered_map<std::string, std::shared_ptr<const rpc_command>> regs;

      (register_rpc_command<RPC>(regs), ...);

      return regs;
    }

    constexpr uint64_t OUTPUT_HISTOGRAM_RECENT_CUTOFF_RESTRICTION = 3 * 86400; // 3 days max, the wallet requests 1.8 days
    constexpr uint64_t round_up(uint64_t value, uint64_t quantum) { return (value + quantum - 1) / quantum * quantum; }

  }

  const std::unordered_map<std::string, std::shared_ptr<const rpc_command>> rpc_commands = register_rpc_commands(rpc::core_rpc_types{});

  const command_line::arg_descriptor<std::string> core_rpc_server::arg_bootstrap_daemon_address = {
      "bootstrap-daemon-address"
    , "URL of a 'bootstrap' remote daemon that the connected wallets can use while this daemon is still not fully synced.\n"
      "Use 'auto' to enable automatic public nodes discovering and bootstrap daemon switching"
    , ""
    };

  const command_line::arg_descriptor<std::string> core_rpc_server::arg_bootstrap_daemon_login = {
      "bootstrap-daemon-login"
    , "Specify username:password for the bootstrap daemon login"
    , ""
    };

  std::optional<std::string_view> rpc_request::body_view() const {
    if (auto* sv = std::get_if<std::string_view>(&body)) return *sv;
    if (auto* s = std::get_if<std::string>(&body)) return *s;
    return std::nullopt;
  }

  //-----------------------------------------------------------------------------------
  void core_rpc_server::init_options(boost::program_options::options_description& desc, boost::program_options::options_description& hidden)
  {
    command_line::add_arg(desc, arg_bootstrap_daemon_address);
    command_line::add_arg(desc, arg_bootstrap_daemon_login);
    cryptonote::rpc_args::init_options(desc, hidden);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  core_rpc_server::core_rpc_server(
      core& cr
    , nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >& p2p
    )
    : m_core(cr)
    , m_p2p(p2p)
    , m_should_use_bootstrap_daemon(false)
    , m_was_bootstrap_ever_used(false)
  {}
  bool core_rpc_server::set_bootstrap_daemon(const std::string &address, std::string_view username_password)
  {
    std::string_view username, password;
    if (auto loc = username_password.find(':'); loc != std::string::npos)
    {
      username = username_password.substr(0, loc);
      password = username_password.substr(loc + 1);
    }
    return set_bootstrap_daemon(address, username, password);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::set_bootstrap_daemon(const std::string &address, std::string_view username, std::string_view password)
  {
    std::optional<std::pair<std::string_view, std::string_view>> credentials;
    if (!username.empty() || !password.empty())
      credentials.emplace(username, password);

    std::unique_lock lock{m_bootstrap_daemon_mutex};

    if (address.empty())
      m_bootstrap_daemon.reset();
    else if (address == "auto")
      m_bootstrap_daemon = std::make_unique<bootstrap_daemon>([this]{ return get_random_public_node(); });
    else
      m_bootstrap_daemon = std::make_unique<bootstrap_daemon>(address, credentials);

    m_should_use_bootstrap_daemon = (bool) m_bootstrap_daemon;

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  std::optional<std::string> core_rpc_server::get_random_public_node()
  {
    GET_PUBLIC_NODES::response response{};
    try
    {
      GET_PUBLIC_NODES::request request{};
      request.gray  = true;
      request.white = true;

      rpc_context context = {};
      context.admin       = true;
      response            = invoke(std::move(request), context);
    }
    catch(const std::exception &e)
    {
      return std::nullopt;
    }

    const auto get_random_node_address = [](const std::vector<public_node>& public_nodes) -> std::string {
      const auto& random_node = public_nodes[crypto::rand_idx(public_nodes.size())];
      const auto address = random_node.host + ":" + std::to_string(random_node.rpc_port);
      return address;
    };

    if (!response.white.empty())
    {
      return get_random_node_address(response.white);
    }

    MDEBUG("No white public node found, checking gray peers");

    if (!response.gray.empty())
    {
      return get_random_node_address(response.gray);
    }

    MERROR("Failed to find any suitable public node");
    return std::nullopt;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::init(const boost::program_options::variables_map& vm)
  {
    if (!set_bootstrap_daemon(command_line::get_arg(vm, arg_bootstrap_daemon_address),
                              command_line::get_arg(vm, arg_bootstrap_daemon_login)))
    {
      MERROR("Failed to parse bootstrap daemon address");
    }
    m_was_bootstrap_ever_used = false;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::check_core_ready()
  {
    return m_p2p.get_payload_object().is_synchronized();
  }


#define CHECK_CORE_READY() do { if(!check_core_ready()){ res.status =  STATUS_BUSY; return res; } } while(0)

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_HEIGHT& get_height, rpc_context context)
  {
    PERF_TIMER(on_get_height);
    /* FIXME
    if (use_bootstrap_daemon_if_necessary<GET_HEIGHT>(req, res))
      return res;
    */
    auto [height, hash] = m_core.get_blockchain_top();
    ++height; // block height to chain height
    get_height.response["status"] = STATUS_OK;
    get_height.response["height"] = height;
    get_height.response_hex["hash"] = hash;

    uint64_t immutable_height = 0;
    cryptonote::checkpoint_t checkpoint;
    if (m_core.get_blockchain_storage().get_db().get_immutable_checkpoint(&checkpoint, height - 1))
    {
      get_height.response["immutable_height"] = checkpoint.height;
      get_height.response_hex["immutable_hash"] = checkpoint.block_hash;
    }
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_INFO& info, rpc_context context)
  {
    PERF_TIMER(on_get_info);
    /* FIXME
    if (use_bootstrap_daemon_if_necessary<GET_INFO>(req, res))
    {
      if (context.admin)
      {
        auto [height, top_hash] = m_core.get_blockchain_top();
        res.height_without_bootstrap = height;
        ++*res.height_without_bootstrap; // turn top block height into blockchain height
        res.was_bootstrap_ever_used = true;

        std::shared_lock lock{m_bootstrap_daemon_mutex};
        if (m_bootstrap_daemon.get() != nullptr)
        {
          res.bootstrap_daemon_address = m_bootstrap_daemon->address();
        }
      }
      return res;
    }
    */
    auto [top_height, top_hash] = m_core.get_blockchain_top();
 
    auto& bs = m_core.get_blockchain_storage();
    auto& db = bs.get_db();

    auto prev_ts = db.get_block_timestamp(top_height);
    auto height = top_height + 1; // turn top block height into blockchain height

    info.response["height"] = height;
    info.response_hex["top_block_hash"] = top_hash;
    info.response["target_height"] = m_core.get_target_blockchain_height();

    bool next_block_is_POS = false;
    if (POS::timings t;
      POS::get_round_timings(bs, height, prev_ts, t)) {
      info.response["POS_ideal_timestamp"] = tools::to_seconds(t.ideal_timestamp.time_since_epoch());
      info.response["POS_target_timestamp"] = tools::to_seconds(t.r0_timestamp.time_since_epoch());
      next_block_is_POS = POS::clock::now() < t.miner_fallback_timestamp;
    }

    if (cryptonote::checkpoint_t checkpoint;
      db.get_immutable_checkpoint(&checkpoint, top_height))
    {
      info.response["immutable_height"] = checkpoint.height;
      info.response_hex["immutable_block_hash"] = checkpoint.block_hash;
    }

    if (next_block_is_POS)
      info.response["POS"] = true;
    else
      info.response["difficulty"] = bs.get_difficulty_for_next_block(next_block_is_POS);

    info.response["target"] = tools::to_seconds((next_block_is_POS ? TARGET_BLOCK_TIME : old::TARGET_BLOCK_TIME_12));
    // This count seems broken: blocks with no outputs (after batching) shouldn't be subtracted, and
    // 0-output txes (MN state changes) arguably shouldn't be, either.
    info.response["tx_count"] = m_core.get_blockchain_storage().get_total_transactions() - height; //without coinbase
    info.response["tx_pool_size"] = m_core.get_pool().get_transactions_count();

    if (context.admin)
    {
      info.response["alt_blocks_count"] = bs.get_alternative_blocks_count();
      auto total_conn = m_p2p.get_public_connections_count();
      auto outgoing_conns = m_p2p.get_public_outgoing_connections_count();
      info.response["outgoing_connections_count"] = outgoing_conns;
      info.response["incoming_connections_count"] = total_conn - outgoing_conns;
      info.response["white_peerlist_size"] = m_p2p.get_public_white_peers_count();
      info.response["grey_peerlist_size"] = m_p2p.get_public_gray_peers_count();
    }

    cryptonote::network_type nettype = m_core.get_nettype();
    info.response["mainnet"] = nettype == network_type::MAINNET;
    if (nettype == network_type::TESTNET) info.response["testnet"] = true;
    else if (nettype == network_type::DEVNET) info.response["devnet"] = true;
    else if (nettype != network_type::MAINNET) info.response["fakechain"] = true;
    info.response["nettype"] = nettype == network_type::MAINNET ? "mainnet" : nettype == network_type::TESTNET ? "testnet" : nettype == network_type::DEVNET ? "devnet" : "fakechain";

    try
    {
      auto cd = db.get_block_cumulative_difficulty(top_height);
      info.response["cumulative_difficulty"] = cd;
    }
    catch(std::exception const &e)
    {
      info.response["status"] = "Error retrieving cumulative difficulty at height " + std::to_string(top_height);
      return;
    }

    info.response["block_size_limit"] = bs.get_current_cumulative_block_weight_limit();
    info.response["block_size_median"] = bs.get_current_cumulative_block_weight_median();

    info.response["bns_counts"] = bs.name_system_db().get_mapping_counts(height);

    if (context.admin)
    {
      bool mn = m_core.master_node();
      info.response["master_node"] = mn;
      info.response["start_time"] = m_core.get_start_time();
      if (mn) {
        info.response["last_storage_server_ping"] = m_core.m_last_storage_server_ping.load();
        info.response["last_belnet_ping"] = m_core.m_last_belnet_ping.load();
      }
      info.response["free_space"] = m_core.get_free_space();

      if (std::shared_lock lock{m_bootstrap_daemon_mutex}; m_bootstrap_daemon) {
        info.response["bootstrap_daemon_address"] = m_bootstrap_daemon->address();
        info.response["height_without_bootstrap"] = height;
        info.response["was_bootstrap_ever_used"] = m_was_bootstrap_ever_used;
      }
    }

    if (m_core.offline())
      info.response["offline"] = true;
    auto db_size = db.get_database_size();
    info.response["database_size"] = context.admin ? db_size : round_up(db_size, 1'000'000'000);
    info.response["version"]       = context.admin ? BELDEX_VERSION_FULL : std::to_string(BELDEX_VERSION[0]);
    info.response["status_line"]   = context.admin ? m_core.get_status_string() :
      "v" + std::to_string(BELDEX_VERSION[0]) + "; Height: " + std::to_string(height);

    info.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_NET_STATS& get_net_stats, rpc_context context)
  {
    PERF_TIMER(on_get_net_stats);
    // No bootstrap daemon check: Only ever get stats about local server
    get_net_stats.response["start_time"] = m_core.get_start_time();
    {
      std::lock_guard lock{epee::net_utils::network_throttle_manager::m_lock_get_global_throttle_in};
      auto [packets, bytes] = epee::net_utils::network_throttle_manager::get_global_throttle_in().get_stats();
      get_net_stats.response["total_packets_in"] = packets;
      get_net_stats.response["total_bytes_in"] = bytes;    
    }
    {
      std::lock_guard lock{epee::net_utils::network_throttle_manager::m_lock_get_global_throttle_out};
      auto [packets, bytes] = epee::net_utils::network_throttle_manager::get_global_throttle_out().get_stats();
      get_net_stats.response["total_packets_out"] = packets;
      get_net_stats.response["total_bytes_out"] = bytes;
    }
    get_net_stats.response["status"] = STATUS_OK;
  }
  namespace {
  //------------------------------------------------------------------------------------------------------------------------------
  class pruned_transaction {
    transaction& tx;
  public:
    pruned_transaction(transaction& tx) : tx(tx) {}
    BEGIN_SERIALIZE_OBJECT()
      tx.serialize_base(ar);
    END_SERIALIZE()
  };
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_BLOCKS_BIN::response core_rpc_server::invoke(GET_BLOCKS_BIN::request&& req, rpc_context context)
  {
    GET_BLOCKS_BIN::response res{};

    PERF_TIMER(on_get_blocks);
    if (use_bootstrap_daemon_if_necessary<GET_BLOCKS_BIN>(req, res))
      return res;

    std::vector<std::pair<std::pair<cryptonote::blobdata, crypto::hash>, std::vector<std::pair<crypto::hash, cryptonote::blobdata> > > > bs;

    if(!m_core.find_blockchain_supplement(req.start_height, req.block_ids, bs, res.current_height, res.start_height, req.prune, !req.no_miner_tx, GET_BLOCKS_BIN::MAX_COUNT))
    {
      res.status = "Failed";
      return res;
    }

    size_t size = 0, ntxes = 0;
    res.blocks.reserve(bs.size());
    res.output_indices.reserve(bs.size());
    for(auto& bd: bs)
    {
      res.blocks.resize(res.blocks.size()+1);
      res.blocks.back().block = bd.first.first;
      size += bd.first.first.size();
      res.output_indices.push_back(GET_BLOCKS_BIN::block_output_indices());
      ntxes += bd.second.size();
      res.output_indices.back().indices.reserve(1 + bd.second.size());
      if (req.no_miner_tx)
        res.output_indices.back().indices.push_back(GET_BLOCKS_BIN::tx_output_indices());
      res.blocks.back().txs.reserve(bd.second.size());
      for (auto& [txhash, txdata] : bd.second)
      {
          auto& entry = res.blocks.back().txs.emplace_back(std::move(txdata), crypto::null_hash);
          size += entry.size();
      }

      const size_t n_txes_to_lookup = bd.second.size() + (req.no_miner_tx ? 0 : 1);
      if (n_txes_to_lookup > 0)
      {
        std::vector<std::vector<uint64_t>> indices;
        bool r = m_core.get_tx_outputs_gindexs(req.no_miner_tx ? bd.second.front().first : bd.first.second, n_txes_to_lookup, indices);
        if (!r || indices.size() != n_txes_to_lookup || res.output_indices.back().indices.size() != (req.no_miner_tx ? 1 : 0))
        {
          res.status = "Failed";
          return res;
        }
        for (size_t i = 0; i < indices.size(); ++i)
          res.output_indices.back().indices.push_back({std::move(indices[i])});
      }
    }

    MDEBUG("on_get_blocks: " << bs.size() << " blocks, " << ntxes << " txes, size " << size);
    res.status = STATUS_OK;
    return res;
  }
  GET_ALT_BLOCKS_HASHES_BIN::response core_rpc_server::invoke(GET_ALT_BLOCKS_HASHES_BIN::request&& req, rpc_context context)
  {
    GET_ALT_BLOCKS_HASHES_BIN::response res{};

    PERF_TIMER(on_get_alt_blocks_hashes);
    if (use_bootstrap_daemon_if_necessary<GET_ALT_BLOCKS_HASHES_BIN>(req, res))
      return res;

    std::vector<block> blks;

    if(!m_core.get_alternative_blocks(blks))
    {
        res.status = "Failed";
        return res;
    }

    res.blks_hashes.reserve(blks.size());

    for (auto const& blk: blks)
    {
        res.blks_hashes.push_back(tools::type_to_hex(get_block_hash(blk)));
    }

    MDEBUG("on_get_alt_blocks_hashes: " << blks.size() << " blocks " );
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_BLOCKS_BY_HEIGHT_BIN::response core_rpc_server::invoke(GET_BLOCKS_BY_HEIGHT_BIN::request&& req, rpc_context context)
  {
    GET_BLOCKS_BY_HEIGHT_BIN::response res{};

    PERF_TIMER(on_get_blocks_by_height);
    if (use_bootstrap_daemon_if_necessary<GET_BLOCKS_BY_HEIGHT_BIN>(req, res))
      return res;

    res.status = "Failed";
    res.blocks.clear();
    res.blocks.reserve(req.heights.size());
    for (uint64_t height : req.heights)
    {
      block blk;
      try
      {
        blk = m_core.get_blockchain_storage().get_db().get_block_from_height(height);
      }
      catch (...)
      {
        res.status = "Error retrieving block at height " + std::to_string(height);
        return res;
      }
      std::vector<transaction> txs;
      m_core.get_transactions(blk.tx_hashes, txs);
      res.blocks.resize(res.blocks.size() + 1);
      res.blocks.back().block = block_to_blob(blk);
      for (auto& tx : txs)
        res.blocks.back().txs.push_back(tx_to_blob(tx));
    }
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_HASHES_BIN::response core_rpc_server::invoke(GET_HASHES_BIN::request&& req, rpc_context context)
  {
    GET_HASHES_BIN::response res{};

    PERF_TIMER(on_get_hashes);
    if (use_bootstrap_daemon_if_necessary<GET_HASHES_BIN>(req, res))
      return res;

    res.start_height = req.start_height;
    if(!m_core.get_blockchain_storage().find_blockchain_supplement(req.block_ids, res.m_block_ids, res.start_height, res.current_height, false))
    {
      res.status = "Failed";
      return res;
    }

    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_OUTPUTS_BIN::response core_rpc_server::invoke(GET_OUTPUTS_BIN::request&& req, rpc_context context)
  {
    GET_OUTPUTS_BIN::response res{};

    PERF_TIMER(on_get_outs_bin);
    if (use_bootstrap_daemon_if_necessary<GET_OUTPUTS_BIN>(req, res))
      return res;

    if (!context.admin && req.outputs.size() > GET_OUTPUTS_BIN::MAX_COUNT)
      res.status = "Too many outs requested";
    else if (m_core.get_outs(req, res))
      res.status = STATUS_OK;
    else
      res.status = "Failed";

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_OUTPUTS& get_outputs, rpc_context context)
  {
    PERF_TIMER(on_get_outs);
    //TODO this bootstrap daemon call to work for new RPC design
    //if (use_bootstrap_daemon_if_necessary<GET_OUTPUTS>(req, res))
      //return;

    if (!context.admin && get_outputs.request.output_indices.size() > GET_OUTPUTS::MAX_COUNT) {
      get_outputs.response["status"] = "Too many outs requested";
      return;
    }

    // This is nasty.  WTF are core methods taking *local rpc* types?
    // FIXME: make core methods take something sensible, like a std::vector<uint64_t>.  (We really
    // don't need the pair since amount is also 0 for Beldex since the beginning of the chain; only in
    // ancient Monero blocks was it non-zero).
    GET_OUTPUTS_BIN::request req_bin{};
    req_bin.get_txid = get_outputs.request.get_txid;
    req_bin.outputs.reserve(get_outputs.request.output_indices.size());
    for (auto oi : get_outputs.request.output_indices)
      req_bin.outputs.push_back({0, oi});

    GET_OUTPUTS_BIN::response res_bin{};
    if (!m_core.get_outs(req_bin, res_bin)){
      get_outputs.response["status"] = "Failed";
      return;
    }

    auto& outs = (get_outputs.response["outs"] = json::array());
    if (!get_outputs.request.as_tuple) {
      for (auto& outkey : res_bin.outs) {
        outs.push_back(json{
          {"key", std::move(outkey.key)},
          {"mask", std::move(outkey.mask)},
          {"unlocked", outkey.unlocked},
          {"height", outkey.height}
        });
        if (get_outputs.request.get_txid)
          outs.back()["txid"] = std::move(outkey.txid);
      }
    } else {
      for (auto& outkey : res_bin.outs) {
        outs.push_back(json::array({
            std::move(outkey.key),
            std::move(outkey.mask),
            outkey.unlocked,
            outkey.height}));
        if (get_outputs.request.get_txid)
          outs.back().push_back(std::move(outkey.txid));
      }
    }

    get_outputs.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN::response core_rpc_server::invoke(GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN::request&& req, rpc_context context)
  {
    GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN::response res{};

    PERF_TIMER(on_get_indexes);
    if (use_bootstrap_daemon_if_necessary<GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN>(req, res))
      return res;

    bool r = m_core.get_tx_outputs_gindexs(req.txid, res.o_indexes);
    if(!r)
    {
      res.status = "Failed";
      return res;
    }
    res.status = STATUS_OK;
    LOG_PRINT_L2("GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN: [" << res.o_indexes.size() << "]");
    return res;
  }

  namespace {
    constexpr uint64_t half_microportion = 9223372036855ULL; // half of 1/1'000'000 of a full portion
    constexpr uint32_t microportion(uint64_t portion) {
      // Rounding integer division to convert our [0, ..., 2^64-4] portion value into [0, ..., 1000000]:
      return portion < half_microportion ? 0 : (portion - half_microportion) / (2*half_microportion) + 1;
    }
    template <typename T>
    std::vector<std::string> hexify(const std::vector<T>& v) {
      std::vector<std::string> hexes;
      hexes.reserve(v.size());
      for (auto& x : v)
        hexes.push_back(tools::type_to_hex(x));
      return hexes;
    }

    struct extra_extractor {
      nlohmann::json& entry;
      const network_type nettype;
      const cryptonote::hf hf_version;
      json_binary_proxy::fmt format;

      // If we encounter duplicate values then we want to produce an array of values, but with just
      // a single one we want just the value itself; this does that.  Returns a reference to the
      // assigned value (whether as a top-level value or array element).
      template <typename T>
      json& set(const std::string& key, T&& value, bool binary = is_binary_parameter<T> || is_binary_container<T>) {
        auto* x = &entry[key];
        if (!x->is_null() && !x->is_array())
          x = &(entry[key] = json::array({std::move(*x)}));
        if (x->is_array())
          x = &x->emplace_back();
        if constexpr (is_binary_parameter<T> || is_binary_container<T> || std::is_convertible_v<T, std::string_view>) {
          if (binary)
            return json_binary_proxy{*x, format} = std::forward<T>(value);
        }
        assert(!binary);
        return *x = std::forward<T>(value);
      }

      void operator()(const tx_extra_pub_key& x) { set("pubkey", x.pub_key); }
      void operator()(const tx_extra_nonce& x) {
        if ((x.nonce.size() == sizeof(crypto::hash) + 1 && x.nonce[0] == TX_EXTRA_NONCE_PAYMENT_ID)
            || (x.nonce.size() == sizeof(crypto::hash8) + 1 && x.nonce[0] == TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID))
          set("payment_id", std::string_view{x.nonce.data() + 1, x.nonce.size() - 1}, true);
        else
          set("extra_nonce", x.nonce, true);
      }
      void operator()(const tx_extra_merge_mining_tag& x) { set("mm_depth", x.depth); set("mm_root", x.merkle_root); }
      void operator()(const tx_extra_additional_pub_keys& x) { set("additional_pubkeys", x.data); }
      void operator()(const tx_extra_burn& x) { set("burn_amount", x.amount); }
      void operator()(const tx_extra_master_node_winner& x) { set("mn_winner", x.m_master_node_key); }
      void operator()(const tx_extra_master_node_pubkey& x) { set("mn_pubkey", x.m_master_node_key); }
      void operator()(const tx_extra_security_signature& x) {  entry.security_sig = tools::type_to_hex(x.m_security_signature); }
      void operator()(const tx_extra_master_node_register& x) {
        json reservations{};
        for (size_t i = 0; i < x.m_portions.size(); i++)
          reservations[get_account_address_as_str(nettype, false, {x.m_public_spend_keys[i], x.m_public_view_keys[i]})]
            = microportion(x.m_portions[i]);
        set("mn_registration", json{
          {"fee", microportion(x.m_portions_for_operator)},
          {"expiry", x.m_expiration_timestamp},
          {"reservations", std::move(reservations)}});
      }
      void operator()(const tx_extra_master_node_contributor& x) {
        set("mn_contributor", get_account_address_as_str(nettype, false, {x.m_spend_public_key, x.m_view_public_key}));
      }
      template <typename T>
      auto& _state_change(const T& x) {
        // Common loading code for nearly-identical state_change and deregister_old variables:
        auto voters = json::array();
        for (auto& v : x.votes)
          voters.push_back(v.validator_index);

        json sc{
            {"height", x.block_height},
            {"index", x.master_node_index},
            {"voters", std::move(voters)}};
        return set("mn_state_change", std::move(sc));
      }
      void operator()(const tx_extra_master_node_deregister_old& x) {
        auto& sc = _state_change(x);
        sc["old_dereg"] = true;
        sc["type"] = "dereg";
      }
      void operator()(const tx_extra_master_node_state_change& x) {
        auto& sc = _state_change(x);
        if (x.reason_consensus_all)
          sc["reasons"] = cryptonote::coded_reasons(x.reason_consensus_all);
        // If `any` has reasons not included in all then list the extra ones separately:
        if (uint16_t reasons_maybe = x.reason_consensus_any & ~x.reason_consensus_all)
          sc["reasons_maybe"] = cryptonote::coded_reasons(reasons_maybe);
        switch (x.state)
        {
          case master_nodes::new_state::decommission: sc["type"] = "decom"; break;
          case master_nodes::new_state::recommission: sc["type"] = "recom"; break;
          case master_nodes::new_state::deregister: sc["type"] = "dereg"; break;
          case master_nodes::new_state::ip_change_penalty: sc["type"] = "ip"; break;
          case master_nodes::new_state::_count: /*leave blank*/ break;
        }
      }
      void operator()(const tx_extra_tx_secret_key& x) { set("tx_secret_key", tools::view_guts(x.key), true); }
      void operator()(const tx_extra_tx_key_image_proofs& x) {
        std::vector<crypto::key_image> kis;
        kis.reserve(x.proofs.size());
        for (auto& proof : x.proofs)
          kis.push_back(proof.key_image);
        set("locked_key_images", std::move(kis));
      }
      void operator()(const tx_extra_tx_key_image_unlock& x) { set("key_image_unlock", x.key_image); }
      void _load_owner(json& parent, const std::string& key, const bns::generic_owner& owner) {
        if (!owner)
          return;
        if (owner.type == bns::generic_owner_sig_type::monero)
          parent[key] = get_account_address_as_str(nettype, owner.wallet.is_subaddress, owner.wallet.address);
        else if (owner.type == bns::generic_owner_sig_type::ed25519)
          json_binary_proxy{parent[key], json_binary_proxy::fmt::hex} = owner.ed25519;
      }
      //TODO CHECK ON HF
      void operator()(const tx_extra_beldex_name_system& x) {
        json bns{};
        bns["version"] = x.version;          
        if ((x.is_buying() || x.is_renewing()) && (x.version == 1))
          bns["blocks"] = bns::expiry_blocks(nettype, x.mapping_years) ;
        if(x.version == 0)
          switch (x.type)
          {
            case bns::mapping_type::belnet: [[fallthrough]];
            case bns::mapping_type::belnet_2years: [[fallthrough]];
            case bns::mapping_type::belnet_5years: [[fallthrough]];
            case bns::mapping_type::belnet_10years: bns["type"] = "belnet"; break;

            case bns::mapping_type::bchat: bns["type"] = "bchat"; break;
            case bns::mapping_type::wallet:  bns["type"] = "wallet"; break;
            case bns::mapping_type::eth_addr:  bns["type"] = "eth_addr"; break;

            case bns::mapping_type::update_record_internal: [[fallthrough]];
            case bns::mapping_type::_count:
              break;
          }
        if (x.is_buying())
          bns["buy"] = true;
        else if (x.is_updating())
          bns["update"] = true;
        else if (x.is_renewing())
          bns["renew"] = true;
        auto bns_bin = json_binary_proxy{bns, format};
        bns_bin["name_hash"] = x.name_hash;
        if (!x.encrypted_bchat_value.empty())
          bns_bin["value_bchat"] = x.encrypted_bchat_value;
        if (!x.encrypted_wallet_value.empty())
          bns_bin["value_wallet"] = x.encrypted_wallet_value;
        if (!x.encrypted_belnet_value.empty())
          bns_bin["value_belnet"] = x.encrypted_belnet_value;
        if (!x.encrypted_eth_addr_value.empty())
          bns_bin["value_eth_addr"] = x.encrypted_eth_addr_value;
        _load_owner(bns, "owner", x.owner);
        _load_owner(bns, "backup_owner", x.backup_owner);
      }

      // Ignore these fields:
      void operator()(const tx_extra_padding&) {}
      void operator()(const tx_extra_mysterious_minergate&) {}
    };


    void load_tx_extra_data(nlohmann::json& e, const transaction& tx, network_type nettype, cryptonote::hf hf_version, bool is_bt)
    {
      e = json::object();
      std::vector<tx_extra_field> extras;
      if (!parse_tx_extra(tx.extra, extras))
        return;
      extra_extractor visitor{e, nettype, hf_version, is_bt ? json_binary_proxy::fmt::bt : json_binary_proxy::fmt::hex};
      for (const auto& extra : extras)
        var::visit(visitor, extra);
    }
  }

  struct tx_info {
    txpool_tx_meta_t meta;
    std::string tx_blob;                // Blob containing the transaction data.
    bool flash;                         // True if this is a signed flash transaction
  };

  static std::unordered_map<crypto::hash, tx_info> get_pool_txs_impl(cryptonote::core& core) {
    auto& bc = core.get_blockchain_storage();
    auto& pool = core.get_pool();

    std::unordered_map<crypto::hash, tx_info> tx_infos;
    tx_infos.reserve(bc.get_txpool_tx_count());

    bc.for_all_txpool_txes(
        [&tx_infos, &pool]
        (const crypto::hash& txid, const txpool_tx_meta_t& meta, const cryptonote::blobdata* bd) {
      transaction tx;
      if (!parse_and_validate_tx_from_blob(*bd, tx))
      {
        MERROR("Failed to parse tx from txpool");
        // continue
        return true;
      }
      auto& txi = tx_infos[txid];
      txi.meta = meta;
      txi.tx_blob = *bd;
      tx.set_hash(txid);
      txi.flash = pool.has_flash(txid);
      return true;
    }, true);

    return tx_infos;
  }

  static auto pool_locks(cryptonote::core& core) {
    auto& pool = core.get_pool();
    std::unique_lock tx_lock{pool, std::defer_lock};
    std::unique_lock bc_lock{core.get_blockchain_storage(), std::defer_lock};
    auto flash_lock = pool.flash_shared_lock(std::defer_lock);
    std::lock(tx_lock, bc_lock, flash_lock);
    return std::make_tuple(std::move(tx_lock), std::move(bc_lock), std::move(flash_lock));
  }

  static std::pair<std::unordered_map<crypto::hash, tx_info>, tx_memory_pool::key_images_container> get_pool_txs_kis(cryptonote::core& core) {
    auto locks = pool_locks(core);
    return {get_pool_txs_impl(core), core.get_pool().get_spent_key_images(true)};
  }

  /*
  static std::unordered_map<crypto::hash, tx_info> get_pool_txs(
      cryptonote::core& core, std::function<void(const transaction&, tx_info&)> post_process = {}) {
    auto locks = pool_locks(core);
    return get_pool_txs_impl(core, std::move(post_process));
  }
  */

  static tx_memory_pool::key_images_container get_pool_kis(
      cryptonote::core& core, std::function<void(const transaction&, tx_info&)> post_process = {}) {
    auto locks = pool_locks(core);
    return core.get_pool().get_spent_key_images(true);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_TRANSACTIONS& get, rpc_context context)
  {
    PERF_TIMER(on_get_transactions);
    /*
    if (use_bootstrap_daemon_if_necessary<GET_TRANSACTIONS>(req, res))
      return res;
    */
    std::unordered_set<crypto::hash> missed_txs;
    using split_tx = std::tuple<crypto::hash, std::string, crypto::hash, std::string>;
    std::vector<split_tx> txs;
    if (!get.request.tx_hashes.empty()) {
      if (!m_core.get_split_transactions_blobs(get.request.tx_hashes, txs, &missed_txs))
      {
        get.response["status"] = STATUS_FAILED;
        return;
      }
      LOG_PRINT_L2("Found " << txs.size() << "/" << get.request.tx_hashes.size() << " transactions on the blockchain");
    }

    // try the pool for any missing txes
    auto& pool = m_core.get_pool();
    std::unordered_map<crypto::hash, tx_info> found_in_pool;
    if (!missed_txs.empty() || get.request.memory_pool)
    {
      try {
        auto [pool_txs, pool_kis] = get_pool_txs_kis(m_core);

        auto split_mempool_tx = [](std::pair<const crypto::hash, tx_info>& info) {
          cryptonote::transaction tx;
          if (!cryptonote::parse_and_validate_tx_from_blob(info.second.tx_blob, tx))
            throw std::runtime_error{"Unable to parse and validate tx from blob"};
          serialization::binary_string_archiver ba;
          try {
            tx.serialize_base(ba);
          } catch (const std::exception& e) {
            throw std::runtime_error{"Failed to serialize transaction base: "s + e.what()};
          }
          std::string pruned = ba.str();
          std::string pruned2{info.second.tx_blob, pruned.size()};
          return split_tx{info.first, std::move(pruned), get_transaction_prunable_hash(tx), std::move(pruned2)};
        };

        if (!get.request.tx_hashes.empty()) {
          // sort to match original request
          std::vector<split_tx> sorted_txs;
          unsigned txs_processed = 0;
          for (const auto& h: get.request.tx_hashes) {
            if (auto missed_it = missed_txs.find(h); missed_it == missed_txs.end()) {
              if (txs.size() == txs_processed) {
                get.response["status"] = "Failed: internal error - txs is empty";
                return;
              }
              // core returns the ones it finds in the right order
              if (std::get<0>(txs[txs_processed]) != h) {
                get.response["status"] = "Failed: internal error - tx hash mismatch";
                return;
              }
              sorted_txs.push_back(std::move(txs[txs_processed]));
              ++txs_processed;
            } else if (auto ptx_it = pool_txs.find(h); ptx_it != pool_txs.end()) {
              sorted_txs.push_back(split_mempool_tx(*ptx_it));
              missed_txs.erase(missed_it);
              found_in_pool.emplace(h, std::move(ptx_it->second));
            }
          }
          txs = std::move(sorted_txs);
          get.response_hex["missed_tx"] = missed_txs; // non-plural here intentional to not break existing clients
          LOG_PRINT_L2("Found " << found_in_pool.size() << "/" << get.request.tx_hashes.size() << " transactions in the pool");
        } else if (get.request.memory_pool) {
          txs.reserve(pool_txs.size());
          std::transform(pool_txs.begin(), pool_txs.end(), std::back_inserter(txs), split_mempool_tx);
          found_in_pool = std::move(pool_txs);

          auto mki = get.response_hex["mempool_key_images"];
          for (auto& [ki, txids] : pool_kis) {
            // The *key* is also binary (hex for json):
            std::string key{get.is_bt() ? tools::view_guts(ki) : tools::type_to_hex(ki)};
            mki[key] = txids;
          }
        }
      } catch (const std::exception& e) {
        MERROR(e.what());
        get.response["status"] = "Failed: "s + e.what();
        return;
      }
    }
    uint64_t immutable_height = m_core.get_blockchain_storage().get_immutable_height();
    auto flash_lock = pool.flash_shared_lock(std::defer_lock); // Defer until/unless we actually need it
   
    auto& txs_out = get.response["txs"];
    txs_out = json::array();
    auto height = m_core.get_current_blockchain_height();
    auto net = nettype();
    auto hf_version = get_network_version(net, height);
    for (const auto& [tx_hash, unprunable_data, prunable_hash, prunable_data]: txs)
    {
      auto& e = txs_out.emplace_back();
      auto e_bin = get.response_hex["txs"].back();
      e_bin["tx_hash"] = tx_hash;
      e["size"] = unprunable_data.size() + prunable_data.size();

      // If the transaction was pruned then the prunable part will be empty but the prunable hash
      // will be non-null.  (Some txes, like coinbase txes, are non-prunable and will have empty
      // *and* null prunable hash).
      bool prunable = prunable_hash != crypto::null_hash;
      bool pruned = prunable && prunable_data.empty();

      if (pruned || (prunable && (get.request.split || get.request.prune)))
        e_bin["prunable_hash"] = prunable_hash;

      std::string tx_data = unprunable_data;
      if (!get.request.prune)
        tx_data += prunable_data;

      if (get.request.split || get.request.prune)
      {
        e_bin["pruned"] = unprunable_data;
        if (get.request.split)
          e_bin["prunable"] = prunable_data;
      }

      if (get.request.data) {
        if (pruned || get.request.prune) {
          if (!e.count("pruned"))
            e_bin["pruned"] = unprunable_data;
        } else {
          e_bin["data"] = tx_data;
        }  
      }

      cryptonote::transaction tx;
      if (get.request.prune || pruned)
      {
        if (!cryptonote::parse_and_validate_tx_base_from_blob(tx_data, tx))
        {
          get.response["status"] = "Failed to parse and validate base tx data";
          return;
        }
      }
      else
      {
        if (!cryptonote::parse_and_validate_tx_from_blob(tx_data, tx))
        {
          get.response["status"] = "Failed to parse and validate tx data";
          return;
        }
      }
      if (get.request.tx_extra)
        load_tx_extra_data(e["extra"], tx, nettype(), hf_version, get.is_bt());

      auto ptx_it = found_in_pool.find(tx_hash);
      bool in_pool = ptx_it != found_in_pool.end();
      e["in_pool"] = in_pool;
      auto height = std::numeric_limits<uint64_t>::max();

      if (uint64_t fee, burned; get_tx_miner_fee(tx, fee, hf_version >= feature::FEE_BURNING, &burned)) {
        e["fee"] = fee;
        e["burned"] = burned;
      }

      if (in_pool)
      {
        const auto& meta = ptx_it->second.meta;
        e["weight"] = meta.weight;
        e["relayed"] = (bool) ptx_it->second.meta.relayed;
        e["received_timestamp"] = ptx_it->second.meta.receive_time;
        e["flash"] = ptx_it->second.flash;
        if (meta.double_spend_seen) e["double_spend_seen"] = true;
        if (meta.do_not_relay) e["do_not_relay"] = true;
        if (meta.last_relayed_time) e["last_relayed_time"] = meta.last_relayed_time;
        if (meta.kept_by_block) e["kept_by_block"] = (bool) meta.kept_by_block;
        if (meta.last_failed_id) e_bin["last_failed_block"] = meta.last_failed_id;
        if (meta.last_failed_height) e["last_failed_height"] = meta.last_failed_height;
        if (meta.max_used_block_id) e_bin["max_used_block"] = meta.max_used_block_id;
        if (meta.max_used_block_height) e["max_used_height"] = meta.max_used_block_height;

      }
      else
      {
        height = m_core.get_blockchain_storage().get_db().get_tx_block_height(tx_hash);
        e["block_height"] = height;
        e["block_timestamp"] = m_core.get_blockchain_storage().get_db().get_block_timestamp(height);
        if (height > immutable_height) {
          if (!flash_lock) flash_lock.lock();
          e["flash"] = pool.has_flash(tx_hash);
        }
      }

      {
        master_nodes::staking_components sc;
        if (master_nodes::tx_get_staking_components_and_amounts(nettype(), hf_version, tx, height, &sc)
            && sc.transferred > 0)
          e["stake_amount"] = sc.transferred;
      }

      // output indices too if not in pool
      if (!in_pool)
      {
        std::vector<uint64_t> indices;
        if (m_core.get_tx_outputs_gindexs(tx_hash, indices))
          e["output_indices"] = std::move(indices);
        else
        {
          get.response["status"] = STATUS_FAILED;
          return;
        }
      }
    }

    LOG_PRINT_L2(get.response["txs"].size() << " transactions found, " << missed_txs.size() << " not found");
    get.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  IS_KEY_IMAGE_SPENT::response core_rpc_server::invoke(IS_KEY_IMAGE_SPENT::request&& req, rpc_context context)
  {
    IS_KEY_IMAGE_SPENT::response res{};

    PERF_TIMER(on_is_key_image_spent);
    if (use_bootstrap_daemon_if_necessary<IS_KEY_IMAGE_SPENT>(req, res))
      return res;

    std::vector<crypto::key_image> key_images;
    for(const auto& ki_hex_str: req.key_images)
    {
      if (!tools::hex_to_type(ki_hex_str, key_images.emplace_back()))
      {
        res.status = "Failed to parse hex representation of key image";
        return res;
      }
    }
    std::vector<bool> spent_status;
    bool r = m_core.are_key_images_spent(key_images, spent_status);
    if(!r)
    {
      res.status = "Failed";
      return res;
    }
    res.spent_status.clear();
    for (size_t n = 0; n < spent_status.size(); ++n)
      res.spent_status.push_back(spent_status[n] ? IS_KEY_IMAGE_SPENT::SPENT_IN_BLOCKCHAIN : IS_KEY_IMAGE_SPENT::UNSPENT);

    // check the pool too
    try {
      auto kis = get_pool_kis(m_core);
      for (size_t n = 0; n < res.spent_status.size(); ++n)
        if (res.spent_status[n] == IS_KEY_IMAGE_SPENT::UNSPENT && kis.count(key_images[n]))
          res.spent_status[n] = IS_KEY_IMAGE_SPENT::SPENT_IN_POOL;
    } catch (const std::exception& e) {
      MERROR("Failed to get pool key images: " << e.what());
      res.status = "Failed";
      return res;
    }
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SEND_RAW_TX::response core_rpc_server::invoke(SEND_RAW_TX::request&& req, rpc_context context)
  {
    SEND_RAW_TX::response res{};

    PERF_TIMER(on_send_raw_tx);
    if (use_bootstrap_daemon_if_necessary<SEND_RAW_TX>(req, res))
      return res;

    CHECK_CORE_READY();

    if (!oxenc::is_hex(req.tx_as_hex))    {
      LOG_PRINT_L0("[on_send_raw_tx]: Failed to parse tx from hexbuff: " << req.tx_as_hex);
      res.status = "Failed";
      return res;
    }
    auto tx_blob = oxenc::from_hex(req.tx_as_hex);

    if (req.flash)
    {
      auto future = m_core.handle_flash_tx(tx_blob);
      auto status = future.wait_for(10s);
      if (status != std::future_status::ready) {
        res.status = "Failed";
        res.reason = "Flash quorum timeout";
        res.flash_status = flash_result::timeout;
        return res;
      }

      try {
        auto result = future.get();
        res.flash_status = result.first;
        if (result.first == flash_result::accepted) {
          res.status = STATUS_OK;
        } else {
          res.status = "Failed";
          res.reason = !result.second.empty() ? result.second : result.first == flash_result::timeout ? "Flash quorum timeout" : "Transaction rejected by flash quorum";
        }
      } catch (const std::exception &e) {
        res.flash_status = flash_result::rejected;
        res.status = "Failed";
        res.reason = std::string{"Transaction failed: "} + e.what();
      }
      return res;
    }

    tx_verification_context tvc{};
    if(!m_core.handle_incoming_tx(tx_blob, tvc, tx_pool_options::new_tx(req.do_not_relay)) || tvc.m_verifivation_failed)
    {
      const vote_verification_context &vvc = tvc.m_vote_ctx;
      res.status          = "Failed";
      std::string reason  = print_tx_verification_context  (tvc);
      reason             += print_vote_verification_context(vvc);
      res.tvc             = tvc;
      const std::string punctuation = res.reason.empty() ? "" : ": ";
      if (tvc.m_verifivation_failed)
      {
        LOG_PRINT_L0("[on_send_raw_tx]: tx verification failed" << punctuation << reason);
      }
      else
      {
        LOG_PRINT_L0("[on_send_raw_tx]: Failed to process tx" << punctuation << reason);
      }
      return res;
    }

    if(!tvc.m_should_be_relayed)
    {
      LOG_PRINT_L0("[on_send_raw_tx]: tx accepted, but not relayed");
      res.reason = "Not relayed";
      res.not_relayed = true;
      res.status = STATUS_OK;
      return res;
    }

    NOTIFY_NEW_TRANSACTIONS::request r{};
    r.txs.push_back(tx_blob);
    cryptonote_connection_context fake_context{};
    m_core.get_protocol()->relay_transactions(r, fake_context);

    //TODO: make sure that tx has reached other nodes here, probably wait to receive reflections from other nodes
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(START_MINING& start_mining, rpc_context context)
  {
    PERF_TIMER(on_start_mining);

    if(!check_core_ready()){ 
      start_mining.response["status"] = STATUS_BUSY;
      return; 
    }

    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, m_core.get_nettype(), start_mining.request.miner_address)){
      start_mining.response["status"] = "Failed, invalid address";
      LOG_PRINT_L0(start_mining.response["status"]);
      return;
    }
    if (info.is_subaddress)
    {
      start_mining.response["status"] = "Mining to subaddress isn't supported yet";
      LOG_PRINT_L0(start_mining.response["status"]);
      return;
    }

    int max_concurrency_count = std::thread::hardware_concurrency() * 4;

    // if we couldn't detect threads, set it to a ridiculously high number
    if(max_concurrency_count == 0)
      max_concurrency_count = 257;

    // if there are more threads requested than the hardware supports
    // then we fail and log that.
    if (start_mining.request.threads_count > max_concurrency_count) {
      start_mining.response["status"] = "Failed, too many threads relative to CPU cores.";
      LOG_PRINT_L0(start_mining.response["status"]);
      return;
    }

    auto& miner = m_core.get_miner();
    if (miner.is_mining())
    {
      start_mining.response["status"] = "Already mining";
      return;
    }

    if(!miner.start(info.address, start_mining.request.threads_count, start_mining.request.num_blocks, start_mining.request.slow_mining))
    {
      start_mining.response["status"] = "Failed, mining not started";
      LOG_PRINT_L0(start_mining.response["status"]);
      return;
    }

    start_mining.response["status"] = STATUS_OK;
    LOG_PRINT_L0(start_mining.response["status"]);
    return;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(STOP_MINING& stop_mining, rpc_context context)
  {
    PERF_TIMER(on_stop_mining);
    cryptonote::miner &miner= m_core.get_miner();
    if(!miner.is_mining())
    {
      stop_mining.response["status"] = "Mining never started";
      LOG_PRINT_L0(stop_mining.response["status"]);
      return;
    }
    if(!miner.stop())
    {
      stop_mining.response["status"] = "Failed, mining not stopped";
      LOG_PRINT_L0(stop_mining.response["status"]);
      return;
    }
    stop_mining.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(MINING_STATUS& mining_status, rpc_context context)
  {
    PERF_TIMER(on_mining_status);

    const miner& lMiner = m_core.get_miner();
    mining_status.response["active"] = lMiner.is_mining();
    mining_status.response["block_target"] = tools::to_seconds(old::TARGET_BLOCK_TIME_12); // old_block_time
    mining_status.response["difficulty"] = m_core.get_blockchain_storage().get_difficulty_for_next_block(false /*POS*/);
    if ( lMiner.is_mining() ) {
      mining_status.response["speed"] = std::lround(lMiner.get_speed());
      mining_status.response["threads_count"] = lMiner.get_threads_count();
      mining_status.response["block_reward"] = lMiner.get_block_reward();
    }
    const account_public_address& lMiningAdr = lMiner.get_mining_address();
    if (lMiner.is_mining())
      mining_status.response["address"] = get_account_address_as_str(nettype(), false, lMiningAdr);
    const auto major_version = m_core.get_blockchain_storage().get_network_version();

    mining_status.response["pow_algorithm"] =
        major_version >= hf::hf13_checkpointing    ? "RandomX (BELDEX variant)"               :
        major_version == hf::hf11_infinite_staking ? "Cryptonight Turtle Light (Variant 2)"   :
                                                               "Cryptonight Heavy (Variant 2)";

    mining_status.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(SAVE_BC& save_bc, rpc_context context)
  {
    PERF_TIMER(on_save_bc);
    if( !m_core.get_blockchain_storage().store_blockchain() )
    {
      save_bc.response["status"] = "Error while storing blockchain";
      LOG_PRINT_L0(save_bc.response["status"]);
      return;
    }
    save_bc.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_PEER_LIST::response core_rpc_server::invoke(GET_PEER_LIST::request&& req, rpc_context context)
  {
    GET_PEER_LIST::response res{};

    PERF_TIMER(on_get_peer_list);
    std::vector<nodetool::peerlist_entry> white_list;
    std::vector<nodetool::peerlist_entry> gray_list;

    if (req.public_only)
    {
      m_p2p.get_public_peerlist(gray_list, white_list);
    }
    else
    {
      m_p2p.get_peerlist(gray_list, white_list);
    }

    for (auto & entry : white_list)
    {
      if (entry.adr.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
        res.white_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv4_network_address>().ip(),
            entry.adr.as<epee::net_utils::ipv4_network_address>().port(), entry.last_seen, entry.pruning_seed, entry.rpc_port);
      else if (entry.adr.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id())
        res.white_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv6_network_address>().host_str(),
            entry.adr.as<epee::net_utils::ipv6_network_address>().port(), entry.last_seen, entry.pruning_seed, entry.rpc_port);
      else
        res.white_list.emplace_back(entry.id, entry.adr.str(), entry.last_seen, entry.pruning_seed, entry.rpc_port);
    }

    for (auto & entry : gray_list)
    {
      if (entry.adr.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
        res.gray_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv4_network_address>().ip(),
            entry.adr.as<epee::net_utils::ipv4_network_address>().port(), entry.last_seen, entry.pruning_seed, entry.rpc_port);
      else if (entry.adr.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id())
        res.gray_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv6_network_address>().host_str(),
            entry.adr.as<epee::net_utils::ipv6_network_address>().port(), entry.last_seen, entry.pruning_seed, entry.rpc_port);
      else
        res.gray_list.emplace_back(entry.id, entry.adr.str(), entry.last_seen, entry.pruning_seed, entry.rpc_port);
    }

    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_PUBLIC_NODES::response core_rpc_server::invoke(GET_PUBLIC_NODES::request&& req, rpc_context context)
  {
    PERF_TIMER(on_get_public_nodes);

    GET_PEER_LIST::response peer_list_res = invoke(GET_PEER_LIST::request{}, context);
    GET_PUBLIC_NODES::response res{};
    res.status = std::move(peer_list_res.status);

    const auto collect = [](const std::vector<GET_PEER_LIST::peer> &peer_list, std::vector<public_node> &public_nodes)
    {
      for (const auto &entry : peer_list)
      {
        if (entry.rpc_port != 0)
        {
          public_nodes.emplace_back(entry);
        }
      }
    };

    if (req.white)
    {
      collect(peer_list_res.white_list, res.white);
    }
    if (req.gray)
    {
      collect(peer_list_res.gray_list, res.gray);
    }

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SET_LOG_LEVEL::response core_rpc_server::invoke(SET_LOG_LEVEL::request&& req, rpc_context context)
  {
    SET_LOG_LEVEL::response res{};

    PERF_TIMER(on_set_log_level);
    if (req.level < 0 || req.level > 4)
    {
      res.status = "Error: log level not valid";
      return res;
    }
    mlog_set_log_level(req.level);
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SET_LOG_CATEGORIES::response core_rpc_server::invoke(SET_LOG_CATEGORIES::request&& req, rpc_context context)
  {
    SET_LOG_CATEGORIES::response res{};

    PERF_TIMER(on_set_log_categories);
    mlog_set_log(req.categories.c_str());
    res.categories = mlog_get_categories();
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_TRANSACTION_POOL_HASHES_BIN::response core_rpc_server::invoke(GET_TRANSACTION_POOL_HASHES_BIN::request&& req, rpc_context context)
  {
    GET_TRANSACTION_POOL_HASHES_BIN::response res{};

    PERF_TIMER(on_get_transaction_pool_hashes);
    if (use_bootstrap_daemon_if_necessary<GET_TRANSACTION_POOL_HASHES_BIN>(req, res))
      return res;

    std::vector<crypto::hash> tx_pool_hashes;
    m_core.get_pool().get_transaction_hashes(tx_pool_hashes, context.admin, req.flashed_txs_only);

    res.tx_hashes = std::move(tx_pool_hashes);
    res.status    = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_TRANSACTION_POOL_HASHES& get_transaction_pool_hashes, rpc_context context)
  {
    PERF_TIMER(on_get_transaction_pool_hashes);
    //TODO handle bootstrap daemon with RPC
    // if (use_bootstrap_daemon_if_necessary<GET_TRANSACTION_POOL_HASHES>(req, res))
    //   return res;

    std::vector<crypto::hash> tx_hashes;
    m_core.get_pool().get_transaction_hashes(tx_hashes, context.admin);
    get_transaction_pool_hashes.response_hex["tx_hashes"] = tx_hashes;
    get_transaction_pool_hashes.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_TRANSACTION_POOL_STATS& stats, rpc_context context)
  {
    PERF_TIMER(on_get_transaction_pool_stats);
    //TODO handle bootstrap daemon
    // if (use_bootstrap_daemon_if_necessary<GET_TRANSACTION_POOL_STATS>(req, res))
    //   return res;

    auto txpool = m_core.get_pool().get_transaction_stats(stats.request.include_unrelayed);
    json pool_stats{
        {"bytes_total", txpool.bytes_total},
        {"bytes_min", txpool.bytes_min},
        {"bytes_max", txpool.bytes_max},
        {"bytes_med", txpool.bytes_med},
        {"fee_total", txpool.fee_total},
        {"oldest", txpool.oldest},
        {"txs_total", txpool.txs_total},
        {"num_failing", txpool.num_failing},
        {"num_10m", txpool.num_10m},
        {"num_not_relayed", txpool.num_not_relayed},
        {"histo", std::move(txpool.histo)},
        {"num_double_spends", txpool.num_double_spends}};

    if (txpool.histo_98pc)
      pool_stats["histo_98pc"] = txpool.histo_98pc;
    else
      pool_stats["histo_max"] = std::time(nullptr) - txpool.oldest;

    stats.response["pool_stats"] = std::move(pool_stats);
    stats.response["status"] = STATUS_OK;

  }
  //------------------------------------------------------------------------------------------------------------------------------
  SET_BOOTSTRAP_DAEMON::response core_rpc_server::invoke(SET_BOOTSTRAP_DAEMON::request&& req, rpc_context context)
  {
    PERF_TIMER(on_set_bootstrap_daemon);

    if (!set_bootstrap_daemon(req.address, req.username, req.password))
      throw rpc_error{ERROR_WRONG_PARAM, "Failed to set bootstrap daemon to address = " + req.address};

    SET_BOOTSTRAP_DAEMON::response res{};
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(STOP_DAEMON& stop_daemon, rpc_context context)
  {
    PERF_TIMER(on_stop_daemon);
    m_p2p.send_stop_signal();
    stop_daemon.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------

  //
  // Beldex
  //
  GET_OUTPUT_BLACKLIST_BIN::response core_rpc_server::invoke(GET_OUTPUT_BLACKLIST_BIN::request&& req, rpc_context context)
  {
    GET_OUTPUT_BLACKLIST_BIN::response res{};

    PERF_TIMER(on_get_output_blacklist_bin);

    if (use_bootstrap_daemon_if_necessary<GET_OUTPUT_BLACKLIST_BIN>(req, res))
      return res;

    try
    {
      m_core.get_output_blacklist(res.blacklist);
    }
    catch (const std::exception &e)
    {
      res.status = std::string("Failed to get output blacklist: ") + e.what();
      return res;
    }

    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GETBLOCKCOUNT& getblockcount, rpc_context context)
  {
    PERF_TIMER(on_getblockcount);
    {
      std::shared_lock lock{m_bootstrap_daemon_mutex};
      if (m_should_use_bootstrap_daemon)
      {
        getblockcount.response["status"] = "This command is unsupported for bootstrap daemon";
        return;
      }
    }
    getblockcount.response["count"] = m_core.get_current_blockchain_height();
    getblockcount.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GETBLOCKHASH::response core_rpc_server::invoke(GETBLOCKHASH::request&& req, rpc_context context)
  {
    GETBLOCKHASH::response res{};

    PERF_TIMER(on_getblockhash);
    {
      std::shared_lock lock{m_bootstrap_daemon_mutex};
      if (m_should_use_bootstrap_daemon)
      {
        res = "This command is unsupported for bootstrap daemon";
        return res;
      }
    }
    if(req.height.size() != 1)
      throw rpc_error{ERROR_WRONG_PARAM, "Wrong parameters, expected height"};

    uint64_t h = req.height[0];
    if(m_core.get_current_blockchain_height() <= h)
      throw rpc_error{ERROR_TOO_BIG_HEIGHT,
        "Requested block height: " + std::to_string(h) + " greater than current top block height: " +  std::to_string(m_core.get_current_blockchain_height() - 1)};

    res = tools::type_to_hex(m_core.get_block_id_by_height(h));
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GETBLOCKTEMPLATE::response core_rpc_server::invoke(GETBLOCKTEMPLATE::request&& req, rpc_context context)
  {
    GETBLOCKTEMPLATE::response res{};

    PERF_TIMER(on_getblocktemplate);
    if (use_bootstrap_daemon_if_necessary<GETBLOCKTEMPLATE>(req, res))
      return res;

    if(!check_core_ready())
      throw rpc_error{ERROR_CORE_BUSY, "Core is busy"};

    if(req.reserve_size > 255)
      throw rpc_error{ERROR_TOO_BIG_RESERVE_SIZE, "Too big reserved size, maximum 255"};

    if(req.reserve_size && !req.extra_nonce.empty())
      throw rpc_error{ERROR_WRONG_PARAM, "Cannot specify both a reserve_size and an extra_nonce"};

    if(req.extra_nonce.size() > 510)
      throw rpc_error{ERROR_TOO_BIG_RESERVE_SIZE, "Too big extra_nonce size, maximum 510 hex chars"};

    cryptonote::address_parse_info info;

    if(!req.wallet_address.size() || !cryptonote::get_account_address_from_str(info, m_core.get_nettype(), req.wallet_address))
      throw rpc_error{ERROR_WRONG_WALLET_ADDRESS, "Failed to parse wallet address"};
    if (info.is_subaddress)
      throw rpc_error{ERROR_MINING_TO_SUBADDRESS, "Mining to subaddress is not supported yet"};

    block b;
    cryptonote::blobdata blob_reserve;
    if(!req.extra_nonce.empty())
    {
      if(!oxenc::is_hex(req.extra_nonce))
        throw rpc_error{ERROR_WRONG_PARAM, "Parameter extra_nonce should be a hex string"};
      blob_reserve = oxenc::from_hex(req.extra_nonce);
    }
    else
      blob_reserve.resize(req.reserve_size, 0);
    cryptonote::difficulty_type diff;
    crypto::hash prev_block;
    if (!req.prev_block.empty())
    {
      if (!tools::hex_to_type(req.prev_block, prev_block))
        throw rpc_error{ERROR_INTERNAL, "Invalid prev_block"};
    }
    if(!m_core.create_miner_block_template(b, req.prev_block.empty() ? NULL : &prev_block, info.address, diff, res.height, res.expected_reward, blob_reserve))
    {
      LOG_ERROR("Failed to create block template");
      throw rpc_error{ERROR_INTERNAL, "Internal error: failed to create block template"};
    }

    if (b.major_version >= hf::hf13_checkpointing)
    {
      uint64_t seed_height, next_height;
      crypto::hash seed_hash;
      crypto::rx_seedheights(res.height, &seed_height, &next_height);
      seed_hash = m_core.get_block_id_by_height(seed_height);
      res.seed_hash = tools::type_to_hex(seed_hash);
      if (next_height != seed_height) {
        seed_hash = m_core.get_block_id_by_height(next_height);
        res.next_seed_hash = tools::type_to_hex(seed_hash);
      }
    }
    res.difficulty = diff;

    blobdata block_blob = t_serializable_object_to_blob(b);
    crypto::public_key tx_pub_key = cryptonote::get_tx_pub_key_from_extra(b.miner_tx);
    if(tx_pub_key == crypto::null_pkey)
    {
      LOG_ERROR("Failed to get tx pub key in coinbase extra");
      throw rpc_error{ERROR_INTERNAL, "Internal error: failed to create block template"};
    }
    res.reserved_offset = block_blob.find(tx_pub_key.data, 0, sizeof(tx_pub_key.data));
    if (res.reserved_offset == block_blob.npos)
    {
      LOG_ERROR("Failed to find tx pub key in blockblob");
      throw rpc_error{ERROR_INTERNAL, "Internal error: failed to create block template"};
    }
    if (req.reserve_size)
      res.reserved_offset += sizeof(tx_pub_key) + 2; //2 bytes: tag for TX_EXTRA_NONCE(1 byte), counter in TX_EXTRA_NONCE(1 byte)
    else
      res.reserved_offset = 0;
    if(res.reserved_offset + req.reserve_size > block_blob.size())
    {
      LOG_ERROR("Failed to calculate offset for ");
      throw rpc_error{ERROR_INTERNAL, "Internal error: failed to create block template"};
    }
    blobdata hashing_blob = get_block_hashing_blob(b);
    res.prev_hash = tools::type_to_hex(b.prev_id);
    res.blocktemplate_blob = oxenc::to_hex(block_blob);
    res.blockhashing_blob =  oxenc::to_hex(hashing_blob);
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SUBMITBLOCK::response core_rpc_server::invoke(SUBMITBLOCK::request&& req, rpc_context context)
  {
    SUBMITBLOCK::response res{};

    PERF_TIMER(on_submitblock);
    {
      std::shared_lock lock{m_bootstrap_daemon_mutex};
      if (m_should_use_bootstrap_daemon)
      {
        res.status = "This command is unsupported for bootstrap daemon";
        return res;
      }
    }
    CHECK_CORE_READY();
    if(req.blob.size()!=1)
      throw rpc_error{ERROR_WRONG_PARAM, "Wrong param"};
    if(!oxenc::is_hex(req.blob[0]))
      throw rpc_error{ERROR_WRONG_BLOCKBLOB, "Wrong block blob"};
    auto blockblob =oxenc::from_hex(req.blob[0]);
    // Fixing of high orphan issue for most pools
    // Thanks Boolberry!
    block b;
    if(!parse_and_validate_block_from_blob(blockblob, b))
      throw rpc_error{ERROR_WRONG_BLOCKBLOB, "Wrong block blob"};

    // Fix from Boolberry neglects to check block
    // size, do that with the function below
    if(!m_core.check_incoming_block_size(blockblob))
      throw rpc_error{ERROR_WRONG_BLOCKBLOB_SIZE, "Block blob size is too big, rejecting block"};

    block_verification_context bvc;
    if(!m_core.handle_block_found(b, bvc))
      throw rpc_error{ERROR_BLOCK_NOT_ACCEPTED, "Block not accepted"};
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GENERATEBLOCKS::response core_rpc_server::invoke(GENERATEBLOCKS::request&& req, rpc_context context)
  {
    GENERATEBLOCKS::response res{};

    PERF_TIMER(on_generateblocks);

    CHECK_CORE_READY();

    res.status = STATUS_OK;

    if(m_core.get_nettype() != network_type::FAKECHAIN)
      throw rpc_error{ERROR_REGTEST_REQUIRED, "Regtest required when generating blocks"};

    SUBMITBLOCK::request submit_req{};
    submit_req.blob.emplace_back(); // string vector containing exactly one block blob

    res.height = m_core.get_blockchain_storage().get_current_blockchain_height();

    for(size_t i = 0; i < req.amount_of_blocks; i++)
    {
      GETBLOCKTEMPLATE::request template_req{};
      template_req.reserve_size = 1;
      template_req.wallet_address = req.wallet_address;
      template_req.prev_block = i == 0 ? req.prev_block : res.blocks.back();
      auto template_res = invoke(std::move(template_req), context);
      res.status = template_res.status;

      blobdata blockblob;
      if(!oxenc::is_hex(template_res.blocktemplate_blob))
        throw rpc_error{ERROR_WRONG_BLOCKBLOB, "Wrong block blob"};
      block b;
      if(!parse_and_validate_block_from_blob(oxenc::from_hex(template_res.blocktemplate_blob), b))
        throw rpc_error{ERROR_WRONG_BLOCKBLOB, "Wrong block blob"};
      b.nonce = req.starting_nonce;
      miner::find_nonce_for_given_block([this](const cryptonote::block &b, uint64_t height, unsigned int threads, crypto::hash &hash) {
        hash = cryptonote::get_block_longhash_w_blockchain(cryptonote::network_type::FAKECHAIN, &(m_core.get_blockchain_storage()), b, height, threads);
        return true;
      }, b, template_res.difficulty, template_res.height);

      submit_req.blob[0] = oxenc::to_hex(block_to_blob(b));
      auto submit_res = invoke(std::move(submit_req), context);
      res.status = submit_res.status;

      res.blocks.push_back(tools::type_to_hex(get_block_hash(b)));
      res.height = template_res.height;
    }

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  uint64_t core_rpc_server::get_block_reward(const block& blk)
  {
    uint64_t reward = 0;
    for(const tx_out& out: blk.miner_tx.vout)
    {
      reward += out.amount;
    }
    return reward;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::fill_block_header_response(const block& blk, bool orphan_status, uint64_t height, const crypto::hash& hash, block_header_response& response, bool fill_pow_hash, bool get_tx_hashes)
  {
    PERF_TIMER(fill_block_header_response);
    response.major_version = static_cast<uint8_t>(blk.major_version);
    response.minor_version = blk.minor_version;
    response.timestamp = blk.timestamp;
    response.prev_hash = tools::type_to_hex(blk.prev_id);
    response.nonce = blk.nonce;
    response.orphan_status = orphan_status;
    response.height = height;
    response.depth = m_core.get_current_blockchain_height() - height - 1;
    response.hash = tools::type_to_hex(hash);
    response.difficulty = m_core.get_blockchain_storage().block_difficulty(height);
    response.cumulative_difficulty = m_core.get_blockchain_storage().get_db().get_block_cumulative_difficulty(height);
    response.block_weight = m_core.get_blockchain_storage().get_db().get_block_weight(height);
    response.reward = get_block_reward(blk);
    if(blk.nonce != 0)
      response.miner_reward = blk.miner_tx.vout[0].amount;
    response.block_size = response.block_weight = m_core.get_blockchain_storage().get_db().get_block_weight(height);
    response.num_txes = blk.tx_hashes.size();
    if (fill_pow_hash)
      response.pow_hash = tools::type_to_hex(get_block_longhash_w_blockchain(m_core.get_nettype(), &(m_core.get_blockchain_storage()), blk, height, 0));
    response.long_term_weight = m_core.get_blockchain_storage().get_db().get_block_long_term_weight(height);
    response.miner_tx_hash = tools::type_to_hex(cryptonote::get_transaction_hash(blk.miner_tx));
    response.master_node_winner = tools::type_to_hex(cryptonote::get_master_node_winner_from_tx_extra(blk.miner_tx.extra));
    if (get_tx_hashes)
    {
      response.tx_hashes.reserve(blk.tx_hashes.size());
      for (const auto& tx_hash : blk.tx_hashes)
        response.tx_hashes.push_back(tools::type_to_hex(tx_hash));
    }
  }

  /// All the common (untemplated) code for use_bootstrap_daemon_if_necessary.  Returns a held lock
  /// if we need to bootstrap, an unheld one if we don't.
  std::unique_lock<std::shared_mutex> core_rpc_server::should_bootstrap_lock()
  {
    // TODO - support bootstrapping via a remote LMQ RPC; requires some argument fiddling

    if (!m_should_use_bootstrap_daemon)
        return {};

    std::unique_lock lock{m_bootstrap_daemon_mutex};
    if (!m_bootstrap_daemon)
    {
      lock.unlock();
      return lock;
    }

    auto current_time = std::chrono::system_clock::now();
    if (!m_p2p.get_payload_object().no_sync() &&
        current_time - m_bootstrap_height_check_time > 30s)  // update every 30s
    {
      m_bootstrap_height_check_time = current_time;

      std::optional<uint64_t> bootstrap_daemon_height = m_bootstrap_daemon->get_height();
      if (!bootstrap_daemon_height)
      {
        MERROR("Failed to fetch bootstrap daemon height");
        lock.unlock();
        return lock;
      }

      uint64_t target_height = m_core.get_target_blockchain_height();
      if (bootstrap_daemon_height < target_height)
      {
        MINFO("Bootstrap daemon is out of sync");
        lock.unlock();
        m_bootstrap_daemon->set_failed();
        return lock;
      }

      uint64_t top_height           = m_core.get_current_blockchain_height();
      m_should_use_bootstrap_daemon = top_height + 10 < bootstrap_daemon_height;
      MINFO((m_should_use_bootstrap_daemon ? "Using" : "Not using") << " the bootstrap daemon (our height: " << top_height << ", bootstrap daemon's height: " << *bootstrap_daemon_height << ")");
    }

    if (!m_should_use_bootstrap_daemon)
    {
      MINFO("The local daemon is fully synced; disabling bootstrap daemon requests");
      lock.unlock();
    }

    return lock;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  // If we have a bootstrap daemon configured and we haven't fully synched yet then forward the
  // request to the bootstrap daemon.  Returns true if the request was bootstrapped, false if the
  // request shouldn't be bootstrapped, and throws an exception if the bootstrap request fails.
  //
  // The RPC type must have a `bool untrusted` member.
  //
  template <typename RPC>
  bool core_rpc_server::use_bootstrap_daemon_if_necessary(const typename RPC::request& req, typename RPC::response& res)
  {
    res.untrusted = false; // If compilation fails here then the type being instantiated doesn't support using a bootstrap daemon
    auto bs_lock = should_bootstrap_lock();
    if (!bs_lock)
      return false;

    std::string command_name{RPC::names().front()};

    if (!m_bootstrap_daemon->invoke<RPC>(req, res))
      throw std::runtime_error{"Bootstrap request failed"};

    m_was_bootstrap_ever_used = true;
    res.untrusted = true;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_LAST_BLOCK_HEADER::response core_rpc_server::invoke(GET_LAST_BLOCK_HEADER::request&& req, rpc_context context)
  {
    GET_LAST_BLOCK_HEADER::response res{};

    PERF_TIMER(on_get_last_block_header);
    if (use_bootstrap_daemon_if_necessary<GET_LAST_BLOCK_HEADER>(req, res))
      return res;

    CHECK_CORE_READY();
    auto [last_block_height, last_block_hash] = m_core.get_blockchain_top();
    block last_block;
    bool have_last_block = m_core.get_block_by_height(last_block_height, last_block);
    if (!have_last_block)
      throw rpc_error{ERROR_INTERNAL, "Internal error: can't get last block."};
    fill_block_header_response(last_block, false, last_block_height, last_block_hash, res.block_header, req.fill_pow_hash && context.admin, req.get_tx_hashes);
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_BLOCK_HEADER_BY_HASH::response core_rpc_server::invoke(GET_BLOCK_HEADER_BY_HASH::request&& req, rpc_context context)
  {
    GET_BLOCK_HEADER_BY_HASH::response res{};

    PERF_TIMER(on_get_block_header_by_hash);
    if (use_bootstrap_daemon_if_necessary<GET_BLOCK_HEADER_BY_HASH>(req, res))
      return res;

    auto get = [this, &req, admin=context.admin](const std::string &hash, block_header_response &block_header) {
      crypto::hash block_hash;
      if (!tools::hex_to_type(hash, block_hash))
        throw rpc_error{ERROR_WRONG_PARAM, "Failed to parse hex representation of block hash. Hex = " + hash + '.'};
      block blk;
      bool orphan = false;
      bool have_block = m_core.get_block_by_hash(block_hash, blk, &orphan);
      if (!have_block)
        throw rpc_error{ERROR_INTERNAL, "Internal error: can't get block by hash. Hash = " + hash + '.'};
      if (blk.miner_tx.vin.size() != 1 || !std::holds_alternative<txin_gen>(blk.miner_tx.vin.front()))
        throw rpc_error{ERROR_INTERNAL, "Internal error: coinbase transaction in the block has the wrong type"};
      uint64_t block_height = var::get<txin_gen>(blk.miner_tx.vin.front()).height;
      fill_block_header_response(blk, orphan, block_height, block_hash, block_header, req.fill_pow_hash && admin, req.get_tx_hashes);
    };

    if (!req.hash.empty())
      get(req.hash, res.block_header.emplace());

    res.block_headers.reserve(req.hashes.size());
    for (const std::string &hash: req.hashes)
      get(hash, res.block_headers.emplace_back());

    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_BLOCK_HEADERS_RANGE::response core_rpc_server::invoke(GET_BLOCK_HEADERS_RANGE::request&& req, rpc_context context)
  {
    GET_BLOCK_HEADERS_RANGE::response res{};

    PERF_TIMER(on_get_block_headers_range);
    if (use_bootstrap_daemon_if_necessary<GET_BLOCK_HEADERS_RANGE>(req, res))
      return res;

    const uint64_t bc_height = m_core.get_current_blockchain_height();
    if (req.start_height >= bc_height || req.end_height >= bc_height || req.start_height > req.end_height)
      throw rpc_error{ERROR_TOO_BIG_HEIGHT, "Invalid start/end heights."};
    for (uint64_t h = req.start_height; h <= req.end_height; ++h)
    {
      block blk;
      bool have_block = m_core.get_block_by_height(h, blk);
      if (!have_block)
        throw rpc_error{ERROR_INTERNAL,
          "Internal error: can't get block by height. Height = " + std::to_string(h) + "."};
      if (blk.miner_tx.vin.size() != 1 || !std::holds_alternative<txin_gen>(blk.miner_tx.vin.front()))
        throw rpc_error{ERROR_INTERNAL, "Internal error: coinbase transaction in the block has the wrong type"};
      uint64_t block_height = var::get<txin_gen>(blk.miner_tx.vin.front()).height;
      if (block_height != h)
        throw rpc_error{ERROR_INTERNAL, "Internal error: coinbase transaction in the block has the wrong height"};
      res.headers.push_back(block_header_response());
      fill_block_header_response(blk, false, block_height, get_block_hash(blk), res.headers.back(), req.fill_pow_hash && context.admin, req.get_tx_hashes);
    }
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_BLOCK_HEADER_BY_HEIGHT::response core_rpc_server::invoke(GET_BLOCK_HEADER_BY_HEIGHT::request&& req, rpc_context context)
  {
    GET_BLOCK_HEADER_BY_HEIGHT::response res{};

    PERF_TIMER(on_get_block_header_by_height);
    if (use_bootstrap_daemon_if_necessary<GET_BLOCK_HEADER_BY_HEIGHT>(req, res))
      return res;

    auto get = [this, curr_height=m_core.get_current_blockchain_height(), pow=req.fill_pow_hash && context.admin, tx_hashes=req.get_tx_hashes]
        (uint64_t height, block_header_response& bhr) {
      if (height >= curr_height)
        throw rpc_error{ERROR_TOO_BIG_HEIGHT,
          "Requested block height: " + std::to_string(height) + " greater than current top block height: " +  std::to_string(curr_height - 1)};
      block blk;
      bool have_block = m_core.get_block_by_height(height, blk);
      if (!have_block)
        throw rpc_error{ERROR_INTERNAL, "Internal error: can't get block by height. Height = " + std::to_string(height) + '.'};
      fill_block_header_response(blk, false, height, get_block_hash(blk), bhr, pow, tx_hashes);
    };

    if (req.height)
      get(*req.height, res.block_header.emplace());
    if (!req.heights.empty())
      res.block_headers.reserve(req.heights.size());
    for (auto height : req.heights)
      get(height, res.block_headers.emplace_back());

    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_BLOCK::response core_rpc_server::invoke(GET_BLOCK::request&& req, rpc_context context)
  {
    GET_BLOCK::response res{};

    PERF_TIMER(on_get_block);
    if (use_bootstrap_daemon_if_necessary<GET_BLOCK>(req, res))
      return res;

    block blk;
    uint64_t block_height;
    bool orphan = false;
    crypto::hash block_hash;
    if (!req.hash.empty())
    {
      if (!tools::hex_to_type(req.hash, block_hash))
        throw rpc_error{ERROR_WRONG_PARAM, "Failed to parse hex representation of block hash. Hex = " + req.hash + '.'};
      if (!m_core.get_block_by_hash(block_hash, blk, &orphan))
        throw rpc_error{ERROR_INTERNAL, "Internal error: can't get block by hash. Hash = " + req.hash + '.'};
      if (blk.miner_tx.vin.size() != 1 || !std::holds_alternative<txin_gen>(blk.miner_tx.vin.front()))
        throw rpc_error{ERROR_INTERNAL, "Internal error: coinbase transaction in the block has the wrong type"};
      block_height = var::get<txin_gen>(blk.miner_tx.vin.front()).height;
    }
    else
    {
      if (auto curr_height = m_core.get_current_blockchain_height(); req.height >= curr_height)
        throw rpc_error{ERROR_TOO_BIG_HEIGHT, std::string("Requested block height: ") + std::to_string(req.height) + " greater than current top block height: " +  std::to_string(curr_height - 1)};
      if (!m_core.get_block_by_height(req.height, blk))
        throw rpc_error{ERROR_INTERNAL, "Internal error: can't get block by height. Height = " + std::to_string(req.height) + '.'};
      block_hash = get_block_hash(blk);
      block_height = req.height;
    }
    fill_block_header_response(blk, orphan, block_height, block_hash, res.block_header, req.fill_pow_hash && context.admin, false /*tx hashes*/);
    res.tx_hashes.reserve(blk.tx_hashes.size());
    for (const auto& tx_hash : blk.tx_hashes)
        res.tx_hashes.push_back(tools::type_to_hex(tx_hash));
    res.blob = oxenc::to_hex(t_serializable_object_to_blob(blk));
    res.json = obj_to_json_str(blk);
    res.status = STATUS_OK;
    return res;
  }

  static json json_connection_info(const connection_info& ci) {
    json info{
        {"incoming", ci.incoming},
        {"ip", ci.ip},
        {"address_type", ci.address_type},
        {"peer_id", ci.peer_id},
        {"recv_count", ci.recv_count},
        {"recv_idle_ms", ci.recv_idle_time.count()},
        {"send_count", ci.send_count},
        {"send_idle_ms", ci.send_idle_time.count()},
        {"state", ci.state},
        {"live_ms", ci.live_time.count()},
        {"avg_download", ci.avg_download},
        {"current_download", ci.current_download},
        {"avg_upload", ci.avg_upload},
        {"current_upload", ci.current_upload},
        {"connection_id", ci.connection_id},
        {"height", ci.height},
    };
    if (ci.ip != ci.host) info["host"] = ci.host;
    if (ci.localhost) info["localhost"] = true;
    if (ci.local_ip) info["local_ip"] = true;
    if (uint16_t port; tools::parse_int(ci.port, port) && port > 0) info["port"] = port;
    // Included for completeness, but undocumented as neither of these are currently actually used
    // or support on Beldex:
    if (ci.rpc_port > 0) info["rpc_port"] = ci.rpc_port;
    if (ci.pruning_seed) info["pruning_seed"] = ci.pruning_seed;
    return info;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_CONNECTIONS& get_connections, rpc_context context)
  {
    PERF_TIMER(on_get_connections);
    auto& c = get_connections.response["connections"];
    c = json::array();
    for (auto& ci : m_p2p.get_payload_object().get_connections())
      c.push_back(json_connection_info(ci));

    get_connections.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(HARD_FORK_INFO& hfinfo, rpc_context context)
  {
    PERF_TIMER(on_hard_fork_info);
    /*
    if (use_bootstrap_daemon_if_necessary<HARD_FORK_INFO>(req, res))
      return res;
    */
    const auto& blockchain = m_core.get_blockchain_storage();
    auto version =
      hfinfo.request.version > 0 ? hfinfo.request.version :
      hfinfo.request.height > 0 ? blockchain.get_network_version(hfinfo.request.height) :
      blockchain.get_network_version();
      hfinfo.response["version"] = version;
      hfinfo.response["enabled"] = blockchain.get_network_version() >= version;
    auto heights = get_hard_fork_heights(m_core.get_nettype(), version);
    if (heights.first)
      hfinfo.response["earliest_height"] = *heights.first;
    if (heights.second)
      hfinfo.response["latest_height"] = *heights.second;
    hfinfo.response["status"] = STATUS_OK;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GETBANS::response core_rpc_server::invoke(GETBANS::request&& req, rpc_context context)
  {
    GETBANS::response res{};

    PERF_TIMER(on_get_bans);

    auto now = time(nullptr);
    std::map<std::string, time_t> blocked_hosts = m_p2p.get_blocked_hosts();
    for (std::map<std::string, time_t>::const_iterator i = blocked_hosts.begin(); i != blocked_hosts.end(); ++i)
    {
      if (i->second > now) {
        GETBANS::ban b;
        b.host = i->first;
        b.ip = 0;
        uint32_t ip;
        if (epee::string_tools::get_ip_int32_from_string(ip, b.host))
          b.ip = ip;
        b.seconds = i->second - now;
        res.bans.push_back(b);
      }
    }
    std::map<epee::net_utils::ipv4_network_subnet, time_t> blocked_subnets = m_p2p.get_blocked_subnets();
    for (std::map<epee::net_utils::ipv4_network_subnet, time_t>::const_iterator i = blocked_subnets.begin(); i != blocked_subnets.end(); ++i)
    {
      if (i->second > now) {
        GETBANS::ban b;
        b.host = i->first.host_str();
        b.ip = 0;
        b.seconds = i->second - now;
        res.bans.push_back(b);
      }
    }

    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  BANNED::response core_rpc_server::invoke(BANNED::request&& req, rpc_context context)
  {
    BANNED::response res{};

    PERF_TIMER(on_banned);

    auto na_parsed = net::get_network_address(req.address, 0);
    if (!na_parsed)
      throw rpc_error{ERROR_WRONG_PARAM, "Unsupported host type"};
    epee::net_utils::network_address na = std::move(*na_parsed);

    time_t seconds;
    if (m_p2p.is_host_blocked(na, &seconds))
    {
      res.banned = true;
      res.seconds = seconds;
    }
    else
    {
      res.banned = false;
      res.seconds = 0;
    }

    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SETBANS::response core_rpc_server::invoke(SETBANS::request&& req, rpc_context context)
  {
    SETBANS::response res{};

    PERF_TIMER(on_set_bans);

    for (auto i = req.bans.begin(); i != req.bans.end(); ++i)
    {
      epee::net_utils::network_address na;

      // try subnet first
      if (!i->host.empty())
      {
        auto ns_parsed = net::get_ipv4_subnet_address(i->host);
        if (ns_parsed)
        {
          if (i->ban)
            m_p2p.block_subnet(*ns_parsed, i->seconds);
          else
            m_p2p.unblock_subnet(*ns_parsed);
          continue;
        }
      }

      // then host
      if (!i->host.empty())
      {
        auto na_parsed = net::get_network_address(i->host, 0);
        if (!na_parsed)
          throw rpc_error{ERROR_WRONG_PARAM, "Unsupported host/subnet type"};
        na = std::move(*na_parsed);
      }
      else
      {
        na = epee::net_utils::ipv4_network_address{i->ip, 0};
      }
      if (i->ban)
        m_p2p.block_host(na, i->seconds);
      else
        m_p2p.unblock_host(na);
    }

    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  FLUSH_TRANSACTION_POOL::response core_rpc_server::invoke(FLUSH_TRANSACTION_POOL::request&& req, rpc_context context)
  {
    FLUSH_TRANSACTION_POOL::response res{};

    PERF_TIMER(on_flush_txpool);

    bool failed = false;
    std::vector<crypto::hash> txids;
    if (req.txids.empty())
    {
      std::vector<transaction> pool_txs;
      m_core.get_pool().get_transactions(pool_txs);
      for (const auto &tx: pool_txs)
      {
        txids.push_back(cryptonote::get_transaction_hash(tx));
      }
    }
    else
    {
      for (const auto &txid_hex: req.txids)
      {
        if(!tools::hex_to_type(txid_hex, txids.emplace_back()))
        {
          failed = true;
          txids.pop_back();
        }
      }
    }
    if (!m_core.get_blockchain_storage().flush_txes_from_pool(txids))
    {
      res.status = "Failed to remove one or more tx(es)";
      return res;
    }

    res.status = failed
      ? txids.empty()
        ? "Failed to parse txid"
        : "Failed to parse some of the txids"
      : STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_OUTPUT_HISTOGRAM::response core_rpc_server::invoke(GET_OUTPUT_HISTOGRAM::request&& req, rpc_context context)
  {
    GET_OUTPUT_HISTOGRAM::response res{};

    PERF_TIMER(on_get_output_histogram);
    if (use_bootstrap_daemon_if_necessary<GET_OUTPUT_HISTOGRAM>(req, res))
      return res;

    if (!context.admin && req.recent_cutoff > 0 && req.recent_cutoff < (uint64_t)time(NULL) - OUTPUT_HISTOGRAM_RECENT_CUTOFF_RESTRICTION)
    {
      res.status = "Recent cutoff is too old";
      return res;
    }

    std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> histogram;
    try
    {
      auto net = nettype();
      histogram = m_core.get_blockchain_storage().get_output_histogram(req.amounts, req.unlocked, req.recent_cutoff, req.min_count,net);
    }
    catch (const std::exception &e)
    {
      res.status = "Failed to get output histogram";
      return res;
    }

    res.histogram.clear();
    res.histogram.reserve(histogram.size());
    for (const auto &i: histogram)
    {
      if (std::get<0>(i.second) >= req.min_count && (std::get<0>(i.second) <= req.max_count || req.max_count == 0))
        res.histogram.push_back(GET_OUTPUT_HISTOGRAM::entry(i.first, std::get<0>(i.second), std::get<1>(i.second), std::get<2>(i.second)));
    }

    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_VERSION::response core_rpc_server::invoke(GET_VERSION::request&& req, rpc_context context)
  {
    GET_VERSION::response res{};

    PERF_TIMER(on_get_version);
    if (use_bootstrap_daemon_if_necessary<GET_VERSION>(req, res))
      return res;

    res.version = pack_version(VERSION);
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_MASTER_NODE_STATUS& mns, rpc_context context)
  {
    auto [top_height, top_hash] = m_core.get_blockchain_top();
    mns.response["height"] = top_height;
    mns.response_hex["block_hash"] = top_hash;
    const auto& keys = m_core.get_master_keys();
    if (!keys.pub) {
      mns.response["status"] = "Not a master node";
      return;
    }
    mns.response["status"] = STATUS_OK;

    auto mn_infos = m_core.get_master_node_list_state({{keys.pub}});
    if (!mn_infos.empty())
      fill_mn_response_entry(mns.response["master_node_state"] = json::object(), mns.is_bt(), {} /*all fields*/, mn_infos.front(), top_height);
    else {
      mns.response["master_node_state"] = json{
          {"public_ip", epee::string_tools::get_ip_string_from_int32(m_core.mn_public_ip())},
          {"storage_port", m_core.storage_https_port()},
          {"storage_lmq_port", m_core.storage_omq_port()},
          {"quorumnet_port", m_core.quorumnet_port()},
          {"master_node_version", BELDEX_VERSION}
      };
      auto rhex = mns.response_hex["master_node_state"];
      rhex["master_node_pubkey"] = keys.pub;
      rhex["pubkey_ed25519"] = keys.pub_ed25519;
      rhex["pubkey_x25519"] = keys.pub_x25519;
    }
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_COINBASE_TX_SUM::response core_rpc_server::invoke(GET_COINBASE_TX_SUM::request&& req, rpc_context context)
  {
    GET_COINBASE_TX_SUM::response res{};

    PERF_TIMER(on_get_coinbase_tx_sum);
    if (auto sums = m_core.get_coinbase_tx_sum(req.height, req.count)) {
        std::tie(res.emission_amount, res.fee_amount, res.burn_amount) = *sums;
        res.status = STATUS_OK;
    } else {
        res.status = STATUS_BUSY; // some other request is already calculating it
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_BASE_FEE_ESTIMATE::response core_rpc_server::invoke(GET_BASE_FEE_ESTIMATE::request&& req, rpc_context context)
  {
    GET_BASE_FEE_ESTIMATE::response res{};

    PERF_TIMER(on_get_base_fee_estimate);
    if (use_bootstrap_daemon_if_necessary<GET_BASE_FEE_ESTIMATE>(req, res))
      return res;

    auto fees = m_core.get_blockchain_storage().get_dynamic_base_fee_estimate(req.grace_blocks);
    res.fee_per_byte = fees.first;
    res.fee_per_output = fees.second;
    res.flash_fee_fixed = beldex::FLASH_BURN_FIXED;
    constexpr auto flash_percent =  beldex::FLASH_MINER_TX_FEE_PERCENT +  beldex::FLASH_BURN_TX_FEE_PERCENT_OLD;
    res.flash_fee_per_byte = res.fee_per_byte * flash_percent / 100;
    res.flash_fee_per_output = res.fee_per_output * flash_percent / 100;
    res.quantization_mask = Blockchain::get_fee_quantization_mask();
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_ALTERNATE_CHAINS::response core_rpc_server::invoke(GET_ALTERNATE_CHAINS::request&& req, rpc_context context)
  {
    GET_ALTERNATE_CHAINS::response res{};

    PERF_TIMER(on_get_alternate_chains);
    try
    {
      std::vector<std::pair<Blockchain::block_extended_info, std::vector<crypto::hash>>> chains = m_core.get_blockchain_storage().get_alternative_chains();
      for (const auto &i: chains)
      {
        res.chains.push_back(GET_ALTERNATE_CHAINS::chain_info{tools::type_to_hex(get_block_hash(i.first.bl)), i.first.height, i.second.size(), i.first.cumulative_difficulty, {}, std::string()});
        res.chains.back().block_hashes.reserve(i.second.size());
        for (const crypto::hash &block_id: i.second)
          res.chains.back().block_hashes.push_back(tools::type_to_hex(block_id));
        if (i.first.height < i.second.size())
        {
          res.status = "Error finding alternate chain attachment point";
          return res;
        }
        cryptonote::block main_chain_parent_block;
        try { main_chain_parent_block = m_core.get_blockchain_storage().get_db().get_block_from_height(i.first.height - i.second.size()); }
        catch (const std::exception &e) { res.status = "Error finding alternate chain attachment point"; return res; }
        res.chains.back().main_chain_parent_block = tools::type_to_hex(get_block_hash(main_chain_parent_block));
      }
      res.status = STATUS_OK;
    }
    catch (...)
    {
      res.status = "Error retrieving alternate chains";
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_LIMIT& limit, rpc_context context)
  {
    PERF_TIMER(on_get_limit);

    limit.response = {
      {"limit_down", epee::net_utils::connection_basic::get_rate_down_limit()},
      {"limit_up", epee::net_utils::connection_basic::get_rate_up_limit()},
      {"status", STATUS_OK}};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(SET_LIMIT& limit, rpc_context context)
  {
    PERF_TIMER(on_set_limit);

    // -1 = reset to default
    //  0 = do not modify
    if (limit.request.limit_down != 0)
      epee::net_utils::connection_basic::set_rate_down_limit(
          limit.request.limit_down == -1 ? nodetool::default_limit_down : limit.request.limit_down);

    if (limit.request.limit_up != 0)
      epee::net_utils::connection_basic::set_rate_up_limit(
          limit.request.limit_up == -1 ? nodetool::default_limit_up : limit.request.limit_up);

    limit.response = {
      {"limit_down", epee::net_utils::connection_basic::get_rate_down_limit()},
      {"limit_up", epee::net_utils::connection_basic::get_rate_up_limit()},
      {"status", STATUS_OK}};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  OUT_PEERS::response core_rpc_server::invoke(OUT_PEERS::request&& req, rpc_context context)
  {
    OUT_PEERS::response res{};

    PERF_TIMER(on_out_peers);
    if (req.set)
      m_p2p.change_max_out_public_peers(req.out_peers);
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  IN_PEERS::response core_rpc_server::invoke(IN_PEERS::request&& req, rpc_context context)
  {
    IN_PEERS::response res{};

    PERF_TIMER(on_in_peers);
    if (req.set)
      m_p2p.change_max_in_public_peers(req.in_peers);
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  POP_BLOCKS::response core_rpc_server::invoke(POP_BLOCKS::request&& req, rpc_context context)
  {
    POP_BLOCKS::response res{};

    PERF_TIMER(on_pop_blocks);

    m_core.get_blockchain_storage().pop_blocks(req.nblocks);

    res.height = m_core.get_current_blockchain_height();
    res.status = STATUS_OK;

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  RELAY_TX::response core_rpc_server::invoke(RELAY_TX::request&& req, rpc_context context)
  {
    RELAY_TX::response res{};

    PERF_TIMER(on_relay_tx);

    res.status = "";
    for (const auto &txid_hex: req.txids)
    {
      crypto::hash txid;
      if (!tools::hex_to_type(txid_hex, txid))
      {
        if (!res.status.empty()) res.status += ", ";
        res.status += "invalid transaction id: " + txid_hex;
        continue;
      }
      cryptonote::blobdata txblob;
      if (m_core.get_pool().get_transaction(txid, txblob))
      {
        cryptonote_connection_context fake_context{};
        NOTIFY_NEW_TRANSACTIONS::request r{};
        r.txs.push_back(txblob);
        m_core.get_protocol()->relay_transactions(r, fake_context);
        //TODO: make sure that tx has reached other nodes here, probably wait to receive reflections from other nodes
      }
      else
      {
        if (!res.status.empty()) res.status += ", ";
        res.status += "transaction not found in pool: " + txid_hex;
      }
    }

    if (res.status.empty())
      res.status = STATUS_OK;

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(SYNC_INFO& sync, rpc_context context)
  {
    PERF_TIMER(on_sync_info);

    auto [top_height, top_hash] = m_core.get_blockchain_top();
    sync.response["height"] = top_height + 1; // turn top block height into blockchain height
    if (auto target_height = m_core.get_target_blockchain_height(); target_height > top_height + 1)
      sync.response["target_height"] = target_height;
    // Don't put this into the response until it actually does something on Oxen:
    if (false)
      sync.response["next_needed_pruning_seed"] = m_p2p.get_payload_object().get_next_needed_pruning_stripe().second;

    auto& peers = sync.response["peers"];
    peers = json{};
    for (auto& ci : m_p2p.get_payload_object().get_connections())
      peers[ci.connection_id] = json_connection_info(ci);
    const auto& block_queue = m_p2p.get_payload_object().get_block_queue();
    auto spans = json::array();
    block_queue.foreach([&spans, &block_queue](const auto& span) {
        uint32_t speed = (uint32_t)(100.0f * block_queue.get_speed(span.connection_id) + 0.5f);
        spans.push_back(json{
          {"start_block_height", span.start_block_height},
          {"nblocks", span.nblocks},
          {"connection_id", tools::type_to_hex(span.connection_id)},
          {"rate", std::lround(span.rate)},
          {"speed", speed},
          {"size", span.size}});
        return true;
    });
    sync.response["overview"] = block_queue.get_overview(top_height + 1);

    sync.response["status"] = STATUS_OK;
  }

  namespace {
    output_distribution_data process_distribution(
        bool cumulative,
        std::uint64_t start_height,
        std::vector<std::uint64_t> distribution,
        std::uint64_t base)
    {
      if (!cumulative && !distribution.empty())
      {
        for (std::size_t n = distribution.size() - 1; 0 < n; --n)
          distribution[n] -= distribution[n - 1];
        distribution[0] -= base;
      }

      return {std::move(distribution), start_height, base};
    }

    static struct {
      std::mutex mutex;
      std::vector<std::uint64_t> cached_distribution;
      std::uint64_t cached_from = 0, cached_to = 0, cached_start_height = 0, cached_base = 0;
      crypto::hash cached_m10_hash = crypto::null_hash;
      crypto::hash cached_top_hash = crypto::null_hash;
      bool cached = false;
    } output_dist_cache;
  }

  namespace detail {
    std::optional<output_distribution_data> get_output_distribution(
        const std::function<bool(uint64_t, uint64_t, uint64_t, uint64_t&, std::vector<uint64_t>&, uint64_t&)>& f,
        uint64_t amount,
        uint64_t from_height,
        uint64_t to_height,
        const std::function<crypto::hash(uint64_t)>& get_hash,
        bool cumulative,
        uint64_t blockchain_height)
    {
      auto& d = output_dist_cache;
      const std::unique_lock lock{d.mutex};

      crypto::hash top_hash = crypto::null_hash;
      if (d.cached_to < blockchain_height)
        top_hash = get_hash(d.cached_to);
      if (d.cached && amount == 0 && d.cached_from == from_height && d.cached_to == to_height && d.cached_top_hash == top_hash)
        return process_distribution(cumulative, d.cached_start_height, d.cached_distribution, d.cached_base);

      std::vector<std::uint64_t> distribution;
      std::uint64_t start_height, base;

      // see if we can extend the cache - a common case
      bool can_extend = d.cached && amount == 0 && d.cached_from == from_height && to_height > d.cached_to && top_hash == d.cached_top_hash;
      if (!can_extend)
      {
        // we kept track of the hash 10 blocks below, if it exists, so if it matches,
        // we can still pop the last 10 cached slots and try again
        if (d.cached && amount == 0 && d.cached_from == from_height && d.cached_to - d.cached_from >= 10 && to_height > d.cached_to - 10)
        {
          crypto::hash hash10 = get_hash(d.cached_to - 10);
          if (hash10 == d.cached_m10_hash)
          {
            d.cached_to -= 10;
            d.cached_top_hash = hash10;
            d.cached_m10_hash = crypto::null_hash;
            CHECK_AND_ASSERT_MES(d.cached_distribution.size() >= 10, std::nullopt, "Cached distribution size does not match cached bounds");
            for (int p = 0; p < 10; ++p)
              d.cached_distribution.pop_back();
            can_extend = true;
          }
        }
      }
      if (can_extend)
      {
        std::vector<std::uint64_t> new_distribution;
        if (!f(amount, d.cached_to + 1, to_height, start_height, new_distribution, base))
          return std::nullopt;
        distribution = d.cached_distribution;
        distribution.reserve(distribution.size() + new_distribution.size());
        for (const auto &e: new_distribution)
          distribution.push_back(e);
        start_height = d.cached_start_height;
        base = d.cached_base;
      }
      else
      {
        if (!f(amount, from_height, to_height, start_height, distribution, base))
          return std::nullopt;
      }

      if (to_height > 0 && to_height >= from_height)
      {
        const std::uint64_t offset = std::max(from_height, start_height);
        if (offset <= to_height && to_height - offset + 1 < distribution.size())
          distribution.resize(to_height - offset + 1);
      }

      if (amount == 0)
      {
        d.cached_from = from_height;
        d.cached_to = to_height;
        d.cached_top_hash = get_hash(d.cached_to);
        d.cached_m10_hash = d.cached_to >= 10 ? get_hash(d.cached_to - 10) : crypto::null_hash;
        d.cached_distribution = distribution;
        d.cached_start_height = start_height;
        d.cached_base = base;
        d.cached = true;
      }

      return process_distribution(cumulative, start_height, std::move(distribution), base);
    }
  }

  //------------------------------------------------------------------------------------------------------------------------------
  GET_OUTPUT_DISTRIBUTION::response core_rpc_server::invoke(GET_OUTPUT_DISTRIBUTION::request&& req, rpc_context context, bool binary)
  {
    GET_OUTPUT_DISTRIBUTION::response res{};

    PERF_TIMER(on_get_output_distribution);
    if (use_bootstrap_daemon_if_necessary<GET_OUTPUT_DISTRIBUTION>(req, res))
      return res;

    try
    {
      // 0 is placeholder for the whole chain
      const uint64_t req_to_height = req.to_height ? req.to_height : (m_core.get_current_blockchain_height() - 1);
      for (uint64_t amount: req.amounts)
      {
        auto data = detail::get_output_distribution(
            [this](auto&&... args) { return m_core.get_output_distribution(std::forward<decltype(args)>(args)...); },
            amount,
            req.from_height,
            req_to_height,
            [this](uint64_t height) { return m_core.get_blockchain_storage().get_db().get_block_hash_from_height(height); },
            req.cumulative,
            m_core.get_current_blockchain_height());
        if (!data)
          throw rpc_error{ERROR_INTERNAL, "Failed to get output distribution"};

        // Force binary & compression off if this is a JSON request because trying to pass binary
        // data through JSON explodes it in terms of size (most values under 0x20 have to be encoded
        // using 6 chars such as "\u0002").
        res.distributions.push_back({std::move(*data), amount, "", binary && req.binary, binary && req.compress});
      }
    }
    catch (const std::exception &e)
    {
      throw rpc_error{ERROR_INTERNAL, "Failed to get output distribution"};
    }

    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_OUTPUT_DISTRIBUTION_BIN::response core_rpc_server::invoke(GET_OUTPUT_DISTRIBUTION_BIN::request&& req, rpc_context context)
  {
    GET_OUTPUT_DISTRIBUTION_BIN::response res{};

    PERF_TIMER(on_get_output_distribution_bin);

    if (!req.binary)
    {
      res.status = "Binary only call";
      return res;
    }

    if (use_bootstrap_daemon_if_necessary<GET_OUTPUT_DISTRIBUTION_BIN>(req, res))
      return res;

    return invoke(std::move(static_cast<GET_OUTPUT_DISTRIBUTION::request&>(req)), context, true);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  PRUNE_BLOCKCHAIN::response core_rpc_server::invoke(PRUNE_BLOCKCHAIN::request&& req, rpc_context context)
  {
    PRUNE_BLOCKCHAIN::response res{};

    try
    {
      if (!(req.check ? m_core.check_blockchain_pruning() : m_core.prune_blockchain()))
        throw rpc_error{ERROR_INTERNAL, req.check ? "Failed to check blockchain pruning" : "Failed to prune blockchain"};
      res.pruning_seed = m_core.get_blockchain_pruning_seed();
      res.pruned = res.pruning_seed != 0;
    }
    catch (const std::exception &e)
    {
      throw rpc_error{ERROR_INTERNAL, "Failed to prune blockchain"};
    }

    res.status = STATUS_OK;
    return res;
  }


  GET_QUORUM_STATE::response core_rpc_server::invoke(GET_QUORUM_STATE::request&& req, rpc_context context)
  {
    GET_QUORUM_STATE::response res{};

    PERF_TIMER(on_get_quorum_state);

    if (req.quorum_type >= tools::enum_count<master_nodes::quorum_type> &&
        req.quorum_type != GET_QUORUM_STATE::ALL_QUORUMS_SENTINEL_VALUE)
      throw rpc_error{ERROR_WRONG_PARAM,
        "Quorum type specifies an invalid value: " + std::to_string(req.quorum_type)};

    auto requested_type = [&req](master_nodes::quorum_type type) {
      return req.quorum_type == GET_QUORUM_STATE::ALL_QUORUMS_SENTINEL_VALUE ||
        req.quorum_type == static_cast<uint8_t>(type);
    };

    bool latest = false;
    uint64_t latest_ob = 0, latest_cp = 0, latest_bl = 0;
    uint64_t start = req.start_height, end = req.end_height;
    uint64_t curr_height = m_core.get_blockchain_storage().get_current_blockchain_height();
    if (start == GET_QUORUM_STATE::HEIGHT_SENTINEL_VALUE &&
        end == GET_QUORUM_STATE::HEIGHT_SENTINEL_VALUE)
    {
      latest = true;
      // Our start block for the latest quorum of each type depends on the type being requested:
      // obligations: top block
      // checkpoint: last block with height divisible by CHECKPOINT_INTERVAL (=4)
      // flash: last block with height divisible by FLASH_QUORUM_INTERVAL (=5)
      // POS: current height (i.e. top block height + 1)
      uint64_t top_height = curr_height - 1;
      latest_ob = top_height;
      latest_cp = std::min(start, top_height - top_height % master_nodes::CHECKPOINT_INTERVAL);
      latest_bl = std::min(start, top_height - top_height % master_nodes::FLASH_QUORUM_INTERVAL);
      if (requested_type(master_nodes::quorum_type::checkpointing))
        start = std::min(start, latest_cp);
      if (requested_type(master_nodes::quorum_type::flash))
        start = std::min(start, latest_bl);
      end = curr_height;
    }
    else if (start == GET_QUORUM_STATE::HEIGHT_SENTINEL_VALUE)
    {
      start = end;
      end   = end + 1;
    }
    else if (end == GET_QUORUM_STATE::HEIGHT_SENTINEL_VALUE)
    {
      end = start + 1;
    }
    else
    {
      if (end > start) end++;
      else if (end != 0) end--;
    }

    start                = std::min(curr_height, start);
    // We can also provide the POS quorum for the current block being produced, so if asked for
    // that make a note.
    bool add_curr_POS = (latest || end > curr_height) && requested_type(master_nodes::quorum_type::POS);
    end = std::min(curr_height, end);

    uint64_t count       = (start > end) ? start - end : end - start;
    if (!context.admin && count > GET_QUORUM_STATE::MAX_COUNT)
      throw rpc_error{ERROR_WRONG_PARAM,
        "Number of requested quorums greater than the allowed limit: "
          + std::to_string(GET_QUORUM_STATE::MAX_COUNT)
          + ", requested: " + std::to_string(count)};

    bool at_least_one_succeeded = false;
    res.quorums.reserve(std::min((uint64_t)16, count));
    auto net = nettype();
    for (size_t height = start; height != end;)
    {
      auto hf_version = get_network_version(net, height);
      {
        auto start_quorum_iterator = static_cast<master_nodes::quorum_type>(0);
        auto end_quorum_iterator   = master_nodes::max_quorum_type_for_hf(hf_version);

        if (req.quorum_type != GET_QUORUM_STATE::ALL_QUORUMS_SENTINEL_VALUE)
        {
          start_quorum_iterator = static_cast<master_nodes::quorum_type>(req.quorum_type);
          end_quorum_iterator   = start_quorum_iterator;
        }

        for (int quorum_int = (int)start_quorum_iterator; quorum_int <= (int)end_quorum_iterator; quorum_int++)
        {
          auto type = static_cast<master_nodes::quorum_type>(quorum_int);
          if (latest)
          { // Latest quorum requested, so skip if this is isn't the latest height for *this* quorum type
            if (type == master_nodes::quorum_type::obligations && height != latest_ob) continue;
            if (type == master_nodes::quorum_type::checkpointing && height != latest_cp) continue;
            if (type == master_nodes::quorum_type::flash && height != latest_bl) continue;
            if (type == master_nodes::quorum_type::POS) continue;
          }
          if (std::shared_ptr<const master_nodes::quorum> quorum = m_core.get_quorum(type, height, true /*include_old*/))
          {
            auto& entry = res.quorums.emplace_back();
            entry.height                                          = height;
            entry.quorum_type                                     = static_cast<uint8_t>(quorum_int);
            entry.quorum.validators = hexify(quorum->validators);
            entry.quorum.workers = hexify(quorum->workers);

            at_least_one_succeeded = true;
          }
        }
      }

      if (end >= start) height++;
      else height--;
    }

    if (auto hf_version = get_network_version(nettype(), curr_height); add_curr_POS && hf_version >= hf::hf17_POS)
    {
      cryptonote::Blockchain const &blockchain   = m_core.get_blockchain_storage();
      cryptonote::block_header const &top_header = blockchain.get_db().get_block_header_from_height(curr_height - 1);

      POS::timings next_timings = {};
      uint8_t POS_round         = 0;
      if (POS::get_round_timings(blockchain, curr_height, top_header.timestamp, next_timings) &&
          POS::convert_time_to_round(POS::clock::now(), next_timings.r0_timestamp, &POS_round))
      {
        auto entropy = master_nodes::get_POS_entropy_for_next_block(blockchain.get_db(), POS_round);
        auto& mn_list = m_core.get_master_node_list();
        auto quorum = generate_POS_quorum(m_core.get_nettype(), mn_list.get_block_leader().key, hf_version, mn_list.active_master_nodes_infos(), entropy, POS_round);
        if (verify_POS_quorum_sizes(quorum))
        {
          auto& entry = res.quorums.emplace_back();
          entry.height = curr_height;
          entry.quorum_type = static_cast<uint8_t>(master_nodes::quorum_type::POS);

          entry.quorum.validators = hexify(quorum.validators);
          entry.quorum.workers = hexify(quorum.workers);

          at_least_one_succeeded = true;
        }
      }
    }

    if (!at_least_one_succeeded)
      throw rpc_error{ERROR_WRONG_PARAM, "Failed to query any quorums at all"};

    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  FLUSH_CACHE::response core_rpc_server::invoke(FLUSH_CACHE::request&& req, rpc_context context)
  {
    FLUSH_CACHE::response res{};
    if (req.bad_txs)
      m_core.flush_bad_txs_cache();
    if (req.bad_blocks)
      m_core.flush_invalid_blocks();
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_MASTER_NODE_REGISTRATION_CMD_RAW::response core_rpc_server::invoke(GET_MASTER_NODE_REGISTRATION_CMD_RAW::request&& req, rpc_context context)
  {
    GET_MASTER_NODE_REGISTRATION_CMD_RAW::response res{};

    PERF_TIMER(on_get_master_node_registration_cmd_raw);

    if (!m_core.master_node())
      throw rpc_error{ERROR_WRONG_PARAM, "Daemon has not been started in master node mode, please relaunch with --master-node flag."};

    auto hf_version = get_network_version(nettype(), m_core.get_current_blockchain_height());
    if (!master_nodes::make_registration_cmd(m_core.get_nettype(), hf_version, req.staking_requirement, req.args, m_core.get_master_keys(), res.registration_cmd, req.make_friendly))
      throw rpc_error{ERROR_INTERNAL, "Failed to make registration command"};

    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_MASTER_NODE_REGISTRATION_CMD::response core_rpc_server::invoke(GET_MASTER_NODE_REGISTRATION_CMD::request&& req, rpc_context context)
  {
    GET_MASTER_NODE_REGISTRATION_CMD::response res{};

    PERF_TIMER(on_get_master_node_registration_cmd);

    std::vector<std::string> args;

    uint64_t const curr_height   = m_core.get_current_blockchain_height();
    uint64_t staking_requirement = master_nodes::get_staking_requirement( curr_height);

    {
      uint64_t portions_cut;
      if (!master_nodes::get_portions_from_percent_str(req.operator_cut, portions_cut))
      {
        res.status = "Invalid value: " + req.operator_cut + ". Should be between [0-100]";
        MERROR(res.status);
        return res;
      }

      args.push_back(std::to_string(portions_cut));
    }

    for (const auto& [address, amount] : req.contributions)
    {
        uint64_t num_portions = master_nodes::get_portions_to_make_amount(staking_requirement, amount);
        args.push_back(address);
        args.push_back(std::to_string(num_portions));
    }

    GET_MASTER_NODE_REGISTRATION_CMD_RAW::request req_old{};

    req_old.staking_requirement = req.staking_requirement;
    req_old.args = std::move(args);
    req_old.make_friendly = false;
    return invoke(std::move(req_old), context);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_MASTER_NODE_BLACKLISTED_KEY_IMAGES::response core_rpc_server::invoke(GET_MASTER_NODE_BLACKLISTED_KEY_IMAGES::request&& req, rpc_context context)
  {
    GET_MASTER_NODE_BLACKLISTED_KEY_IMAGES::response res{};

    PERF_TIMER(on_get_master_node_blacklisted_key_images);
    auto &blacklist = m_core.get_master_node_blacklisted_key_images();

    res.status = STATUS_OK;
    res.blacklist.reserve(blacklist.size());
    for (const master_nodes::key_image_blacklist_entry &entry : blacklist)
    {
      res.blacklist.emplace_back();
      auto &new_entry = res.blacklist.back();
      new_entry.key_image     = tools::type_to_hex(entry.key_image);
      new_entry.unlock_height = entry.unlock_height;
      new_entry.amount = entry.amount;
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_MASTER_KEYS::response core_rpc_server::invoke(GET_MASTER_KEYS::request&& req, rpc_context context)
  {
    GET_MASTER_KEYS::response res{};

    PERF_TIMER(on_get_master_node_key);

    const auto& keys = m_core.get_master_keys();
    if (keys.pub)
      res.master_node_pubkey = tools::type_to_hex(keys.pub);
    res.master_node_ed25519_pubkey = tools::type_to_hex(keys.pub_ed25519);
    res.master_node_x25519_pubkey = tools::type_to_hex(keys.pub_x25519);
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_MASTER_PRIVKEYS::response core_rpc_server::invoke(GET_MASTER_PRIVKEYS::request&& req, rpc_context context)
  {
    GET_MASTER_PRIVKEYS::response res{};

    PERF_TIMER(on_get_master_node_key);

    const auto& keys = m_core.get_master_keys();
    if (keys.key != crypto::null_skey)
      res.master_node_privkey = tools::type_to_hex(keys.key.data);
    res.master_node_ed25519_privkey = tools::type_to_hex(keys.key_ed25519.data);
    res.master_node_x25519_privkey = tools::type_to_hex(keys.key_x25519.data);
    res.status = STATUS_OK;
    return res;
  }

  static time_t reachable_to_time_t(
      std::chrono::steady_clock::time_point t,
      std::chrono::system_clock::time_point system_now,
      std::chrono::steady_clock::time_point steady_now) {
    if (t == master_nodes::NEVER)
      return 0;
    return std::chrono::system_clock::to_time_t(
            std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                system_now + (t - steady_now)));
  }

  static bool requested(const std::unordered_set<std::string>& requested, const std::string& key) {
    return requested.empty() ||
      (requested.count("all")
       ? !requested.count("-" + key)
       : requested.count(key));
  }

  template <typename Dict, typename T, typename... More>
  static void set_if_requested(const std::unordered_set<std::string>& reqed, Dict& dict,
      const std::string& key, T&& value, More&&... more) {
    if (requested(reqed, key))
      dict[key] = std::forward<T>(value);
    if constexpr (sizeof...(More) > 0)
      set_if_requested(reqed, dict, std::forward<More>(more)...);
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::fill_mn_response_entry(json& entry, bool is_bt, const std::unordered_set<std::string>& reqed, const master_nodes::master_node_pubkey_info& mn_info, uint64_t top_height)
  {
    auto hf_version = m_core.get_blockchain_storage().get_network_version();
    auto binary_format = is_bt ? json_binary_proxy::fmt::bt : json_binary_proxy::fmt::hex;
    json_binary_proxy binary{entry, binary_format};

    const auto &info = *mn_info.info;
    set_if_requested(reqed, binary, "master_node_pubkey", mn_info.pubkey);
    set_if_requested(reqed, entry,
        "registration_height", info.registration_height,
        "requested_unlock_height", info.requested_unlock_height,
        "last_reward_block_height", info.last_reward_block_height,
        "last_reward_transaction_index", info.last_reward_transaction_index,
        "active", info.is_active(),
        "funded", info.is_fully_funded(),
        "state_height", info.is_fully_funded()
            ? (info.is_decommissioned() ? info.last_decommission_height : info.active_since_height)
            : info.last_reward_block_height,
        "earned_downtime_blocks", master_nodes::quorum_cop::calculate_decommission_credit(info, top_height, hf_version),
        "decommission_count", info.decommission_count,
        "total_contributed", info.total_contributed,
        "staking_requirement", info.staking_requirement,
        "portions_for_operator", info.portions_for_operator,
        "operator_fee", microportion(info.portions_for_operator),
        "operator_address", cryptonote::get_account_address_as_str(m_core.get_nettype(), false/*subaddress*/, info.operator_address),
        "swarm_id", info.swarm_id,
        "swarm", tools::int_to_string(info.swarm_id, 16),
        "registration_hf_version", info.registration_hf_version
      );

    if (requested(reqed, "total_reserved") && info.total_reserved != info.total_contributed)
      entry["total_reserved"] = info.total_reserved;

    if (info.last_decommission_reason_consensus_any) {
      set_if_requested(reqed, entry,
          "last_decommission_reason_consensus_all", info.last_decommission_reason_consensus_all,
          "last_decommission_reason_consensus_any", info.last_decommission_reason_consensus_any);

      if (requested(reqed, "last_decomm_reasons")) {
        auto& reasons = (entry["last_decomm_reasons"] = json{
              {"all", cryptonote::coded_reasons(info.last_decommission_reason_consensus_all)}});
        if (auto some = cryptonote::coded_reasons(info.last_decommission_reason_consensus_any & ~info.last_decommission_reason_consensus_all);
            !some.empty())
          reasons["some"] = std::move(some);
      }
    }

    auto& netconf = m_core.get_net_config();
    // FIXME: accessing proofs one-by-one like this is kind of gross.
    m_core.get_master_node_list().access_proof(mn_info.pubkey, [&](const auto& proof) {
      if (proof.proof->public_ip != 0)
        set_if_requested(reqed, entry,
            "master_node_version", proof.proof->version,
            "belnet_version", proof.proof->belnet_version,
            "storage_server_version", proof.proof->storage_server_version,
            "public_ip", epee::string_tools::get_ip_string_from_int32(proof.proof->public_ip),
            "storage_port", proof.proof->storage_https_port,
            "storage_lmq_port", proof.proof->storage_omq_port,
            "quorumnet_port", proof.proof->qnet_port);
      if (proof.proof->pubkey_ed25519)
        set_if_requested(reqed, binary,
            "pubkey_ed25519", proof.proof->pubkey_ed25519,
            "pubkey_x25519", proof.pubkey_x25519);

      auto system_now = std::chrono::system_clock::now();
      auto steady_now = std::chrono::steady_clock::now();
      set_if_requested(reqed, entry, "last_uptime_proof", proof.timestamp);
      if (m_core.master_node()) {
        set_if_requested(reqed, entry,
            "storage_server_reachable", !proof.ss_reachable.unreachable_for(netconf.UPTIME_PROOF_VALIDITY - netconf.UPTIME_PROOF_FREQUENCY, steady_now),
            "belnet_reachable", !proof.belnet_reachable.unreachable_for(netconf.UPTIME_PROOF_VALIDITY - netconf.UPTIME_PROOF_FREQUENCY, steady_now));
        if (proof.ss_reachable.first_unreachable != master_nodes::NEVER && requested(reqed, "storage_server_first_unreachable"))
          entry["storage_server_first_unreachable"] = reachable_to_time_t(proof.ss_reachable.first_unreachable, system_now, steady_now);
        if (proof.ss_reachable.last_unreachable != master_nodes::NEVER && requested(reqed, "storage_server_last_unreachable"))
          entry["storage_server_last_unreachable"] = reachable_to_time_t(proof.ss_reachable.last_unreachable, system_now, steady_now);
        if (proof.ss_reachable.last_reachable != master_nodes::NEVER && requested(reqed, "storage_server_last_reachable"))
          entry["storage_server_last_reachable"] = reachable_to_time_t(proof.ss_reachable.last_reachable, system_now, steady_now);
        if (proof.belnet_reachable.first_unreachable != master_nodes::NEVER && requested(reqed, "belnet_first_unreachable"))
          entry["belnet_first_unreachable"] = reachable_to_time_t(proof.belnet_reachable.first_unreachable, system_now, steady_now);
        if (proof.belnet_reachable.last_unreachable != master_nodes::NEVER && requested(reqed, "belnet_last_unreachable"))
          entry["belnet_last_unreachable"] = reachable_to_time_t(proof.belnet_reachable.last_unreachable, system_now, steady_now);
        if (proof.belnet_reachable.last_reachable != master_nodes::NEVER && requested(reqed, "belnet_last_reachable"))
          entry["belnet_last_reachable"] = reachable_to_time_t(proof.belnet_reachable.last_reachable, system_now, steady_now);
      }

      if (requested(reqed, "checkpoint_votes") && !proof.checkpoint_participation.empty()) {
        std::vector<uint64_t> voted, missed;
        for (auto& cpp : proof.checkpoint_participation)
          (cpp.pass() ? voted : missed).push_back(cpp.height);
        std::sort(voted.begin(), voted.end());
        std::sort(missed.begin(), missed.end());
        entry["checkpoint_votes"] = json{
            {"voted", voted},
            {"missed", missed}};
      }
      if (requested(reqed, "POS_votes") && !proof.POS_participation.empty()) {
        std::vector<std::pair<uint64_t, uint8_t>> voted, missed;
        for (auto& ppp : proof.POS_participation)
          (ppp.pass() ? voted : missed).emplace_back(ppp.height, ppp.round);
        std::sort(voted.begin(), voted.end());
        std::sort(missed.begin(), missed.end());
        entry["POS_votes"]["voted"] = voted;
        entry["POS_votes"]["missed"] = missed;
      }
      if (requested(reqed, "quorumnet_tests") && !proof.timestamp_participation.empty()) {
        auto fails = proof.timestamp_participation.failures();
        entry["quorumnet_tests"] = json::array({proof.timestamp_participation.size() - fails, fails});
      }
      if (requested(reqed, "timesync_tests") && !proof.timesync_status.empty()) {
        auto fails = proof.timesync_status.failures();
        entry["timesync_tests"] = json::array({proof.timesync_status.size() - fails, fails});
      }
    });

    if (requested(reqed, "contributors")) {
      auto& contributors = (entry["contributors"] = json::array());
      for (const auto& contributor : info.contributors) {
        auto& c = contributors.emplace_back(json{
            {"amount", contributor.amount},
            {"address", cryptonote::get_account_address_as_str(m_core.get_nettype(), false/*subaddress*/, contributor.address)}});
        if (contributor.reserved != contributor.amount)
          c["reserved"] = contributor.reserved;
        if (requested(reqed, "locked_contributions")) {
          auto& locked = (c["locked_contributions"] = json::array());
          for (const auto& src : contributor.locked_contributions) {
            auto& lc = locked.emplace_back(json{{"amount", src.amount}});
            json_binary_proxy lc_binary{lc, binary_format};
            lc_binary["key_image"] = src.key_image;
            lc_binary["key_image_pub_key"] = src.key_image_pub_key;
          }
        }
      }
    }
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(GET_MASTER_NODES& mns, rpc_context context)
  {
    auto& req = mns.request;
    mns.response["status"] = STATUS_OK;
    auto [top_height, top_hash] = m_core.get_blockchain_top();
    auto [hf, mnode_rev] = get_network_version_revision(nettype(), top_height);
    set_if_requested(req.fields, mns.response,
        "height", top_height,
        "target_height", m_core.get_target_blockchain_height(),
        "hardfork", hf,
        "mnode_revision", mnode_rev);
    set_if_requested(req.fields, mns.response_hex,
        "block_hash", top_hash);

    if (req.poll_block_hash) {
      bool unchanged = req.poll_block_hash == top_hash;
      mns.response["unchanged"] = unchanged;
      if (unchanged)
        return;
      if (!requested(req.fields, "block_hash"))
        mns.response_hex["block_hash"] = top_hash; // Force it on a poll request even if it wasn't a requested field
    }

    auto mn_infos = m_core.get_master_node_list_state(req.master_node_pubkeys);

    if (req.active_only)
      mn_infos.erase(
        std::remove_if(mn_infos.begin(), mn_infos.end(), [](const master_nodes::master_node_pubkey_info& mnpk_info) {
          return !mnpk_info.info->is_active();
        }),
        mn_infos.end());

    const int top_mn_index = (int) mn_infos.size() - 1;
    if (req.limit < 0 || req.limit > top_mn_index) {
      // We asked for -1 (no limit but shuffle) or a value >= the count, so just shuffle the entire list
      std::shuffle(mn_infos.begin(), mn_infos.end(), tools::rng);
    } else if (req.limit > 0) {
      // We need to select N random elements, in random order, from yyyyyyyy.  We could (and used
      // to) just shuffle the entire list and return the first N, but that is quite inefficient when
      // the list is large and N is small.  So instead this algorithm is going to select a random
      // the elements beginning at position 1), and swap it into element 1, to get [xx]yyyyyy, then
      // keep repeating until our set of x's is big enough, say [xxx]yyyyy.  At that point we chop
      // of the y's to just be left with [xxx], and only required N swaps in total.
      for (int i = 0; i < req.limit; i++)
      {
        int j = std::uniform_int_distribution<int>{i, top_mn_index}(tools::rng);
        using std::swap;
        if (i != j)
          swap(mn_infos[i], mn_infos[j]);
      }

      mn_infos.resize(req.limit);
    }

    auto& mn_states = (mns.response["master_node_states"] = json::array());
    for (auto &pubkey_info : mn_infos)
      fill_mn_response_entry(mn_states.emplace_back(json::object()), mns.is_bt(), req.fields, pubkey_info, top_height);
  }

  namespace {
    // Handles a ping.  Returns true if the ping was significant (i.e. first ping after startup, or
    // after the ping had expired).  `Success` is a callback that is invoked with a single boolean
    // argument: true if this ping should trigger an immediate proof send (i.e. first ping after
    // startup or after a ping expiry), false for an ordinary ping.
    template <typename RPC, typename Success>
    auto handle_ping(
            core& core,
            std::array<uint16_t, 3> cur_version,
            std::array<uint16_t, 3> required,
            std::string_view pubkey_ed25519,
            std::string_view name,
            std::atomic<std::time_t>& update,
            std::chrono::seconds lifetime,
            Success success)
    {
      std::string our_pubkey_ed25519 = tools::type_to_hex(core.get_master_keys().pub_ed25519);
      typename RPC::response res{};
      if (cur_version < required) {
        res.status = fmt::format("Outdated {}. Current: {}.{}.{}, Required: {}.{}.{}",name, cur_version[0], cur_version[1], cur_version[2], required[0], required[1], required[2]);
        MERROR(res.status);
      } else if (!pubkey_ed25519.empty() && !(pubkey_ed25519.find_first_not_of('0') == std::string_view::npos) // TODO: once belnet & ss are always sending this we can remove this empty bypass
          && (pubkey_ed25519 != our_pubkey_ed25519)) {
        res.status = fmt::format("Invalid {} pubkey: expected {}, received {}", name, our_pubkey_ed25519, pubkey_ed25519);
        MERROR(res.status);
      } else {
        auto now = std::time(nullptr);
        auto old = update.exchange(now);
        bool significant = std::chrono::seconds{now - old} > lifetime; // Print loudly for the first ping after startup/expiry
        if (significant)
          MGINFO_GREEN(fmt::format("Received ping from {} {}.{}.{}", name, cur_version[0], cur_version[1], cur_version[2]));
        else
          MDEBUG(fmt::format("Accepted ping from {} {}.{}.{}", name, cur_version[0], cur_version[1], cur_version[2]));
        success(significant);
        res.status = STATUS_OK;
      }
      return res;
    }
  }

  //------------------------------------------------------------------------------------------------------------------------------
  STORAGE_SERVER_PING::response core_rpc_server::invoke(STORAGE_SERVER_PING::request&& req, rpc_context context)
  {
    m_core.ss_version = req.version;
    return handle_ping<STORAGE_SERVER_PING>(m_core,
      req.version, master_nodes::MIN_STORAGE_SERVER_VERSION,
      req.pubkey_ed25519,
      "Storage Server", m_core.m_last_storage_server_ping, m_core.get_net_config().UPTIME_PROOF_FREQUENCY,
      [this, &req](bool significant) {
        m_core.m_storage_https_port = req.https_port;
        m_core.m_storage_omq_port = req.omq_port;
        if (significant)
          m_core.reset_proof_interval();
      });
  }
  //------------------------------------------------------------------------------------------------------------------------------
  BELNET_PING::response core_rpc_server::invoke(BELNET_PING::request&& req, rpc_context context)
  {
    m_core.belnet_version = req.version;
    return handle_ping<BELNET_PING>(m_core,
        req.version, master_nodes::MIN_BELNET_VERSION,
        req.pubkey_ed25519,
        "Belnet", m_core.m_last_belnet_ping, m_core.get_net_config().UPTIME_PROOF_FREQUENCY,
        [this](bool significant) { if (significant) m_core.reset_proof_interval(); });
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_STAKING_REQUIREMENT::response core_rpc_server::invoke(GET_STAKING_REQUIREMENT::request&& req, rpc_context context)
  {
    GET_STAKING_REQUIREMENT::response res{};

    PERF_TIMER(on_get_staking_requirement);
    res.height = req.height > 0 ? req.height : m_core.get_current_blockchain_height();

    res.staking_requirement = master_nodes::get_staking_requirement(res.height);
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  static void check_quantity_limit(size_t count, size_t max, char const *container_name = nullptr)
  {
    if (count > max)
    {
      std::ostringstream err;
      err << "Number of requested entries";
      if (container_name) err << " in " << container_name;
      err << " greater than the allowed limit: " << max << ", requested: " << count;
      throw rpc_error{ERROR_WRONG_PARAM, err.str()};
    }
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_CHECKPOINTS::response core_rpc_server::invoke(GET_CHECKPOINTS::request&& req, rpc_context context)
  {
    GET_CHECKPOINTS::response res{};

    if (use_bootstrap_daemon_if_necessary<GET_CHECKPOINTS>(req, res))
      return res;

    if (!context.admin)
      check_quantity_limit(req.count, GET_CHECKPOINTS::MAX_COUNT);

    res.status             = STATUS_OK;
    BlockchainDB const &db = m_core.get_blockchain_storage().get_db();

    std::vector<checkpoint_t> checkpoints;
    if (req.start_height == GET_CHECKPOINTS::HEIGHT_SENTINEL_VALUE &&
        req.end_height   == GET_CHECKPOINTS::HEIGHT_SENTINEL_VALUE)
    {
      checkpoint_t top_checkpoint;
      if (db.get_top_checkpoint(top_checkpoint))
        checkpoints = db.get_checkpoints_range(top_checkpoint.height, 0, req.count);
    }
    else if (req.start_height == GET_CHECKPOINTS::HEIGHT_SENTINEL_VALUE)
    {
      checkpoints = db.get_checkpoints_range(req.end_height, 0, req.count);
    }
    else if (req.end_height == GET_CHECKPOINTS::HEIGHT_SENTINEL_VALUE)
    {
      checkpoints = db.get_checkpoints_range(req.start_height, UINT64_MAX, req.count);
    }
    else
    {
      checkpoints = db.get_checkpoints_range(req.start_height, req.end_height);
    }

    res.checkpoints.reserve(checkpoints.size());
    for (checkpoint_t const &checkpoint : checkpoints)
      res.checkpoints.push_back(checkpoint);

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_MN_STATE_CHANGES::response core_rpc_server::invoke(GET_MN_STATE_CHANGES::request&& req, rpc_context context)
  {
    GET_MN_STATE_CHANGES::response res{};

    using blob_t = cryptonote::blobdata;
    using block_pair_t = std::pair<blob_t, block>;
    std::vector<block_pair_t> blocks;

    const auto& db = m_core.get_blockchain_storage();
    const uint64_t current_height = db.get_current_blockchain_height();

    uint64_t end_height;
    if (req.end_height == GET_MN_STATE_CHANGES::HEIGHT_SENTINEL_VALUE) {
      // current height is the block being mined, so exclude it from the results
      end_height = current_height - 1;
    } else {
      end_height = req.end_height;
    }

    if (end_height < req.start_height)
      throw rpc_error{ERROR_WRONG_PARAM, "The provided end_height needs to be higher than start_height"};

    if (!db.get_blocks(req.start_height, end_height - req.start_height + 1, blocks))
      throw rpc_error{ERROR_INTERNAL, "Could not query block at requested height: " + std::to_string(req.start_height)};

    res.start_height = req.start_height;
    res.end_height = end_height;

    std::vector<blob_t> blobs;
    for (const auto& block : blocks)
    {
      blobs.clear();
      if (!db.get_transactions_blobs(block.second.tx_hashes, blobs))
      {
        MERROR("Could not query block at requested height: " << cryptonote::get_block_height(block.second));
        continue;
      }
      const auto hard_fork_version = block.second.major_version;
      for (const auto& blob : blobs)
      {
        cryptonote::transaction tx;
        if (!cryptonote::parse_and_validate_tx_from_blob(blob, tx))
        {
          MERROR("tx could not be validated from blob, possibly corrupt blockchain");
          continue;
        }
        if (tx.type == cryptonote::txtype::state_change)
        {
          cryptonote::tx_extra_master_node_state_change state_change;
          if (!cryptonote::get_master_node_state_change_from_tx_extra(tx.extra, state_change, hard_fork_version))
          {
            LOG_ERROR("Could not get state change from tx, possibly corrupt tx, hf_version "<< static_cast<int>(hard_fork_version));
            continue;
          }

          switch(state_change.state) {
            case master_nodes::new_state::deregister:
              res.total_deregister++;
              break;

            case master_nodes::new_state::decommission:
              res.total_decommission++;
              break;

            case master_nodes::new_state::recommission:
              res.total_recommission++;
              break;

            case master_nodes::new_state::ip_change_penalty:
              res.total_ip_change_penalty++;
              break;

            default:
              MERROR("Unhandled state in on_get_master_nodes_state_changes");
              break;
          }
        }

        if (tx.type == cryptonote::txtype::key_image_unlock)
        {
          res.total_unlock++;
        }
      }
    }

    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  REPORT_PEER_STATUS::response core_rpc_server::invoke(REPORT_PEER_STATUS::request&& req, rpc_context context)
  {
    REPORT_PEER_STATUS::response res{};

    crypto::public_key pubkey;
    if (!tools::hex_to_type(req.pubkey, pubkey)) {
      MERROR("Could not parse public key: " << req.pubkey);
      throw rpc_error{ERROR_WRONG_PARAM, "Could not parse public key"};
    }

    bool success = false;
    if (req.type == "belnet")
      success = m_core.get_master_node_list().set_belnet_peer_reachable(pubkey, req.passed);
    else if (req.type == "storage" || req.type == "reachability" /* TODO: old name, can be removed once SS no longer uses it */)
      success = m_core.get_master_node_list().set_storage_server_peer_reachable(pubkey, req.passed);
    else
      throw rpc_error{ERROR_WRONG_PARAM, "Unknown status type"};
    if (!success)
      throw rpc_error{ERROR_WRONG_PARAM, "Pubkey not found"};

    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  TEST_TRIGGER_P2P_RESYNC::response core_rpc_server::invoke(TEST_TRIGGER_P2P_RESYNC::request&& req, rpc_context context)
  {
    TEST_TRIGGER_P2P_RESYNC::response res{};

    m_p2p.reset_peer_handshake_timer();
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  TEST_TRIGGER_UPTIME_PROOF::response core_rpc_server::invoke(TEST_TRIGGER_UPTIME_PROOF::request&& req, rpc_context context)
  {
    if (m_core.get_nettype() != cryptonote::network_type::MAINNET)
      m_core.submit_uptime_proof();

    TEST_TRIGGER_UPTIME_PROOF::response res{};
    res.status = STATUS_OK;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  BNS_NAMES_TO_OWNERS::response core_rpc_server::invoke(BNS_NAMES_TO_OWNERS::request&& req, rpc_context context)
  {
    BNS_NAMES_TO_OWNERS::response res{};

    if (!context.admin)
      check_quantity_limit(req.entries.size(), BNS_NAMES_TO_OWNERS::MAX_REQUEST_ENTRIES);

    std::optional<uint64_t> height = m_core.get_current_blockchain_height();
    auto hf_version = get_network_version(nettype(), *height);
    if (req.include_expired) height = std::nullopt;

    std::vector<bns::mapping_type> types;

    bns::name_system_db &db = m_core.get_blockchain_storage().name_system_db();
    for (size_t request_index = 0; request_index < req.entries.size(); request_index++)
    {
      std::string const &req_name_hash = req.entries[request_index];

      // This also takes 32 raw bytes, but that is undocumented (because it is painful to pass
      // through json).
      auto name_hash = bns::name_hash_input_to_base64(req_name_hash);
      if (!name_hash)
        throw rpc_error{ERROR_WRONG_PARAM, "Invalid name_hash: expected hash as 64 hex digits or 43/44 base64 characters"};

      std::vector<bns::mapping_record> records = db.get_mappings(*name_hash, height);
      for (auto const &record : records)
      {
        auto& entry = res.entries.emplace_back();
        entry.entry_index                                      = request_index;
        entry.name_hash                                        = record.name_hash;
        entry.owner                                            = record.owner.to_string(nettype());
        if (record.backup_owner) entry.backup_owner            = record.backup_owner.to_string(nettype());
        entry.encrypted_bchat_value                            = oxenc::to_hex(record.encrypted_bchat_value.to_view());
        entry.encrypted_wallet_value                           = oxenc::to_hex(record.encrypted_wallet_value.to_view());
        entry.encrypted_belnet_value                           = oxenc::to_hex(record.encrypted_belnet_value.to_view());
        entry.encrypted_eth_addr_value                         = oxenc::to_hex(record.encrypted_eth_addr_value.to_view());
        entry.expiration_height                                = record.expiration_height;
        entry.update_height                                    = record.update_height;
        entry.txid                                             = tools::type_to_hex(record.txid);
      }
    }

    res.status = STATUS_OK;
    return res;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  BNS_LOOKUP::response core_rpc_server::invoke(BNS_LOOKUP::request&& req, rpc_context context)
  {
    BNS_LOOKUP::response res{};

    std::string name = tools::lowercase_ascii_string(std::move(req.name));
    
    BNS_NAMES_TO_OWNERS::request name_to_owner_req{};
    name_to_owner_req.entries.push_back(bns::name_to_base64_hash(name));   
    auto name_to_owner_res = invoke(std::move(name_to_owner_req), context);

    if(name_to_owner_res.entries.size() != 1){
        throw rpc_error{ERROR_INVALID_RESULT, "Invalid data returned from BNS_NAMES_TO_OWNERS"};
    }

    auto entries = name_to_owner_res.entries.back();
    {
      res.name_hash                                         = entries.name_hash;
      res.owner                                             = entries.owner;
      if (entries.backup_owner) res.backup_owner            = entries.backup_owner;
      res.expiration_height                                 = entries.expiration_height;
      res.update_height                                     = entries.update_height;
      res.txid                                              = entries.txid;

      if(!entries.encrypted_bchat_value.empty()){
        BNS_VALUE_DECRYPT::request bns_value_decrypt_req{name, "bchat", entries.encrypted_bchat_value};
        auto bns_value_decrypt_res = invoke(std::move(bns_value_decrypt_req), context);
        res.bchat_value = bns_value_decrypt_res.value;
      }
      if(!entries.encrypted_belnet_value.empty()){
        BNS_VALUE_DECRYPT::request bns_value_decrypt_req{name, "belnet", entries.encrypted_belnet_value};
        auto bns_value_decrypt_res = invoke(std::move(bns_value_decrypt_req), context);
        res.belnet_value = bns_value_decrypt_res.value;
      }
      if(!entries.encrypted_wallet_value.empty()){
        BNS_VALUE_DECRYPT::request bns_value_decrypt_req{name, "wallet", entries.encrypted_wallet_value};
        auto bns_value_decrypt_res = invoke(std::move(bns_value_decrypt_req), context);
        res.wallet_value = bns_value_decrypt_res.value;
      }
      if(!entries.encrypted_eth_addr_value.empty()){
        BNS_VALUE_DECRYPT::request bns_value_decrypt_req{name, "eth_addr", entries.encrypted_eth_addr_value};
        auto bns_value_decrypt_res = invoke(std::move(bns_value_decrypt_req), context);
        res.eth_addr_value = bns_value_decrypt_res.value;
      }
    }

    res.status = STATUS_OK;
    return res;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  BNS_OWNERS_TO_NAMES::response core_rpc_server::invoke(BNS_OWNERS_TO_NAMES::request&& req, rpc_context context)
  {
    BNS_OWNERS_TO_NAMES::response res{};

    if (!context.admin)
      check_quantity_limit(req.entries.size(), BNS_OWNERS_TO_NAMES::MAX_REQUEST_ENTRIES);

    std::unordered_map<bns::generic_owner, size_t> owner_to_request_index;
    std::vector<bns::generic_owner> owners;

    owners.reserve(req.entries.size());
    for (size_t request_index = 0; request_index < req.entries.size(); request_index++)
    {
      std::string const &owner     = req.entries[request_index];
      bns::generic_owner bns_owner = {};
      std::string errmsg;
      if (!bns::parse_owner_to_generic_owner(m_core.get_nettype(), owner, bns_owner, &errmsg))
        throw rpc_error{ERROR_WRONG_PARAM, std::move(errmsg)};

      // TODO(beldex): We now serialize both owner and backup_owner, since if
      // we specify an owner that is backup owner, we don't show the (other)
      // owner. For RPC compatibility we keep the request_index around until the
      // next hard fork (16)
      owners.push_back(bns_owner);
      owner_to_request_index[bns_owner] = request_index;
    }

    bns::name_system_db &db = m_core.get_blockchain_storage().name_system_db();
    std::optional<uint64_t> height;
    if (!req.include_expired) height = m_core.get_current_blockchain_height();

    std::vector<bns::mapping_record> records = db.get_mappings_by_owners(owners, height);
    for (auto &record : records)
    {
      auto it = owner_to_request_index.end();
      if (record.owner)
          it = owner_to_request_index.find(record.owner);
      if (it == owner_to_request_index.end() && record.backup_owner)
          it = owner_to_request_index.find(record.backup_owner);
      if (it == owner_to_request_index.end())
        throw rpc_error{ERROR_INTERNAL,
            (record.owner ? ("Owner=" + record.owner.to_string(nettype()) + " ") : ""s) +
            (record.backup_owner ? ("BackupOwner=" + record.backup_owner.to_string(nettype()) + " ") : ""s) +
            " could not be mapped back a index in the request 'entries' array"};

      auto& entry = res.entries.emplace_back();
      entry.request_index   = it->second;
      entry.name_hash       = std::move(record.name_hash);
      if (record.owner) entry.owner = record.owner.to_string(nettype());
      if (record.backup_owner) entry.backup_owner = record.backup_owner.to_string(nettype());
      entry.encrypted_bchat_value = oxenc::to_hex(record.encrypted_bchat_value.to_view());
      entry.encrypted_wallet_value = oxenc::to_hex(record.encrypted_wallet_value.to_view());
      entry.encrypted_belnet_value = oxenc::to_hex(record.encrypted_belnet_value.to_view());
      entry.encrypted_eth_addr_value = oxenc::to_hex(record.encrypted_eth_addr_value.to_view());
      entry.update_height   = record.update_height;
      entry.expiration_height = record.expiration_height;
      entry.txid            = tools::type_to_hex(record.txid);
    }

    res.status = STATUS_OK;
    return res;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void core_rpc_server::invoke(BNS_RESOLVE& resolve, rpc_context context)
  {
    auto& req = resolve.request;
    if (req.type < 0 || req.type >= tools::enum_count<bns::mapping_type>)
      throw rpc_error{ERROR_WRONG_PARAM, "Unable to resolve BNS address: 'type' parameter not specified"};

    auto name_hash = bns::name_hash_input_to_base64(req.name_hash);
    if (!name_hash)
      throw rpc_error{ERROR_WRONG_PARAM, "Unable to resolve BNS address: invalid 'name_hash' value '" + req.name_hash + "'"};


    auto hf_version = m_core.get_blockchain_storage().get_network_version();
    auto type = static_cast<bns::mapping_type>(req.type);

    if (auto mapping = m_core.get_blockchain_storage().name_system_db().resolve(
        type, *name_hash, m_core.get_current_blockchain_height()))
    {
      auto [val, nonce] = mapping->value_nonce(type);
      resolve.response_hex["encrypted_value"] = val;
      if (val.size() < mapping->to_view().size())
        resolve.response_hex["nonce"] = nonce;
    }
  }
  //------------------------------------------------------------------------------------------------------------------------------
  BNS_VALUE_DECRYPT::response core_rpc_server::invoke(BNS_VALUE_DECRYPT::request&& req, rpc_context context)
  {
    BNS_VALUE_DECRYPT::response res{};

    // ---------------------------------------------------------------------------------------------
    //
    // Validate encrypted value
    //
    // ---------------------------------------------------------------------------------------------
    if (req.encrypted_value.size() % 2 != 0)
      throw rpc_error{ERROR_INVALID_VALUE_LENGTH, "Value length not divisible by 2, length=" + std::to_string(req.encrypted_value.size())};

    if ((req.encrypted_value.size() >= (bns::mapping_value::BUFFER_SIZE * 2)) && !(req.type =="wallet"))
      throw rpc_error{ERROR_INVALID_VALUE_LENGTH, "Value too long to decrypt=" + req.encrypted_value};

    if (!oxenc::is_hex(req.encrypted_value))
      throw rpc_error{ERROR_INVALID_VALUE_LENGTH, "Value is not hex=" + req.encrypted_value};

    // ---------------------------------------------------------------------------------------------
    //
    // Validate type and name
    //
    // ---------------------------------------------------------------------------------------------
    std::string reason;
    bns::mapping_type type = {};

    auto hf_version = m_core.get_blockchain_storage().get_network_version();
    if (!bns::validate_mapping_type(req.type, hf_version, &type, &reason))
      throw rpc_error{ERROR_INVALID_VALUE_LENGTH, "Invalid BNS type: " + reason};

     if (!bns::validate_bns_name(req.name, &reason))
      throw rpc_error{ERROR_INVALID_VALUE_LENGTH, "Invalid BNS name '" + req.name + "': " + reason};
    
    // ---------------------------------------------------------------------------------------------
    //
    // Decrypt value
    //
    // ---------------------------------------------------------------------------------------------
    bns::mapping_value value = {};
    value.len = req.encrypted_value.size() / 2;
    value.encrypted = true;
    oxenc::from_hex(req.encrypted_value.begin(), req.encrypted_value.end(), value.buffer.begin());

    if (!value.decrypt(req.name, type))
      throw rpc_error{ERROR_INTERNAL, "Value decryption failure"};

    res.value = value.to_readable_value(nettype(), type);
    return res;
  }
}  // namespace cryptonote::rpc
