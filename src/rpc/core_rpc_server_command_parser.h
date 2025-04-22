#pragma once

#include "core_rpc_server_commands_defs.h"
#include <nlohmann/json.hpp>
#include <oxenc/bt_serialize.h>

namespace cryptonote::rpc {

  using rpc_input = std::variant<std::monostate, nlohmann::json, oxenc::bt_dict_consumer>;

  inline void parse_request(NO_ARGS&, rpc_input) {}

  void parse_request(BNS_RESOLVE& bns, rpc_input in);
  void parse_request(GET_MASTER_NODES& mns, rpc_input in);
  void parse_request(START_MINING& start_mining, rpc_input in);
  void parse_request(STOP_MINING& stop_mining, rpc_input in);
  void parse_request(MINING_STATUS& mining_status, rpc_input in);
  void parse_request(GET_TRANSACTION_POOL_STATS& get_transaction_pool_stats, rpc_input in);
  void parse_request(GET_TRANSACTION_POOL_HASHES& get_transaction_pool_hashes, rpc_input in);
  void parse_request(GET_BLOCK_COUNT& getblockcount, rpc_input in);
  void parse_request(STOP_DAEMON& stop_daemon, rpc_input in);
  void parse_request(SAVE_BC& save_bc, rpc_input in);
  void parse_request(GET_OUTPUTS& get_outputs, rpc_input in);
  void parse_request(GET_TRANSACTION_POOL_STATS& pstats, rpc_input in);
  void parse_request(GET_TRANSACTIONS& hfinfo, rpc_input in);
  void parse_request(HARD_FORK_INFO& hfinfo, rpc_input in);
  void parse_request(SET_LIMIT& limit, rpc_input in);
  void parse_request(IS_KEY_IMAGE_SPENT& spent, rpc_input in);
  void parse_request(SUBMIT_TRANSACTION& tx, rpc_input in);
  void parse_request(GET_BLOCK_HASH& bh, rpc_input in);
  void parse_request(GET_PEER_LIST& bh, rpc_input in);
  void parse_request(SET_LOG_LEVEL& set_log_level, rpc_input in);
  void parse_request(SET_LOG_CATEGORIES& set_log_categories, rpc_input in);
  void parse_request(BANNED& banned, rpc_input in);
  void parse_request(FLUSH_TRANSACTION_POOL& flush_transaction_pool, rpc_input in);
  void parse_request(GET_COINBASE_TX_SUM& get_coinbase_tx_sum, rpc_input in);
  void parse_request(GET_BASE_FEE_ESTIMATE& get_base_fee_estimate, rpc_input in);
  void parse_request(OUT_PEERS& out_peers, rpc_input in);
  void parse_request(IN_PEERS& in_peers, rpc_input in);
  void parse_request(POP_BLOCKS& pop_blocks, rpc_input in);
  void parse_request(BELNET_PING& belnet_ping, rpc_input in);
  void parse_request(STORAGE_SERVER_PING& storage_server_ping, rpc_input in);
  void parse_request(PRUNE_BLOCKCHAIN& prune_blockchain, rpc_input in);
  void parse_request(REPORT_PEER_STATUS& report_peer_status, rpc_input in);
  void parse_request(GET_MN_STATE_CHANGES& get_mn_state_changes, rpc_input in);
  void parse_request(FLUSH_CACHE& flush_cache, rpc_input in);
  void parse_request(GET_LAST_BLOCK_HEADER& get_lash_block_header, rpc_input in);
  void parse_request(SETBANS& set_bans, rpc_input in);
}