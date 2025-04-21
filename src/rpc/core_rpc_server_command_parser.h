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
}