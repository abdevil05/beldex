#pragma once

#include <cstdint>
#include <vector>

// #include "common/pod-class.h" // beldex/src
#include "wire/json/fwd.h"
#include "rpc/message_data_structs.h" // monero/src
#define POD_CLASS struct

namespace crypto
{
  POD_CLASS hash;
}

namespace cryptonote
{
  namespace rpc
  {
    struct block_with_transactions;
  }
}

namespace lws
{
namespace rpc
{
  struct get_blocks_fast_request
  {
    get_blocks_fast_request() = delete;
    std::vector<crypto::hash> block_ids;
    std::uint64_t start_height;
    bool prune;
  };
  struct get_blocks_fast_response
  {
    get_blocks_fast_response() = delete;
    std::vector<cryptonote::rpc::block_with_transactions> blocks;
    std::vector<std::vector<std::vector<std::uint64_t>>> output_indices;
    std::uint64_t start_height;
    std::uint64_t current_height;
  };
  struct get_blocks_fast
  {
    using request = get_blocks_fast_request;
    using response = get_blocks_fast_response;
  };
  void read_bytes(wire::json_reader&, get_blocks_fast_response&);
} // rpc
} // lws