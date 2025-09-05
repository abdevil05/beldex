#pragma once

#include <cstdint>
#include <string>

#include "common/expect.h" // monero/src
#include "crypto/hash.h"   // monero/src
#include "wire/json/fwd.h"

namespace lws
{
namespace rpc
{
  //! Represents only the last block listed in "minimal-chain_main" pub.
  struct minimal_chain_pub
  {
    std::uint64_t top_block_height;
    crypto::hash top_block_id;

    static expect<minimal_chain_pub> from_json(std::string&&);
  };
}
}