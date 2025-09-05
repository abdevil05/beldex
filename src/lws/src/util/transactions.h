#pragma once

#include <boost/optional/optional.hpp>
#include <cstdint>
#include <utility>

// #include "common/pod-class.h"
#include "ringct/rctTypes.h"

#define POD_CLASS struct

namespace crypto
{
  POD_CLASS hash8;
  POD_CLASS key_derivation;
}

namespace lws
{
  void decrypt_payment_id(crypto::hash8& out, const crypto::key_derivation& key);
  boost::optional<std::pair<std::uint64_t, rct::key>> decode_amount(const rct::key& commitment, const rct::ecdhTuple& info, const crypto::key_derivation& sk, std::size_t index, const bool bulletproof2);
}
