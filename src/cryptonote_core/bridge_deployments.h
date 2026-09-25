// Copyright (c) 2026, The Beldex Project
#pragma once

#include <array>
#include <cstdint>
#include "cryptonote_config.h"

namespace cryptonote {

// Consensus deployment identities, NOT operator settings or the wallet routing list.
// Exactly one immutable proxy per (native network, EVM chain) is supported because
// observed_key_epoch and serving_key_epoch are currently keyed by chain ID.
struct bridge_deployment {
  network_type network;
  uint64_t chain_id;
  std::array<uint8_t, 20> proxy;
};

// Populate only from reviewed deployment approvals, via a coordinated protocol
// release. No approved production/testnet/devnet addresses were supplied for this
// change. Empty means disabled, never trust-on-first-use or a runtime fallback.
inline constexpr std::array<bridge_deployment, 0> BRIDGE_DEPLOYMENTS{};

// Test-only network fixtures. FAKECHAIN is a distinct native network, never an
// alias for DEVNET, TESTNET or MAINNET in this lookup.
inline constexpr std::array<uint8_t, 20> FAKECHAIN_BRIDGE_PROXY = {
  0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
  0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22
};
inline constexpr std::array FAKECHAIN_BRIDGE_DEPLOYMENTS = {
  bridge_deployment{FAKECHAIN, 1, FAKECHAIN_BRIDGE_PROXY},
  bridge_deployment{FAKECHAIN, 2, FAKECHAIN_BRIDGE_PROXY},
  bridge_deployment{FAKECHAIN, 42, FAKECHAIN_BRIDGE_PROXY},
};

template <size_t N>
constexpr bool valid_bridge_deployments(const std::array<bridge_deployment, N>& entries,
                                        bool test_fixtures = false)
{
  for (size_t i = 0; i < N; ++i)
  {
    const auto& entry = entries[i];
    if (entry.chain_id == 0) return false;
    if (test_fixtures ? entry.network != FAKECHAIN
                      : (entry.network != MAINNET && entry.network != TESTNET && entry.network != DEVNET))
      return false;
    bool nonzero = false;
    for (auto byte : entry.proxy) nonzero = nonzero || byte != 0;
    if (!nonzero) return false;
    for (size_t j = 0; j < i; ++j)
      if (entries[j].network == entry.network && entries[j].chain_id == entry.chain_id)
        return false;
  }
  return true;
}
static_assert(valid_bridge_deployments(BRIDGE_DEPLOYMENTS), "invalid canonical bridge deployments");
static_assert(valid_bridge_deployments(FAKECHAIN_BRIDGE_DEPLOYMENTS, true), "invalid bridge fixtures");

inline constexpr const bridge_deployment* find_bridge_deployment(network_type network, uint64_t chain_id)
{
  if (network == FAKECHAIN)
  {
    for (const auto& entry : FAKECHAIN_BRIDGE_DEPLOYMENTS)
      if (entry.chain_id == chain_id) return &entry;
    return nullptr;
  }
  for (const auto& entry : BRIDGE_DEPLOYMENTS)
    if (entry.network == network && entry.chain_id == chain_id) return &entry;
  return nullptr;
}
} // namespace cryptonote
