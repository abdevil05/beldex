# Canonical bridge deployment identities

Native rotation acknowledgements must match an approved `(Beldex network,
EVM chain ID, wBDX proxy address)` entry in
`src/cryptonote_core/bridge_deployments.h`. This consensus registry is distinct
from `SUPPORTED_BRIDGE_CHAINS`, which is only a wallet deposit-routing allowlist.

The shared `verify_bridge_rotation_evidence` checks this registry before accepting
committee evidence. It is called by native state application, blockchain transaction
validation and the OMQ acknowledgement intake. Correct quorum signatures for an
unregistered chain or another proxy are insufficient. No runtime environment,
RPC response or first observed acknowledgement can register a proxy.

## Current activation status

No approved real-network proxy addresses were supplied for this change. Therefore
`BRIDGE_DEPLOYMENTS` is empty: MAINNET, TESTNET and DEVNET rotation acknowledgements
are deliberately disabled until approved records are added. This is enforcement
infrastructure, not an activated deployment registry. It may block bond release on
those networks; do not deploy it as a normal rolling upgrade.

The separate FAKECHAIN records are unit-test fixtures. The lookup does not treat
DEVNET as FAKECHAIN, and those fixtures confer no authority on real networks.

## Registering an approved deployment

1. Obtain approval of the native network, EVM chain ID and exact 20-byte **proxy**
   address. Do not use the implementation address. Verify the deployment provenance
   independently; local signer configuration is not consensus authorization.
2. Add that tuple to the compile-time `BRIDGE_DEPLOYMENTS` array with its explicit
   element count. The static validator rejects zero chains/proxies, invalid native
   networks and duplicate `(network, chain)` entries.
3. Add positive and negative tests for the approved network/chain/proxy tuple.
   Replace the current empty-registry assertions for networks actually enabled.
4. Coordinate a protocol activation and historical replay/state migration plan.
   Existing observed epochs must be audited against their actual source proxy;
   validating future acknowledgements cannot repair previously accepted state.
5. Establish initial observations for every active deployment before enabling bridge
   service, preserving the fail-closed unbond baseline gate.

Only one immutable proxy per native network/EVM chain is supported by this patch,
because observed key epochs and unbond snapshots currently use chain IDs. Do not
replace an existing proxy entry to transfer its state or bond obligations to a new
contract. Proxy replacement, chain retirement and multiple deployments on one EVM
chain need an explicit versioned registry/state migration design. A governance
transaction-based registration mechanism is not implemented here.

This patch does not prove EVM finality, validate the proposed successor against a
DKG commitment, complete the live acknowledgement workflow, or prove snapshot
completeness. Those are separate requirements. No contracts or nodes were deployed.

## Regression checks

```sh
cmake --build build/local-validation --target unit_tests -j2
build/local-validation/tests/unit_tests/unit_tests \
  --gtest_filter='GatewayBridge*.*:BridgeRegistration.*:GatewayWithdrawal.*'
```

The new wrong-proxy/unknown-chain tests carry valid freshly generated quorum
signatures. They assert rejection in the shared verifier and native state path,
unchanged observed epochs and a still-locked bond, followed by successful release
using an acknowledgement for the canonical FAKECHAIN deployment.
