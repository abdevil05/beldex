# beldex-bridge-relayer (Phase I)

A **permissionless, keyless courier** for the Beldex Sovereign Bridge. It carries an
already-committee-signed wBDX payload to its destination EVM chain and pays gas to broadcast
it. It holds **no bridge key** and forges nothing — the authorizing signature is complete
before the relayer touches it, and the wBDX contract verifies it on-chain. Relayers are
therefore **never a trust component** (whitepaper §3.1): if every relayer disappears, any
user builds the same transaction from the signed payload and submits it themselves.

## What's here

```
src/abi.rs      byte-exact calldata for mint / rotateSigner / activateRotation
src/payload.rs  RelayPayload (self-contained signed payload) + JSON codec + PreparedCall
src/submit.rs   TxSubmitter broadcast seam + a mock
src/http_submit.rs  EIP-1559 HTTP submitter (feature `submit-http`)
src/main.rs     `prepare`, `relay`, and `mint-digest` CLI commands
```

## Build & test

Standalone crate (like `bridge/signer/`):

```bash
cd bridge/relayer
cargo test
```

## Submit-your-own (the liveness guarantee)

`prepare` reads a signed payload and prints the exact call to broadcast — no bridge key, no
running service:

```bash
beldex-bridge-relayer prepare payload.json
# chain_id: 1
# to:       0x<wbdx contract>
# data:     0x7f00000a...        # mint(to, amount, beldexTxid, outputIndex, sig)

# broadcast with any wallet / tooling, paying your own gas:
cast send 0x<contract> 0x<data> --rpc-url <chain rpc> --private-key <your gas key>
```

Payload JSON (produced by a signer, or hand-assembled):

```json
{ "kind": "mint", "contract": "<40hex>", "chain_id": 1, "to": "<40hex>",
  "key_epoch": 1, "amount": "1000", "beldex_txid": "<64hex>",
  "output_index": 0, "sig": "<130hex r‖s‖v>" }

{ "kind": "rotate", "contract": "<40hex>", "chain_id": 1,
  "new_signer": "<40hex>", "new_key_epoch": 7, "nonce": 3,
  "deadline": 1900000000, "sig": "<130hex>" }

{ "kind": "activate", "contract": "<40hex>", "chain_id": 1,
  "sig": "<130hex>" }
```

## Reference relayer

Build with `--features submit-http`, set `RELAYER_GAS_KEY` and `RELAYER_CHAINS`, then run
`beldex-bridge-relayer relay payload.json`. It estimates gas first, constructs and signs a
type-2 EIP-1559 transaction, broadcasts with `eth_sendRawTransaction`, and returns the hash.
The gas key is an ordinary funded EVM account, never a bridge signing share. The
`prepare`/`to_prepared` path remains the permissionless fallback.
