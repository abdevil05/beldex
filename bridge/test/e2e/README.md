# Retired Phase L bridge walkthrough

The former instructions used obsolete payloads, backing assumptions and deployment
arguments. They are no longer an executable acceptance runbook.
`deploy_anvil.sh` now exits with status 2 without broadcasting; this is deliberate.

Use these maintained regression entry points from the Beldex repository root:

```bash
# No deployments, key rotations, payments or chain resets:
bash utils/local-devnet/security-acceptance.sh
# Optional real CGGMP21 protocol tests over the test mesh:
bash utils/local-devnet/security-acceptance.sh --real-mpc
```

For interactive disposable-chain functionality, consult:

- `utils/local-devnet/bootstrap-bridge.sh` and `utils/local-devnet/serve-live.sh`.
- The sibling `bridge-contract/devnet/01-deploy.sh` and its numbered mint/rotation
  helpers. Review signer, guardian, native-network, minimum redemption, timelock
  and two-window backing configuration before executing a deployment.
- [Signer runtime and relay recovery requirements](../../signer/README.md).
- [Gas relayer persistent-state requirements](../../relayer/README.md).

These are code entry points, not a claim that all scenarios have passed acceptance.
Do not restore synthetic mint examples as evidence of real backing. The current signer
has autonomous mint/release wiring, but complete native-owner handoff and live
rotation-acknowledgement/bond settlement remain open security work.

One host, six processes and reversible Anvil cannot prove independent threshold custody
or irreversible cross-chain finality. Insecure-canary overrides are for valueless local
testing only; they are not remediations.
