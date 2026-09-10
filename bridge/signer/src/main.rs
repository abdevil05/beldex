//! `beldex-bridge-signer` entry point (Phase C scaffold).
//!
//! At this stage the binary only loads and validates configuration and reports
//! the modules that are wired. The service loop (connect to `beldexd` OMQ, fetch
//! the committee, run DKG/refresh, serve signing sessions) is added as C.2–C.5
//! integrate the audited TSS crates — see `DUE_DILIGENCE.md`.

use std::collections::HashMap;
use std::process::ExitCode;

use beldex_bridge_signer::config::{self, Config};
use beldex_bridge_signer::SIGNER_VERSION;

const PREFIX: &str = "BRIDGE_SIGNER_";

/// The current executable persists DKG material as local files.  Never silently
/// treat the configuration labels for external custody as implemented, and make
/// even the local-file development path an explicit operator decision.
#[cfg(feature = "live-dkg")]
fn require_share_custody(cfg: &Config) -> Result<(), String> {
    use beldex_bridge_signer::config::ShareStoreBackend;

    match cfg.share_store {
        ShareStoreBackend::Memory => {
            let allowed = std::env::var("BRIDGE_SIGNER_ALLOW_FILE_SHARES")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if allowed {
                Ok(())
            } else {
                Err("local share files are disabled; set BRIDGE_SIGNER_ALLOW_FILE_SHARES=1 only for an isolated development environment".into())
            }
        }
        ShareStoreBackend::Vault => Err(
            "share_store=vault selected, but no Vault custody adapter is linked; refusing local-file fallback".into(),
        ),
        ShareStoreBackend::Enclave => Err(
            "share_store=enclave selected, but no enclave custody adapter is linked; refusing local-file fallback".into(),
        ),
    }
}

/// Build the config map from (1) an optional `.env` file, then (2) real process
/// environment variables which override it. In both, keys are `BRIDGE_SIGNER_<KEY>`
/// and are lower-cased without the prefix (e.g. `BRIDGE_SIGNER_GATEWAY_ID` ->
/// `gateway_id`). The `.env` path defaults to `./.env` and can be overridden with
/// `BRIDGE_SIGNER_DOTENV` (or disabled by pointing it at a missing file).
fn config_map() -> HashMap<String, String> {
    let mut map = HashMap::new();

    // (1) .env file (lower priority).
    let dotenv_path =
        std::env::var(format!("{PREFIX}DOTENV")).unwrap_or_else(|_| ".env".to_string());
    match std::fs::read_to_string(&dotenv_path) {
        Ok(contents) => {
            for (k, v) in config::parse_dotenv(&contents) {
                if let Some(rest) = k.strip_prefix(PREFIX) {
                    map.insert(rest.to_ascii_lowercase(), v);
                }
            }
            eprintln!("(loaded config from {dotenv_path})");
        }
        Err(_) => eprintln!("(no {dotenv_path} file; using environment only)"),
    }

    // (2) real env vars (higher priority) override the .env.
    for (k, v) in std::env::vars() {
        if let Some(rest) = k.strip_prefix(PREFIX) {
            map.insert(rest.to_ascii_lowercase(), v);
        }
    }
    map
}

fn print_status(cfg: &Config) {
    let [a, b, c] = SIGNER_VERSION;
    println!("beldex-bridge-signer v{a}.{b}.{c}");
    println!("  beldexd RPC : {}", cfg.beldexd_rpc_url);
    println!("  OxenMQ      : {}", cfg.oxenmq_endpoint);
    println!("  gateway     : {}", hex(&cfg.gateway_id));
    println!("  self MN     : {}", hex(&cfg.self_mn_pubkey));
    println!("  live committee/threshold source: beldexd bridge.committee (consensus)");
    println!("  live epoch source: native consensus; no static override");
    if cfg.bridge_epoch_blocks.is_some() || cfg.committee_threshold.is_some() {
        println!(
            "  deprecated static epoch/threshold inputs ignored: {:?}/{:?}",
            cfg.bridge_epoch_blocks, cfg.committee_threshold
        );
    }
    println!("  share store : {:?}", cfg.share_store);
    if cfg!(feature = "live-dkg") {
        println!("subcommands:");
        println!("  dkg  — run the dual DKG over the mesh (persists Pgw share if SHARE_DIR set)");
        println!("  sign — run the Pgw FROST signing over the mesh (loads the persisted share)");
    } else {
        println!("(build with --features live-dkg for the `dkg` / `sign` subcommands)");
    }
    if cfg!(feature = "evm-watcher-http") {
        println!(
            "  watch-evm — poll EVM chains for finalized wBDX burns (BRIDGE_SIGNER_EVM_CHAINS)"
        );
    } else {
        println!("(build with --features evm-watcher-http for the `watch-evm` subcommand)");
    }
    if cfg!(feature = "autonomy") {
        println!("  serve — autonomous watcher pipeline: detect + dedup deposit/burn duties (dry-run backend)");
        println!("          with --features serve-live + BRIDGE_SIGNER_SERVE_LIVE=1: coordinated live signing");
    } else {
        println!("(build with --features autonomy for the `serve` subcommand)");
    }
    if cfg!(feature = "omq-client") {
        println!("  relay-watch — subscribe to the daemon's mint bus and broadcast each payload");
        println!("                (no bridge key needed; this is the relayer-operator command)");
    }
    if cfg!(feature = "omq-mesh") {
        println!("  check-curve — verify that the linked libzmq supports encrypted CURVE sockets");
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn mesh_listen_endpoint(port: u16) -> String {
    let host =
        std::env::var("BRIDGE_SIGNER_MESH_BIND_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    format!("tcp://{host}:{port}")
}

/// Fail-fast runtime capability probe for the production mesh encryption path.
/// Building against libzmq is not sufficient: distributions can compile it without
/// libsodium, in which case every CURVE socket operation fails only after a ceremony
/// has already started.
#[cfg(feature = "omq-mesh")]
fn run_check_curve() -> Result<(), String> {
    zmq::CurveKeyPair::new()
        .map(|_| println!("CURVE support: available"))
        .map_err(|e| {
            format!(
                "linked libzmq does not provide CURVE support ({e}); rebuild/install libzmq with libsodium"
            )
        })
}

#[cfg(not(feature = "omq-mesh"))]
fn run_check_curve() -> Result<(), String> {
    Err("this signer was built without the `omq-mesh` feature".into())
}

/// `dkg` subcommand: fetch the live committee and run the `Pgw` FROST DKG across
/// the authenticated mesh (C.2). Only built with `--features live-dkg`.
#[cfg(feature = "live-dkg")]
fn run_dkg(cfg: &Config) -> Result<(), String> {
    use beldex_bridge_signer::dkg_driver::live::{
        run_live_capture, MeshIdentity, PeerTransportAddr,
    };
    use beldex_bridge_signer::ffi;
    use beldex_bridge_signer::omq_client::OmqCommitteeClient;
    use std::time::Duration;

    require_share_custody(cfg)?;

    let env = |k: &str| std::env::var(k).map_err(|_| format!("missing env {k}"));
    let h32 = |s: &str, k: &str| config::parse_hex32(s).ok_or(format!("{k} must be 32-byte hex"));
    let h64 = |s: &str, k: &str| config::parse_hex64(s).ok_or(format!("{k} must be 64-byte hex"));

    // 1) Read the live committee (now carrying signer_keys, S4). Prefer the index
    //    the daemon reports for itself (OMQ `self_index`) so no per-node pubkey
    //    config is needed; fall back to matching the configured MN pubkey.
    let client = OmqCommitteeClient::new(cfg.oxenmq_endpoint.clone());
    let committee = client.fetch_committee(None).map_err(|e| e.to_string())?;
    let self_index = committee
        .daemon_self_index
        .or_else(|| committee.self_index(&cfg.self_mn_pubkey))
        .ok_or("this node is not on the current bridge committee")? as u16;
    if !committee.has_signer_keys() {
        return Err(
            "bridge.committee returned no signer_keys — update beldexd (mesh auth needs them)"
                .into(),
        );
    }
    println!(
        "committee epoch {} height {} size {} threshold {}; self_index {}",
        committee.epoch,
        committee.height,
        committee.size(),
        committee.threshold,
        self_index
    );

    // A single-host deployment (local devnet) sets a port base: every node shares
    // the committee's IP but listens on `port_base + index`. **Dual DKG** (both
    // legs) requires this mode so each leg gets a distinct port range.
    let port_base: Option<u16> = std::env::var("BRIDGE_SIGNER_MESH_PORT_BASE")
        .ok()
        .and_then(|s| s.parse().ok());

    // 2) This node's mesh keys (x25519 channel + ed25519 message-auth), derived
    //    once. Turnkey path: read the masternode ed25519 key file
    //    (`<data-dir>/key_ed25519`, 64 bytes) and derive both — exactly as beldexd
    //    does. Fallback: explicit MESH_* env vars. The per-leg listen port is
    //    applied when building each leg's identity.
    let (curve_secret, curve_public, ed25519_secret) =
        if let Ok(key_path) = std::env::var("BRIDGE_SIGNER_MN_KEY_FILE") {
            let sk_bytes =
                std::fs::read(&key_path).map_err(|e| format!("read MN key {key_path}: {e}"))?;
            if sk_bytes.len() != 64 {
                return Err(format!(
                    "MN key {key_path} is {} bytes, expected 64 (key_ed25519)",
                    sk_bytes.len()
                ));
            }
            let mut ed25519_secret = [0u8; 64];
            ed25519_secret.copy_from_slice(&sk_bytes);
            let mut ed_pub = [0u8; 32];
            ed_pub.copy_from_slice(&ed25519_secret[32..64]); // libsodium sk = seed‖pub
            let cs = ffi::ed25519_sk_to_x25519(&ed25519_secret)?;
            let cp = ffi::ed25519_pk_to_x25519(&ed_pub)?;
            println!("mesh identity: derived from MN key {key_path}");
            (cs, cp, ed25519_secret)
        } else {
            (
                h32(&env("BRIDGE_SIGNER_MESH_CURVE_SK")?, "MESH_CURVE_SK")?,
                h32(&env("BRIDGE_SIGNER_MESH_CURVE_PK")?, "MESH_CURVE_PK")?,
                h64(&env("BRIDGE_SIGNER_MESH_ED25519_SK")?, "MESH_ED25519_SK")?,
            )
        };

    // Safety self-check: our derived x25519 must match what the committee advertises
    // (else peers dial the wrong key and every CURVE handshake fails).
    if let Some(expected) = committee.member_x25519.get(self_index as usize) {
        if !expected.iter().all(|&b| b == 0) && curve_public != *expected {
            return Err("this node's derived x25519 does not match its bridge.committee entry (wrong MN key file / curve key?)".into());
        }
    }

    let to_addr = |(index, endpoint, curve_pubkey): (u16, String, [u8; 32])| PeerTransportAddr {
        index,
        endpoint,
        curve_pubkey,
    };
    let make_identity = move |listen: String| MeshIdentity {
        listen_endpoint: listen,
        curve_secret,
        curve_public,
        ed25519_secret,
    };

    let key_generation: u32 = std::env::var("BRIDGE_SIGNER_DKG_KEYGEN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let ceremony_id = beldex_bridge_signer::dkg_tag::validate_live_ceremony_id()?;
    println!("DKG ceremony id: {}", hex(&ceremony_id));
    let timeout = Duration::from_secs(
        std::env::var("BRIDGE_SIGNER_DKG_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(120),
    );
    // Channel encryption. Production: CURVE (needs libzmq built with CURVE). Set
    // BRIDGE_SIGNER_MESH_USE_CURVE=false for a libzmq without CURVE — plain sockets,
    // but per-message ed25519 auth (S4) stays on.
    let use_curve = std::env::var("BRIDGE_SIGNER_MESH_USE_CURVE")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);
    if !use_curve {
        println!("WARNING: mesh CURVE disabled (plain channel); message auth (S4) still enforced");
    }

    // 3) Which key(s) to generate: pgw | pevm | both (default `both` — the dual DKG).
    let leg_sel = std::env::var("BRIDGE_SIGNER_DKG_LEG").unwrap_or_else(|_| "both".into());
    let run_pgw = leg_sel == "both" || leg_sel == "pgw";
    let run_pevm = leg_sel == "both" || leg_sel == "pevm";
    if !run_pgw && !run_pevm {
        return Err(format!(
            "BRIDGE_SIGNER_DKG_LEG must be pgw|pevm|both (got '{leg_sel}')"
        ));
    }
    if run_pevm && port_base.is_none() {
        return Err("the Pevm leg / dual DKG needs BRIDGE_SIGNER_MESH_PORT_BASE (distinct port ranges per leg)".into());
    }

    // Pevm ports live PEVM_PORT_OFFSET above the Pgw ports, so the two legs never
    // collide when run back-to-back on one host. Kept small (100, not 1000) so the
    // Pevm range stays near the Pgw base and away from ports the host may already
    // use — e.g. macOS's AirPlay Receiver on :7000, which a base of 6000 + 1000
    // would hit for self_index 0. Overridable via BRIDGE_SIGNER_MESH_PEVM_OFFSET.
    let pevm_offset: u16 = std::env::var("BRIDGE_SIGNER_MESH_PEVM_OFFSET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let check_size = |peers: &[PeerTransportAddr]| -> Result<(), String> {
        if peers.len() + 1 != committee.size() {
            return Err(format!(
                "peer book has {} peers; committee size is {} (need {} peers + self)",
                peers.len(),
                committee.size(),
                committee.size() - 1
            ));
        }
        Ok(())
    };

    // --- Pgw (ed25519 / FROST) ------------------------------------------------
    if run_pgw {
        let (identity, peers) = match port_base {
            Some(base) => {
                println!("Pgw peer book: bridge.committee, single-host ports {base}+index");
                let peers: Vec<PeerTransportAddr> = committee
                    .peer_transport_indexed(self_index as usize, base)
                    .into_iter()
                    .map(to_addr)
                    .collect();
                (
                    make_identity(mesh_listen_endpoint(base + self_index)),
                    peers,
                )
            }
            None => {
                // Single-leg legacy resolution: explicit listen + (peers file or the
                // committee's shared mesh port).
                let listen = std::env::var("BRIDGE_SIGNER_MESH_LISTEN").map_err(|_| {
                    "set BRIDGE_SIGNER_MESH_PORT_BASE (or MESH_LISTEN + a peer source)".to_string()
                })?;
                let peers: Vec<PeerTransportAddr> = if let Ok(peers_path) =
                    std::env::var("BRIDGE_SIGNER_PEERS_FILE")
                {
                    println!("Pgw peer book: peers file {peers_path}");
                    let text = std::fs::read_to_string(&peers_path)
                        .map_err(|e| format!("read peers file {peers_path}: {e}"))?;
                    let mut peers = Vec::new();
                    for (lineno, raw) in text.lines().enumerate() {
                        let line = raw.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() != 3 {
                            return Err(format!(
                                "peers file line {}: expected `index endpoint curve_hex`",
                                lineno + 1
                            ));
                        }
                        let index: u16 = parts[0]
                            .parse()
                            .map_err(|_| format!("peers line {}: bad index", lineno + 1))?;
                        if index == self_index {
                            continue;
                        }
                        peers.push(PeerTransportAddr {
                            index,
                            endpoint: parts[1].to_string(),
                            curve_pubkey: h32(parts[2], "peer curve key")?,
                        });
                    }
                    peers
                } else if committee.has_network_info() {
                    let mesh_port: u16 = std::env::var("BRIDGE_SIGNER_MESH_PORT")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(5580);
                    println!("Pgw peer book: bridge.committee shared port {mesh_port}");
                    committee
                        .peer_transport(self_index as usize, mesh_port)
                        .into_iter()
                        .map(to_addr)
                        .collect()
                } else {
                    return Err("no peer source: set BRIDGE_SIGNER_MESH_PORT_BASE or BRIDGE_SIGNER_PEERS_FILE".into());
                };
                (make_identity(listen), peers)
            }
        };
        check_size(&peers)?;

        let mut rng = rand::rngs::OsRng;
        println!("running Pgw FROST DKG over the mesh (key generation {key_generation})…");
        let (group_vk, kp_blob, pk_blob) = run_live_capture(
            &committee,
            self_index,
            key_generation,
            &identity,
            &peers,
            use_curve,
            &mut rng,
            timeout,
        )
        .map_err(|e| format!("Pgw dkg failed: {e:?}"))?;
        println!(
            "Pgw DKG complete — group ed25519 key (gateway owner_key): {}",
            hex(&group_vk)
        );
        // Persist the share material so a later `sign` invocation can load it. This
        // is a dev file store; production custody (Vault/enclave) is D.1.
        if let Ok(dir) = std::env::var("BRIDGE_SIGNER_SHARE_DIR") {
            persist_pgw_material(&dir, self_index, &kp_blob, &pk_blob, &group_vk)?;
            println!("Pgw share material written to {dir}/pgw-{self_index}.{{keypackage,pubkeypackage,groupvk}}");
        }
    }

    // --- Pevm (secp256k1 / CGGMP21) -------------------------------------------
    if run_pevm {
        let base = port_base.expect("checked above") + pevm_offset;
        #[cfg(feature = "live-pevm-dkg")]
        {
            use beldex_bridge_signer::cggmp21_aux_driver::{
                complete_key_share_blob, run_cggmp21_aux_over_transport,
            };
            use beldex_bridge_signer::cggmp21_driver::run_cggmp21_keygen_over_transport;
            use beldex_bridge_signer::dkg_driver::live::assemble_mesh;
            println!("Pevm peer book: bridge.committee, single-host ports {base}+index");
            let peers: Vec<PeerTransportAddr> = committee
                .peer_transport_indexed(self_index as usize, base)
                .into_iter()
                .map(to_addr)
                .collect();
            check_size(&peers)?;
            let identity = make_identity(mesh_listen_endpoint(base + self_index));

            // One mesh for both Pevm phases (keygen then aux) — avoids a port
            // rebind race between them and reuses the established links.
            let mut transport = assemble_mesh(&committee, self_index, &identity, &peers, use_curve)
                .map_err(|e| format!("Pevm mesh assembly failed: {e:?}"))?;

            println!(
                "running Pevm cggmp21 keygen over the mesh (key generation {key_generation})…"
            );
            let (x33, incomplete_blob) = run_cggmp21_keygen_over_transport(
                &committee,
                self_index,
                key_generation,
                &mut transport,
                timeout,
            )
            .map_err(|e| format!("Pevm keygen failed: {e:?}"))?;

            // Derive the EVM signer address the wBDX contract checks (ecrecover):
            // decompress the group key, keccak256 the uncompressed point, take the
            // last 20 bytes.
            use k256::ecdsa::VerifyingKey;
            use sha3::{Digest, Keccak256};
            let addr = VerifyingKey::from_sec1_bytes(&x33)
                .map(|vk| {
                    let enc = vk.to_encoded_point(false);
                    let h = Keccak256::digest(&enc.as_bytes()[1..]);
                    let mut a = [0u8; 20];
                    a.copy_from_slice(&h[12..]);
                    a
                })
                .map_err(|e| format!("Pevm group key is not a valid secp256k1 point: {e}"))?;
            println!(
                "Pevm keygen complete — wBDX signer address 0x{} (group key {})",
                hex(&addr),
                hex(&x33)
            );

            // Aux-info over the same mesh, then combine into the complete share the
            // signing driver needs. This is the slow safe-prime phase.
            println!("running Pevm aux-info generation over the mesh…");
            let aux_blob = run_cggmp21_aux_over_transport(
                &committee,
                self_index,
                key_generation,
                &mut transport,
                timeout,
            )
            .map_err(|e| format!("Pevm aux-info failed: {e:?}"))?;
            let complete_blob = complete_key_share_blob(&incomplete_blob, &aux_blob)
                .map_err(|e| format!("Pevm share completion failed: {e:?}"))?;
            println!("Pevm complete share ready (keygen + aux-info)");

            if let Ok(dir) = std::env::var("BRIDGE_SIGNER_SHARE_DIR") {
                persist_pevm_material(&dir, self_index, &complete_blob, &x33)?;
                println!(
                    "Pevm share material written to {dir}/pevm-{self_index}.{{keyshare,groupkey}}"
                );
            }
        }
        #[cfg(not(feature = "live-pevm-dkg"))]
        {
            let _ = base;
            return Err("the Pevm leg needs a build with --features live-pevm-dkg".into());
        }
    }

    println!("(shares in the scaffold in-memory store; production custody = Vault/enclave)");
    Ok(())
}

#[cfg(not(feature = "live-dkg"))]
fn run_dkg(_cfg: &Config) -> Result<(), String> {
    Err("the `dkg` subcommand requires a build with `--features live-dkg`".into())
}

/// Write this node's `Pgw` DKG material to `<dir>/pgw-<index>.{keypackage,
/// pubkeypackage,groupvk}` for a later `sign` invocation. Dev file store only.
#[cfg(feature = "live-dkg")]
fn persist_pgw_material(
    dir: &str,
    self_index: u16,
    kp: &[u8],
    pk: &[u8],
    vk: &[u8; 32],
) -> Result<(), String> {
    secure_share_dir(dir)?;
    let write = |suffix: &str, bytes: &[u8]| {
        secure_share_write(&format!("{dir}/pgw-{self_index}.{suffix}"), bytes)
            .map_err(|e| format!("write {suffix}: {e}"))
    };
    write("keypackage", kp)?;
    write("pubkeypackage", pk)?;
    write("groupvk", vk)?;
    Ok(())
}

/// Write this node's complete `Pevm` share to `<dir>/pevm-<index>.{keyshare,
/// groupkey}` for a later `sign` invocation. Dev file store only.
#[cfg(feature = "live-pevm-dkg")]
fn persist_pevm_material(
    dir: &str,
    self_index: u16,
    keyshare: &[u8],
    x33: &[u8; 33],
) -> Result<(), String> {
    secure_share_dir(dir)?;
    secure_share_write(&format!("{dir}/pevm-{self_index}.keyshare"), keyshare)
        .map_err(|e| format!("write keyshare: {e}"))?;
    secure_share_write(&format!("{dir}/pevm-{self_index}.groupkey"), x33)
        .map_err(|e| format!("write groupkey: {e}"))?;
    Ok(())
}

#[cfg(feature = "live-dkg")]
fn secure_share_dir(dir: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).map_err(|e| format!("create share dir {dir}: {e}"))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod share dir {dir}: {e}"))
}

#[cfg(feature = "live-dkg")]
fn secure_share_write(path: &str, bytes: &[u8]) -> Result<(), String> {
    beldex_bridge_signer::share_store::atomic_private_write(std::path::Path::new(path), bytes)
        .map_err(|e| format!("atomic share write {path}: {e}"))
}

/// `sign` subcommand: load this node's persisted share material and run the signing
/// driver for the selected leg across the authenticated mesh. `BRIDGE_SIGNER_SIGN_LEG`
/// = `pgw` (FROST → libsodium-verified ed25519 release; default) or `pevm` (cggmp21
/// → ecrecover'd wBDX mint). Only built with `--features live-dkg`; the `pevm` leg
/// additionally needs `live-pevm-dkg`. Run `dkg` first with `BRIDGE_SIGNER_SHARE_DIR`.
#[cfg(feature = "live-dkg")]
fn run_sign(cfg: &Config) -> Result<(), String> {
    use beldex_bridge_signer::dkg_driver::live::{MeshIdentity, PeerTransportAddr};
    use beldex_bridge_signer::ffi;
    use beldex_bridge_signer::omq_client::OmqCommitteeClient;
    use std::time::Duration;

    require_share_custody(cfg)?;

    // 1) Committee + self_index.
    let client = OmqCommitteeClient::new(cfg.oxenmq_endpoint.clone());
    let committee = client.fetch_committee(None).map_err(|e| e.to_string())?;
    let self_index = committee
        .daemon_self_index
        .or_else(|| committee.self_index(&cfg.self_mn_pubkey))
        .ok_or("this node is not on the current bridge committee")? as u16;
    if !committee.has_signer_keys() {
        return Err("bridge.committee returned no signer_keys — update beldexd".into());
    }

    // 2) Leg + signer set (default: the first `threshold` committee members).
    let leg = std::env::var("BRIDGE_SIGNER_SIGN_LEG").unwrap_or_else(|_| "pgw".into());
    let signers: Vec<u16> = match std::env::var("BRIDGE_SIGNER_SIGN_SIGNERS") {
        Ok(s) => s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
        Err(_) => (0..committee.threshold as u16).collect(),
    };
    println!(
        "committee epoch {} size {} threshold {}; self_index {}; leg {}; signer set {:?}",
        committee.epoch,
        committee.size(),
        committee.threshold,
        self_index,
        leg,
        signers
    );
    if !signers.contains(&self_index) {
        println!("this node ({self_index}) is not in the signer set — nothing to do");
        return Ok(());
    }

    // 3) Shared config + mesh identity material (from the MN key).
    let dir = std::env::var("BRIDGE_SIGNER_SHARE_DIR")
        .map_err(|_| "set BRIDGE_SIGNER_SHARE_DIR (where `dkg` wrote the shares)".to_string())?;
    let port_base: u16 = std::env::var("BRIDGE_SIGNER_MESH_PORT_BASE")
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or("set BRIDGE_SIGNER_MESH_PORT_BASE (single-host devnet)")?;
    let pevm_offset: u16 = std::env::var("BRIDGE_SIGNER_MESH_PEVM_OFFSET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let key_path = std::env::var("BRIDGE_SIGNER_MN_KEY_FILE")
        .map_err(|_| "set BRIDGE_SIGNER_MN_KEY_FILE".to_string())?;
    let sk_bytes = std::fs::read(&key_path).map_err(|e| format!("read MN key {key_path}: {e}"))?;
    if sk_bytes.len() != 64 {
        return Err(format!(
            "MN key {key_path} is {} bytes, expected 64",
            sk_bytes.len()
        ));
    }
    let mut ed25519_secret = [0u8; 64];
    ed25519_secret.copy_from_slice(&sk_bytes);
    let mut ed_pub = [0u8; 32];
    ed_pub.copy_from_slice(&ed25519_secret[32..64]);
    let curve_secret = ffi::ed25519_sk_to_x25519(&ed25519_secret)?;
    let curve_public = ffi::ed25519_pk_to_x25519(&ed_pub)?;
    if let Some(expected) = committee.member_x25519.get(self_index as usize) {
        if !expected.iter().all(|&b| b == 0) && curve_public != *expected {
            return Err("derived x25519 does not match this node's bridge.committee entry".into());
        }
    }
    let use_curve = std::env::var("BRIDGE_SIGNER_MESH_USE_CURVE")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);
    if !use_curve {
        println!("WARNING: mesh CURVE disabled (plain channel); message auth (S4) still enforced");
    }
    let timeout = Duration::from_secs(
        std::env::var("BRIDGE_SIGNER_SIGN_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(120),
    );

    // Build this node's identity + peer book for a given single-host port base.
    let build_mesh = |base: u16| -> (MeshIdentity, Vec<PeerTransportAddr>) {
        let identity = MeshIdentity {
            listen_endpoint: mesh_listen_endpoint(base + self_index),
            curve_secret,
            curve_public,
            ed25519_secret,
        };
        let peers = committee
            .peer_transport_indexed(self_index as usize, base)
            .into_iter()
            .map(|(index, endpoint, curve_pubkey)| PeerTransportAddr {
                index,
                endpoint,
                curve_pubkey,
            })
            .collect();
        (identity, peers)
    };

    match leg.as_str() {
        "pgw" => {
            let (identity, peers) = build_mesh(port_base);
            sign_pgw(
                &committee, self_index, &signers, &dir, &identity, &peers, use_curve, timeout,
            )
        }
        "pevm" => {
            let (identity, peers) = build_mesh(port_base + pevm_offset);
            sign_pevm(
                &committee, self_index, &signers, &dir, &identity, &peers, use_curve, timeout,
            )
        }
        other => Err(format!(
            "BRIDGE_SIGNER_SIGN_LEG must be pgw|pevm (got '{other}')"
        )),
    }
}

/// `Pgw` leg of `sign`: FROST threshold-sign a 32-byte digest over the mesh and
/// verify the aggregate under libsodium (the consensus check).
#[cfg(feature = "live-dkg")]
#[allow(clippy::too_many_arguments)]
fn sign_pgw(
    committee: &beldex_bridge_signer::committee::CommitteeView,
    self_index: u16,
    signers: &[u16],
    dir: &str,
    identity: &beldex_bridge_signer::dkg_driver::live::MeshIdentity,
    peers: &[beldex_bridge_signer::dkg_driver::live::PeerTransportAddr],
    use_curve: bool,
    timeout: std::time::Duration,
) -> Result<(), String> {
    use beldex_bridge_signer::ffi;
    use beldex_bridge_signer::frost_sign_driver::live::run_live_sign;
    use frost_ed25519 as frost;

    let message: [u8; 32] = match std::env::var("BRIDGE_SIGNER_SIGN_DIGEST") {
        Ok(h) => config::parse_hex32(&h).ok_or("BRIDGE_SIGNER_SIGN_DIGEST must be 32-byte hex")?,
        Err(_) => {
            println!("WARNING: no BRIDGE_SIGNER_SIGN_DIGEST set — signing a fixed demo digest");
            [0x5au8; 32]
        }
    };
    let read = |suffix: &str| {
        std::fs::read(format!("{dir}/pgw-{self_index}.{suffix}")).map_err(|e| {
            format!("read {suffix}: {e} (run `dkg` first with BRIDGE_SIGNER_SHARE_DIR set)")
        })
    };
    let key_package = frost::keys::KeyPackage::deserialize(&read("keypackage")?)
        .map_err(|e| format!("bad keypackage: {e}"))?;
    let pubkey_package = frost::keys::PublicKeyPackage::deserialize(&read("pubkeypackage")?)
        .map_err(|e| format!("bad pubkeypackage: {e}"))?;
    let group_vk: [u8; 32] = pubkey_package
        .verifying_key()
        .serialize()
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("cannot serialize group verifying key")?;

    let mut rng = rand::rngs::OsRng;
    println!("running Pgw FROST signing over the mesh…");
    let sig = run_live_sign(
        committee,
        self_index,
        signers,
        key_package,
        pubkey_package,
        message,
        0,
        identity,
        peers,
        use_curve,
        &mut rng,
        timeout,
    )
    .map_err(|e| format!("Pgw sign failed: {e:?}"))?;

    let ok = ffi::ed25519_verify_consensus(&sig, &message, &group_vk);
    println!("Pgw signature : {}", hex(&sig));
    println!("  over digest : {}", hex(&message));
    println!("  owner_key   : {}", hex(&group_vk));
    println!(
        "  libsodium   : {}",
        if ok {
            "VERIFIED (consensus would accept)"
        } else {
            "REJECTED"
        }
    );
    if !ok {
        return Err("the aggregated signature failed libsodium verification".into());
    }
    Ok(())
}

/// `Pevm` leg of `sign`: cggmp21 threshold-sign a mint preimage over the mesh and
/// `ecrecover` the aggregate to the wBDX signer address (the on-chain check).
#[cfg(feature = "live-pevm-dkg")]
#[allow(clippy::too_many_arguments)]
fn sign_pevm(
    committee: &beldex_bridge_signer::committee::CommitteeView,
    self_index: u16,
    signers: &[u16],
    dir: &str,
    identity: &beldex_bridge_signer::dkg_driver::live::MeshIdentity,
    peers: &[beldex_bridge_signer::dkg_driver::live::PeerTransportAddr],
    use_curve: bool,
    timeout: std::time::Duration,
) -> Result<(), String> {
    use beldex_bridge_signer::cggmp21_sign_driver::live::run_live_pevm_sign;
    use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
    use sha3::{Digest, Keccak256};

    // The mint preimage the contract keccaks + ecrecovers. Demo default; in
    // production this is the ABI-encoded mint tuple.
    let preimage: Vec<u8> = match std::env::var("BRIDGE_SIGNER_SIGN_PREIMAGE") {
        Ok(h) => hex_to_bytes(&h).ok_or("BRIDGE_SIGNER_SIGN_PREIMAGE must be hex")?,
        Err(_) => {
            println!(
                "WARNING: no BRIDGE_SIGNER_SIGN_PREIMAGE set — signing a fixed demo mint preimage"
            );
            b"BELDEX_BRIDGE_MINT_V2 || chainid || wBDX || keyEpoch || to || amount || beldexTxid || outputIndex".to_vec()
        }
    };
    let key_share = std::fs::read(format!("{dir}/pevm-{self_index}.keyshare"))
        .map_err(|e| format!("read pevm keyshare: {e} (run `dkg` first with SHARE_DIR set)"))?;

    println!("running Pevm cggmp21 signing over the mesh…");
    let attempt: u32 = std::env::var("BRIDGE_SIGNER_SIGN_ATTEMPT")
        .unwrap_or_else(|_| "0".into())
        .parse()
        .map_err(|_| "BRIDGE_SIGNER_SIGN_ATTEMPT must be a uint32")?;
    let (rs, x33) = run_live_pevm_sign(
        committee, self_index, signers, &key_share, &preimage, attempt, identity, peers, use_curve,
        timeout,
    )
    .map_err(|e| format!("Pevm sign failed: {e:?}"))?;

    // Derive the expected wBDX address from the group key, then ecrecover.
    let expected = VerifyingKey::from_sec1_bytes(&x33)
        .map(|vk| {
            let enc = vk.to_encoded_point(false);
            let h = Keccak256::digest(&enc.as_bytes()[1..]);
            let mut a = [0u8; 20];
            a.copy_from_slice(&h[12..]);
            a
        })
        .map_err(|e| format!("Pevm group key invalid: {e}"))?;
    let digest32: [u8; 32] = Keccak256::digest(&preimage).into();
    let k_sig = K256Sig::from_slice(&rs).map_err(|e| format!("bad signature bytes: {e}"))?;
    let k_sig = k_sig.normalize_s().unwrap_or(k_sig);
    let mut recovered = None;
    for rec in [0u8, 1u8] {
        if let Ok(vk) = VerifyingKey::recover_from_prehash(
            &digest32,
            &k_sig,
            RecoveryId::from_byte(rec).unwrap(),
        ) {
            let enc = vk.to_encoded_point(false);
            let h = Keccak256::digest(&enc.as_bytes()[1..]);
            if h[12..] == expected {
                recovered = Some(rec);
                break;
            }
        }
    }
    println!("Pevm signature: {}{}", hex(&rs[..32]), hex(&rs[32..]));
    println!("  over digest : {}", hex(&digest32));
    println!("  wBDX signer : 0x{}", hex(&expected));
    match recovered {
        Some(rec) => println!("  ecrecover   : VERIFIED (v={})", 27 + rec),
        None => {
            println!("  ecrecover   : FAILED");
            return Err("the aggregated signature did not ecrecover to the wBDX signer".into());
        }
    }
    Ok(())
}

#[cfg(all(feature = "live-dkg", not(feature = "live-pevm-dkg")))]
#[allow(clippy::too_many_arguments)]
fn sign_pevm(
    _committee: &beldex_bridge_signer::committee::CommitteeView,
    _self_index: u16,
    _signers: &[u16],
    _dir: &str,
    _identity: &beldex_bridge_signer::dkg_driver::live::MeshIdentity,
    _peers: &[beldex_bridge_signer::dkg_driver::live::PeerTransportAddr],
    _use_curve: bool,
    _timeout: std::time::Duration,
) -> Result<(), String> {
    Err("the Pevm sign leg needs a build with --features live-pevm-dkg".into())
}

/// Parse an even-length hex string to bytes (for `BRIDGE_SIGNER_SIGN_PREIMAGE`).
#[cfg(feature = "live-pevm-dkg")]
fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(not(feature = "live-dkg"))]
fn run_sign(_cfg: &Config) -> Result<(), String> {
    Err("the `sign` subcommand requires a build with `--features live-dkg`".into())
}

/// Check the cross-chain economic invariant and the configured contract state before
/// either a watcher-only or autonomous service is allowed to start.
#[cfg(feature = "evm-watcher-http")]
fn validate_evm_deployments(
    configs: &[beldex_bridge_signer::evm_watcher::EvmChainConfig],
) -> Result<(), String> {
    validate_implementation_pins(configs)?;
    let global_backing: u128 = std::env::var("BRIDGE_SIGNER_GLOBAL_BOND_BACKING")
        .map_err(|_| {
            "set BRIDGE_SIGNER_GLOBAL_BOND_BACKING to the native backing allocated across all EVM deployments"
                .to_string()
        })?
        .parse()
        .map_err(|_| "BRIDGE_SIGNER_GLOBAL_BOND_BACKING must be a decimal u128".to_string())?;
    let boundary_exposure = configs.iter().try_fold(0u128, |total, c| {
        c.per_epoch_cap
            .checked_mul(2)
            .and_then(|v| total.checked_add(v))
            .ok_or_else(|| "aggregate EVM boundary exposure overflows u128".to_string())
    })?;
    if global_backing == 0 || boundary_exposure > global_backing {
        return Err(format!(
            "unsafe aggregate caps: 2 * sum(per_epoch_cap) = {boundary_exposure} exceeds global backing {global_backing}"
        ));
    }
    for chain in configs {
        chain.validate_contract()?;
    }
    Ok(())
}

#[cfg(feature = "evm-watcher-http")]
fn validate_implementation_pins(
    configs: &[beldex_bridge_signer::evm_watcher::EvmChainConfig],
) -> Result<(), String> {
    let raw=std::env::var("BRIDGE_SIGNER_IMPLEMENTATION_MANIFEST")
        .map_err(|_|"set BRIDGE_SIGNER_IMPLEMENTATION_MANIFEST to reviewed proxy/implementation code-hash approvals")?;
    let manifest: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("implementation manifest: {e}"))?;
    for config in configs {
        let rpc = beldex_bridge_signer::evm_watcher::HttpJsonRpc::new(config.rpc_url.clone());
        beldex_bridge_signer::implementation_pin::verify(
            &rpc,
            config.chain_id,
            config.contract,
            &manifest,
        )?;
    }
    Ok(())
}

#[cfg(feature = "evm-watcher-http")]
fn reject_reversible_dev_rpc_for_live_release(
    configs: &[beldex_bridge_signer::evm_watcher::EvmChainConfig],
) -> Result<(), String> {
    let acknowledged = std::env::var("BRIDGE_SIGNER_ALLOW_REVERSIBLE_EVM")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if acknowledged {
        eprintln!(
            "WARNING: reversible EVM RPC explicitly allowed; a snapshot/revert after a native release can double-spend the bridge"
        );
        return Ok(());
    }
    for chain in configs {
        let version = chain.rpc_client_version()?;
        let lower = version.to_ascii_lowercase();
        if ["anvil", "hardhat", "ganache"]
            .iter()
            .any(|name| lower.contains(name))
        {
            return Err(format!(
                "chain {} RPC identifies as `{version}`; live native releases are disabled on reversible dev nodes. Set BRIDGE_SIGNER_ALLOW_REVERSIBLE_EVM=1 only for an explicitly unsafe local canary",
                chain.chain_id
            ));
        }
    }
    Ok(())
}

/// A numeric confirmation count is a heuristic, not an irreversible consensus
/// boundary.  Native releases cannot be rolled back when an EVM branch changes, so
/// live mode requires a finalized RPC tag unless an operator explicitly marks
/// the run as an unsafe development canary.
#[cfg(feature = "evm-watcher-http")]
fn require_consensus_aware_evm_finality(
    configs: &[beldex_bridge_signer::evm_watcher::EvmChainConfig],
) -> Result<(), String> {
    let allow_depth = std::env::var("BRIDGE_SIGNER_ALLOW_DEPTH_FINALITY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let weak: Vec<u64> = configs
        .iter()
        .filter(|c| c.finality != beldex_bridge_signer::evm_watcher::EvmFinality::Finalized)
        .map(|c| c.chain_id)
        .collect();
    if weak.is_empty() {
        return Ok(());
    }
    if allow_depth {
        eprintln!(
            "WARNING: non-finalized settlement explicitly allowed for chains {weak:?}; a reorg can make native releases insolvent"
        );
        return Ok(());
    }
    Err(format!(
        "chains {weak:?} do not use finalized finality; live native releases require `finality: \"finalized\"`. A safe head is not irreversible. Set BRIDGE_SIGNER_ALLOW_DEPTH_FINALITY=1 only for an explicitly unsafe local canary"
    ))
}

#[cfg(all(feature = "autonomy", feature = "evm-watcher-http"))]
fn validate_native_reserve_solvency(
    beldexd_rpc: &str,
    gateway_id: &str,
    configs: &[beldex_bridge_signer::evm_watcher::EvmChainConfig],
) -> Result<(), String> {
    use beldex_bridge_signer::beldex_watcher::{BeldexRpc, HttpBeldexRpc};
    use serde_json::json;

    let reserves = HttpBeldexRpc::new(beldexd_rpc.to_string())
        .call("bridge_get_reserves", json!({"gateway_id": gateway_id}))
        .map_err(|e| format!("bridge_get_reserves: {e:?}"))?;
    let as_u128 = |name: &str| -> Result<u128, String> {
        let value = reserves
            .get(name)
            .ok_or_else(|| format!("bridge_get_reserves missing `{name}`"))?;
        match value {
            serde_json::Value::String(s) => s
                .parse()
                .map_err(|_| format!("bridge_get_reserves `{name}` is not a u128")),
            serde_json::Value::Number(n) => n
                .as_u64()
                .map(u128::from)
                .ok_or_else(|| format!("bridge_get_reserves `{name}` is not an unsigned integer")),
            _ => Err(format!("bridge_get_reserves `{name}` has the wrong type")),
        }
    };
    if reserves.get("registered").and_then(|v| v.as_bool()) != Some(true) {
        return Err("configured gateway is not registered".into());
    }
    if reserves.get("bridge_reserve").and_then(|v| v.as_bool()) != Some(true) {
        return Err("configured gateway is not marked bridge_reserve".into());
    }
    let native_balance = as_u128("gateway_balance")?;
    let wrapped_supply = configs.iter().try_fold(0u128, |sum, chain| {
        sum.checked_add(chain.total_supply()?)
            .ok_or_else(|| "aggregate wBDX supply overflows u128".to_string())
    })?;
    if wrapped_supply > native_balance {
        return Err(format!(
            "insolvent bridge: aggregate wBDX supply {wrapped_supply} exceeds native gateway balance {native_balance}"
        ));
    }
    println!(
        "  reserve parity: native gateway balance {native_balance}, aggregate wBDX supply {wrapped_supply}"
    );
    Ok(())
}

#[cfg(feature = "autonomy")]
#[derive(Default)]
struct DurableWatchState {
    beldex_next: Option<u64>,
    evm_next: std::collections::BTreeMap<u64, u64>,
    evm_anchors: std::collections::BTreeMap<u64, (u64, [u8; 32])>,
}

#[cfg(feature = "autonomy")]
fn load_watch_state(path: &str) -> Result<DurableWatchState, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(e) => return Err(format!("read watcher state {path}: {e}")),
    };
    let mut state = DurableWatchState::default();
    for (line_no, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("watcher state {path}:{} missing `=`", line_no + 1))?;
        if key == "beldex_next" {
            let value: u64 = value
                .parse()
                .map_err(|_| format!("watcher state {path}:{} invalid height", line_no + 1))?;
            state.beldex_next = Some(value);
        } else if let Some(chain) = key.strip_prefix("evm_anchor_") {
            let chain: u64 = chain
                .parse()
                .map_err(|_| format!("watcher state {path}:{} invalid chain id", line_no + 1))?;
            let (height, hash) = value.split_once(',').ok_or_else(|| {
                format!(
                    "watcher state {path}:{} invalid finalized anchor",
                    line_no + 1
                )
            })?;
            let height: u64 = height.parse().map_err(|_| {
                format!("watcher state {path}:{} invalid anchor height", line_no + 1)
            })?;
            let hash = config::parse_hex32(hash).ok_or_else(|| {
                format!("watcher state {path}:{} invalid anchor hash", line_no + 1)
            })?;
            if state.evm_anchors.insert(chain, (height, hash)).is_some() {
                return Err(format!(
                    "watcher state {path}:{} duplicates chain {chain} anchor",
                    line_no + 1
                ));
            }
        } else if let Some(chain) = key.strip_prefix("evm_") {
            let chain: u64 = chain
                .parse()
                .map_err(|_| format!("watcher state {path}:{} invalid chain id", line_no + 1))?;
            let value: u64 = value
                .parse()
                .map_err(|_| format!("watcher state {path}:{} invalid height", line_no + 1))?;
            if state.evm_next.insert(chain, value).is_some() {
                return Err(format!(
                    "watcher state {path}:{} duplicates chain {chain}",
                    line_no + 1
                ));
            }
        } else {
            return Err(format!(
                "watcher state {path}:{} unknown key `{key}`",
                line_no + 1
            ));
        }
    }
    Ok(state)
}

#[cfg(feature = "autonomy")]
fn persist_watch_state(
    path: &str,
    beldex_next: u64,
    evm_next: impl IntoIterator<Item = (u64, u64)>,
    evm_anchors: impl IntoIterator<Item = (u64, (u64, [u8; 32]))>,
) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = std::path::Path::new(path)
        .parent()
        .ok_or_else(|| format!("watcher state path has no parent: {path}"))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("create watcher state directory {}: {e}", parent.display()))?;
    let temp = format!("{path}.tmp-{}", std::process::id());
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|e| format!("open watcher state temp {temp}: {e}"))?;
    writeln!(file, "beldex_next={beldex_next}").map_err(|e| format!("write watcher state: {e}"))?;
    for (chain, height) in evm_next {
        writeln!(file, "evm_{chain}={height}").map_err(|e| format!("write watcher state: {e}"))?;
    }
    for (chain, (height, hash)) in evm_anchors {
        writeln!(file, "evm_anchor_{chain}={height},{}", hex(&hash))
            .map_err(|e| format!("write watcher state: {e}"))?;
    }
    file.sync_all()
        .map_err(|e| format!("fsync watcher state: {e}"))?;
    std::fs::rename(&temp, path).map_err(|e| format!("commit watcher state {path}: {e}"))?;
    std::fs::File::open(parent)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("fsync watcher state directory: {e}"))
}

/// `watch-evm` subcommand: build one EVM watcher per chain from
/// `BRIDGE_SIGNER_EVM_CHAINS` and poll for finalized wBDX burns (E.2). Prints each
/// finalized `ReleaseEvent` and its canonical id (what members agree on). Only built
/// with `--features evm-watcher-http`.
#[cfg(feature = "evm-watcher-http")]
fn run_watch_evm(_cfg: &Config) -> Result<(), String> {
    use beldex_bridge_signer::evm_watcher::{build_registry, parse_evm_chains};
    use std::time::Duration;

    let chains_json = std::env::var("BRIDGE_SIGNER_EVM_CHAINS").map_err(|_| {
        "set BRIDGE_SIGNER_EVM_CHAINS — a JSON array of \
         {chain_id, contract, key_epoch, confirmations, rpc, per_tx_max, per_epoch_cap, start_block}"
            .to_string()
    })?;
    let configs = parse_evm_chains(&chains_json)?;
    if configs.is_empty() {
        return Err("BRIDGE_SIGNER_EVM_CHAINS is empty — no chains to watch".into());
    }
    validate_evm_deployments(&configs)?;
    let live_requested = std::env::var("BRIDGE_SIGNER_SERVE_LIVE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if live_requested {
        reject_reversible_dev_rpc_for_live_release(&configs)?;
        require_consensus_aware_evm_finality(&configs)?;
    }
    // Build the E.3 registry (validates uniqueness) even though the loop below only
    // needs the watchers — it is the config's single source of truth.
    let _registry = build_registry(&configs)?;

    // The L1 genesis binds every release canonical id (S6/S14, no cross-net replay).
    let genesis: [u8; 32] = match std::env::var("BRIDGE_SIGNER_GENESIS_HASH") {
        Ok(h) => config::parse_hex32(&h).ok_or("BRIDGE_SIGNER_GENESIS_HASH must be 32-byte hex")?,
        Err(_) => {
            println!(
                "WARNING: no BRIDGE_SIGNER_GENESIS_HASH — using zeros for release canonical ids"
            );
            [0u8; 32]
        }
    };
    let poll_secs: u64 = std::env::var("BRIDGE_SIGNER_WATCH_POLL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);
    // Bound the loop for a scripted run; unset = run until interrupted.
    let max_iters: Option<u64> = std::env::var("BRIDGE_SIGNER_WATCH_ITERS")
        .ok()
        .and_then(|s| s.parse().ok());

    let mut watchers: Vec<_> = configs
        .iter()
        .map(|c| (c.chain_id, c.build_watcher()))
        .collect();
    println!(
        "watching {} EVM chain(s), polling every {poll_secs}s: {:?}",
        watchers.len(),
        configs.iter().map(|c| c.chain_id).collect::<Vec<_>>()
    );

    let mut iter = 0u64;
    loop {
        for (chain_id, w) in watchers.iter_mut() {
            match w.advance() {
                Ok(update) => {
                    for ev in &update.finalized {
                        let cid = ev.canonical_id(genesis);
                        println!(
                            "chain {chain_id}: RELEASE finalized — amount={} recipient=0x{} evm_txid=0x{} canonical_id=0x{}",
                            ev.amount,
                            hex(&ev.beldex_recipient),
                            hex(&ev.evm_txid),
                            hex(&cid),
                        );
                    }
                    for d in &update.dropped {
                        println!(
                            "chain {chain_id}: burn dropped (reorg) at height {}",
                            d.inclusion_height
                        );
                    }
                }
                Err(e) => eprintln!("chain {chain_id}: advance error: {e:?}"),
            }
        }
        iter += 1;
        if max_iters.is_some_and(|m| iter >= m) {
            break;
        }
        std::thread::sleep(Duration::from_secs(poll_secs));
    }
    Ok(())
}

#[cfg(not(feature = "evm-watcher-http"))]
fn run_watch_evm(_cfg: &Config) -> Result<(), String> {
    Err("the `watch-evm` subcommand requires a build with `--features evm-watcher-http`".into())
}

/// `serve` subcommand: the **autonomous watcher pipeline** (Phase L). Builds the Beldex
/// deposit watcher + one EVM burn watcher per chain, then runs the orchestrator loop
/// ([`service::serve`]) — each tick ingests finalized deposits/burns, deduplicates them into
/// duties, and (with the **dry-run** `LoggingBackend`) reports each detected duty. This
/// exercises the full autonomy pipeline (observe → resolve → dedup → duty) end to end; the
/// live signing+submission backend swaps in for `LoggingBackend`. Needs `--features autonomy`.
#[cfg(feature = "autonomy")]
fn run_serve(cfg: &Config) -> Result<(), String> {
    use beldex_bridge_signer::beldex_watcher::{BeldexWatcher, HttpBeldexRpc};
    use beldex_bridge_signer::evm_watcher::{build_registry, parse_evm_chains};
    use beldex_bridge_signer::orchestrator::{Duty, Orchestrator};
    use beldex_bridge_signer::service::{serve, LoggingBackend, ServeOptions, WatcherEventSource};
    use std::time::Duration;

    // EVM chains (burns → releases).
    let chains_json = std::env::var("BRIDGE_SIGNER_EVM_CHAINS").map_err(|_| {
        "set BRIDGE_SIGNER_EVM_CHAINS (a JSON array of chain configs; see watch-evm)".to_string()
    })?;
    let mut configs = parse_evm_chains(&chains_json)?;
    if configs.is_empty() {
        return Err("BRIDGE_SIGNER_EVM_CHAINS is empty — no chains to watch".into());
    }
    validate_evm_deployments(&configs)?;
    let live_requested = std::env::var("BRIDGE_SIGNER_SERVE_LIVE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if live_requested {
        reject_reversible_dev_rpc_for_live_release(&configs)?;
        require_consensus_aware_evm_finality(&configs)?;
    }
    let watch_state_path = std::env::var("BRIDGE_SIGNER_WATCH_STATE_FILE").ok();
    let watch_state = match watch_state_path.as_deref() {
        Some(path) => load_watch_state(path)?,
        None if live_requested => {
            return Err("set BRIDGE_SIGNER_WATCH_STATE_FILE; live watchers are fail-closed without durable cursors".into())
        }
        None => DurableWatchState::default(),
    };
    for chain in &mut configs {
        if let Some(resume) = watch_state.evm_next.get(&chain.chain_id) {
            chain.start_block = *resume;
        }
    }
    let registry = build_registry(&configs)?;
    let evm: Vec<_> = configs
        .iter()
        .map(|c| {
            let watcher = c.build_watcher();
            match watch_state.evm_anchors.get(&c.chain_id) {
                Some((height, hash)) => watcher.with_finalized_anchor(*height, *hash),
                None => watcher,
            }
        })
        .collect();

    // Beldex gateway deposits (→ mints).
    let beldexd_rpc =
        std::env::var("BRIDGE_SIGNER_BELDEXD_RPC").unwrap_or_else(|_| cfg.beldexd_rpc_url.clone());
    let gateway_id = std::env::var("BRIDGE_SIGNER_GATEWAY_ID").map_err(|_| {
        "set BRIDGE_SIGNER_GATEWAY_ID (the bridge gateway to watch for deposits)".to_string()
    })?;
    validate_native_reserve_solvency(&beldexd_rpc, &gateway_id, &configs)?;
    let mut start_height: u64 = std::env::var("BRIDGE_SIGNER_BELDEX_START_HEIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if let Some(resume) = watch_state.beldex_next {
        start_height = resume;
    }
    let view_secret = config::parse_hex32(
        &std::env::var("BRIDGE_SIGNER_GATEWAY_VIEW_SECRET").map_err(|_| {
            "set BRIDGE_SIGNER_GATEWAY_VIEW_SECRET (32-byte hex; the gateway view secret that decrypts A.5 memos)"
                .to_string()
        })?,
    )
    .ok_or("BRIDGE_SIGNER_GATEWAY_VIEW_SECRET must be 32-byte hex")?;
    // Echo the watcher config: a wrong gateway id / RPC / start height otherwise reads as
    // an eternally quiet, "healthy" pipeline (the watcher successfully finds nothing).
    println!(
        "  beldex watcher: gateway {gateway_id} via {beldexd_rpc}, from height {start_height}"
    );

    // Cloned before the watcher consumes them — the live backend reuses both.
    let beldexd_rpc_for_live = beldexd_rpc.clone();
    let gateway_id_for_live = gateway_id.clone();
    // Finality posture. Strict by default: a deposit is only actionable at or below
    // `get_info.immutable_height`. beldexd omits that field entirely on a chain that has
    // never checkpointed — and it never will below CHECKPOINT_QUORUM_SIZE (20) active
    // masternodes, so every local devnet is in that bucket: deposits confirm and no mint
    // duty is ever created, silently, because a poll error is treated as transient.
    // Setting this to N falls back to `top_height - N` in exactly that case; a daemon that
    // does report a checkpoint ignores it outright.
    // An empty value counts as unset (strict), so a launcher can pass the variable
    // through unconditionally — `FOO=${X:+...}` does not work as an assignment prefix,
    // because a word produced by expansion is parsed as the command name, not a prefix.
    let beldex_confirmations: Option<u64> =
        match std::env::var("BRIDGE_SIGNER_BELDEX_CONFIRMATIONS") {
            Ok(s) if s.trim().is_empty() => None,
            Ok(s) => Some(s.trim().parse::<u64>().map_err(|_| {
                "BRIDGE_SIGNER_BELDEX_CONFIRMATIONS must be a non-negative integer".to_string()
            })?),
            Err(_) => None,
        };
    let mut beldex = BeldexWatcher::new(HttpBeldexRpc::new(beldexd_rpc), gateway_id, start_height);
    if let Some(n) = beldex_confirmations {
        println!("  beldex finality: RELAXED — a chain with no checkpoint falls back to top_height - {n}");
        beldex = beldex.with_fallback_confirmations(n);
    }

    let mut src = WatcherEventSource {
        beldex,
        evm,
        view_secret,
        registry,
    };
    let mut orch = Orchestrator::new();

    let poll_secs: u64 = std::env::var("BRIDGE_SIGNER_WATCH_POLL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);
    let max_ticks: Option<u64> = std::env::var("BRIDGE_SIGNER_WATCH_ITERS")
        .ok()
        .and_then(|s| s.parse().ok());
    let opts = ServeOptions {
        interval: Duration::from_secs(poll_secs),
        max_ticks,
    };

    // Live backend path (build with `--features serve-live`, enable with BRIDGE_SIGNER_SERVE_LIVE=1):
    // signs each duty over the mesh, emits mint payloads, self-submits releases.
    #[cfg(feature = "serve-live")]
    if std::env::var("BRIDGE_SIGNER_SERVE_LIVE")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false)
    {
        return run_serve_live(
            cfg,
            &mut src,
            &mut orch,
            &opts,
            &configs,
            &beldexd_rpc_for_live,
            &gateway_id_for_live,
            poll_secs,
        );
    }
    let _ = (&beldexd_rpc_for_live, &gateway_id_for_live); // consumed only by the live path

    println!(
        "serve: autonomous watcher pipeline — DRY-RUN backend (detects + dedups duties, does NOT sign/submit)"
    );
    println!(
        "  polling every {poll_secs}s across {} EVM chain(s)",
        configs.len()
    );

    let mut backend = LoggingBackend::new(|d: &Duty| match d {
        Duty::Mint(e) => println!(
            "MINT duty: beldex_txid=0x{} chain={} to=0x{} amount={}",
            hex(&e.beldex_txid),
            e.dst_chain.0,
            hex(&e.to),
            e.amount
        ),
        Duty::Release(e) => println!(
            "RELEASE duty: evm_txid=0x{} chain={} amount={} recipient=0x{}",
            hex(&e.evm_txid),
            e.chain.0,
            e.amount,
            hex(&e.beldex_recipient)
        ),
    });

    let reports = serve(&mut orch, &mut src, &mut backend, &opts, || false);
    let (pending, in_flight, done) = orch.counts();
    println!(
        "serve: finished after {} tick(s); duties pending={pending} in_flight={in_flight} done={done}",
        reports.len()
    );
    Ok(())
}

#[cfg(not(feature = "autonomy"))]
fn run_serve(_cfg: &Config) -> Result<(), String> {
    Err("the `serve` subcommand requires a build with `--features autonomy`".into())
}

/// `relay-watch` — subscribe to the daemon's mint bus and hand each payload to a broadcaster.
///
/// This is what a **relayer operator** runs. It needs no bridge key, no share material, no
/// signer-host access — only an OMQ endpoint it can reach — which is the whole point of
/// Phase I: relaying is permissionless and carries no authority. Each payload is piped to
/// `BRIDGE_SIGNER_RELAY_CMD` (default `beldex-bridge-relayer relay -`), whose own environment
/// holds the gas key.
///
/// Received payloads are persisted before submission and retired only after destination
/// reconciliation. A successful broadcast is not settlement.
#[cfg(feature = "serve-live")]
fn run_relay_watch_standalone() -> Result<(), String> {
    use beldex_bridge_signer::evm_watcher::{build_registry, parse_evm_chains, HttpJsonRpc};
    use beldex_bridge_signer::omq_client::OmqMintSubscriber;
    use beldex_bridge_signer::reconcile::EvmMintReconciler;
    use std::time::Duration;

    // Comma-separated list: subscribe to EVERY endpoint given. Signers publish to their own
    // daemons by default, so a relayer that watches several daemons is robust to any one
    // signer being a straggler (its daemon then simply carries no publish that round);
    // duplicates across daemons are deduped below by txid.
    let endpoints = std::env::var("BRIDGE_SIGNER_OXENMQ_ENDPOINT").map_err(|_| {
        "set BRIDGE_SIGNER_OXENMQ_ENDPOINT (one or more comma-separated beldexd OMQ sockets \
         to subscribe to, e.g. ipc://<node>/devnet/beldexd.sock)"
            .to_string()
    })?;
    let cmd = std::env::var("BRIDGE_SIGNER_RELAY_CMD")
        .unwrap_or_else(|_| "beldex-bridge-relayer relay -".to_string());
    let outbox = std::env::var("BRIDGE_SIGNER_RELAY_OUTBOX_DIR")
        .map_err(|_| "set BRIDGE_SIGNER_RELAY_OUTBOX_DIR to a persistent relay-only directory")?;
    if outbox.trim().is_empty() {
        return Err("BRIDGE_SIGNER_RELAY_OUTBOX_DIR must not be empty".into());
    }
    let configs = parse_evm_chains(
        &std::env::var("BRIDGE_SIGNER_EVM_CHAINS")
            .map_err(|_| "set BRIDGE_SIGNER_EVM_CHAINS for settlement reconciliation")?,
    )?;
    if configs.is_empty() {
        return Err("relay-watch requires at least one configured destination chain".into());
    }
    let _registry = build_registry(&configs)?;
    require_consensus_aware_evm_finality(&configs)?;
    std::fs::create_dir_all(&outbox).map_err(|e| format!("create relay outbox: {e}"))?;
    let mut reconciler = EvmMintReconciler {
        chains: configs
            .iter()
            .map(|c| {
                (
                    c.chain_id,
                    (
                        HttpJsonRpc::new(c.rpc_url.clone()),
                        c.contract,
                        c.finality.settlement_tag().to_string(),
                    ),
                )
            })
            .collect(),
    };
    let mut subs: Vec<OmqMintSubscriber> = endpoints
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|e| {
            println!("relay-watch: subscribing to {e}");
            OmqMintSubscriber::new(e.to_string())
        })
        .collect();
    if subs.is_empty() {
        return Err("BRIDGE_SIGNER_OXENMQ_ENDPOINT contained no endpoints".into());
    }
    println!("  each mint payload → `{cmd}`");
    println!("  (this process holds NO bridge key; the gas key lives in the relay command)");
    let per_sub_timeout = Duration::from_millis(5000 / subs.len().max(1) as u64);
    let mut next_retry = std::time::Instant::now();
    loop {
        // Replay the disk queue even when the bus is silent or restarted. Neither a
        // relay exit status nor a returned transaction hash deletes a pending record.
        if std::time::Instant::now() >= next_retry {
            validate_implementation_pins(&configs)?;
            drain_mint_outbox(&outbox, Some(&cmd), None, &mut reconciler)?;
            next_retry = std::time::Instant::now() + Duration::from_secs(30);
        }
        for sub in subs.iter_mut() {
            match sub.poll(per_sub_timeout) {
                Ok(Some(payload)) => {
                    let id = match relay_payload_identity(&payload, &configs) {
                        Ok(id) => id,
                        Err(e) => {
                            eprintln!("relay-watch: rejected payload: {e}");
                            continue;
                        }
                    };
                    // A different signature/key epoch must not be blocked by an older
                    // failed payload with the same deposit identity.
                    persist_outbox_record(&outbox, &id, &payload)?;
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("relay-watch: {e}; will retry that endpoint");
                }
            }
        }
    }
}

#[cfg(not(feature = "serve-live"))]
fn run_relay_watch_standalone() -> Result<(), String> {
    Err("durable `relay-watch` requires `--features serve-live` (no signer key is required)".into())
}

#[cfg(feature = "serve-live")]
fn relay_payload_identity(
    payload: &str,
    configs: &[beldex_bridge_signer::evm_watcher::EvmChainConfig],
) -> Result<String, String> {
    use sha3::{Digest, Keccak256};
    let value: serde_json::Value =
        serde_json::from_str(payload).map_err(|e| format!("invalid JSON: {e}"))?;
    if value.get("kind").and_then(|v| v.as_str()) != Some("mint") {
        return Err("mint bus accepts only mint payloads".into());
    }
    let chain = value
        .get("chain_id")
        .and_then(|v| v.as_u64())
        .ok_or("invalid chain_id")?;
    let contract = value
        .get("contract")
        .and_then(|v| v.as_str())
        .and_then(|v| hex_to_bytes(v.strip_prefix("0x").unwrap_or(v)))
        .ok_or("invalid contract")?;
    if !configs
        .iter()
        .any(|c| c.chain_id == chain && c.contract.as_slice() == contract)
    {
        return Err("payload chain/contract is not a configured destination".into());
    }
    let txid = value
        .get("beldex_txid")
        .and_then(|v| v.as_str())
        .and_then(config::parse_hex32)
        .ok_or("invalid beldex_txid")?;
    let index = value
        .get("output_index")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
        .ok_or("invalid output_index")?;
    let canonical = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    Ok(format!(
        "{chain}-{}-{index}-{}",
        hex(&txid),
        hex(&Keccak256::digest(canonical))
    ))
}

/// Run `cmd` (via the shell, so it can carry arguments/pipes) and write `payload` to its
/// stdin — the mint hand-off from the keyless signer to a gas-paying relayer. Returns the
/// command's stdout on success. Best-effort by design: see the call site.
/// (`serve-live` implies `live-dkg` implies `omq-client`, so this one gate covers both the
/// `serve --live` hand-off and the standalone `relay-watch`.)
#[cfg(feature = "omq-client")]
fn pipe_to_relay(cmd: &str, payload: &str) -> Result<String, String> {
    pipe_to_relay_bounded(cmd, payload, std::time::Duration::from_secs(60))
}

#[cfg(feature = "omq-client")]
fn pipe_to_relay_bounded(
    cmd: &str,
    payload: &str,
    limit: std::time::Duration,
) -> Result<String, String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // GNU timeout supervises the command's process group, including ordinary
    // subprocesses. Missing supervision is an error, never an unbounded fallback.
    let mut child = Command::new("timeout")
        .arg("--signal=TERM")
        .arg("--kill-after=5s")
        .arg(format!("{}s", limit.as_secs_f64()))
        .arg("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn `{cmd}`: {e}"))?;
    child
        .stdin
        .take()
        .ok_or("no stdin on the relay command")?
        .write_all(payload.as_bytes())
        .map_err(|e| format!("write to relay stdin: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait for relay: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "exit {}: {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Atomically persist a completed mint before any best-effort bus/relayer hand-off.
/// A successful return means a crash/restart cannot erase the committee signature.
#[cfg(feature = "serve-live")]
fn persist_mint_outbox(
    dir: &str,
    ev: &beldex_bridge_signer::watch::MintEvent,
    payload: &str,
) -> Result<String, String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    std::fs::create_dir_all(dir).map_err(|e| format!("create mint outbox {dir}: {e}"))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750))
        .map_err(|e| format!("chmod mint outbox {dir}: {e}"))?;
    let txid = hex(&ev.beldex_txid);
    let final_path = format!("{dir}/{txid}-{}.pending.json", ev.output_index);
    let temp_path = format!("{final_path}.tmp-{}", std::process::id());
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o640)
        .open(&temp_path)
        .map_err(|e| format!("open mint outbox temp {temp_path}: {e}"))?;
    file.write_all(payload.as_bytes())
        .map_err(|e| format!("write mint outbox: {e}"))?;
    file.write_all(b"\n")
        .map_err(|e| format!("write mint outbox newline: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("fsync mint outbox: {e}"))?;
    std::fs::rename(&temp_path, &final_path)
        .map_err(|e| format!("commit mint outbox {final_path}: {e}"))?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("fsync mint outbox directory: {e}"))?;
    Ok(final_path)
}

#[cfg(feature = "serve-live")]
fn persist_release_outbox(
    dir: &str,
    ev: &beldex_bridge_signer::watch::ReleaseEvent,
    tx_blob: &str,
    signature: &[u8; 64],
) -> Result<String, String> {
    let payload = serde_json::json!({
        "kind": "release",
        "chain_id": ev.chain.0,
        "evm_txid": hex(&ev.evm_txid),
        "log_index": ev.log_index,
        "tx_blob": tx_blob,
        "signature": hex(signature),
    })
    .to_string();
    persist_outbox_record(
        dir,
        &format!("{}-{}-{}", ev.chain.0, hex(&ev.evm_txid), ev.log_index),
        &payload,
    )
}

/// Store the full observed duty before persisting a scan cursor. Signed outboxes
/// alone cannot recover a crash between observation and threshold signing.
#[cfg(feature = "serve-live")]
fn persist_observed_duty(
    dir: &str,
    duty: &beldex_bridge_signer::orchestrator::Duty,
) -> Result<String, String> {
    use beldex_bridge_signer::orchestrator::Duty;
    let (id, value) = match duty {
        Duty::Mint(e) => (
            format!("mint-{}-{}", hex(&e.beldex_txid), e.output_index),
            serde_json::json!({
                "kind":"mint", "txid":hex(&e.beldex_txid), "index":e.output_index,
                "chain":e.dst_chain.0, "epoch":e.key_epoch, "to":hex(&e.to), "amount":e.amount.to_string()
            }),
        ),
        Duty::Release(e) => (
            format!("release-{}-{}-{}", e.chain.0, hex(&e.evm_txid), e.log_index),
            serde_json::json!({
                "kind":"release", "txid":hex(&e.evm_txid), "index":e.log_index,
                "chain":e.chain.0, "recipient":hex(&e.beldex_recipient), "amount":e.amount.to_string()
            }),
        ),
    };
    persist_outbox_record(dir, &id, &value.to_string())
}

#[cfg(feature = "serve-live")]
fn read_observed_duty(
    path: &std::path::Path,
) -> Result<beldex_bridge_signer::orchestrator::Duty, String> {
    use beldex_bridge_signer::chain_registry::ChainId;
    use beldex_bridge_signer::orchestrator::Duty;
    use beldex_bridge_signer::watch::{MintEvent, ReleaseEvent};
    let bytes = std::fs::read(path).map_err(|e| format!("read observed duty: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("decode observed duty: {e}"))?;
    let text = |k: &str| v[k].as_str().ok_or_else(|| format!("invalid duty {k}"));
    let number = |k: &str| v[k].as_u64().ok_or_else(|| format!("invalid duty {k}"));
    let txid = config::parse_hex32(text("txid")?).ok_or("invalid duty txid")?;
    let index = u32::try_from(number("index")?).map_err(|_| "invalid duty index")?;
    let chain = ChainId(number("chain")?);
    let amount = text("amount")?
        .parse::<u128>()
        .map_err(|_| "invalid duty amount")?;
    match text("kind")? {
        "mint" => Ok(Duty::Mint(MintEvent {
            beldex_txid: txid,
            output_index: index,
            dst_chain: chain,
            key_epoch: number("epoch")?,
            amount,
            to: hex_to_bytes(text("to")?)
                .and_then(|b| b.try_into().ok())
                .ok_or("invalid duty recipient")?,
        })),
        "release" => Ok(Duty::Release(ReleaseEvent {
            evm_txid: txid,
            log_index: index,
            chain,
            amount,
            beldex_recipient: hex_to_bytes(text("recipient")?).ok_or("invalid duty recipient")?,
        })),
        _ => Err("unknown observed duty kind".into()),
    }
}

#[cfg(feature = "serve-live")]
fn persist_outbox_record(dir: &str, id: &str, payload: &str) -> Result<String, String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    std::fs::create_dir_all(dir).map_err(|e| format!("create outbox {dir}: {e}"))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750))
        .map_err(|e| format!("chmod outbox {dir}: {e}"))?;
    let final_path = format!("{dir}/{id}.pending.json");
    if std::path::Path::new(&final_path).exists() {
        return Ok(final_path);
    }
    let temp_path = format!("{final_path}.tmp-{}", std::process::id());
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(&temp_path)
        .map_err(|e| format!("open outbox temp {temp_path}: {e}"))?;
    writeln!(file, "{payload}").map_err(|e| format!("write outbox: {e}"))?;
    file.sync_all().map_err(|e| format!("fsync outbox: {e}"))?;
    std::fs::rename(&temp_path, &final_path)
        .map_err(|e| format!("commit outbox {final_path}: {e}"))?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("fsync outbox directory: {e}"))?;
    Ok(final_path)
}

#[cfg(feature = "serve-live")]
fn pending_outbox_files(dir: &str) -> Result<Vec<std::path::PathBuf>, String> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| format!("read outbox {dir}: {e}"))? {
        let path = entry.map_err(|e| format!("read outbox entry: {e}"))?.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".pending.json"))
        {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

#[cfg(feature = "serve-live")]
fn mark_outbox_finalized(path: &std::path::Path) -> Result<(), String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("outbox path is not utf-8")?;
    let final_name = name
        .strip_suffix(".pending.json")
        .map(|n| format!("{n}.finalized.json"))
        .ok_or("not a pending outbox record")?;
    let final_path = path.with_file_name(final_name);
    std::fs::rename(path, &final_path).map_err(|e| format!("finalize outbox record: {e}"))?;
    let parent = path.parent().ok_or("outbox record has no parent")?;
    std::fs::File::open(parent)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("fsync finalized outbox directory: {e}"))
}

#[cfg(feature = "serve-live")]
fn drain_mint_outbox<R: beldex_bridge_signer::reconcile::DutyReconciler>(
    dir: &str,
    relay_cmd: Option<&str>,
    bus: Option<(&str, u16, [u8; 64], [u8; 32])>,
    reconciler: &mut R,
) -> Result<(), String> {
    use beldex_bridge_signer::chain_registry::ChainId;
    use beldex_bridge_signer::orchestrator::Duty;
    use beldex_bridge_signer::watch::MintEvent;

    for path in pending_outbox_files(dir)? {
        let payload = std::fs::read_to_string(&path)
            .map_err(|e| format!("read mint outbox {}: {e}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&payload)
            .map_err(|e| format!("parse mint outbox {}: {e}", path.display()))?;
        let txid = value
            .get("beldex_txid")
            .and_then(|v| v.as_str())
            .and_then(config::parse_hex32)
            .ok_or_else(|| format!("mint outbox {} has invalid beldex_txid", path.display()))?;
        let duty =
            Duty::Mint(MintEvent {
                beldex_txid: txid,
                output_index: value
                    .get("output_index")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or_else(|| {
                        format!("mint outbox {} has invalid output_index", path.display())
                    })?,
                dst_chain: ChainId(value.get("chain_id").and_then(|v| v.as_u64()).ok_or_else(
                    || format!("mint outbox {} has invalid chain_id", path.display()),
                )?),
                key_epoch: 0,
                to: [0u8; 20],
                amount: 0,
            });
        match reconciler.is_settled(&duty) {
            Some(true) => {
                mark_outbox_finalized(&path)?;
                println!("  mint finalized on destination: {}", path.display());
            }
            Some(false) => {
                if let Some((endpoint, index, signing_key, genesis)) = bus {
                    use beldex_bridge_signer::omq_client::{
                        mint_publish_message, OmqCommitteeClient,
                    };
                    let msg = mint_publish_message(&genesis, payload.trim());
                    match beldex_bridge_signer::ffi::ed25519_sign_detached(&signing_key, &msg)
                        .and_then(|sig| {
                            OmqCommitteeClient::new(endpoint.to_string())
                                .publish_mint_payload(payload.trim(), index, &sig)
                                .map_err(|_| "mint bus publication failed")
                        }) {
                        Ok(status) => println!(
                            "  mint outbox bus publish/retry {}: {status}",
                            path.display()
                        ),
                        Err(e) => eprintln!(
                            "  mint outbox bus publish failed {} ({e}); retained for retry",
                            path.display()
                        ),
                    }
                }
                if let Some(cmd) = relay_cmd {
                    match pipe_to_relay(cmd, payload.trim()) {
                        Ok(out) => println!(
                            "  mint outbox broadcast/rebroadcast {}: {}",
                            path.display(),
                            out.trim()
                        ),
                        Err(e) => eprintln!(
                            "  mint outbox broadcast failed {} ({e}); retained for retry",
                            path.display()
                        ),
                    }
                }
            }
            None => eprintln!(
                "  mint settlement undetermined for {}; retained for retry",
                path.display()
            ),
        }
    }
    Ok(())
}

#[cfg(feature = "serve-live")]
fn drain_release_outbox(
    dir: &str,
    rpc: &mut beldex_bridge_signer::live_backend::HttpGatewayRpc,
    reconciler: &mut beldex_bridge_signer::reconcile::GatewayReleaseReconciler,
) -> Result<(), String> {
    use beldex_bridge_signer::chain_registry::ChainId;
    use beldex_bridge_signer::live_backend::GatewayRpc;
    use beldex_bridge_signer::orchestrator::Duty;
    use beldex_bridge_signer::reconcile::DutyReconciler;
    use beldex_bridge_signer::watch::ReleaseEvent;

    for path in pending_outbox_files(dir)? {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("read release outbox {}: {e}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("parse release outbox {}: {e}", path.display()))?;
        let txid = value
            .get("evm_txid")
            .and_then(|v| v.as_str())
            .and_then(config::parse_hex32)
            .ok_or_else(|| format!("release outbox {} has invalid evm_txid", path.display()))?;
        let duty =
            Duty::Release(ReleaseEvent {
                evm_txid: txid,
                log_index: value
                    .get("log_index")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or_else(|| {
                        format!("release outbox {} has invalid log_index", path.display())
                    })?,
                chain: ChainId(value.get("chain_id").and_then(|v| v.as_u64()).ok_or_else(
                    || format!("release outbox {} has invalid chain_id", path.display()),
                )?),
                amount: 0,
                beldex_recipient: Vec::new(),
            });
        match reconciler.is_settled(&duty) {
            Some(true) => {
                mark_outbox_finalized(&path)?;
                println!("  release finalized on destination: {}", path.display());
            }
            Some(false) => {
                let blob = value
                    .get("tx_blob")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("release outbox {} has no tx_blob", path.display()))?;
                let sig = value
                    .get("signature")
                    .and_then(|v| v.as_str())
                    .and_then(config::parse_hex64)
                    .ok_or_else(|| {
                        format!("release outbox {} has invalid signature", path.display())
                    })?;
                match rpc.submit_transfer(blob, &sig) {
                    Ok(id) => println!(
                        "  release outbox broadcast/rebroadcast {}: {id}",
                        path.display()
                    ),
                    Err(e) => eprintln!(
                        "  release outbox broadcast failed {} ({e}); retained for retry",
                        path.display()
                    ),
                }
            }
            None => eprintln!(
                "  release settlement undetermined for {}; retained for retry",
                path.display()
            ),
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "serve-live"))]
mod main_tests {
    use super::*;
    use beldex_bridge_signer::chain_registry::ChainId;
    use beldex_bridge_signer::watch::MintEvent;

    #[test]
    fn relay_hook_timeout_is_retryable_instead_of_hanging_the_worker() {
        let started = std::time::Instant::now();
        assert!(
            pipe_to_relay_bounded("sleep 10", "{}", std::time::Duration::from_millis(100)).is_err()
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
    }

    #[test]
    fn relay_queue_survives_failure_and_only_settlement_retires_it() {
        struct Answer(Option<bool>);
        impl beldex_bridge_signer::reconcile::DutyReconciler for Answer {
            fn is_settled(&mut self, _: &beldex_bridge_signer::orchestrator::Duty) -> Option<bool> {
                self.0
            }
        }
        let dir =
            std::env::temp_dir().join(format!("bridge-relay-recovery-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let payload = serde_json::json!({"kind":"mint","chain_id":1,"beldex_txid":hex(&[0x11;32]),"output_index":0}).to_string();
        persist_outbox_record(dir.to_str().unwrap(), "deposit", &payload).unwrap();
        drain_mint_outbox(
            dir.to_str().unwrap(),
            Some("exit 23"),
            None,
            &mut Answer(Some(false)),
        )
        .unwrap();
        assert_eq!(
            pending_outbox_files(dir.to_str().unwrap()).unwrap().len(),
            1
        );
        drain_mint_outbox(
            dir.to_str().unwrap(),
            Some("exit 0"),
            None,
            &mut Answer(None),
        )
        .unwrap();
        assert_eq!(
            pending_outbox_files(dir.to_str().unwrap()).unwrap().len(),
            1
        );
        drain_mint_outbox(
            dir.to_str().unwrap(),
            Some("exit 0"),
            None,
            &mut Answer(Some(false)),
        )
        .unwrap();
        assert_eq!(
            pending_outbox_files(dir.to_str().unwrap()).unwrap().len(),
            1,
            "successful relay is not settlement"
        );
        drain_mint_outbox(dir.to_str().unwrap(), None, None, &mut Answer(Some(true))).unwrap();
        assert!(pending_outbox_files(dir.to_str().unwrap())
            .unwrap()
            .is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn relay_identity_parses_json_and_binds_destination_and_payload() {
        let configs = beldex_bridge_signer::evm_watcher::parse_evm_chains(
            &serde_json::json!([
                {"chain_id":1,"contract":hex(&[0x22;20]),"rpc":"http://unused","key_epoch":1,
             "confirmations":1,"per_epoch_cap":"100","per_tx_max":"10","finality":"finalized"}
            ])
            .to_string(),
        )
        .unwrap();
        let mut payload = serde_json::json!({"kind":"mint","chain_id":1,"contract":hex(&[0x22;20]),
            "beldex_txid":hex(&[0x11;32]),"output_index":0,"sig":"11"});
        let first = relay_payload_identity(&payload.to_string(), &configs).unwrap();
        assert_eq!(
            first,
            relay_payload_identity(&serde_json::to_string_pretty(&payload).unwrap(), &configs)
                .unwrap()
        );
        payload["sig"] = serde_json::json!("22");
        assert_ne!(
            first,
            relay_payload_identity(&payload.to_string(), &configs).unwrap()
        );
        payload["chain_id"] = serde_json::json!(2);
        assert!(relay_payload_identity(&payload.to_string(), &configs).is_err());
        payload["chain_id"] = serde_json::json!(1);
        payload["output_index"] = serde_json::json!(u64::MAX);
        assert!(relay_payload_identity(&payload.to_string(), &configs).is_err());
        payload["output_index"] = serde_json::json!(0);
        payload["contract"] = serde_json::json!(hex(&[0x33; 20]));
        assert!(relay_payload_identity(&payload.to_string(), &configs).is_err());
    }

    #[test]
    fn observed_release_recovers_before_signing_and_separates_chains() {
        use beldex_bridge_signer::orchestrator::Duty;
        use beldex_bridge_signer::watch::ReleaseEvent;
        let dir = std::env::temp_dir().join(format!("bridge-duty-journal-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let event = ReleaseEvent {
            evm_txid: [0x65; 32],
            log_index: 3,
            chain: ChainId(1),
            amount: 12345,
            beldex_recipient: b"recipient".to_vec(),
        };
        let duty = Duty::Release(event.clone());
        let path = persist_observed_duty(dir.to_str().unwrap(), &duty).unwrap();
        assert_eq!(
            read_observed_duty(std::path::Path::new(&path)).unwrap(),
            duty
        );
        let other = Duty::Release(ReleaseEvent {
            chain: ChainId(2),
            ..event
        });
        let other_path = persist_observed_duty(dir.to_str().unwrap(), &other).unwrap();
        assert_ne!(path, other_path);
        assert_eq!(
            pending_outbox_files(dir.to_str().unwrap()).unwrap().len(),
            2
        );
        mark_outbox_finalized(std::path::Path::new(&path)).unwrap();
        assert_eq!(
            pending_outbox_files(dir.to_str().unwrap()).unwrap().len(),
            1
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn mint_outbox_is_committed_with_restrictive_permissions() {
        let dir =
            std::env::temp_dir().join(format!("beldex-bridge-outbox-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ev = MintEvent {
            beldex_txid: [0x11; 32],
            output_index: 7,
            dst_chain: ChainId(1),
            key_epoch: 3,
            to: [0x22; 20],
            amount: 10,
        };
        let path = persist_mint_outbox(dir.to_str().unwrap(), &ev, "{\"kind\":\"mint\"}")
            .expect("persist outbox");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"kind\":\"mint\"}\n"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o750
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn outbox_record_moves_from_pending_to_finalized_atomically() {
        let dir = std::env::temp_dir().join(format!(
            "beldex-bridge-release-outbox-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let ev = beldex_bridge_signer::watch::ReleaseEvent {
            evm_txid: [0x33; 32],
            log_index: 4,
            chain: ChainId(31337),
            amount: 10,
            beldex_recipient: b"bx".to_vec(),
        };
        let path = persist_release_outbox(dir.to_str().unwrap(), &ev, "deadbeef", &[0x44; 64])
            .expect("persist release");
        assert!(path.ends_with(".pending.json"));
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed["log_index"], 4);
        mark_outbox_finalized(std::path::Path::new(&path)).unwrap();
        assert!(!std::path::Path::new(&path).exists());
        assert!(dir
            .join(format!("31337-{}-4.finalized.json", hex(&[0x33; 32])))
            .exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn watcher_state_round_trips_with_restrictive_permissions() {
        let dir = std::env::temp_dir().join(format!(
            "beldex-bridge-watch-state-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("watch.state");
        persist_watch_state(
            path.to_str().unwrap(),
            123,
            [(1, 456), (31_337, 789)],
            [(1, (455, [0xAB; 32]))],
        )
        .unwrap();
        let loaded = load_watch_state(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.beldex_next, Some(123));
        assert_eq!(loaded.evm_next.get(&1), Some(&456));
        assert_eq!(loaded.evm_next.get(&31_337), Some(&789));
        assert_eq!(loaded.evm_anchors.get(&1), Some(&(455, [0xAB; 32])));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

/// Loaded, reusable signing context for the live `serve` backend: the committee view, this
/// node's index, both legs' key material, and the mesh identity parameters. A
/// duty's sign closure ([`LiveSigners::pevm_sign`] / [`LiveSigners::pgw_sign`]) rebuilds the
/// per-leg mesh and runs one session — mirroring the `sign` subcommand, but driven by the
/// autonomy loop instead of an operator-supplied digest.
#[cfg(feature = "serve-live")]
struct LiveSigners {
    committee: beldex_bridge_signer::committee::CommitteeView,
    self_index: u16,
    pgw_key_package: frost_ed25519::keys::KeyPackage,
    pgw_pubkey_package: frost_ed25519::keys::PublicKeyPackage,
    pgw_group_vk: [u8; 32],
    pevm_key_share: Vec<u8>,
    curve_secret: [u8; 32],
    curve_public: [u8; 32],
    ed25519_secret: [u8; 64],
    port_base: u16,
    pevm_offset: u16,
    use_curve: bool,
    single_host: bool,
    timeout: std::time::Duration,
}

#[cfg(feature = "serve-live")]
impl LiveSigners {
    fn build_mesh(
        &self,
        base: u16,
    ) -> (
        beldex_bridge_signer::dkg_driver::live::MeshIdentity,
        Vec<beldex_bridge_signer::dkg_driver::live::PeerTransportAddr>,
    ) {
        use beldex_bridge_signer::dkg_driver::live::{MeshIdentity, PeerTransportAddr};
        let listen_port = if self.single_host {
            base + self.self_index
        } else {
            base
        };
        let identity = MeshIdentity {
            listen_endpoint: mesh_listen_endpoint(listen_port),
            curve_secret: self.curve_secret,
            curve_public: self.curve_public,
            ed25519_secret: self.ed25519_secret,
        };
        let peers = if self.single_host {
            self.committee
                .peer_transport_indexed(self.self_index as usize, base)
        } else {
            self.committee
                .peer_transport(self.self_index as usize, base)
        }
        .into_iter()
        .map(|(index, endpoint, curve_pubkey)| PeerTransportAddr {
            index,
            endpoint,
            curve_pubkey,
        })
        .collect();
        (identity, peers)
    }

    /// `Pgw`: FROST-sign a 32-byte digest over the mesh, verify the aggregate under libsodium
    /// (the L1 consensus check), and return the 64-byte ed25519 signature.
    ///
    /// `signers` is the round's participant set — under coordinated autonomy this is the
    /// session's canonical ACK set (only members that independently verified the payload,
    /// C.5), not a static roster. `attempt` namespaces the round's mesh frames so a retry
    /// never ingests the failed attempt's messages.
    fn pgw_sign(
        &self,
        message: &[u8; 32],
        signers: &[u16],
        attempt: u32,
    ) -> Result<[u8; 64], String> {
        use beldex_bridge_signer::ffi;
        use beldex_bridge_signer::frost_sign_driver::live::run_live_sign;
        let (identity, peers) = self.build_mesh(self.port_base);
        let mut rng = rand::rngs::OsRng;
        let sig = run_live_sign(
            &self.committee,
            self.self_index,
            signers,
            self.pgw_key_package.clone(),
            self.pgw_pubkey_package.clone(),
            *message,
            attempt,
            &identity,
            &peers,
            self.use_curve,
            &mut rng,
            self.timeout,
        )
        .map_err(|e| format!("Pgw sign failed: {e:?}"))?;
        if !ffi::ed25519_verify_consensus(&sig, message, &self.pgw_group_vk) {
            return Err("Pgw aggregate failed libsodium verification".into());
        }
        Ok(sig)
    }

    /// `Pevm`: cggmp21-sign a mint preimage over the mesh, then `ecrecover` to find the
    /// recovery id and return the 65-byte `r‖s‖v` the wBDX contract verifies.
    /// `signers`/`attempt` as in [`LiveSigners::pgw_sign`].
    fn pevm_sign(
        &self,
        preimage: &[u8],
        signers: &[u16],
        attempt: u32,
    ) -> Result<[u8; 65], String> {
        use beldex_bridge_signer::cggmp21_sign_driver::live::run_live_pevm_sign;
        use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
        use sha3::{Digest, Keccak256};
        let (identity, peers) = self.build_mesh(self.port_base + self.pevm_offset);
        let (rs, x33) = run_live_pevm_sign(
            &self.committee,
            self.self_index,
            signers,
            &self.pevm_key_share,
            preimage,
            attempt,
            &identity,
            &peers,
            self.use_curve,
            self.timeout,
        )
        .map_err(|e| format!("Pevm sign failed: {e:?}"))?;

        let expected = VerifyingKey::from_sec1_bytes(&x33)
            .map(|vk| {
                let enc = vk.to_encoded_point(false);
                let h = Keccak256::digest(&enc.as_bytes()[1..]);
                let mut a = [0u8; 20];
                a.copy_from_slice(&h[12..]);
                a
            })
            .map_err(|e| format!("Pevm group key invalid: {e}"))?;
        let digest32: [u8; 32] = Keccak256::digest(preimage).into();
        let k_sig = K256Sig::from_slice(&rs).map_err(|e| format!("bad signature bytes: {e}"))?;
        let k_sig = k_sig.normalize_s().unwrap_or(k_sig);
        for rec in [0u8, 1u8] {
            if let Ok(vk) = VerifyingKey::recover_from_prehash(
                &digest32,
                &k_sig,
                RecoveryId::from_byte(rec).unwrap(),
            ) {
                let enc = vk.to_encoded_point(false);
                let h = Keccak256::digest(&enc.as_bytes()[1..]);
                if h[12..] == expected {
                    let mut out = [0u8; 65];
                    out[..64].copy_from_slice(&rs[..]);
                    out[64] = 27 + rec;
                    return Ok(out);
                }
            }
        }
        Err("Pevm aggregate did not ecrecover to the wBDX signer".into())
    }
}

/// Build the [`LiveSigners`] context: fetch the committee, resolve this node's index + signer
/// set, load both legs' key material (`dkg` output under `BRIDGE_SIGNER_SHARE_DIR`), and derive
/// the mesh identity from the MN key. Mirrors the `sign` subcommand's setup.
#[cfg(feature = "serve-live")]
fn build_live_signers(cfg: &Config) -> Result<LiveSigners, String> {
    use beldex_bridge_signer::ffi;
    use beldex_bridge_signer::omq_client::OmqCommitteeClient;
    use frost_ed25519 as frost;
    use std::time::Duration;

    require_share_custody(cfg)?;

    let client = OmqCommitteeClient::new(cfg.oxenmq_endpoint.clone());
    let committee = client.fetch_committee(None).map_err(|e| e.to_string())?;
    let self_index = committee
        .daemon_self_index
        .or_else(|| committee.self_index(&cfg.self_mn_pubkey))
        .ok_or("this node is not on the current bridge committee")? as u16;
    if !committee.has_signer_keys() {
        return Err("bridge.committee returned no signer_keys — update beldexd".into());
    }
    let single_host = std::env::var("BRIDGE_SIGNER_ALLOW_SINGLE_HOST_COMMITTEE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if single_host {
        eprintln!(
            "WARNING: single-host committee explicitly allowed; process, host, and file compromise can capture the full threshold"
        );
    } else {
        if !committee.has_network_info() {
            return Err("production live signing requires per-member IP/x25519 network information; set BRIDGE_SIGNER_ALLOW_SINGLE_HOST_COMMITTEE=1 only for an unsafe local canary".into());
        }
        let unique_hosts: std::collections::BTreeSet<&str> =
            committee.member_ips.iter().map(String::as_str).collect();
        if unique_hosts.len() < committee.threshold
            || committee
                .member_ips
                .iter()
                .any(|ip| ip == "127.0.0.1" || ip == "::1" || ip == "localhost")
        {
            return Err(format!(
                "committee has only {} independent non-loopback host identities (threshold {}); refusing correlated live custody",
                unique_hosts.len(),
                committee.threshold
            ));
        }
    }
    let dir = std::env::var("BRIDGE_SIGNER_SHARE_DIR")
        .map_err(|_| "set BRIDGE_SIGNER_SHARE_DIR (where `dkg` wrote the shares)".to_string())?;
    let port_base: u16 = std::env::var("BRIDGE_SIGNER_MESH_PORT_BASE")
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or("set BRIDGE_SIGNER_MESH_PORT_BASE (single-host devnet)")?;
    let pevm_offset: u16 = std::env::var("BRIDGE_SIGNER_MESH_PEVM_OFFSET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let key_path = std::env::var("BRIDGE_SIGNER_MN_KEY_FILE")
        .map_err(|_| "set BRIDGE_SIGNER_MN_KEY_FILE".to_string())?;
    let sk_bytes = std::fs::read(&key_path).map_err(|e| format!("read MN key {key_path}: {e}"))?;
    if sk_bytes.len() != 64 {
        return Err(format!(
            "MN key {key_path} is {} bytes, expected 64",
            sk_bytes.len()
        ));
    }
    let mut ed25519_secret = [0u8; 64];
    ed25519_secret.copy_from_slice(&sk_bytes);
    let mut ed_pub = [0u8; 32];
    ed_pub.copy_from_slice(&ed25519_secret[32..64]);
    let curve_secret = ffi::ed25519_sk_to_x25519(&ed25519_secret)?;
    let curve_public = ffi::ed25519_pk_to_x25519(&ed_pub)?;
    if let Some(expected) = committee.member_x25519.get(self_index as usize) {
        if !expected.iter().all(|&b| b == 0) && curve_public != *expected {
            return Err("derived x25519 does not match this node's bridge.committee entry".into());
        }
    }
    let use_curve = std::env::var("BRIDGE_SIGNER_MESH_USE_CURVE")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);
    let timeout = Duration::from_secs(
        std::env::var("BRIDGE_SIGNER_SIGN_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(120),
    );

    // Pgw FROST material. The share files are indexed by this node's committee index AT
    // DKG TIME; committee indices are canonical (pubkey-sorted) per epoch, so they are
    // stable while the committee's membership is stable. If the file for our CURRENT
    // index is missing but a differently-indexed share exists, the committee has changed
    // (membership, or a daemon predating the canonical-order rule) — say so explicitly,
    // because the bare ENOENT reads as "dkg never ran".
    if !std::path::Path::new(&format!("{dir}/pgw-{self_index}.keypackage")).exists() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            let others: Vec<String> = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.starts_with("pgw-") && n.ends_with(".keypackage"))
                .collect();
            if !others.is_empty() {
                return Err(format!(
                    "this node's committee index is now {self_index}, but its share dir holds \
                     {others:?} — the committee order/membership changed since the DKG ran. \
                     Re-run the DKG for the current committee (shares, the contract signer, \
                     and the gateway owner key must all be regenerated together)."
                ));
            }
        }
    }
    let read = |suffix: &str| {
        std::fs::read(format!("{dir}/pgw-{self_index}.{suffix}")).map_err(|e| {
            format!("read pgw {suffix}: {e} (run `dkg` first with BRIDGE_SIGNER_SHARE_DIR set)")
        })
    };
    let pgw_key_package = frost::keys::KeyPackage::deserialize(&read("keypackage")?)
        .map_err(|e| format!("bad pgw keypackage: {e}"))?;
    let pgw_pubkey_package = frost::keys::PublicKeyPackage::deserialize(&read("pubkeypackage")?)
        .map_err(|e| format!("bad pgw pubkeypackage: {e}"))?;
    let pgw_group_vk: [u8; 32] = pgw_pubkey_package
        .verifying_key()
        .serialize()
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("cannot serialize pgw group verifying key")?;

    // Pevm cggmp21 keyshare (raw bytes; the driver deserializes).
    let pevm_key_share =
        std::fs::read(format!("{dir}/pevm-{self_index}.keyshare")).map_err(|e| {
            format!("read pevm keyshare: {e} (run `dkg` first with BRIDGE_SIGNER_SHARE_DIR set)")
        })?;

    Ok(LiveSigners {
        committee,
        self_index,
        pgw_key_package,
        pgw_pubkey_package,
        pgw_group_vk,
        pevm_key_share,
        curve_secret,
        curve_public,
        ed25519_secret,
        port_base,
        pevm_offset,
        use_curve,
        single_host,
        timeout,
    })
}

/// The live `serve` path: the **coordinated autonomy loop**. Composes the
/// [`Coordinator`](beldex_bridge_signer::coordinator::Coordinator) (deterministic per-duty
/// sessions + leader over the S4-authenticated OMQ mesh) with
/// [`DualPolicy`](beldex_bridge_signer::release_policy::DualPolicy) (mint C.5 byte-rebuild +
/// release R1–R6 via the member's own daemon), [`LiveSigners`] (per-duty Pevm/Pgw mesh
/// sessions), and [`HttpGatewayRpc`] (release build with the replay-guard ref + verify +
/// submit). Enabled by `--features serve-live` + `BRIDGE_SIGNER_SERVE_LIVE=1`.
#[cfg(feature = "serve-live")]
#[allow(clippy::too_many_arguments)]
fn run_serve_live<B, C>(
    cfg: &Config,
    src: &mut beldex_bridge_signer::service::WatcherEventSource<B, C>,
    orch: &mut beldex_bridge_signer::orchestrator::Orchestrator,
    opts: &beldex_bridge_signer::service::ServeOptions,
    configs: &[beldex_bridge_signer::evm_watcher::EvmChainConfig],
    beldexd_rpc: &str,
    gateway_id: &str,
    poll_secs: u64,
) -> Result<(), String>
where
    B: beldex_bridge_signer::beldex_watcher::BeldexRpc,
    C: beldex_bridge_signer::evm_watcher::JsonRpcClient,
{
    use beldex_bridge_signer::coordinator::{BuildError, Coordinator, MintPolicy};
    use beldex_bridge_signer::evm_watcher::HttpJsonRpc;
    use beldex_bridge_signer::live_backend::{mint_relay_payload_json, GatewayRpc, HttpGatewayRpc};
    use beldex_bridge_signer::omq_mesh::{MeshAuth, OmqMeshConfig, OmqPeerTransport, PeerAddr};
    use beldex_bridge_signer::orchestrator::{Duty, EventSource, ExecOutcome};
    use beldex_bridge_signer::reconcile::{
        DualReconciler, DutyReconciler, EvmMintReconciler, GatewayReleaseReconciler,
    };
    use beldex_bridge_signer::release_policy::{DualPolicy, ReleasePolicy, ReleaseProposal};
    use beldex_bridge_signer::transport::Leg;
    use beldex_bridge_signer::watch::ReleaseEvent;
    use beldex_bridge_signer::wire_auth::{LibsodiumEd25519, LibsodiumSigner};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    let bus_genesis =
        config::parse_hex32(&std::env::var("BRIDGE_SIGNER_GENESIS_HASH").map_err(|_| {
            "set BRIDGE_SIGNER_GENESIS_HASH; live mode refuses an unbound network domain"
                .to_string()
        })?)
        .filter(|g| *g != [0u8; 32])
        .ok_or("BRIDGE_SIGNER_GENESIS_HASH must be non-zero 32-byte hex")?;

    let ls = Rc::new(build_live_signers(cfg)?);
    let committee = ls.committee.clone();
    let self_index = ls.self_index;

    // --- Coordinator mesh: its own port range (the per-session sign meshes bind
    // port_base / port_base+pevm_offset per session; the coordinator's transport is
    // long-lived, so it gets a dedicated offset), CURVE + S4 auth from the committee.
    let coord_offset: u16 = std::env::var("BRIDGE_SIGNER_MESH_COORD_OFFSET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let base = ls.port_base + coord_offset;
    let peers: Vec<PeerAddr> = if ls.single_host {
        committee.peer_transport_indexed(self_index as usize, base)
    } else {
        committee.peer_transport(self_index as usize, base)
    }
    .into_iter()
    .map(|(index, endpoint, curve_pubkey)| PeerAddr {
        index,
        endpoint,
        curve_pubkey,
        signer_ed25519: committee
            .signer_keys
            .get(index as usize)
            .copied()
            .unwrap_or([0u8; 32]),
    })
    .collect();
    let mesh_cfg = OmqMeshConfig {
        self_index,
        listen_endpoint: mesh_listen_endpoint(if ls.single_host {
            base + self_index
        } else {
            base
        }),
        use_curve: ls.use_curve,
        self_curve_secret: ls.curve_secret,
        self_curve_public: ls.curve_public,
        peers,
    };
    let auth = MeshAuth::from_committee(
        Box::new(LibsodiumSigner {
            sk64: ls.ed25519_secret,
        }),
        Box::new(LibsodiumEd25519),
        &committee,
    )
    .ok_or("bridge.committee returned no signer_keys — cannot authenticate the coordinator mesh")?;
    let mut net = OmqPeerTransport::bind(&mesh_cfg)
        .map_err(|e| format!("coordinator mesh bind: {e:?}"))?
        .with_auth(auth);

    // --- Policies. One shared daemon RPC client for build / inspect / submit (the loop is
    // single-threaded; the closures never call each other, so RefCell borrows never nest).
    let rpc = Rc::new(RefCell::new(HttpGatewayRpc::new(beldexd_rpc.to_string())));
    let contracts: BTreeMap<u64, [u8; 20]> =
        configs.iter().map(|c| (c.chain_id, c.contract)).collect();
    let release_gateway =
        std::env::var("BRIDGE_SIGNER_RELEASE_GATEWAY").unwrap_or_else(|_| gateway_id.to_string());
    let release_fee: u64 = std::env::var("BRIDGE_SIGNER_RELEASE_FEE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let max_fee: u64 = std::env::var("BRIDGE_SIGNER_RELEASE_MAX_FEE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(release_fee);
    let per_tx_cap: u128 = std::env::var("BRIDGE_SIGNER_RELEASE_PER_TX_CAP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(u128::MAX);

    // Leader-side release build: gateway_create_transfer + the HF23 replay-guard ref +
    // the disclosed tx key (verifiers open the stealth outputs with it).
    let build_rpc = rpc.clone();
    let build_gw = release_gateway.clone();
    let build_tx = move |ev: &ReleaseEvent| {
        let recipient = String::from_utf8(ev.beldex_recipient.clone()).map_err(|_| {
            BuildError::Unactionable("burn recipient is not a utf-8 address".into())
        })?;
        let amount = ev
            .amount
            .checked_sub(u128::from(release_fee))
            .ok_or_else(|| BuildError::Unactionable("burn amount does not cover the fee".into()))?;
        build_rpc
            .borrow_mut()
            .create_release(
                &build_gw,
                &recipient,
                amount,
                release_fee,
                ev.chain.0,
                &ev.evm_txid,
                ev.log_index,
            )
            .map_err(BuildError::Transient)
    };

    // Member-side inspection: this node's OWN daemon reads the proposed withdrawal.
    let insp_rpc = rpc.clone();
    let insp_gw = release_gateway.clone();
    let inspect = move |p: &ReleaseProposal, expected: &[u8]| {
        let addr = std::str::from_utf8(expected).map_err(|_| "recipient not utf-8".to_string())?;
        insp_rpc.borrow_mut().decode_withdrawal(p, addr, &insp_gw)
    };

    let policy = DualPolicy {
        mint: MintPolicy {
            contracts: contracts.clone(),
        },
        release: ReleasePolicy {
            build_tx,
            inspect,
            release_gateway: release_gateway.clone(),
            max_fee,
            per_tx_cap,
        },
    };

    // --- The per-duty threshold signers: one mesh round per duty among the session's
    // canonical ACK set (only members that independently verified the payload — C.5),
    // namespaced by the session attempt so a retry never ingests stale frames.
    let sign_ls = ls.clone();
    let signing_committee_endpoint = cfg.oxenmq_endpoint.clone();
    let sign =
        move |leg: Leg, message: &[u8], signers: &[u16], attempt: u32| -> Result<Vec<u8>, String> {
            let current = beldex_bridge_signer::omq_client::OmqCommitteeClient::new(
                signing_committee_endpoint.clone(),
            )
            .fetch_committee(None)
            .map_err(|e| format!("pre-sign committee check: {e}"))?;
            if current.epoch != sign_ls.committee.epoch
                || current.members != sign_ls.committee.members
                || current.signer_keys != sign_ls.committee.signer_keys
                || current.threshold != sign_ls.committee.threshold
            {
                return Err(
                    "committee changed before signing; restart after the dual-key handoff".into(),
                );
            }
            println!("  signing {leg:?} round: participants {signers:?} attempt {attempt}");
            match leg {
                Leg::Pevm => sign_ls
                    .pevm_sign(message, signers, attempt)
                    .map(|s| s.to_vec()),
                Leg::Pgw => {
                    let m: [u8; 32] = message
                        .try_into()
                        .map_err(|_| "Pgw signing message must be 32 bytes".to_string())?;
                    sign_ls.pgw_sign(&m, signers, attempt).map(|s| s.to_vec())
                }
            }
        };

    // --- Completion: emit the mint relayer payload / self-submit the release.
    //
    // Mint hand-off. The signer holds no EVM gas key by design, so it does not broadcast:
    // it produces the signed payload and hands it off. Two mechanisms, in order:
    //
    //   1. `BRIDGE_SIGNER_RELAY_CMD` — spawn that command and write the payload JSON to its
    //      stdin (e.g. `beldex-bridge-relayer relay -`). The gas key lives in *that*
    //      process's environment, never here.
    //   2. Atomically persist the JSON in BRIDGE_SIGNER_MINT_OUTBOX_DIR, then print
    //      `MINT-PAYLOAD <json>`.  The fsynced outbox file is the durable artifact.
    //
    // Broadcast failure therefore does NOT fail the duty: re-running a whole mesh signing
    // round to retry an HTTP call would be the wrong layer, and the payload is already
    // public and reusable. Failures are logged loudly instead.
    //
    // Enabling the hook on several nodes is safe but not free: a *late* duplicate costs
    // nothing (gas estimation catches `Replay()` before broadcasting), while *simultaneous*
    // duplicates all pass estimation and all but one revert on-chain, burning gas. Set
    // `BRIDGE_SIGNER_RELAY_STAGGER_MS` (multiplied by this node's committee index) so
    // configured relayers fire in sequence rather than at once. Each needs its own gas key —
    // a shared key means colliding nonces.
    // Preferred hand-off: publish to the daemon's mint bus (`bridge.mint_payload`), which
    // fans out to every subscribed relayer. Relayers then need no signer-host access at all.
    // The daemon dedups by (beldex_txid, output_index), so all t+1 members publishing is expected and only
    // one fan-out occurs. Off by default only because it needs the OMQ endpoint.
    let publish_bus = std::env::var("BRIDGE_SIGNER_PUBLISH_MINT_BUS")
        .map(|v| v != "0" && v != "false")
        .unwrap_or(true);
    // The daemon accepts a publication only from a seated committee member, so we sign each
    // one with this node's `signer_ed25519` — the same key the mesh authenticates with, and
    // the one consensus records for our committee index.
    // Where to publish. Default: this node's own daemon — correct when relayers subscribe
    // broadly. But a publisher→own-daemon / subscriber→one-daemon topology only intersects
    // by luck (found live: the one subscribed daemon's signer was a straggler that round,
    // so every fan-out happened where nobody listened). BRIDGE_SIGNER_MINT_BUS_ENDPOINT
    // points all signers at a common bus daemon; publishing is signature-authenticated,
    // not socket-authenticated, so a remote daemon works fine.
    let bus_endpoint = std::env::var("BRIDGE_SIGNER_MINT_BUS_ENDPOINT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| cfg.oxenmq_endpoint.clone());
    let bus_client = if publish_bus {
        println!("  mint hand-off: publishing to bridge.mint_payload at {bus_endpoint}");
        Some(beldex_bridge_signer::omq_client::OmqCommitteeClient::new(
            bus_endpoint.clone(),
        ))
    } else {
        None
    };
    let bus_sign_key = ls.ed25519_secret;

    let relay_cmd = std::env::var("BRIDGE_SIGNER_RELAY_CMD")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let mint_outbox_dir = std::env::var("BRIDGE_SIGNER_MINT_OUTBOX_DIR")
        .map_err(|_| "set BRIDGE_SIGNER_MINT_OUTBOX_DIR; live mint completion is fail-closed without a durable outbox".to_string())?;
    let release_outbox_dir = std::env::var("BRIDGE_SIGNER_RELEASE_OUTBOX_DIR")
        .map_err(|_| "set BRIDGE_SIGNER_RELEASE_OUTBOX_DIR; live release completion is fail-closed without a durable outbox".to_string())?;
    std::fs::create_dir_all(&mint_outbox_dir)
        .map_err(|e| format!("create mint outbox {mint_outbox_dir}: {e}"))?;
    std::fs::create_dir_all(&release_outbox_dir)
        .map_err(|e| format!("create release outbox {release_outbox_dir}: {e}"))?;
    let relay_stagger_ms: u64 = std::env::var("BRIDGE_SIGNER_RELAY_STAGGER_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    match &relay_cmd {
        Some(c) => println!(
            "  mint hand-off: piping payloads to `{c}` (stagger {}ms)",
            relay_stagger_ms * self_index as u64
        ),
        None => {
            println!("  mint hand-off: log only (set BRIDGE_SIGNER_RELAY_CMD to auto-broadcast)")
        }
    }

    let retry_mint_outbox_dir = mint_outbox_dir.clone();
    let retry_release_outbox_dir = release_outbox_dir.clone();
    let retry_relay_cmd = relay_cmd.clone();
    let retry_bus_endpoint = bus_endpoint.clone();
    let retry_publish_bus = publish_bus;
    let retry_bus_key = bus_sign_key;
    let retry_bus_genesis = bus_genesis;
    let retry_rpc = rpc.clone();
    let done_rpc = rpc.clone();
    let done_contracts = contracts;
    let complete = move |d: &Duty, proposal: &[u8], sig: &[u8]| -> ExecOutcome {
        match d {
            Duty::Mint(ev) => {
                let Some(&contract) = done_contracts.get(&ev.dst_chain.0) else {
                    return ExecOutcome::Abandon;
                };
                let payload = mint_relay_payload_json(ev, contract, sig);
                match persist_mint_outbox(&mint_outbox_dir, ev, &payload) {
                    Ok(path) => println!("  mint payload durably stored: {path}"),
                    Err(e) => {
                        eprintln!("  mint outbox persistence failed ({e}); duty will retry");
                        return ExecOutcome::Retry;
                    }
                }
                println!("MINT-PAYLOAD {payload}");
                if let Some(bus) = &bus_client {
                    use beldex_bridge_signer::omq_client::mint_publish_message;
                    let msg = mint_publish_message(&bus_genesis, &payload);
                    match beldex_bridge_signer::ffi::ed25519_sign_detached(&bus_sign_key, &msg) {
                        Ok(pub_sig) => match bus
                            .publish_mint_payload(&payload, self_index, &pub_sig)
                        {
                            // `DUPLICATE` = a peer in the same quorum published it first.
                            // Expected and desirable: one fan-out per deposit, not t+1.
                            Ok(status) => println!("  published to mint bus: {status}"),
                            Err(e) => {
                                eprintln!("  mint-bus publish failed ({e}) — payload still logged")
                            }
                        },
                        Err(e) => {
                            eprintln!("  mint-bus signing failed ({e}) — payload still logged")
                        }
                    }
                }
                if let Some(cmd) = &relay_cmd {
                    if relay_stagger_ms > 0 && self_index > 0 {
                        std::thread::sleep(std::time::Duration::from_millis(
                            relay_stagger_ms * self_index as u64,
                        ));
                    }
                    match pipe_to_relay(cmd, &payload) {
                        Ok(out) => println!("  relayed: {}", out.trim()),
                        Err(e) => eprintln!(
                            "  RELAY FAILED ({e}) — the MINT-PAYLOAD line above is still valid; \
                             broadcast it with `beldex-bridge-relayer relay -`"
                        ),
                    }
                }
                ExecOutcome::Submitted
            }
            Duty::Release(ev) => {
                let Some(p) = ReleaseProposal::decode(proposal) else {
                    return ExecOutcome::Abandon; // cannot happen for an accepted proposal
                };
                if sig.len() != 64 {
                    return ExecOutcome::Retry;
                }
                let mut s64 = [0u8; 64];
                s64.copy_from_slice(sig);
                let blob_hex: String = p
                    .unsigned_tx_blob
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                if let Err(e) = persist_release_outbox(&release_outbox_dir, ev, &blob_hex, &s64) {
                    eprintln!("release outbox persistence failed ({e}); duty will retry");
                    return ExecOutcome::Retry;
                }
                match done_rpc.borrow_mut().submit_transfer(&blob_hex, &s64) {
                    Ok(txid) => {
                        println!("RELEASE submitted: {txid}");
                        ExecOutcome::Submitted
                    }
                    Err(e) => {
                        // Every finalizing node submits the SAME signed tx; only the first
                        // lands, and the daemon reports the rest as duplicates / replays.
                        // That is success, not failure — retrying would reopen a session
                        // for a settled burn and churn against the consensus replay guard.
                        let el = e.to_lowercase();
                        if el.contains("already")
                            || el.contains("replay")
                            || el.contains("discharged")
                        {
                            println!("RELEASE already submitted by a peer (ok): {e}");
                            ExecOutcome::Submitted
                        } else {
                            eprintln!("release submit failed (will retry): {e}");
                            // The signed transaction is durable. Submission is retried
                            // independently without reopening the threshold session.
                            ExecOutcome::Submitted
                        }
                    }
                }
            }
        }
    };

    let mut coord = Coordinator::new(committee, self_index, policy, sign, complete);
    if let Some(t) = std::env::var("BRIDGE_SIGNER_STAGE_TIMEOUT_TICKS")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        coord.stage_timeout_ticks = t;
    }

    println!("serve: LIVE COORDINATED mode — per-duty sessions over the authenticated mesh");
    println!(
        "  committee epoch {} size {} threshold {}; self_index {self_index}",
        coord.committee.epoch,
        coord.committee.size(),
        coord.committee.threshold
    );
    println!(
        "  coordinator mesh on port base {base}; polling every {poll_secs}s across {} EVM chain(s)",
        configs.len()
    );

    // On-chain reconciliation: a restarted signer must not re-work settled duties. Each
    // newly observed duty is checked once (mints: processedDeposits; releases: the daemon's
    // release-ref set); an undeterminable answer leaves it unregistered so a later poll
    // retries. Disable with BRIDGE_SIGNER_RECONCILE=0 (then every duty is worked).
    let reconcile_on = std::env::var("BRIDGE_SIGNER_RECONCILE")
        .map(|v| v != "0" && v != "false")
        .unwrap_or(true);
    let mut reconciler = DualReconciler {
        // Per-chain client + contract, so a multi-chain deployment queries the right chain.
        mint: EvmMintReconciler {
            chains: configs
                .iter()
                .map(|c| {
                    (
                        c.chain_id,
                        (
                            HttpJsonRpc::new(c.rpc_url.clone()),
                            c.contract,
                            c.finality.settlement_tag().to_string(),
                        ),
                    )
                })
                .collect(),
        },
        release: GatewayReleaseReconciler::new(beldexd_rpc.to_string(), release_gateway.clone())
            .with_fallback_confirmations(
                std::env::var("BRIDGE_SIGNER_BELDEX_CONFIRMATIONS")
                    .ok()
                    .and_then(|v| v.parse().ok()),
            ),
    };
    if !reconcile_on {
        return Err("live mode requires settlement reconciliation".into());
    }
    let duty_journal = format!(
        "{}.duties",
        std::env::var("BRIDGE_SIGNER_WATCH_STATE_FILE")
            .map_err(|_| "live mode requires BRIDGE_SIGNER_WATCH_STATE_FILE")?
    );
    std::fs::create_dir_all(&duty_journal).map_err(|e| format!("create duty journal: {e}"))?;

    let mut ticks = 0u64;
    let committee_refresh_ticks: u64 = std::env::var("BRIDGE_SIGNER_COMMITTEE_REFRESH_TICKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(12);
    let committee_client =
        beldex_bridge_signer::omq_client::OmqCommitteeClient::new(cfg.oxenmq_endpoint.clone());
    loop {
        validate_implementation_pins(&configs)?;
        // A long-lived signer must never continue under a committee snapshot that
        // consensus has replaced. Hot-swapping shares and sockets mid-session is
        // unsafe; fail closed and let the supervisor restart against the already
        // promoted dual-key share set.
        if ticks > 0 && ticks % committee_refresh_ticks == 0 {
            let latest = committee_client
                .fetch_committee(None)
                .map_err(|e| format!("committee refresh failed: {e}"))?;
            if latest.epoch != coord.committee.epoch
                || latest.members != coord.committee.members
                || latest.signer_keys != coord.committee.signer_keys
            {
                return Err(format!(
                    "bridge committee changed (loaded epoch {}, current epoch {}); stopping before signing with stale authority. Promote the matching dual DKG shares and restart this signer",
                    coord.committee.epoch, latest.epoch
                ));
            }
        }

        // A finality failure must also stop old queued duties and outbox retries.
        // Merely suppressing new watcher events would leave those payments live.
        for watcher in &mut src.evm {
            watcher.validate_finality().map_err(|e| {
                format!("EVM finality validation failed; stopping payment processing: {e:?}")
            })?;
        }

        // Signed artifacts remain pending until the destination replay guard proves
        // inclusion. Broadcast failures and mempool eviction therefore trigger
        // rebroadcast of the identical artifact, never a second signing ceremony.
        drain_mint_outbox(
            &retry_mint_outbox_dir,
            retry_relay_cmd.as_deref(),
            retry_publish_bus.then_some((
                retry_bus_endpoint.as_str(),
                self_index,
                retry_bus_key,
                retry_bus_genesis,
            )),
            &mut reconciler.mint,
        )?;
        drain_release_outbox(
            &retry_release_outbox_dir,
            &mut retry_rpc.borrow_mut(),
            &mut reconciler.release,
        )?;

        // Commit observations before any cursor can advance. Retry unknown RPC
        // results from disk: finalized EVM observations are not re-emitted by
        // the watcher after their inclusion block has been consumed.
        for m in src.poll_mints() {
            persist_observed_duty(&duty_journal, &Duty::Mint(m))?;
        }
        for r in src.poll_releases() {
            persist_observed_duty(&duty_journal, &Duty::Release(r))?;
        }
        for path in pending_outbox_files(&duty_journal)? {
            let mut duty = read_observed_duty(&path)?;
            // A recovered mint must be authorized by the currently configured
            // key epoch following an explicit handoff, not a retired key.
            if let Duty::Mint(ref mut event) = duty {
                if let Some(chain) = configs.iter().find(|c| c.chain_id == event.dst_chain.0) {
                    event.key_epoch = chain.key_epoch;
                }
            }
            match reconciler.is_settled(&duty) {
                Some(true) => {
                    let key = duty.key();
                    orch.observe(duty);
                    orch.mark_done(&key);
                    mark_outbox_finalized(&path)?;
                }
                Some(false) => {
                    orch.observe(duty);
                }
                None => { /* retained for retry, including across restart */ }
            }
        }
        if let Ok(path) = std::env::var("BRIDGE_SIGNER_WATCH_STATE_FILE") {
            persist_watch_state(
                &path,
                src.beldex.finalized_up_to().saturating_add(1),
                src.evm
                    .iter()
                    .map(|w| (w.chain().0, w.durable_resume_block())),
                src.evm
                    .iter()
                    .filter_map(|w| w.durable_finality_anchor().map(|a| (w.chain().0, a))),
            )?;
        }
        validate_implementation_pins(&configs)?;
        let rep = coord.step(orch, &mut net);
        if let Some(error) = &rep.transport_error {
            eprintln!("coordinator transport failure; current attempts stopped: {error}");
        }
        if rep != Default::default() {
            let (pending, in_flight, done) = orch.counts();
            println!(
                "tick {ticks}: opened={} acked={} nacked={} signed={} completed={} requeued={} abandoned={} resolved={} | duties p={pending} f={in_flight} d={done}",
                rep.opened, rep.acked, rep.nacked, rep.signed, rep.completed, rep.requeued, rep.abandoned, rep.resolved
            );
        }
        // Idle heartbeat (~once a minute): proves the watchers are scanning and shows how
        // far finality has advanced — a stalled `finalized_up_to` means the chain (or the
        // miner) stopped; one that advances past a deposit with no duty means the deposit
        // didn't resolve (and the `deposit held` line above says why).
        if ticks % 12 == 0 {
            validate_native_reserve_solvency(beldexd_rpc, gateway_id, configs)?;
            let (pending, in_flight, done) = orch.counts();
            // The EVM half matters as much as the Beldex half. A burn is held in the
            // watcher's `pending` set until its inclusion block is `confirmations` deep
            // (watch.rs FinalityGate: depth = tip - inclusion_height), so on an idle
            // automine chain — anvil started without --block-time — the tip stops at the
            // block containing the burn, depth stays 0, and the release never opens.
            // Without a pending count that is indistinguishable from "no burn happened",
            // which is the one thing the operator most needs to tell apart.
            let evm: Vec<String> = src
                .evm
                .iter()
                .map(|w| {
                    let tip = w
                        .tip()
                        .map(|t| t.to_string())
                        .unwrap_or_else(|e| format!("unreachable({e:?})"));
                    format!(
                        "chain {} tip={} pending={}",
                        w.chain().0,
                        tip,
                        w.pending_len()
                    )
                })
                .collect();
            println!(
                "watch: beldex finalized_up_to={} | evm {} | duties p={pending} f={in_flight} d={done}",
                src.beldex.finalized_up_to(),
                evm.join("; ")
            );
        }
        ticks += 1;
        if opts.max_ticks.is_some_and(|max| ticks >= max) {
            break;
        }
        if !opts.interval.is_zero() {
            std::thread::sleep(opts.interval);
        }
    }

    let (pending, in_flight, done) = orch.counts();
    println!("serve: finished after {ticks} tick(s); duties pending={pending} in_flight={in_flight} done={done}");
    Ok(())
}

fn main() -> ExitCode {
    let subcommand = std::env::args().nth(1);

    // Like relay-watch, this probe does not require a signer identity or bridge config.
    if subcommand.as_deref() == Some("check-curve") {
        return match run_check_curve() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("check-curve: {e}");
                ExitCode::FAILURE
            }
        };
    }

    // `relay-watch` is dispatched BEFORE the config load, deliberately: it is the
    // relayer-operator command, and a relayer holds no signer identity — no gateway, no MN
    // key, no shares. Requiring the full signer config here would force operators to invent
    // dummy values for keys they must not have. It needs exactly one setting: the OMQ
    // endpoint to subscribe to.
    if subcommand.as_deref() == Some("relay-watch") {
        return match run_relay_watch_standalone() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("relay-watch: {e}");
                ExitCode::FAILURE
            }
        };
    }

    let cfg = match Config::from_map(&config_map()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            eprintln!("set BRIDGE_SIGNER_<KEY> env vars (gateway_id, self_mn_pubkey, ...)");
            return ExitCode::FAILURE;
        }
    };

    match subcommand.as_deref() {
        Some("dkg") => match run_dkg(&cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("dkg: {e}");
                ExitCode::FAILURE
            }
        },
        Some("sign") => match run_sign(&cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sign: {e}");
                ExitCode::FAILURE
            }
        },
        Some("watch-evm") => match run_watch_evm(&cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("watch-evm: {e}");
                ExitCode::FAILURE
            }
        },
        Some("serve") => match run_serve(&cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("serve: {e}");
                ExitCode::FAILURE
            }
        },
        // ("relay-watch" is dispatched before the config load — see the top of main.)
        _ => {
            print_status(&cfg);
            ExitCode::SUCCESS
        }
    }
}
