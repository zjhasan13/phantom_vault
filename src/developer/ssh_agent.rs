//! Phase 16 (Option 2c) — Native OpenSSH-agent-compatible named pipe.
//!
//! Serve `vault ssh-agent`: unlock once, then expose vault `SSH:` credentials
//! (OpenSSH private keys in the password field) over a local named pipe using
//! the SSH agent wire protocol (identities + sign, ed25519).
//!
//! Safety decision: we serve `\\.\pipe\phantom-vault-ssh-agent` by default and
//! NEVER squat the system `openssh-ssh-agent` pipe uninvited (that would
//! hijack the user's real agent). Override with `PHANTOM_SSH_PIPE` only if
//! you know what you are doing. Clients point via `SSH_AUTH_SOCK`.

use crate::models::Vault;
use ed25519_dalek::Signer as _;
use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::PrivateKey;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const DEFAULT_PIPE: &str = r"\\.\pipe\phantom-vault-ssh-agent";
const MAX_MSG: usize = 1024 * 1024;

/// Resolve the pipe name (env override mirrors `serve_cli`).
pub fn pipe_name() -> String {
    std::env::var("PHANTOM_SSH_PIPE").unwrap_or_else(|_| DEFAULT_PIPE.to_string())
}

/// Probe whether an agent is listening (status badge only — connects and
/// drops immediately, no auth, no requests sent). The open runs on a blocking
/// thread under a 400 ms timeout (a busy pipe would otherwise block); builds
/// its own throwaway runtime, so plain `#[test]` callers never nest runtimes.
pub fn is_serving(pipe_name: &str) -> bool {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return false,
    };
    rt.block_on(async {
        let name = pipe_name.to_string();
        tokio::time::timeout(
            std::time::Duration::from_millis(400),
            tokio::task::spawn_blocking(move || {
                tokio::net::windows::named_pipe::ClientOptions::new().open(&name)
            }),
        )
        .await
        .is_ok_and(|r| matches!(r, Ok(Ok(_))))
    })
}

const MSG_FAILURE: u8 = 5;
const MSG_REQ_IDENTITIES: u8 = 11;
const MSG_IDENTITIES_ANSWER: u8 = 12;
const MSG_SIGN_REQUEST: u8 = 13;
const MSG_SIGN_RESPONSE: u8 = 14;

pub struct AgentKey {
    pub comment: String,
    pub pubkey: [u8; 32],
    signing: ed25519_dalek::SigningKey,
}

// Explicit wipe: dalek zeroizes `secret_key` in its own Drop, but that only
// fires when the SigningKey itself is dropped. ZeroizeOnDrop makes the intent
// part of the type contract (Arc<Vec<AgentKey>> drop, session teardown).
impl zeroize::Zeroize for AgentKey {
    fn zeroize(&mut self) {
        self.comment.zeroize();
        self.pubkey.zeroize();
        // No Zeroize impl on SigningKey 2.x: replace it so the old key's Drop
        // runs now and wipes secret_key, instead of lingering until struct drop.
        self.signing = ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]);
    }
}

impl Drop for AgentKey {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for AgentKey {}

// Manual Debug: never leak key material into logs.
impl std::fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentKey")
            .field("comment", &self.comment)
            .finish_non_exhaustive()
    }
}

/// OpenSSH-style `SHA256:` fingerprint for a pasted private key (any type).
/// Auto-fills the fingerprint field when the user leaves it blank.
/// Unparseable input → None (caller keeps the field blank, never blocks save).
pub fn fingerprint_of_private(pem: &str) -> Option<String> {
    let key = ssh_key::PrivateKey::from_openssh(pem.trim()).ok()?;
    Some(key.fingerprint(ssh_key::HashAlg::Sha256).to_string())
}

/// Collect ed25519 keys from vault credentials titled `SSH: <comment>`.
/// Private key PEM lives in the password field. Non-ed25519 entries are
/// skipped (never error — one bad entry must not kill the agent).
pub fn collect_keys(vault: &Vault) -> Vec<AgentKey> {
    let mut out = Vec::new();
    for cred in &vault.credentials {
        let Some(comment) = cred.title.strip_prefix("SSH:") else {
            continue;
        };
        let comment = comment.trim().to_string();
        let Ok(private) = PrivateKey::from_openssh(cred.password.trim()) else {
            continue;
        };
        let KeypairData::Ed25519(pair) = private.key_data() else {
            continue;
        };
        let pair: &Ed25519Keypair = pair;
        let Ok(signing) = ed25519_dalek::SigningKey::try_from(pair) else {
            continue;
        };
        out.push(AgentKey {
            comment,
            pubkey: signing.verifying_key().to_bytes(),
            signing,
        });
    }
    out
}

// ---- wire codec (pure, unit tested) ----

fn put_string(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn get_string(msg: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let end = pos.checked_add(4)?;
    let len = u32::from_be_bytes(msg.get(*pos..end)?.try_into().ok()?) as usize;
    *pos = end;
    let end = pos.checked_add(len)?;
    let out = msg.get(*pos..end)?.to_vec();
    *pos = end;
    Some(out)
}

fn key_blob(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::new();
    put_string(&mut b, b"ssh-ed25519");
    put_string(&mut b, pubkey);
    b
}

/// Parse a key blob back to (algo, pubkey). Rejects non-ed25519 blobs.
fn parse_blob(blob: &[u8]) -> Option<[u8; 32]> {
    let mut pos = 0;
    let algo = get_string(blob, &mut pos)?;
    let key = get_string(blob, &mut pos)?;
    if algo != b"ssh-ed25519" || key.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&key);
    Some(out)
}

fn identities_answer(keys: &[AgentKey]) -> Vec<u8> {
    let mut body = vec![MSG_IDENTITIES_ANSWER];
    body.extend_from_slice(&(keys.len() as u32).to_be_bytes());
    for k in keys {
        put_string(&mut body, &key_blob(&k.pubkey));
        put_string(&mut body, k.comment.as_bytes());
    }
    body
}

fn sign_response(sig: &[u8; 64]) -> Vec<u8> {
    let mut inner = Vec::new();
    put_string(&mut inner, b"ssh-ed25519");
    put_string(&mut inner, sig);
    let mut body = vec![MSG_SIGN_RESPONSE];
    put_string(&mut body, &inner);
    body
}

/// Dispatch one request payload → response payload. Pure logic; IO-free.
fn dispatch(keys: &[AgentKey], req: &[u8]) -> Vec<u8> {
    let Some((&kind, rest)) = req.split_first() else {
        return vec![MSG_FAILURE];
    };
    match kind {
        MSG_REQ_IDENTITIES => identities_answer(keys),
        MSG_SIGN_REQUEST => {
            let mut pos = 0;
            let (Some(blob), Some(data)) =
                (get_string(rest, &mut pos), get_string(rest, &mut pos))
            else {
                return vec![MSG_FAILURE];
            };
            // flags (u32) follows; read-and-ignore (agent constraints out of scope).
            let Some(want) = parse_blob(&blob) else {
                return vec![MSG_FAILURE];
            };
            let Some(key) = keys.iter().find(|k| k.pubkey == want) else {
                return vec![MSG_FAILURE];
            };
            let sig = key.signing.sign(&data).to_bytes();
            sign_response(&sig)
        }
        _ => vec![MSG_FAILURE],
    }
}

async fn handle_client(
    keys: Arc<Vec<AgentKey>>,
    mut stream: tokio::net::windows::named_pipe::NamedPipeServer,
) {
    loop {
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > MAX_MSG {
            break;
        }
        let mut req = vec![0u8; len];
        if stream.read_exact(&mut req).await.is_err() {
            break;
        }
        let resp = dispatch(&keys, &req);
        let out_len = (resp.len() as u32).to_be_bytes();
        if stream.write_all(&out_len).await.is_err() {
            break;
        }
        if stream.write_all(&resp).await.is_err() {
            break;
        }
    }
}

/// In-app session state: at most one UI-started agent at a time. The stop
/// flag is set by Stop, by vault lock (keys must never outlive unlock), and
/// by process exit (thread is borrowed, not detached from fate).
static SSH_SESSION: std::sync::OnceLock<std::sync::Mutex<Option<std::sync::Arc<std::sync::atomic::AtomicBool>>>> =
    std::sync::OnceLock::new();

fn session() -> &'static std::sync::Mutex<Option<std::sync::Arc<std::sync::atomic::AtomicBool>>> {
    SSH_SESSION.get_or_init(|| std::sync::Mutex::new(None))
}

/// True while a UI-started agent session is armed (keys live on its thread).
/// The pipe probe (`is_serving`) remains the ground truth for display.
/// Test-only: production reads liveness from the pipe, not this flag.
#[cfg(test)]
pub fn session_armed() -> bool {
    session()
        .lock()
        .map(|s| s.is_some())
        .unwrap_or(false)
}

/// Start serving `keys` on the app's pipe in a background thread. Refuses
/// when a pipe is already serving (ours or a foreign agent — never steal).
/// Stop via [`stop_agent`] (button, vault lock). Unlocked + non-decoy only
/// (enforced by the caller — this fn cannot see UI state).
pub fn start_agent(keys: Vec<AgentKey>) -> Result<(), String> {
    if keys.is_empty() {
        return Err("no ed25519 keys — add a credential titled \"SSH: <name>\"".into());
    }
    if is_serving(&pipe_name()) {
        return Err("an agent is already serving this pipe".into());
    }
    let mut guard = session()
        .lock()
        .map_err(|_| "agent session busy".to_string())?;
    if guard.is_some() {
        return Err("agent already starting".into());
    }
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_thread = std::sync::Arc::clone(&stop);
    let keys = std::sync::Arc::new(keys);
    std::thread::spawn(move || {
        serve_keys_thread(keys, stop_thread);
    });
    *guard = Some(stop);
    Ok(())
}

/// Stop the UI-started agent session, if any. Idempotent — safe to call on
/// every lock (the normal case is "nothing running"). The serving thread
/// exits at the next 200ms accept tick; keys die with it.
pub fn stop_agent() {
    let flag = session()
        .lock()
        .map(|mut s| s.take())
        .unwrap_or(None);
    if let Some(stop) = flag {
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Thread body for [`start_agent`]: own runtime, own keys snapshot.
fn serve_keys_thread(
    keys: std::sync::Arc<Vec<AgentKey>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let pipe_name = pipe_name();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return,
    };
    rt.block_on(async {
        use tokio::net::windows::named_pipe::ServerOptions;
        loop {
            if stop.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            let server = match ServerOptions::new().create(&pipe_name) {
                Ok(s) => s,
                Err(_) => break,
            };
            // 200ms accept tick so Stop/lock is honored promptly (else the
            // thread could block on connect() past lock with keys alive).
            match tokio::time::timeout(std::time::Duration::from_millis(200), server.connect()).await
            {
                Ok(Ok(())) => {
                    let keys = std::sync::Arc::clone(&keys);
                    tokio::spawn(async move {
                        handle_client(keys, server).await;
                    });
                }
                Ok(Err(_)) => continue,
                Err(_) => continue, // tick elapsed — re-check stop flag
            }
        }
    });
}

/// Foreground entrypoint: `vault ssh-agent`. Ctrl+C stops (keys die with us).
pub fn serve_cli() -> i32 {
    eprint!("Master password: ");
    let mut password = match rpassword::read_password() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ssh-agent: cannot read password: {e}");
            return 2;
        }
    };
    let pw = secrecy::SecretString::new(password.trim().to_string());
    {
        use zeroize::Zeroize;
        password.zeroize();
    }
    let (vault, _) = match crate::storage::load_vault_versioned_secret(
        &pw,
        super::vault_run::VAULT_FILE,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ssh-agent: unlock failed: {e}");
            return 1;
        }
    };
    drop(pw);
    let keys = Arc::new(collect_keys(&vault));
    drop(vault);
    if keys.is_empty() {
        eprintln!("ssh-agent: no ed25519 keys found — add a credential titled \"SSH: <name>\" holding the OpenSSH private key.");
        return 2;
    }
    let pipe_name = pipe_name();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("ssh-agent: runtime failed: {e}");
            return 1;
        }
    };
    println!(
        "ssh-agent: serving {} key(s) on {pipe_name} (Ctrl+C to stop)",
        keys.len()
    );
    rt.block_on(async {
        use tokio::net::windows::named_pipe::ServerOptions;
        loop {
            let server = match ServerOptions::new().create(&pipe_name) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("ssh-agent: pipe failed: {e}");
                    break;
                }
            };
            if server.connect().await.is_err() {
                continue;
            }
            let keys = Arc::clone(&keys);
            tokio::spawn(async move {
                handle_client(keys, server).await;
            });
        }
    });
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    #[test]
    fn agent_key_wipes_on_drop() {
        // Compile-time contract: explicit wipe instead of relying on dalek's
        // internal drop order (the Arc<Vec<AgentKey>> outlives individual ops).
        assert_zeroize_on_drop::<AgentKey>();
    }

    fn test_keys() -> Vec<AgentKey> {
        // Deterministic test key (NOT a real secret — committed fixture).
        let seed = [9u8; 32];
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        vec![AgentKey {
            comment: "test@example".into(),
            pubkey: signing.verifying_key().to_bytes(),
            signing,
        }]
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        body.to_vec()
    }

    // Session tests share one process-global session: serialize on the
    // session mutex itself (start/stop are idempotent, resets are safe).
    static SESSION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn test_key_pem() -> String {
        // Deterministic fixture (NOT a real secret — same committed constant
        // style as test_keys()): rendered through the real OpenSSH encoder,
        // so the fingerprint path parses exactly what users paste.
        use ssh_key::private::Ed25519Keypair;
        let pair = Ed25519Keypair::from_seed(&[9u8; 32]);
        let key = PrivateKey::from(pair);
        key.to_openssh(ssh_key::LineEnding::LF)
            .map(|s| s.to_string())
            .unwrap()
    }

    #[test]
    fn fingerprint_derives_stable_sha256() {
        let pem = test_key_pem();
        let fp = fingerprint_of_private(&pem).expect("fixture must parse");
        assert!(fp.starts_with("SHA256:"), "OpenSSH style, got {fp}");
        assert_eq!(fp.len(), 7 + 43, "32 raw bytes = 43 unpadded b64 chars");
        // Stable + whitespace-tolerant.
        assert_eq!(fingerprint_of_private(&format!("  {pem}\n")), Some(fp));
    }

    #[test]
    fn fingerprint_rejects_garbage() {
        assert_eq!(fingerprint_of_private(""), None);
        assert_eq!(fingerprint_of_private("not a key"), None);
        assert_eq!(
            fingerprint_of_private("-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----"),
            None
        );
    }

    #[test]
    fn start_refuses_empty_keys_and_double_start() {
        let _l = SESSION_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        stop_agent();
        assert!(start_agent(Vec::new()).is_err());
        assert!(!session_armed());
    }

    #[test]
    fn stop_is_idempotent_without_session() {
        let _l = SESSION_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        stop_agent();
        stop_agent();
        assert!(!session_armed());
    }

    #[test]
    fn start_stop_session_lifecycle() {
        let _l = SESSION_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        stop_agent();
        // Isolated pipe name: never touch a real developer agent session.
        std::env::set_var(
            "PHANTOM_SSH_PIPE",
            r"\\.\pipe\phantom-vault-ssh-agent-test",
        );
        if is_serving(&pipe_name()) {
            std::env::remove_var("PHANTOM_SSH_PIPE");
            return; // foreign agent on the test pipe — skip, don't steal
        }
        assert!(start_agent(test_keys()).is_ok());
        assert!(session_armed());
        assert!(start_agent(test_keys()).is_err()); // already serving
        stop_agent();
        assert!(!session_armed());
        std::env::remove_var("PHANTOM_SSH_PIPE");
    }

    #[test]
    fn identities_roundtrip() {
        let keys = test_keys();
        let resp = dispatch(&keys, &frame(&[MSG_REQ_IDENTITIES]));
        assert_eq!(resp[0], MSG_IDENTITIES_ANSWER);
        let count = u32::from_be_bytes(resp[1..5].try_into().unwrap());
        assert_eq!(count, 1);
    }

    #[test]
    fn sign_and_verify() {
        use ed25519_dalek::Verifier as _;
        let keys = test_keys();
        let blob = key_blob(&keys[0].pubkey);
        let data = b"ssh-connection-test-data";
        let mut req = vec![MSG_SIGN_REQUEST];
        put_string(&mut req, &blob);
        put_string(&mut req, data);
        req.extend_from_slice(&0u32.to_be_bytes());
        let resp = dispatch(&keys, &req);
        assert_eq!(resp[0], MSG_SIGN_RESPONSE);
        let mut pos = 1;
        let inner = get_string(&resp, &mut pos).unwrap();
        let mut ipos = 0;
        let algo = get_string(&inner, &mut ipos).unwrap();
        let sig = get_string(&inner, &mut ipos).unwrap();
        assert_eq!(algo, b"ssh-ed25519");
        assert_eq!(sig.len(), 64);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&keys[0].pubkey).unwrap();
        vk.verify(
            data,
            &ed25519_dalek::Signature::from_slice(&sig).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn unknown_key_fails() {
        let keys = test_keys();
        let blob = key_blob(&[7u8; 32]);
        let mut req = vec![MSG_SIGN_REQUEST];
        put_string(&mut req, &blob);
        put_string(&mut req, b"data");
        req.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(dispatch(&keys, &req), vec![MSG_FAILURE]);
    }

    #[test]
    fn garbage_fails() {
        let keys = test_keys();
        assert_eq!(dispatch(&keys, &[]), vec![MSG_FAILURE]);
        assert_eq!(dispatch(&keys, &[99]), vec![MSG_FAILURE]);
    }

    #[test]
    fn probe_reports_absent_pipe() {
        assert!(!is_serving(r"\\.\pipe\pv-test-definitely-absent-9f3k2"));
    }

    #[test]
    fn probe_sees_live_pipe() {
        use tokio::net::windows::named_pipe::ServerOptions;
        let name = format!(r"\\.\pipe\pv-test-live-{}", std::process::id());
        // A client open() only completes once the server accepts — mirror a
        // real agent with a background acceptor thread.
        let name_in_thread = name.clone();
        let server_thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                // NOTE: create() itself needs the reactor context in tokio 1.53+.
                let server = ServerOptions::new().create(&name_in_thread).unwrap();
                let _ = server.connect().await;
                std::thread::sleep(std::time::Duration::from_millis(500));
            });
        });
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(is_serving(&name));
        let _ = server_thread.join();
    }

    #[test]
    fn collect_skips_non_ssh_titles() {
        use crate::models::{Credential, Vault};
        let mut v = Vault::new();
        v.credentials.push(Credential {
            id: "1".into(),
            title: "GitHub".into(),
            username: "u".into(),
            password: "p".into(),
            totp_secret: String::new(),
            urls: Vec::new(),
            apps: Vec::new(),
            backup_codes: Vec::new(),
            custom_fields: Vec::new(),
            notes: String::new(),
                    folder: crate::models::DEFAULT_FOLDER.to_string(),
                
            reprompt: false,
        
                    attachments: Vec::new(),
                    travel_safe: false,
                    last_changed: crate::models::current_timestamp(),
                    password_history: Vec::new(),
                    favorite: false,
                    deleted_at: None,
                });
        assert!(collect_keys(&v).is_empty());
    }
}
