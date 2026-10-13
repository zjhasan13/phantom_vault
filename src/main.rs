// GUI subsystem: no console window beside the app. stdio pipes (native-host
// bridge) keep working - only the visible console is suppressed.
#![windows_subsystem = "windows"]

#[allow(dead_code)]
mod crypto;
#[allow(dead_code)]
mod models;
#[allow(dead_code)]
mod storage;
mod totp_engine;
// Diet: mi-malloc returns freed pages to Windows instead of hoarding heap.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
mod authenticator;
mod core;
mod developer;
mod error;
mod importer;
mod security;
mod sync;
mod windows_native;

use arboard::Clipboard;
use authenticator::universal_2fa::{
    self, merge_2fa_with_policy, strip_dup_suffix, DupConflict, DupPolicy, MergeReport,
    DUP_SUFFIX,
};
use core::generator::{PasswordGenerator, PasswordPolicy};
use data_encoding::BASE32_NOPAD;
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use models::{dup_key, dup_marks, Credential, TotpAccount, Vault};
use slint::{ComponentHandle, Model, ModelRc, VecModel};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use storage::save_vault_secret;
use zeroize::Zeroize;

slint::include_modules!();

const VAULT_FILE: &str = "my_secure_vault.enc";

/// Minimum seconds a TOTP code must have left before we let it be copied.
///
/// Not cosmetic: with ~3s remaining, a code can expire between the click and
/// the user pasting it into a login form, and a rejected code reads as "my
/// authenticator is broken" rather than "you were too slow". 3s is the point
/// where typing a password plus submitting is no longer reliably possible.
/// HOTP is exempt — it has no expiry window.
const TOTP_COPY_GUARD_SECS: u64 = 3;
const HELLO_TOKEN_FILE: &str = "vault_hello.dpapi";
/// Bridge liveness beacon (NOT a secret — just a timestamp). Written every
/// 20s while unlocked; the native host refuses to serve when stale (>75s).
/// Closing/crashing the app stops the beats, so a leftover Hello token file
/// alone can NEVER unlock the bridge (P1: closed-app serving).
const HEARTBEAT_FILE: &str = "vault_heartbeat.json";

/// Start the bridge heartbeat after an unlock (real or decoy cover — the
/// decoy bridge is designed to serve, so it needs liveness too). Idempotent:
/// re-unlocking while a beater lives just adds a redundant writer; every
/// beater exits on its own once the master store is wiped (lock).
fn start_bridge_heartbeat(master: &Arc<Mutex<Option<SecretString>>>) {
    let _ = std::fs::write(HEARTBEAT_FILE, crate::models::current_timestamp().to_string());
    let m = Arc::clone(master);
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(20));
        if lock_master_pw(&m).as_ref().is_none() {
            break;
        }
        let _ = std::fs::write(HEARTBEAT_FILE, crate::models::current_timestamp().to_string());
    });
}

/// Stop the beats (lock + exit paths). The Hello token is removed by the
/// existing lock scrub; both files die here so neither survives app exit.
fn stop_bridge_heartbeat() {
    let _ = std::fs::remove_file(HEARTBEAT_FILE);
    let _ = std::fs::remove_file(HELLO_TOKEN_FILE);
}

/// PR-1: seal the master passphrase for Hello unlocks (single choke point).
/// Used by the auto path in `unlock_with_password` and the explicit
/// New-Device [Re-enroll Hello] button. Returns true on success.
fn seal_hello_token(master: &SecretString) -> bool {
    match core::memory::DpapiGuard::protect(master.expose_secret().as_bytes()) {
        Ok(blob) => std::fs::write(HELLO_TOKEN_FILE, blob).is_ok(),
        Err(_) => false,
    }
}

/// PR-1: true when a Hello token file exists but cannot be unprotected
/// (foreign-machine/user DPAPI seal, or corruption). Missing file means
/// "never enrolled" — not a new-device signal. Pure filesystem probe.
fn is_hello_token_unreadable_at(path: &std::path::Path) -> bool {
    match std::fs::read(path) {
        Err(_) => false,
        Ok(blob) => core::memory::DpapiGuard::unprotect(&blob).is_err(),
    }
}

fn is_hello_token_unreadable() -> bool {
    is_hello_token_unreadable_at(std::path::Path::new(HELLO_TOKEN_FILE))
}

/// Native-host launch detector: humans type `native-host`, but Chromium
/// launches the bridge as `<exe> chrome-extension://<id>/ [...]` (origin URL
/// as argv[1]). Both spellings must enter the stdio serve loop — otherwise
/// Chrome sees a code-2 exit and the popup hangs on "Loading…".
/// Pure — unit tested.
fn is_native_host_launch(arg: &str) -> bool {
    arg == "native-host" || arg.starts_with("chrome-extension://")
}

fn tokio_rt() -> Option<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .ok()
}

/// Phase 13 (+23 chain): minimize (NEVER hide) our windows, then keystroke-fill.
/// Clipboard is never touched. Runs fully on a worker thread.
///
/// Crash root-cause (fixed): `MainWindow::hide()` left zero visible windows,
/// so the Slint/winit event loop tore everything down. Minimizing releases
/// focus while keeping the loop alive.
///
/// Phase 23: when `totp_secret` is non-empty, a 30s UIA watcher arms after the
/// password Enter. If an OTP screen appears, the live code is typed + Enter,
/// hands-free. Secrets ride zeroizing wrappers and die with the thread.
///
/// Unified auto-type request: logins type user{TAB}pass{ENTER} (golden path),
/// cards type number{TAB}MM/YY{TAB}CVV, identities type
/// name{TAB}email{TAB}phone{TAB}address (no submit). `last_changed == 0`
/// means "unknown" and skips the stale nudge (only logins track rotation).
struct TypeRequest {
    kind: i32,
    fields: Vec<String>,
    press_enter: bool,
    item_id: String,
    item_title: String,
    last_changed: u64,
    totp_secret: String,
}

/// Build a TypeRequest from the vault by (kind, id). Returns None for
/// unknown ids or trashed items (trashed items never auto-type).
fn type_request_for(vault: &Vault, kind: i32, id: &str) -> Option<TypeRequest> {
    match kind {
        1 => vault.credentials.iter().find(|c| c.id == id && c.deleted_at.is_none()).map(|c| TypeRequest {
            kind,
            fields: vec![c.username.clone(), c.password.clone()],
            press_enter: true,
            item_id: c.id.clone(),
            item_title: c.title.clone(),
            last_changed: c.last_changed,
            totp_secret: c.totp_secret.clone(),
        }),
        2 => vault.licenses.iter().find(|l| l.id == id && l.deleted_at.is_none()).map(|l| TypeRequest {
            kind,
            fields: vec![l.license_key.clone()],
            press_enter: false,
            item_id: l.id.clone(),
            item_title: l.app_name.clone(),
            last_changed: 0,
            totp_secret: String::new(),
        }),
        3 => vault.notes.iter().find(|n| n.id == id && n.deleted_at.is_none()).map(|n| TypeRequest {
            kind,
            fields: vec![n.content.clone()],
            press_enter: false,
            item_id: n.id.clone(),
            item_title: n.title.clone(),
            last_changed: 0,
            totp_secret: String::new(),
        }),
        // Card: separate MM / YY boxes are the checkout norm — 4 TAB stops.
        4 => vault.cards.iter().find(|k| k.id == id && k.deleted_at.is_none()).map(|k| TypeRequest {
            kind,
            fields: vec![
                k.card_number.clone(),
                k.exp_month.trim().to_string(),
                k.exp_year.trim().to_string(),
                k.cvv.clone(),
            ],
            press_enter: false,
            item_id: k.id.clone(),
            item_title: k.title.clone(),
            last_changed: 0,
            totp_secret: String::new(),
        }),
        5 => vault.identities.iter().find(|i| i.id == id && i.deleted_at.is_none()).map(|i| TypeRequest {
            kind,
            fields: vec![i.full_name.clone(), i.email.clone(), i.phone.clone(), i.address.clone()],
            press_enter: false,
            item_id: i.id.clone(),
            item_title: i.title.clone(),
            last_changed: 0,
            totp_secret: String::new(),
        }),
        6 => vault.ssh_keys.iter().find(|s| s.id == id && s.deleted_at.is_none()).map(|s| TypeRequest {
            kind,
            fields: vec![s.private_key.clone()],
            press_enter: false,
            item_id: s.id.clone(),
            item_title: s.title.clone(),
            last_changed: 0,
            totp_secret: String::new(),
        }),
        // Standalone 2FA (kind 8): Fill types the FRESH live code (no Enter).
        // Computed at request time so it never goes stale like a list snapshot.
        8 => vault.totp_accounts.iter().find(|a| a.id == id).map(|a| {
            let code = crate::totp_engine::generate_code_for_account(a)
                .map(|(c, _)| c)
                .unwrap_or_else(|_| "------".to_string());
            TypeRequest {
                kind,
                fields: vec![code],
                press_enter: false,
                item_id: a.id.clone(),
                item_title: if a.issuer.is_empty() { a.account_name.clone() } else { a.issuer.clone() },
                last_changed: 0,
                totp_secret: String::new(),
            }
        }),
        _ => None,
    }
}

const STALE_TYPE_SECS: u64 = 180 * 24 * 3600;

/// Login fast-path with vault metadata (title/last_changed for audit +
/// stale nudge); falls back to the passed values when the id is unknown.
fn login_type_request(
    vault: &Vault,
    id: &str,
    user: &str,
    pass: &str,
    totp: &str,
) -> TypeRequest {
    if let Some(r) = type_request_for(vault, 1, id) {
        return r;
    }
    TypeRequest {
        kind: 1,
        fields: vec![user.to_string(), pass.to_string()],
        press_enter: true,
        item_id: id.to_string(),
        item_title: String::new(),
        last_changed: 0,
        totp_secret: totp.to_string(),
    }
}

/// Moat #4: hands-free 2FA chain switch (`chain_2fa.pref`).
/// Missing file = ON (existing behavior preserved).
fn chain_2fa_enabled() -> bool {
    std::fs::read_to_string("chain_2fa.pref")
        .map(|s| s.trim() != "0")
        .unwrap_or(true)
}

fn trigger_autotype(
    main_weak: slint::Weak<MainWindow>,
    qb_weak: slint::Weak<QuickBarWindow>,
    qb_visible: Arc<std::sync::atomic::AtomicBool>,
    ui_visible: Arc<std::sync::atomic::AtomicBool>,
    req: TypeRequest,
) {
    use windows_native::autotype::{type_card, type_fields, type_identity, type_sequence};
    // Spoof guard FIRST (before minimizing — minimizing changes foreground).
    // A typosquat/leet executable refuses the keystrokes entirely.
    if let Ok(ctx) = windows_native::desktop_autofill::inspect_active_context() {
        if let Some(brand) =
            windows_native::desktop_autofill::executable_spoof_brand(&ctx.exe_name)
        {
            let msg = format!(
                "🚨 App-Spoof Hazard: Suspicious executable '{}' detected (impersonating {})! Auto-type blocked for security.",
                if ctx.exe_name.is_empty() { "?" } else { &ctx.exe_name },
                brand
            );
            crate::security::access_log::log_event("autotype-blocked-spoof", &ctx.exe_name);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = main_weak.upgrade() {
                    ui.set_notification_text(msg.into());
                }
            });
            return;
        }
    }
    if let Some(ui) = main_weak.upgrade() {
        ui.set_notification_text("⌨️ vault minimized — focus the target field…".into());
        ui.window().set_minimized(true);
    }
    // Resource diet: loops deep-sleep while the main window is down.
    ui_visible.store(false, std::sync::atomic::Ordering::SeqCst);
    if let Some(qb) = qb_weak.upgrade() {
        qb.hide().ok();
    }
    qb_visible.store(false, std::sync::atomic::Ordering::SeqCst);
    thread::spawn(move || {
        // Even an unexpected panic mid-typing must restore the window —
        // never leave the user staring at a vanished vault.
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Batch-1: sensitive fields ride VirtualLock-pinned pages.
            // Login golden path keeps byte-identical type_sequence behavior.
            match req.kind {
                4 if req.fields.len() == 4 => type_card(
                    &req.fields[0],
                    &req.fields[1],
                    &req.fields[2],
                    &req.fields[3],
                ),
                5 if req.fields.len() == 4 => type_identity(
                    &req.fields[0],
                    &req.fields[1],
                    &req.fields[2],
                    &req.fields[3],
                ),
                _ => {
                    if req.press_enter && req.fields.len() == 2 {
                        // Heap-pinned: LockedBytes locks the actual password
                        // bytes (generic LockedMemory would pin only the
                        // 24-byte String fat pointer).
                        let secret = core::memory::LockedBytes::new(
                            req.fields[1].clone().into_bytes(),
                        )
                        .map_err(|e| crate::error::VaultError::AutoType(e.to_string()))?;
                        let out = type_sequence(&req.fields[0], secret.expose_str());
                        drop(secret);
                        out
                    } else {
                        let refs: Vec<&str> = req.fields.iter().map(|s| s.as_str()).collect();
                        type_fields(&refs, req.press_enter)
                    }
                }
            }
        }))
        .map_err(|_| {
            crate::error::VaultError::AutoType("typing aborted unexpectedly".into())
        })
        .and_then(|r| r);
        let ok = res.is_ok();
        if ok {
            // Fill audit: sidecar (popup "Last filled" + dashboard) + access log.
            windows_native::native_host::record_ext_fill(&req.item_id);
            crate::security::access_log::log_event("autotype/fill", &req.item_title);
        }
        let stale = ok
            && req.last_changed != 0
            && crate::models::current_timestamp().saturating_sub(req.last_changed)
                > STALE_TYPE_SECS;
        let chained = ok && !req.totp_secret.trim().is_empty() && chain_2fa_enabled();
        // Arm the 2FA watcher BEFORE restoring UI (overlaps the app's
        // password-submit round-trip instead of serializing after it).
        let chain_handle = chained.then(|| {
            let weak = main_weak.clone();
            let mut secret = req.totp_secret.trim().to_string();
            thread::spawn(move || {
                let code = chain_2fa_watch(&secret);
                {
                    use zeroize::Zeroize;
                    secret.zeroize();
                }
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        match code {
                            Some(_) => ui.set_notification_text(
                                "⚡ Auto-filled 2FA verification code hands-free!".into(),
                            ),
                            None => ui.set_notification_text(
                                "⌨️ Typed — no OTP screen appeared within 30s.".into(),
                            ),
                        }
                    }
                });
            })
        });
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = main_weak.upgrade() {
                // Restore BEFORE touching UI so the user sees the result.
                ui.window().set_minimized(false);
                ui.show().ok();
                ui_visible.store(true, std::sync::atomic::Ordering::SeqCst);
                match &res {
                    Ok(()) => {
                        if stale {
                            ui.set_notification_text(
                                "⚠️ Auto-typed: Password is over 6 months old. Consider updating it.".into(),
                            );
                        } else if chain_handle.is_none() {
                            ui.set_notification_text(
                                "⌨️ Typed — clipboard never touched.".into(),
                            );
                        }
                    }
                    Err(e) => ui.set_notification_text(format!("⚠️ Auto-Type: {e}").into()),
                }
            }
        });
    });
}

/// Phase 23: 30s OTP watch. Polls for an OTP screen, then types the live
/// code + Enter. Returns Some on success. All secrets zeroized on the way out.
fn chain_2fa_watch(totp_secret: &str) -> Option<()> {
    use core::memory::LockedBytes;
    use windows_native::desktop_autofill::otp_screen_visible;
    let secret = LockedBytes::new(totp_secret.trim().to_string().into_bytes()).ok()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if otp_screen_visible() {
            std::thread::sleep(Duration::from_millis(300));
            let (code, _) = totp_engine::generate_live_code(secret.expose_str()).ok()?;
            let mut code = code;
            let typed =
                windows_native::autotype::type_text_raw(&code, true).is_ok();
            {
                use zeroize::Zeroize;
                code.zeroize();
            }
            drop(secret);
            return typed.then_some(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    drop(secret);
    None
}

/// Phase 20: single choke-point for EVERY secret copy in the app.
/// Win+V + cloud excluded, guarded auto-clear (dynamic timeout secs). If the
/// native path fails, falls back to arboard (still auto-cleared).
fn secure_copy_with_feedback(
    main_weak: slint::Weak<MainWindow>,
    text: String,
    copied_msg: &str,
    auto_clear_secs: u64,
) {
    let weak_ok = main_weak.clone();
    let weak_clear = main_weak.clone();
    let weak_fb_msg = main_weak.clone();
    let weak_fb_clear = main_weak.clone();
    let msg = copied_msg.to_string();
    let secs = auto_clear_secs.clamp(5, 300);
    // Access trail: WHAT was copied never enters the log — only THAT a copy
    // happened. Coercion-time review stays possible without new leakage.
    security::access_log::log_event("copy", "clipboard");
    // Pastejacking guard (rules Cat 4): hidden CR/LF, ANSI escapes, and shell
    // traps never reach the clipboard from any copy path (autotype already
    // strips via the same helper).
    let text = windows_native::autotype::sanitize_field(&text);
    if text.is_empty() {
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak_ok.upgrade() {
                ui.set_notification_text("⚠️ Nothing safe to copy.".into());
                ui.set_notification_kind("warn".into());
            }
        });
        return;
    }
    let fb_msg = format!("📋 Copied (fallback path — auto-clearing in {secs}s)");
    match windows_native::clipboard::copy_sensitive(&text, secs, move || {
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak_clear.upgrade() {
                ui.set_notification_text("🧹 Clipboard auto-cleared for security!".into());
                ui.set_notification_kind("info".into());
            }
        });
    }) {
        Ok(()) => {
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak_ok.upgrade() {
                    ui.set_notification_text(msg.into());
                    ui.set_notification_kind("success".into());
                }
            });
        }
        Err(_) => {
            if let Ok(mut clipboard) = Clipboard::new() {
                let _ = clipboard.set_text(text.as_str());
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak_fb_msg.upgrade() {
                        ui.set_notification_text(fb_msg.into());
                    }
                });
                thread::spawn(move || {
                    thread::sleep(Duration::from_secs(secs));
                    if let Ok(mut cb) = Clipboard::new() {
                        let _ = cb.clear();
                    }
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak_fb_clear.upgrade() {
                            ui.set_notification_text("🧹 Clipboard auto-cleared for security!".into());
                        }
                    });
                });
            }
        }
    }
}

/// Copy-button flash: records WHAT was copied (text + item id) so buttons
/// flip to ✓, then clears after 1.5s. Generation-guarded: rapid copies
/// restart the window instead of flickering or clearing early.
fn copy_generation() -> &'static std::sync::atomic::AtomicU64 {
    static GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    &GEN
}

fn mark_copied(main_weak: slint::Weak<MainWindow>, text: String, id: String) {
    use std::sync::atomic::Ordering::SeqCst;
    let gen = copy_generation().fetch_add(1, SeqCst) + 1;
    let weak = main_weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_last_copied(text.into());
            ui.set_last_copied_id(id.into());
        }
    });
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(1500));
        if copy_generation().load(SeqCst) != gen {
            return;
        }
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = main_weak.upgrade() {
                ui.set_last_copied(String::new().into());
                ui.set_last_copied_id(String::new().into());
            }
        });
    });
}

/// Shred targets for a factory reset inside `dir`: primary vault, rotated
/// generations, decoy container, Hello token, and every DPAPI seal.
/// Prefs/schedules/icon cache are not secret stores — kept. Pure over the
/// directory listing — unit tested with a temp dir.
fn collect_factory_targets_in(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for name in [
        VAULT_FILE,
        &format!("{VAULT_FILE}.bak"),
        security::decoy::DECOY_FILE,
        HELLO_TOKEN_FILE,
        security::app_pin::PIN_FILE,
        security::app_pin::PIN_ATTEMPTS_FILE,
        security::ext_pin::EXT_PIN_FILE,
        // Bridge liveness beacon: stale alone can't serve (no token), but
        // a reset must leave zero bridge state behind.
        HEARTBEAT_FILE,
        // PR-3: a reset vault genuinely has no sheet — warn again.
        RECOVERY_EXPORTED_FILE,
    ] {
        let p = dir.join(name);
        if p.is_file() && !out.contains(&p) {
            out.push(p);
        }
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let p = e.path();
            if !p.is_file() || out.contains(&p) {
                continue;
            }
            if name.ends_with(".dpapi")
                || (name.starts_with("my_secure_vault.bak.") && name.ends_with(".enc"))
            {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// One-shot recovery-sheet nudge state (`shards_nudged.pref`). Missing = nag.
fn shard_nudge_seen() -> bool {
    std::fs::read_to_string("shards_nudged.pref")
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

fn mark_shard_nudged() {
    let _ = std::fs::write("shards_nudged.pref", "1");
}

/// PR-3: persistent recovery-sheet export state (`recovery_exported.pref`,
/// separate from the nudge pref). Missing/anything-else = "Not Backed Up".
const RECOVERY_EXPORTED_FILE: &str = "recovery_exported.pref";

fn recovery_exported_at(path: &std::path::Path) -> bool {
    std::fs::read_to_string(path)
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

fn recovery_exported() -> bool {
    recovery_exported_at(std::path::Path::new(RECOVERY_EXPORTED_FILE))
}

fn mark_recovery_exported() {
    let _ = std::fs::write(RECOVERY_EXPORTED_FILE, "1");
}

/// Shared Shamir-split core behind Settings + the post-setup nudge banner.
/// Needs an unlocked master; decoy vaults have no recovery sheet.
fn generate_shards_into(ui: &MainWindow, master_arc: &Arc<Mutex<Option<SecretString>>>) {
    if ui.get_is_decoy() {
        ui.set_sync_status("⛔ Decoy mode has no recovery sheet.".into());
        return;
    }
    let master_opt = lock_master_pw(master_arc).clone();
    let Some(master_pw) = master_opt else {
        ui.set_sync_status("⚠️ Vault not unlocked.".into());
        return;
    };
    if master_pw.expose_secret().len() > security::shamir::WORD_SECRET_MAX {
        ui.set_sync_status("⚠️ Master password over 64 bytes — shorten it to print shards.".into());
        return;
    }
    match security::shamir::Shamir::split(master_pw.expose_secret()) {
        Ok(sheets) => {
            ui.set_shard_1(sheets[0].clone().into());
            ui.set_shard_2(sheets[1].clone().into());
            ui.set_shard_3(sheets[2].clone().into());
            ui.set_shard_4(sheets[3].clone().into());
            ui.set_shard_5(sheets[4].clone().into());
            ui.set_show_shards(true);
            ui.set_sync_status("📄 Sheet ready — print on paper, then Hide.".into());
        }
        Err(e) => {
            ui.set_sync_status(format!("⚠️ {e}").into());
        }
    }
}

/// Post-shred UI landing: purged models, locked shell, clean onboarding
/// wizard. Runs on the event loop after RAM + disk are already clean.
fn finish_factory_reset_ui(ui: &MainWindow, qb: &slint::Weak<QuickBarWindow>) {
    ui.set_credentials(ModelRc::new(VecModel::from(Vec::<CredentialView>::new())));
    ui.set_total_matches_count(0);
    ui.set_auth_accounts(ModelRc::new(VecModel::from(Vec::<AuthView>::new())));
    ui.set_auth_rows(ModelRc::new(VecModel::from(Vec::<ModelRc<AuthView>>::new())));
    ui.set_passkeys(ModelRc::new(VecModel::from(Vec::<PasskeyView>::new())));
    ui.set_passkeys_trash(ModelRc::new(VecModel::from(Vec::<PasskeyView>::new())));
    if let Some(q) = qb.upgrade() {
        q.set_filtered_results(ModelRc::new(VecModel::from(Vec::<CredentialView>::new())));
    }
    ui.set_d_id(String::new().into());
    ui.set_show_detail(false);
    ui.set_show_factory_reset(false);
    ui.set_fr_password(String::new().into());
    ui.set_fr_delete_text(String::new().into());
    ui.set_fr_error(String::new().into());
    ui.set_fr_armed(false);
    ui.set_fr_countdown(0);
    ui.set_is_unlocked(false);
    ui.set_is_decoy(false);
    ui.set_has_vault_file(false);
    ui.set_show_onboarding(true);
    ui.set_onboarding_step(1);
    ui.set_ob_strength_label(String::new().into());
    ui.set_ob_strength_frac(0.0);
    ui.set_ob_error(String::new().into());
    ui.set_ob_new_text(String::new().into());
    ui.set_ob_confirm_text(String::new().into());
    set_trash_label(ui, &Vault::new());
    security::access_log::log_event("factory-reset", "shred");
}

/// C1 Hardening: poison-recovering lock helpers. A panic in one worker must
/// never death-spiral the rest of the app — recover the inner state, warn
/// once on stderr, and carry on.
fn lock_vault(arc: &Arc<Mutex<Vault>>) -> std::sync::MutexGuard<'_, Vault> {
    arc.lock().unwrap_or_else(|poisoned| {
        eprintln!("⚠️ Warning: Vault mutex was poisoned, recovering inner state safely.");
        poisoned.into_inner()
    })
}

fn lock_master_pw(
    arc: &Arc<Mutex<Option<SecretString>>>,
) -> std::sync::MutexGuard<'_, Option<SecretString>> {
    arc.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Phase 25: poison-recovering lock for the proximity config (same pattern
/// as `lock_vault` — a panicked worker must never wedge the Settings page).
fn prox_config_lock(
    arc: &Arc<Mutex<windows_native::proximity_lock::ProximityConfig>>,
) -> std::sync::MutexGuard<'_, windows_native::proximity_lock::ProximityConfig> {
    arc.lock().unwrap_or_else(|poisoned| {
        eprintln!("⚠️ Warning: proximity config mutex was poisoned, recovering.");
        poisoned.into_inner()
    })
}

/// Phase 15 (Option 1): best-effort RAM wipe of all vault secrets.
/// Called by the Panic Nuke hotkey and the anti-debug watchdog, right
/// before hard exit. OS reclaims the rest on process death.
fn panic_wipe(vault_arc: &Arc<Mutex<Vault>>, master_arc: &Arc<Mutex<Option<SecretString>>>) {
    use zeroize::Zeroize;
    if let Ok(mut vault) = vault_arc.lock() {
        for c in vault.credentials.iter_mut() {
            c.id.zeroize();
            c.title.zeroize();
            c.username.zeroize();
            c.password.zeroize();
            c.totp_secret.zeroize();
            c.urls.zeroize();
            c.notes.zeroize();
            for a in c.attachments.iter_mut() {
                a.id.zeroize();
                a.filename.zeroize();
                a.mime_type.zeroize();
                a.data.zeroize();
            }
            c.attachments.clear();
        }
        vault.credentials.clear();
        for t in vault.totp_accounts.iter_mut() {
            t.id.zeroize();
            t.account_name.zeroize();
            t.issuer.zeroize();
            t.secret.zeroize();
        }
        vault.totp_accounts.clear();
        for l in vault.licenses.iter_mut() {
            l.id.zeroize();
            l.app_name.zeroize();
            l.license_key.zeroize();
            l.expiry_date.zeroize();
            for a in l.attachments.iter_mut() {
                a.id.zeroize();
                a.filename.zeroize();
                a.mime_type.zeroize();
                a.data.zeroize();
            }
            l.attachments.clear();
        }
        vault.licenses.clear();
        for n in vault.notes.iter_mut() {
            n.id.zeroize();
            n.title.zeroize();
            n.content.zeroize();
        }
        vault.notes.clear();
        for k in vault.cards.iter_mut() {
            k.id.zeroize();
            k.title.zeroize();
            k.cardholder_name.zeroize();
            k.card_number.zeroize();
            k.exp_month.zeroize();
            k.exp_year.zeroize();
            k.cvv.zeroize();
            k.notes.zeroize();
        }
        vault.cards.clear();
        for i in vault.identities.iter_mut() {
            i.id.zeroize();
            i.title.zeroize();
            i.full_name.zeroize();
            i.nid_or_passport.zeroize();
            i.email.zeroize();
            i.phone.zeroize();
            i.address.zeroize();
            i.notes.zeroize();
        }
        vault.identities.clear();
        for s in vault.ssh_keys.iter_mut() {
            s.id.zeroize();
            s.title.zeroize();
            s.public_key.zeroize();
            s.private_key.zeroize();
            s.fingerprint.zeroize();
            s.notes.zeroize();
        }
        vault.ssh_keys.clear();
        // Resident passkey seeds are the hottest material in RAM — scrub first-class.
        for p in vault.passkeys.iter_mut() {
            p.id.zeroize();
            p.rp_id.zeroize();
            p.user_name.zeroize();
            p.user_handle.zeroize();
            p.credential_id.zeroize();
            p.private_key_pkcs8.zeroize();
            p.public_key_der.zeroize();
        }
        vault.passkeys.clear();
    }
    // SecretString zeroizes its heap buffer on drop — take + drop IS the wipe.
    if let Ok(mut master) = master_arc.lock() {
        drop(master.take());
    }
}

/// Shared lock path (inactivity, session-lock, manual): RAM wipe via
/// panic_wipe + unconditional clipboard flush (a copied secret must never
/// outlive the session) + access-log line + lock-screen UI.
///
/// Audit finding: the Rust vault was wiped but Slint-side models/props
/// (detail secrets, history, form drafts, health badges) survived in UI-layer
/// RAM — exactly what Mimikatz-style dumping hunts. Everything secret-shaped
/// below is scrubbed here; the next unlock repopulates from disk.
/// UI-callback arity is structural (8 principals: two windows, vault, master,
// drafts, editing state + status strings). Split would churn 40 call sites.
#[allow(clippy::too_many_arguments)]
fn lock_vault_now(
    main_weak: slint::Weak<MainWindow>,
    cap_weak: slint::Weak<QuickCaptureWindow>,
    vault_arc: &Arc<Mutex<Vault>>,
    master_arc: &Arc<Mutex<Option<SecretString>>>,
    pending_cf: &Arc<Mutex<Vec<models::CustomField>>>,
    editing_item: &Arc<Mutex<Option<(i32, String)>>>,
    status_msg: &str,
    log_detail: &str,
) {
    // C4: kill the Hello bridge credential FIRST — otherwise Win+L / idle /
    // proximity lock wipes RAM but leaves vault_hello.dpapi for any process.
    let _ = std::fs::remove_file(HELLO_TOKEN_FILE);
    // P1 fix: stop the bridge beats too — a stale heartbeat refuses serves.
    stop_bridge_heartbeat();
    panic_wipe(vault_arc, master_arc);
    // SSH agent session dies with unlock: signing keys must never outlive
    // the vault (the serving thread exits at its next 1s accept tick).
    developer::ssh_agent::stop_agent();
    // Lightweight release: trim the working set AFTER the wipe (never before —
    // trimming first would page wiped secrets back in on next touch). Locked
    // CPU stays 0% (all loops deep-sleep) and RAM drops to OS-kept pages.
    windows_native::tray::trim_working_set();
    // Unsent form drafts (may hold Hidden custom-field secrets).
    if let Ok(mut p) = pending_cf.lock() {
        p.clear();
    }
    if let Ok(mut e) = editing_item.lock() {
        *e = None;
    }
    // Stale audit badges must never bleed into the next vault/decoy.
    if let Ok(mut reg) = health_registry().lock() {
        reg.clear();
    }
    windows_native::clipboard::flush_now();
    security::access_log::log_event("lock", log_detail);
    let weak = main_weak.clone();
    let cap = cap_weak.clone();
    let status = status_msg.to_string();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        ui.set_is_unlocked(false);
        ui.set_status_text(status.into());
        ui.set_notification_text("🔒 Vault locked.".into());
        // Bulk-select is session state, never persisted — drop it with the
        // secret-holding models so a stale check can't survive re-unlock.
        selection_registry().lock().unwrap_or_else(|p| p.into_inner()).clear();
        // Staged import rows are plaintext-adjacent — never survive lock.
        // H8: poison-recovering (a poisoned mutex under panic=abort would
        // otherwise kill the lock-scrub mid-wipe, leaving secrets in UI).
        *pending_import_store().lock().unwrap_or_else(|p| p.into_inner()) = None;
        clear_favicon_bytes();
        ui.set_select_mode(false);
        ui.set_selected_count(0);
        ui.set_selected_label(String::new().into());
        // Purge every secret-holding list model…
        ui.set_credentials(ModelRc::new(VecModel::from(Vec::<CredentialView>::new())));
        ui.set_total_matches_count(0);
        ui.set_auth_accounts(ModelRc::new(VecModel::from(Vec::<AuthView>::new())));
        ui.set_auth_rows(ModelRc::new(VecModel::from(Vec::<ModelRc<AuthView>>::new())));
        ui.set_passkeys(ModelRc::new(VecModel::from(Vec::<PasskeyView>::new())));
        ui.set_passkeys_trash(ModelRc::new(VecModel::from(Vec::<PasskeyView>::new())));
        ui.set_d_custom(ModelRc::new(VecModel::from(Vec::<CustomFieldView>::new())));
        ui.set_d_attachments(ModelRc::new(VecModel::from(Vec::<AttachmentView>::new())));
        ui.set_d_history(ModelRc::new(VecModel::from(Vec::<HistoryView>::new())));
        ui.set_custom_fields(ModelRc::new(VecModel::from(Vec::<CustomFieldView>::new())));
        // …and every secret-holding scalar prop (detail, forms, modals).
        ui.set_d_id(String::new().into());
        ui.set_d_title(String::new().into());
        ui.set_d_user(String::new().into());
        ui.set_d_secret(String::new().into());
        ui.set_d_meta(String::new().into());
        ui.set_d_url(String::new().into());
        ui.set_d_notes(String::new().into());
        ui.set_d_urls_extra(String::new().into());
        ui.set_d_folder(String::new().into());
        ui.set_d_totp(String::new().into());
        ui.set_d_backup(String::new().into());
        ui.set_d_secret_visible(false);
        ui.set_d_pw_strength(0.0);
        ui.set_d_pw_strength_label(String::new().into());
        ui.set_show_detail(false);
        ui.set_show_pin_pad(false);
        ui.set_pin_error(String::new().into());
        ui.set_f_title(String::new().into());
        ui.set_f_a(String::new().into());
        ui.set_f_b(String::new().into());
        ui.set_f_c(String::new().into());
        ui.set_f_urls(ModelRc::new(VecModel::from(Vec::<slint::SharedString>::new())));
        ui.set_f_url_rules(ModelRc::new(VecModel::from(Vec::<i32>::new())));
        ui.set_f_d(String::new().into());
        ui.set_f_e(String::new().into());
        ui.set_f_company(String::new().into());
        ui.set_f_city(String::new().into());
        ui.set_f_state(String::new().into());
        ui.set_f_zip(String::new().into());
        ui.set_f_country(String::new().into());
        ui.set_f_notes(String::new().into());
        ui.set_f_totp(String::new().into());
        ui.set_f_backup(String::new().into());
        ui.set_import_input(String::new().into());
        // Capture-window drafts live on the other component — purge there.
        if let Some(cap) = cap.upgrade() {
            cap.set_cap_title(String::new().into());
            cap.set_cap_user(String::new().into());
            cap.set_cap_pass(String::new().into());
            cap.set_cap_totp(String::new().into());
            cap.hide().ok();
        }
        ui.set_pk_rp(String::new().into());
        ui.set_pk_user(String::new().into());
        ui.set_cf_name(String::new().into());
        ui.set_cf_value(String::new().into());
        ui.set_duress_input(String::new().into());
        ui.set_rp_id(String::new().into());
        ui.set_rp_user(String::new().into());
        ui.set_rp_secret(String::new().into());
        ui.set_rp_error(String::new().into());
        ui.set_rp_show(false);
        // PR-1: new-device modal must never survive a lock.
        ui.set_show_new_device_modal(false);
        ui.set_new_device_error(String::new().into());
        // SSH agent dies with unlock (stop_agent above) — the button must
        // read Stopped and the status returns to the probe ground truth.
        ui.set_ssh_agent_running(false);
        ui.set_ssh_status("○ Stopped".into());
    });
}

/// Cat 8 global offline kill-switch: ONE toggle silences every network path
/// (GitHub sync + HIBP audit). Process-wide static so all 13 sync call sites
/// and both audit paths honor it with zero signature churn.
static NET_ALLOWED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

fn net_allowed() -> bool {
    NET_ALLOWED.load(std::sync::atomic::Ordering::SeqCst)
}

fn set_net_allowed(on: bool) {
    NET_ALLOWED.store(on, std::sync::atomic::Ordering::SeqCst);
}

/// Phase 15 (Option 1): canary lookup by leaked password material.
/// Returns the tripped honeytoken title (and records the trip) if matched.
fn check_canary_trip(
    vault_arc: &Arc<Mutex<Vault>>,
    password: &str,
    via: &str,
) -> Option<String> {
    let vault = vault_arc.lock().ok()?;
    let found = security::canary::find_canary_by_password(&vault, password)?;
    let title = found.title.clone();
    security::canary::record_trip(&title, via);
    Some(title)
}

/// Phase 12: fire-and-forget push of the local ciphertext blob.
/// Runs on its own thread; never blocks UI. Every early failure is LOUD —
/// silent returns here were the sync-hang culprit (user stared at "Syncing…").
fn trigger_sync_push(main_weak: slint::Weak<MainWindow>) {
    std::thread::spawn(move || {
        // Helper: report a status and stop. Keeps every exit path visible.
        let report = |msg: String| {
            let weak = main_weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    ui.set_sync_status(msg.into());
                }
            });
        };
        // Cat 8 kill-switch: never touch the network when offline.
        if !net_allowed() {
            report("📴 Offline mode — sync skipped.".into());
            return;
        }
        let Ok((cfg, token)) = sync::github_sync::load_credentials() else {
            report("⚠️ Missing credentials. Paste token and click Connect first.".into());
            return;
        };
        let Ok(blob) = std::fs::read(VAULT_FILE) else {
            use zeroize::Zeroize;
            let mut token = token;
            token.zeroize();
            report("⚠️ Local vault file not found on disk.".into());
            return;
        };
        // Token lives only in this worker thread's stack; zeroize on the way out.
        let mut token = token;
        let Some(rt) = tokio_rt() else {
            use zeroize::Zeroize;
            token.zeroize();
            report("⚠️ Could not start network runtime.".into());
            return;
        };
        let head = sync::github_sync::load_head_sha();
        let res = rt.block_on(sync::github_sync::push_remote(
            &cfg.owner,
            &cfg.repo,
            &token,
            &blob,
            head.clone(),
            head,
        ));
        use zeroize::Zeroize;
        token.zeroize();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = main_weak.upgrade() {
                match res {
                    Ok(new_sha) => {
                        sync::github_sync::store_head_sha(&new_sha);
                        ui.set_sync_status("☁️ Synced — ciphertext pushed.".into());
                        ui.set_notification_text("☁️ Vault synced.".into());
                        security::access_log::log_event("sync", "push ok");
                    }
                    Err(e) => {
                        ui.set_sync_status(format!("⚠️ Sync: {e}").into());
                    }
                }
            }
        });
    });
}

/// Phase 12: startup pull. Ciphertext-only; safe pre-unlock (no password needed).
/// - Local missing + remote present → adopt remote, record head sha.
/// - Both present but bytes differ → keep local, warn (never silent-overwrite).
fn run_startup_pull(main_weak: slint::Weak<MainWindow>) {
    // Prefill configured repo into the settings form.
    if let Ok(cfg) = sync::github_sync::load_repo() {
        let weak = main_weak.clone();
        let status = format!(
            "Connected to {}/{} (ciphertext only).",
            cfg.owner, cfg.repo
        );
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_sync_owner(cfg.owner.into());
                ui.set_sync_repo(cfg.repo.into());
                ui.set_sync_status(status.into());
            }
        });
    } else {
        return;
    }
    // Cat 8 kill-switch: prefill stays (local config), network never fires.
    if !net_allowed() {
        let weak = main_weak.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_sync_status("📴 Offline mode — startup pull skipped.".into());
            }
        });
        return;
    }
    std::thread::spawn(move || {
        let Ok((cfg, token)) = sync::github_sync::load_credentials() else {
            return;
        };
        let mut token = token;
        let Some(rt) = tokio_rt() else {
            return;
        };
        let remote =
            rt.block_on(sync::github_sync::pull_remote(&cfg.owner, &cfg.repo, &token));
        use zeroize::Zeroize;
        token.zeroize();
        let Ok(remote) = remote else {
            return;
        };
        let Some((bytes, sha)) = remote else {
            return;
        };
        let local = std::fs::read(VAULT_FILE).unwrap_or_default();
        if local.is_empty() {
            // Fresh device: adopt the remote ciphertext as-is (shred-guarded).
            if security::shredder::secure_write(std::path::Path::new(VAULT_FILE), &bytes).is_ok() {
                sync::github_sync::store_head_sha(&sha);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = main_weak.upgrade() {
                        ui.set_sync_status("⬇️ Vault restored from private repo.".into());
                    }
                });
            }
        } else if local != bytes {
            // Divergence: keep local (never silent-overwrite), flag it.
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = main_weak.upgrade() {
                    ui.set_sync_status(
                        "⚠️ Remote differs — local kept. Press Sync Now after review.".into(),
                    );
                }
            });
        } else {
            sync::github_sync::store_head_sha(&sha);
        }
    });
}

/// Shared unlock pipeline (password + Hello-biometric paths converge here).
/// Heavy Argon2id + disk I/O runs on a background thread; UI updates are
/// dispatched via `slint::invoke_from_event_loop`. When `cache_hello_token`
/// is set, the passphrase is DPAPI-sealed for future Hello unlocks.
/// Cat 8 AND-mode (`and_mode`, password-first flows only): the worker first
/// VERIFIES the password (transient decrypt), immediately zeroizes that copy,
/// and only chains the full publish pipeline after Windows Hello succeeds —
/// so `active_vault`, the UI list, and the master store stay untouched until
/// BOTH factors pass. Costs one extra KDF (~0.3s), never a partial unlock.
/// Phase 27: shared publish pipeline — moves a decrypted vault + proven
/// password into live UI state (lists, folders, QuickBar, sync, tickers).
/// Called by the password arm AND by the TOTP-gate verifier, so both factors
/// converge on one code path. `master_store: None` keeps an already-stashed
/// master (verify path); `Some` stores a fresh one (password path).
#[allow(clippy::too_many_arguments)]
fn publish_unlocked_vault(
    ui: &MainWindow,
    qb_weak: &slint::Weak<QuickBarWindow>,
    vault_arc: &Arc<Mutex<Vault>>,
    master_pw_arc: &Arc<Mutex<Option<SecretString>>>,
    search_state: &Arc<Mutex<FilterState>>,
    ui_visible: &Arc<std::sync::atomic::AtomicBool>,
    vault: Vault,
    master_store: Option<SecretString>,
    purged_n: usize,
    and_downgrade: bool,
) {
    if let Some(pw) = master_store {
        *lock_master_pw(master_pw_arc) = Some(pw);
    }
    // Bridge liveness starts here (P1 fix): the heartbeat proves a live,
    // unlocked app — the Hello token file alone no longer suffices.
    start_bridge_heartbeat(master_pw_arc);
    *search_state.lock().unwrap() = FilterState::default();
    ui.set_search_query("".into());
    ui.set_health_filter("".into());
    // View props must mirror the reset filter — otherwise a
    // pre-lock Trash/Favorites view desyncs from the list.
    ui.set_showing_trash(false);
    ui.set_show_fav_only(false);
    ui.set_show_empty_confirm(false);
    ui.set_type_filter(0);
    ui.set_folder_filter("All".into());
    let mut vault = vault;
    vault.ensure_folders();
    sync_folders_to_ui(&vault, ui);
    let items = vault_to_items(&vault, &FilterState::default());
    ui.set_credentials(items.clone());
    ui.set_total_matches_count(total_matches() as i32);
    set_trash_label(ui, &vault);
    if let Some(qb) = qb_weak.upgrade() {
        qb.set_filtered_results(vault_quickbar(&vault, "", search_state.lock().unwrap().travel_only));
    }
    // Phase 27 mirror: settings card reflects the armed gate (never the secret).
    ui.set_totp2fa_on(vault.totp_unlock_enabled);
    ui.set_totp2fa_secret("".into());
    *lock_vault(vault_arc) = vault;
    ui.set_is_unlocked(true);
    ui.set_show_onboarding(false);
    ui.set_has_vault_file(true);
    ui.set_is_decoy(false);
    ui.set_show_totp_step(false);
    ui.set_totp_step_error("".into());
    ui.set_status_text("✅ Vault unlocked".into());
    // One-shot recovery-sheet nudge (never nagged before → banner until the
    // user Generates or defers; the decoy cover path above stays silent).
    if !shard_nudge_seen() {
        ui.set_show_shard_nudge(true);
    }
    // PR-3: persistent badge state, painted every unlock (portable-USB dir
    // without the pref correctly shows "Not Backed Up").
    ui.set_recovery_backed_up(recovery_exported());
    ui.set_canary_count(
        lock_vault(&vault_arc)
            .credentials
            .iter()
            .filter(|c| security::canary::is_canary(c))
            .count() as i32,
    );
    // Hardware binding (rules Cat 6): warn-only machine check.
    // Registry + DPAPI read is milliseconds — safe inline.
    // PR-1 New-Device Modal (blocking): fires when the vault was bound to a
    // different machine OR the Hello token exists but can't be unprotected
    // (foreign DPAPI seal). Re-shows every unlock until enrolled — no pref.
    let device_mismatch = windows_native::device_bind::check_device();
    if device_mismatch {
        ui.set_notification_text(
            "⚠️ Bound to a different machine (ignore for portable USB).".into(),
        );
    }
    let hello_broken = is_hello_token_unreadable();
    if device_mismatch || hello_broken {
        ui.set_new_device_reason(
            if hello_broken && !device_mismatch {
                "hello-token".into()
            } else {
                "different-machine".into()
            },
        );
        ui.set_show_new_device_modal(true);
    }
    if and_downgrade {
        ui.set_notification_text(
            "⚠️ Two-factor unlock is ON but Hello isn't enrolled — password-only this time.".into(),
        );
    }
    if purged_n > 0 {
        ui.set_notification_text(
            format!("🗑️ {purged_n} expired trash items shredded.").into(),
        );
    }
    security::access_log::log_event("unlock", "password ok");
    trigger_sync_push(ui.as_weak());
    // Favicons resolve in the background (disk first, one gated batch for
    // misses) and pop into the list when ready — unlock never waits.
    trigger_favicon_prefetch(
        Arc::clone(vault_arc),
        Arc::clone(search_state),
        ui.as_weak(),
    );

    // Phase 24: authenticator list now + live refresh ticker.
    // The same 1s loop drives the hero countdown AND rebuilds every grid
    // row each tick, so per-card rings count down in real time (TOTP gen is
    // a few HMACs — negligible; models are built on the event-loop thread).
    {
        let v = lock_vault(vault_arc);
        ui.set_auth_accounts(rebuild_auth_list(&v));
        ui.set_auth_rows(rebuild_auth_rows(&v, ui.get_totp_search_query().as_str()));
        // Fresh unlock resets the filter (see above), so the
        // hub starts unfiltered; trashed keys get their own
        // hub section instead of the sidebar Trash view.
        ui.set_passkeys(rebuild_passkeys(&v, false));
        ui.set_passkeys_trash(rebuild_trashed_passkeys(&v));
    }
    let window_for_totp = ui.as_weak();
    let vault_for_auth = Arc::clone(vault_arc);
    let master_for_auth = Arc::clone(master_pw_arc);
    let visible_for_auth = Arc::clone(ui_visible);
    thread::spawn(move || {
        loop {
            // Resource diet: locked vault or hidden main window → deep sleep
            // in 1s slices (wakes within a second of restore/unlock). No
            // TOTP crypto, no event-loop wakeups: true 0% idle.
            let idle = lock_master_pw(&master_for_auth).is_none()
                || !visible_for_auth.load(std::sync::atomic::Ordering::SeqCst);
            if idle {
                for _ in 0..10 {
                    thread::sleep(Duration::from_secs(1));
                    let awake = lock_master_pw(&master_for_auth).is_some()
                        && visible_for_auth.load(std::sync::atomic::Ordering::SeqCst);
                    if awake {
                        break;
                    }
                }
                continue;
            }
            // Phase 24+Hardening: hero renders the FIRST live
            // 2FA account dynamically (any algorithm/digits)
            // instead of a hardcoded demo secret.
            let hero: Option<(String, String, String)> = {
                let v = lock_vault(&vault_for_auth);
                v.totp_accounts.iter().find_map(|a| {
                    totp_engine::generate_code_for_account(a)
                        .ok()
                        .map(|(code, remaining)| {
                            let label = if a.issuer.is_empty() {
                                a.account_name.clone()
                            } else {
                                format!("{} ({})", a.account_name, a.issuer)
                            };
                            let when = if remaining == u64::MAX {
                                "HOTP".to_string()
                            } else {
                                format!("{remaining}s")
                            };
                            (label, code, when)
                        })
                })
            };
            let window_clone = window_for_totp.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = window_clone.upgrade() {
                    // Prefer the selected item's embedded TOTP so the
                    // Column 3 per-item hero shows a live code; fall back
                    // to the first vault 2FA account otherwise.
                    let selected: Option<(String, String, String)> = {
                        let secret = ui.get_d_totp().to_string();
                        if secret.trim().is_empty() {
                            None
                        } else {
                            totp_engine::generate_live_code(secret.trim()).ok().map(
                                |(code, remaining)| {
                                    let when = if remaining == u64::MAX {
                                        "HOTP".to_string()
                                    } else {
                                        format!("{remaining}s")
                                    };
                                    (ui.get_d_title().to_string(), code, when)
                                },
                            )
                        }
                    };
                    if let Some((label, code, when)) = selected.or(hero) {
                        ui.set_hero_account(label.into());
                        ui.set_live_totp_code(code.into());
                        ui.set_totp_countdown(when.into());
                    } else {
                        ui.set_hero_account("LIVE 2FA".into());
                        ui.set_live_totp_code("------".into());
                        ui.set_totp_countdown("--".into());
                    }
                }
            });
            // Every tick rebuilds the grid models (per-card countdown rings
            // stay live); vault locking is a mutex grab, TOTP gen is trivial.
            // ModelRc is !Send: move the vault handle in,
            // build the model on the event-loop thread.
            let vault_for_row = Arc::clone(&vault_for_auth);
            let window_clone = window_for_totp.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = window_clone.upgrade() {
                    let v = lock_vault(&vault_for_row);
                    ui.set_auth_accounts(rebuild_auth_list(&v));
                    ui.set_auth_rows(rebuild_auth_rows(&v, ui.get_totp_search_query().as_str()));
                }
            });
            thread::sleep(Duration::from_secs(1));
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn unlock_with_password(    pass: SecretString,
    main_weak: slint::Weak<MainWindow>,
    vault_arc: Arc<Mutex<Vault>>,
    master_pw_arc: Arc<Mutex<Option<SecretString>>>,
    search_state: Arc<Mutex<FilterState>>,
    qb_weak: slint::Weak<QuickBarWindow>,
    ui_visible: Arc<std::sync::atomic::AtomicBool>,
    cache_hello_token: bool,
    and_mode: bool,
) {
    if pass.expose_secret().is_empty() {
        if let Some(ui) = main_weak.upgrade() {
            ui.set_status_text("⚠️ Password cannot be empty!".into());
        }
        return;
    }

    if let Some(ui) = main_weak.upgrade() {
        ui.set_unlock_error_message("".into());
        ui.set_status_text("⏳ Decrypting vault (Argon2id)…".into());
    }

    std::thread::spawn(move || {
        // Cat 8 brute-force backoff: pay the delay BEFORE burning Argon2id.
        // UI update goes through the event loop (never touch Slint off-thread).
        let backoff_path = security::backoff::default_path();
        let wait =
            security::backoff::delay_for_failures(security::backoff::read_failures(&backoff_path));
        if wait > 0 {
            let weak = main_weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    ui.set_status_text(
                        format!("⏳ Too many attempts — retrying in {wait}s…").into(),
                    );
                }
            });
            std::thread::sleep(Duration::from_secs(wait));
        }
        // Heavy work: Argon2id KDF + XChaCha20Poly1305 + file I/O
        // (+ ML-KEM-768 hybrid on save, transparent v1→v2 migration on unlock)
        let mut loaded_result: Result<Vault, String> = if Path::new(VAULT_FILE).exists() {
            match storage::load_vault_versioned_secret(&pass, VAULT_FILE) {
                Ok((vault, was_legacy)) => {
                    if was_legacy {
                        // C11: never re-seal blindly over the only good copy.
                        // Stage to .migrating, reload-round-trip, then rename.
                        let stage = format!("{VAULT_FILE}.migrating");
                        match save_vault_secret(&vault, &pass, &stage)
                            .and_then(|_| storage::load_vault_versioned_secret(&pass, &stage)
                                .map(|_| ()))
                        {
                            Ok(()) => {
                                if std::fs::rename(&stage, VAULT_FILE).is_err() {
                                    let _ = std::fs::remove_file(&stage);
                                }
                            }
                            Err(e) => {
                                let _ = std::fs::remove_file(&stage);
                                eprintln!("migration re-seal refused: {e}");
                            }
                        }
                    }
                    Ok(vault)
                }
                Err(e) => Err(e),
            }
        } else {
            // First run: initialize with an obviously-fake demo credential
            // (M18: never ship a live-looking `ghp_` PAT prefix).
            let mut init_vault = Vault::new();
            init_vault.credentials.push(Credential {
                id: "1".into(),
                title: "Example Demo Login".into(),
                username: "demo@example.invalid".into(),
                password: "DEMO-ONLY-REPLACE-ME".into(),
                totp_secret: String::new(),
                backup_codes: Vec::new(),
                custom_fields: Vec::new(),
                urls: vec!["https://github.com".into()],
                notes: "Primary Token".into(),
                    folder: crate::models::DEFAULT_FOLDER.to_string(),
                
                reprompt: false,
            
                    attachments: Vec::new(),
                    travel_safe: false,
                    last_changed: crate::models::current_timestamp(),
                    password_history: Vec::new(),
                    favorite: false,
                    deleted_at: None,
                });
            // M18: no preloaded 2FA secret — the Google-Authenticator docs
            // example is universally known. Users add their own seed.
            init_vault.totp_accounts.push(TotpAccount {
                id: "2".into(),
                account_name: "Example Demo 2FA (add your own seed)".into(),
                issuer: "Example".into(),
                secret: String::new(),
                digits: 6,
                period: 30,
                algorithm: "SHA1".to_string(),
                otp_type: "totp".to_string(),
                counter: 0,
                favorite: false,
            });

            match save_vault_secret(&init_vault, &pass, VAULT_FILE) {
                Ok(()) => Ok(init_vault),
                Err(e) => Err(format!("Failed to create vault: {}", e)),
            }
        };

        // Phase 11: on success, DPAPI-seal the passphrase for Hello unlocks.
        // Failures are silent — Hello simply stays unavailable.
        if cache_hello_token && loaded_result.is_ok() {
            seal_hello_token(&pass);
        }

        // Phase 15 (Option 1): duress fallback. Only attempted when the real
        // vault rejects the password AND a decoy container exists. The extra
        // Argon2id cost lands solely on failed attempts — never on the happy path.
        let decoy_vault: Option<Vault> =
            if loaded_result.is_err() && security::decoy::decoy_exists() {
                security::decoy::try_open_decoy(pass.expose_secret())
            } else {
                None
            };

        // Cat 8 backoff bookkeeping: success clears the counter (never locks
        // the owner out); any real-vault rejection bumps it — even when a
        // decoy cover opens, so guessing can't launder the counter clean.
        match &loaded_result {
            Ok(_) => security::backoff::record_success(&backoff_path),
            Err(_) => security::backoff::record_failure(&backoff_path),
        }

        // Trash retention: shred >30-day trashed items now (best-effort
        // re-seal via the DoD-guarded writer; unlock proceeds regardless).
        // Real vault only — the decoy branch below publishes untouched.
        let purged_n: usize = if let Ok(v) = loaded_result.as_mut() {
            let n = v.purge_expired_trash(
                crate::models::current_timestamp(),
                crate::models::TRASH_RETENTION_SECS,
            );
            if n > 0 {
                let _ = save_vault_secret(v, &pass, VAULT_FILE);
            }
            n
        } else {
            0
        };

        // Cat 8 AND-mode gate (password-first only): the decrypt above was a
        // mere VERIFICATION. Scrub that transient copy now; the publish
        // pipeline below runs only via a chained second unlock AFTER Hello
        // succeeds — active_vault, UI, and master store stay sealed until
        // BOTH factors pass. No cached Hello credential ⇒ loud downgrade to
        // password-only (the success branch announces it).
        let hello_enrolled = Path::new(HELLO_TOKEN_FILE).exists();
        if and_mode && loaded_result.is_ok() && decoy_vault.is_none() && hello_enrolled
        {
            if let Ok(v) = loaded_result.as_mut() {
                zeroize::Zeroize::zeroize(v);
            }
            let weak_and = main_weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak_and.upgrade() {
                    ui.set_status_text("✅ Password OK — confirm Windows Hello…".into());
                }
            });
            let (w2, v2, m2, s2, q2) = (
                main_weak.clone(),
                Arc::clone(&vault_arc),
                Arc::clone(&master_pw_arc),
                Arc::clone(&search_state),
                qb_weak.clone(),
            );
            let pass2 = pass.clone();
            std::thread::spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => {
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = w2.upgrade() {
                                ui.set_unlock_error_message(
                                    "Could not start biometric service.".into(),
                                );
                                ui.set_status_text(
                                    "Vault is locked. Enter Master Password:".into(),
                                );
                            }
                        });
                        return;
                    }
                };
                match runtime.block_on(windows_native::hello::WindowsHello::authenticate(
                    "Unlock PHANTOM_VAULT (2nd factor)",
                )) {
                    Ok(true) => {
                        // Second factor passed — full publish pipeline, fresh KDF.
                        unlock_with_password(pass2, w2, v2, m2, s2, q2, Arc::clone(&ui_visible), false, false);
                    }
                    _ => {
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = w2.upgrade() {
                                ui.set_unlock_error_message(
                                    "Windows Hello required (two-factor unlock) — vault stayed locked."
                                        .into(),
                                );
                                ui.set_status_text(
                                    "Vault is locked. Enter Master Password:".into(),
                                );
                            }
                        });
                    }
                }
            });
            return;
        }
        let and_downgrade =
            and_mode && loaded_result.is_ok() && decoy_vault.is_none() && !hello_enrolled;

        let pass_for_store = pass.clone();
        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = main_weak.upgrade() else {
                return;
            };
            match loaded_result {
                Ok(vault) => {
                    if vault.totp_unlock_enabled {
                        // Phase 27 gate: password proven — park the decrypted
                        // vault + master WITHOUT publishing any UI state, then
                        // demand the authenticator code. Decoy vaults never
                        // carry the flag (provisioned fresh), so no cover leak.
                        *lock_master_pw(&master_pw_arc) = Some(pass_for_store);
                        *lock_vault(&vault_arc) = vault;
                        ui.set_show_totp_step(true);
                        ui.set_totp_step_error("".into());
                        ui.set_status_text("✅ Password OK — enter authenticator code".into());
                        security::access_log::log_event("unlock", "password ok, totp pending");
                        return;
                    }
                    publish_unlocked_vault(
                        &ui,
                        &qb_weak,
                        &vault_arc,
                        &master_pw_arc,
                        &search_state,
                        &ui_visible,
                        vault,
                        Some(pass_for_store),
                        purged_n,
                        and_downgrade,
                    );
                }
                Err(e) => {
                    // Duress path: verified decoy opens a believable fake vault.
                    // No migration, no Hello cache, no sync — pure read-mostly cover.
                    if let Some(decoy) = decoy_vault {
                        // Decoy-aware bridge: seal the duress passphrase so the
                        // extension host serves ONLY the decoy container while
                        // this cover is active. The next real-password unlock
                        // re-seals the true master, restoring Hello.
                        if let Ok(blob) = core::memory::DpapiGuard::protect(pass_for_store.expose_secret().as_bytes()) {
                            let _ = std::fs::write(HELLO_TOKEN_FILE, blob);
                        }
                        *lock_master_pw(&master_pw_arc) = Some(pass_for_store);
                        // Decoy cover is a full publish for bridging purposes:
                        // the host serves ONLY the decoy, so it needs liveness.
                        start_bridge_heartbeat(&master_pw_arc);
                        *search_state.lock().unwrap() = FilterState::default();
                        ui.set_search_query("".into());
                        ui.set_showing_trash(false);
                        ui.set_show_fav_only(false);
                        ui.set_show_empty_confirm(false);
                        ui.set_type_filter(0);
                        ui.set_folder_filter("All".into());
                        let items = vault_to_items(&decoy, &FilterState::default());
                        ui.set_credentials(items.clone());
                        ui.set_total_matches_count(total_matches() as i32);
                        set_trash_label(&ui, &decoy);
                        if let Some(qb) = qb_weak.upgrade() {
                            qb.set_filtered_results(vault_quickbar(&decoy, "", search_state.lock().unwrap().travel_only));
                        }
                        *lock_vault(&vault_arc) = decoy;
                        ui.set_is_unlocked(true);
                        ui.set_show_onboarding(false);
                        ui.set_is_decoy(true);
    ui.set_status_text("✅ Vault unlocked".into());
    // TEMP DEBUG (2FA width hunt): real window pixels at unlock.
    let sz = ui.window().size();
    security::access_log::log_event("dbg", &format!("win {}x{}", sz.width, sz.height));
                        // Deliberately NO access-log line here: writing
                        // "decoy cover" to the real log would blow the cover
                        // for anyone reviewing it under coercion.
                        return;
                    }
                    let is_wrong_pw = e.contains("Wrong password")
                        || e.contains("Decryption failed")
                        || e.contains("corrupted");
                    if is_wrong_pw {
                        ui.set_status_text("❌ Wrong Password! Could not decrypt vault.".into());
                    } else {
                        ui.set_status_text(format!("❌ {}", e).into());
                    }
                }
            }
        });
    });
}

/// Card expiry splitter: "MM/YY" (also tolerates "MM-YY", "MM YY", "MM.YY",
/// bare "MM") into (month, year). Mirrors `importer::split_expiry` so the UI
/// add/edit path stores exactly what the importer stores (the expiry year
/// used to be dropped here). Pure — unit tested.
fn split_card_expiry(raw: &str) -> (String, String) {
    let t = raw.trim().replace([' ', '-', '.'], "/");
    let mut parts = t.split('/');
    let m = parts.next().unwrap_or("").trim().to_string();
    let y = parts.next().unwrap_or("").trim().to_string();
    (m, y)
}

/// Card brand from BIN prefix (digits only; spaces/dashes stripped).
/// Prefix-only, no length gate — Luhn below is the validity check.
/// Unknown → "" (caller omits the brand chip, never shows "Unknown").
fn card_brand(number: &str) -> &'static str {
    let d: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
    // MasterCard 2221–2720 range needs numeric compare, not prefix.
    if d.starts_with('4') {
        "Visa"
    } else if d.len() >= 4
        && (d.starts_with("51")
            || d.starts_with("52")
            || d.starts_with("53")
            || d.starts_with("54")
            || d.starts_with("55")
            || (2221..=2720).contains(&d[..4].parse::<u32>().unwrap_or(0)))
    {
        "Mastercard"
    } else if d.starts_with("34") || d.starts_with("37") {
        "Amex"
    } else if d.starts_with("6011")
        || d.starts_with("65")
        || (d.len() >= 3 && (644..=649).contains(&d[..3].parse::<u32>().unwrap_or(0)))
    {
        "Discover"
    } else if d.starts_with("300")
        || d.starts_with("301")
        || d.starts_with("302")
        || d.starts_with("303")
        || d.starts_with("304")
        || d.starts_with("305")
        || d.starts_with("36")
        || d.starts_with("38")
    {
        "Diners"
    } else if d.starts_with("35") {
        "JCB"
    } else if d.starts_with("62") {
        "UnionPay"
    } else {
        ""
    }
}

/// Luhn checksum over digits (spaces/dashes ignored). Empty → false
/// (callers treat empty as "not provided", not "invalid").
fn luhn_valid(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.is_empty() {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, d)| {
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 {
                    x - 9
                } else {
                    x
                }
            } else {
                *d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Validated MM/YY parse for card saves. Empty = optional → blank pair.
/// Otherwise requires exactly MM 01–12 + YY 2 digits (after the same
/// separator normalization as the splitter). Garbage → None so the save
/// gate can refuse LOUD instead of persisting ("13/99" as month 13).
fn parse_card_expiry(raw: &str) -> Option<(String, String)> {
    let t = raw.trim();
    if t.is_empty() {
        return Some((String::new(), String::new()));
    }
    let (m, y) = split_card_expiry(raw);
    let mm_ok = m.len() == 2
        && m.bytes().all(|b| b.is_ascii_digit())
        && (1..=12).contains(&m.parse::<u32>().unwrap_or(0));
    let yy_ok = y.len() == 2 && y.bytes().all(|b| b.is_ascii_digit());
    if mm_ok && yy_ok {
        Some((m, y))
    } else {
        None
    }
}

/// Audit scope: only live (non-trashed) logins are health-checked.
/// Trashed items are shredded within 30 days — scoring their stale/breached
/// passwords only adds noise to the report and its badges. Pure — tested.
fn audit_scope_credentials(vault: &Vault) -> Vec<Credential> {
    vault
        .credentials
        .iter()
        .filter(|c| c.deleted_at.is_none())
        .cloned()
        .collect()
}

/// Phase 24: render every authenticator account through the dynamic engine.
/// Failures render as "------" (never blank, never panics).
/// Group digits like the reference grid ("513710" → "513 710").
/// Pure — unit tested.
fn group_code(code: &str) -> String {
    let digits: String = code.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if digits.is_empty() {
        // Placeholders like "------" carry no digits — show them verbatim.
        return code.to_string();
    }
    if digits.len() == 6 {
        format!("{} {}", &digits[..3], &digits[3..])
    } else {
        digits
    }
}

/// Brand letter + tint from the issuer (screenshot parity). Pure — tested.
fn brand_of(issuer: &str, fallback: &str) -> (char, slint::Color) {
    let key = issuer.trim().to_lowercase();
    let tint = match key.as_str() {
        s if s.contains("google") => slint::Color::from_rgb_u8(66, 133, 244),
        s if s.contains("facebook") || s.contains("meta") => slint::Color::from_rgb_u8(24, 119, 242),
        s if s.contains("discord") => slint::Color::from_rgb_u8(88, 101, 242),
        s if s.contains("github") => slint::Color::from_rgb_u8(238, 241, 255),
        s if s.contains("twitter") || key == "x" => slint::Color::from_rgb_u8(29, 161, 242),
        s if s.contains("instagram") => slint::Color::from_rgb_u8(225, 48, 108),
        s if s.contains("bitwarden") => slint::Color::from_rgb_u8(23, 93, 220),
        s if s.contains("steam") => slint::Color::from_rgb_u8(102, 192, 244),
        _ => slint::Color::from_rgb_u8(139, 124, 246),
    };
    let letter = issuer
        .trim()
        .chars()
        .find(|c| c.is_alphanumeric())
        .or_else(|| fallback.trim().chars().find(|c| c.is_alphanumeric()))
        .map(|c| c.to_ascii_uppercase())
        .unwrap_or('?');
    (letter, tint)
}

/// Flat authenticator rows (single source; list + grid wrap it).
/// Sort: ⭐ favorites first, then issuer A→Z, then account A→Z — starring
/// GitHub moves it straight to the top. Pure — unit tested.
/// 2FA issuer → domain (delegates to the shared favicon map; issuers are
/// human names like "Google", not URLs).
fn famous_issuer_domain(issuer: &str) -> Option<&'static str> {
    crate::core::favicon::famous_domain(issuer)
}

/// Icon domain for a 2FA account: domain-like issuer/account first, then the
/// famous-issuer map, then a vault-login match (same issuer/title text lends
/// its URL). Pure — unit tested.
fn totp_icon_domain(vault: &Vault, issuer: &str, account: &str) -> Option<String> {
    if let Some(d) = crate::core::favicon::icon_domain(issuer, account) {
        return Some(d);
    }
    if let Some(d) = famous_issuer_domain(issuer) {
        return Some(d.to_string());
    }
    let needle = issuer.trim().to_lowercase();
    if needle.is_empty() {
        return None;
    }
    vault
        .credentials
        .iter()
        .find(|c| {
            c.deleted_at.is_none()
                && (c.title.to_lowercase().contains(&needle) || needle.contains(&c.title.to_lowercase()))
        })
        .and_then(|c| c.urls.first())
        .and_then(|u| crate::core::favicon::domain_of_url(u.url()))
}

/// Cached favicon image for a domain (event-loop thread only — `Image`
/// is !Send, same rule as the login list). None when toggled off/uncached.
fn favicon_image_for_domain(domain: &str) -> Option<slint::Image> {
    if !crate::core::favicon::show_favicons() {
        return None;
    }
    let bytes = favicon_bytes_for_domain(domain)?;
    png_bytes_to_image(&bytes)
}

/// Identity of a card for duplicate-detection purposes lives in `models`
/// (`dup_key` / `dup_marks`), shared with the native bridge so its ranked
/// lookup candidates use exactly one definition of "duplicate".
/// "GitHub / zjhasan13" — what the badge tooltip explains the collision is.
/// The secret is never included: it must not reach a tooltip or a log line.
fn dup_of_label(accs: &[&TotpAccount], a: &TotpAccount) -> String {
    let k = dup_key(&a.issuer, &a.account_name);
    let others: Vec<String> = accs
        .iter()
        .filter(|o| o.id != a.id && dup_key(&o.issuer, &o.account_name) == k)
        .map(|o| strip_dup_suffix(o.account_name.trim()).to_string())
        .collect();
    if others.is_empty() {
        return String::new();
    }
    format!(
        "{} / {} — {} other card(s) use this name with a different secret",
        a.issuer.trim(),
        strip_dup_suffix(a.account_name.trim()),
        others.len()
    )
}

/// Colliding batch awaiting the user's dedup answer. One slot on purpose: a
/// second import arriving mid-dialog would otherwise silently overwrite the
/// first batch and import neither.
fn pending_twofa_store() -> &'static Mutex<Option<Vec<TotpAccount>>> {
    static SLOT: std::sync::OnceLock<Mutex<Option<Vec<TotpAccount>>>> = std::sync::OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// Classify an incoming batch against the CURRENT vault without writing.
/// Pure — unit tested.
///
/// This is the same rule the merge applies (`norm_secret` + suffix-stripped
/// name). If the two ever disagree the user gets asked about a "conflict" that
/// the merge then silently skips, which is worse than not asking at all.
fn dup_conflicts_against(vault: &Vault, accounts: &[TotpAccount]) -> Vec<DupConflict> {
    let mut out = Vec::new();
    for a in accounts {
        let inc = universal_2fa::norm_secret(&a.secret);
        if let Some(e) = vault.totp_accounts.iter().find(|e| {
            dup_key(&e.issuer, &e.account_name) == dup_key(&a.issuer, &a.account_name)
        }) {
            if universal_2fa::norm_secret(&e.secret) != inc {
                out.push(DupConflict {
                    issuer: a.issuer.clone(),
                    name: a.account_name.clone(),
                    existing_id: e.id.clone(),
                    existing_secret: universal_2fa::norm_secret(&e.secret),
                    incoming_secret: inc,
                });
            }
        }
    }
    out
}

fn build_auth_rows(vault: &Vault) -> Vec<AuthView> {
    let mut accs: Vec<&TotpAccount> = vault.totp_accounts.iter().collect();
    let dup_flags = dup_marks(&accs);
    // Resolved to concrete strings up front: `accs` is consumed by the sort
    // below, so the tooltip cannot be derived inside the mapping closure.
    let dup_of: std::collections::HashMap<String, String> = accs
        .iter()
        .map(|a| (a.id.clone(), dup_of_label(&accs, a)))
        .collect();
    accs.sort_by(|a, b| {
        b.favorite
            .cmp(&a.favorite)
            .then_with(|| a.issuer.to_lowercase().cmp(&b.issuer.to_lowercase()))
            // Compare the BARE name so a duplicated pair stays adjacent and
            // alphabetical, instead of sorting the marker as part of the name.
            .then_with(|| {
                strip_dup_suffix(&a.account_name)
                    .to_lowercase()
                    .cmp(&strip_dup_suffix(&b.account_name).to_lowercase())
            })
            // A collision's surviving card is the newest import, and the newest
            // import is the one that works — so the suffixed card sorts first
            // and is the card the eye lands on.
            .then_with(|| {
                b.account_name
                    .ends_with(DUP_SUFFIX)
                    .cmp(&a.account_name.ends_with(DUP_SUFFIX))
            })
            .then_with(|| a.id.cmp(&b.id))
    });
    accs.into_iter()
        .zip(dup_flags)
        .map(|(a, is_dup)| {
            let gen = totp_engine::generate_code_for_account(a);
            let broken = gen.is_err();
            let (code, remaining) = gen.unwrap_or(("------".to_string(), 0));
            // Broken secrets surface LOUDLY in the hub ("Next: ⚠️…") so the
            // user knows exactly which accounts need re-enrolling — and why
            // the GA export QR skips them.
            let next = if broken {
                "⚠️ bad secret — re-enroll".to_string()
            } else {
                totp_engine::next_code_for_account(a).unwrap_or_else(|_| "------".to_string())
            };
            let kind = match a.otp_type.trim().to_lowercase().as_str() {
                "hotp" => "HOTP",
                "steam" => "STEAM",
                _ => "TOTP",
            };
            let is_hotp = kind == "HOTP";
            // HOTP has no clock (remaining == u64::MAX): ring shows static badge.
            let secs = if is_hotp || remaining == u64::MAX {
                -1
            } else {
                remaining.min(i32::MAX as u64) as i32
            };
            let countdown = if secs < 0 { "HOTP".to_string() } else { format!("{secs}s") };
            // The revealed "Next" line carries its own countdown so the two
            // numbers on the card can never be read as one. `remaining` is the
            // wait until the NEXT window opens, which is what a user needs to
            // know before reaching for that number instead of the live one.
            let next_label = if broken {
                next.clone()
            } else if is_hotp {
                format!("NEXT (counter {}) · {}", a.counter + 1, group_code(&next))
            } else {
                format!("NEXT in {countdown} · {}", group_code(&next))
            };
            let (icon, tint) = brand_of(&a.issuer, &a.account_name);
            // 2FA card icon: same favicon cache as the login list (letter
            // circle stays as the fallback when uncached/toggled off).
            let (has_icon, icon_img) = totp_icon_domain(vault, &a.issuer, &a.account_name)
                .and_then(|d| favicon_image_for_domain(&d))
                .map(|img| (true, img))
                .unwrap_or((false, slint::Image::default()));
            AuthView {
                id: a.id.clone().into(),
                name: a.account_name.clone().into(),
                issuer: a.issuer.clone().into(),
                code: code.clone().into(),
                display: group_code(&code).into(),
                next: if broken {
                    // group_code() strips everything non-alphanumeric, which
                    // would turn the warning into "badsecretreenroll". Only
                    // real codes get grouped.
                    next.clone().into()
                } else {
                    group_code(&next).into()
                },
                next_label: next_label.into(),
                icon: icon.to_string().into(),
                has_icon,
                icon_img,
                tint,
                kind: kind.into(),
                is_hotp,
                secs,
                countdown: countdown.into(),
                fav: a.favorite,
                is_dup,
                dup_of: if is_dup {
                    dup_of.get(&a.id).cloned().unwrap_or_default().into()
                } else {
                    "".into()
                },
            }
        })
        .collect()
}

/// Remove one authenticator account by id. Returns true when something was
/// removed (the caller re-seals + refreshes). Pure — unit tested.
fn remove_totp_account(vault: &mut Vault, id: &str) -> bool {
    let before = vault.totp_accounts.len();
    vault.totp_accounts.retain(|a| a.id != id);
    vault.totp_accounts.len() != before
}

fn rebuild_auth_list(vault: &Vault) -> ModelRc<AuthView> {
    ModelRc::new(VecModel::from(build_auth_rows(vault)))
}

/// 2FA Hub search predicate (issuer + account, case-insensitive).
/// Empty query matches everything. Pure — unit tested.
fn totp_matches(name: &str, issuer: &str, query: &str) -> bool {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return true;
    }
    issuer.to_lowercase().contains(&q) || name.to_lowercase().contains(&q)
}

/// Chunk a flat row vec into grid rows of N (last row may be short —
/// the Slint grid pads it with invisible spacers so narrow rows keep the
/// same column widths instead of zigzagging). Pure — unit tested.
fn chunk_rows_of<T: Clone>(items: Vec<T>, n: usize) -> Vec<Vec<T>> {
    let n = n.max(1);
    items.chunks(n).map(|c| c.to_vec()).collect()
}

/// Authenticator grid stride: 4 columns — full-bleed on wide screens, no
/// dead space on the right (compact cards, not billboards).
const AUTH_GRID_COLS: usize = 4;

/// Grid model for the authenticator page: `[[AuthView]]` rows of 4,
/// filtered by the ISOLATED hub query (never the vault `search_query`).
/// Park a colliding batch and open the dedup dialog. Returns true when the
/// caller must STOP — nothing has been written in that case.
///
/// Called from the ingest threads, so it hops to the event loop itself. The
/// batch is held in `pending_twofa_store()` rather than being captured by the
/// dialog callbacks, which is what lets Cancel drop it without undoing anything.
fn park_twofa_for_dup(ui: &MainWindow, accounts: Vec<TotpAccount>, conflicts: Vec<DupConflict>) -> bool {
    if conflicts.is_empty() {
        return false;
    }
    *pending_twofa_store().lock().unwrap_or_else(|p| p.into_inner()) = Some(accounts);
    let who = conflicts
        .iter()
        .map(|c| format!("{} / {}", c.issuer.trim(), strip_dup_suffix(c.name.trim())))
        .collect::<Vec<_>>();
    let mut seen: Vec<String> = Vec::new();
    for w in who {
        if !seen.contains(&w) {
            seen.push(w);
        }
    }
    ui.set_dup_title(format!("⚠️ Already saved: {}", seen.join(", ")).into());
    // Secrets are deliberately NOT rendered. Naming the account is enough to
    // act on, and a modal is the worst possible place to echo key material.
    ui.set_dup_body(format!(
        "{n} account(s) in this import use a name you already have, but with a different secret. \
         Keep both to end up with two cards (the new one is marked and shown first). \
         Replace to overwrite the stored secret on the existing card, keeping its name and favourite.",
        n = conflicts.len()
    ).into());
    ui.set_show_dup_confirm(true);
    true
}

fn rebuild_auth_rows(vault: &Vault, query: &str) -> ModelRc<ModelRc<AuthView>> {
    let q = query.trim().to_lowercase();
    let flat: Vec<AuthView> = if q.is_empty() {
        build_auth_rows(vault)
    } else {
        build_auth_rows(vault)
            .into_iter()
            .filter(|r| totp_matches(r.name.as_str(), r.issuer.as_str(), &q))
            .collect()
    };
    let rows: Vec<ModelRc<AuthView>> = chunk_rows_of(flat, AUTH_GRID_COLS)
        .into_iter()
        .map(|r| ModelRc::new(VecModel::from(r)))
        .collect();
    ModelRc::new(VecModel::from(rows))
}

/// Retired-password rows: secret + relative age, newest first.
/// The secret rides the row (copy button needs it); the list lives only in
/// RAM on the detail view and dies with it — never logged, never synced raw.
/// Grouped health-report rows for the audit dialog: severity-ordered
/// (breached → reused → weak → stale) with section headers.
/// Header rows carry id "" (never clickable, never secrets). Pure — tested.
fn health_rows_for(results: &[security::breach_check::BreachResult]) -> Vec<HealthRow> {
    let mut rows: Vec<HealthRow> = Vec::new();
    let mut groups: [Vec<&security::breach_check::BreachResult>; 4] =
        [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    for r in results {
        if r.breached.is_some() {
            groups[0].push(r);
        } else if r.reused {
            groups[1].push(r);
        } else if r.weak {
            groups[2].push(r);
        } else if r.stale {
            groups[3].push(r);
        }
    }
    let headers = [
        "🚨 BREACHED — change these now",
        "🔁 REUSED — give each site its own password",
        "🔓 WEAK — strengthen or regenerate",
        "🕰️ STALE — over 6 months old",
    ];
    for (sev, (group, header)) in groups.iter().zip(headers.iter()).enumerate() {
        if group.is_empty() {
            continue;
        }
        rows.push(HealthRow {
            id: String::new().into(),
            title: header.to_string().into(),
            flags: String::new().into(),
            sev: -1,
        });
        for r in group {
            let mut flags = Vec::new();
            if let Some(n) = r.breached {
                flags.push(format!("breached×{n}"));
            }
            if r.reused {
                flags.push("reused".to_string());
            }
            if r.weak {
                flags.push("weak".to_string());
            }
            if r.stale {
                flags.push("stale 6m+".to_string());
            }
            rows.push(HealthRow {
                id: r.credential_id.clone().into(),
                title: r.title.clone().into(),
                flags: flags.join(" • ").into(),
                sev: sev as i32,
            });
        }
    }
    rows
}

fn rebuild_history(c: &Credential) -> ModelRc<HistoryView> {
    let now = crate::models::current_timestamp();
    let rows: Vec<HistoryView> = c
        .password_history
        .iter()
        .map(|h| HistoryView {
            password: h.password.clone().into(),
            when: format!("Changed {}", crate::models::ago(h.changed_at, now)).into(),
        })
        .collect();
    ModelRc::new(VecModel::from(rows))
}

/// Mutable favorite flag for any of the 8 kinds (toggle path).
fn fav_flag_mut<'a>(vault: &'a mut Vault, kind: i32, id: &str) -> Option<&'a mut bool> {
    match kind {
        1 => vault.credentials.iter_mut().find(|c| c.id == id).map(|c| &mut c.favorite),
        2 => vault.licenses.iter_mut().find(|l| l.id == id).map(|l| &mut l.favorite),
        3 => vault.notes.iter_mut().find(|n| n.id == id).map(|n| &mut n.favorite),
        4 => vault.cards.iter_mut().find(|k| k.id == id).map(|k| &mut k.favorite),
        5 => vault.identities.iter_mut().find(|i| i.id == id).map(|i| &mut i.favorite),
        6 => vault.ssh_keys.iter_mut().find(|s| s.id == id).map(|s| &mut s.favorite),
        7 => vault.passkeys.iter_mut().find(|p| p.id == id).map(|p| &mut p.favorite),
        8 => vault.totp_accounts.iter_mut().find(|a| a.id == id).map(|a| &mut a.favorite),
        _ => None,
    }
}

/// Read-only favorite flag for any of the 8 kinds (refresh path).
fn fav_flag(vault: &Vault, kind: i32, id: &str) -> Option<bool> {
    match kind {
        1 => vault.credentials.iter().find(|c| c.id == id).map(|c| c.favorite),
        2 => vault.licenses.iter().find(|l| l.id == id).map(|l| l.favorite),
        3 => vault.notes.iter().find(|n| n.id == id).map(|n| n.favorite),
        4 => vault.cards.iter().find(|k| k.id == id).map(|k| k.favorite),
        5 => vault.identities.iter().find(|i| i.id == id).map(|i| i.favorite),
        6 => vault.ssh_keys.iter().find(|s| s.id == id).map(|s| s.favorite),
        7 => vault.passkeys.iter().find(|p| p.id == id).map(|p| p.favorite),
        8 => vault.totp_accounts.iter().find(|a| a.id == id).map(|a| a.favorite),
        _ => None,
    }
}

/// Master-reprompt gate for out-of-band flows (QuickBar copy/type, pill fill).
/// Reprompt arms logins only; returns (user, secret) when the MainWindow
/// reprompt modal must come first. Pure lookup — unit tested.
fn reprompt_gate(vault: &Vault, kind: i32, id: &str) -> Option<(String, String)> {
    if kind != 1 {
        return None;
    }
    vault.credentials.iter().find(|c| c.id == id).and_then(|c| {
        if c.reprompt {
            Some((c.username.clone(), c.password.clone()))
        } else {
            None
        }
    })
}

/// Sidebar Trash badge label ("Trash" / "Trash (3)"). The icon rides the
/// NavItem separately, so this stays a plain label.
fn set_trash_label(ui: &MainWindow, vault: &Vault) {
    let n = vault.trash_count();
    ui.set_trash_label(if n == 0 {
        "Trash".into()
    } else {
        format!("Trash ({n})").into()
    });
}

/// Resident passkey rows for the hub (`meta` preformatted — no Slint typing risk).
/// Trashed keys never surface here (hub trash section lists them via
/// `rebuild_trashed_passkeys`); `fav_only` mirrors the sidebar ⭐ filter.
fn rebuild_passkeys(vault: &Vault, fav_only: bool) -> ModelRc<PasskeyView> {
    let rows: Vec<PasskeyView> = vault
        .passkeys
        .iter()
        .filter(|p| p.deleted_at.is_none() && (!fav_only || p.favorite))
        .map(|p| PasskeyView {
            id: p.id.clone().into(),
            rp: p.rp_id.clone().into(),
            user: p.user_name.clone().into(),
            meta: format!("{} signs", p.sign_count).into(),
            fav: p.favorite,
        })
        .collect();
    ModelRc::new(VecModel::from(rows))
}

/// Trashed passkey rows for the hub trash section (restore/shred actions).
fn rebuild_trashed_passkeys(vault: &Vault) -> ModelRc<PasskeyView> {
    let rows: Vec<PasskeyView> = vault
        .passkeys
        .iter()
        .filter(|p| p.deleted_at.is_some())
        .map(|p| PasskeyView {
            id: p.id.clone().into(),
            rp: p.rp_id.clone().into(),
            user: p.user_name.clone().into(),
            meta: format!("{} signs", p.sign_count).into(),
            fav: p.favorite,
        })
        .collect();
    ModelRc::new(VecModel::from(rows))
}

/// Item-kind codes shared with Slint: 0 All, 1 login, 2 license, 3 note,
/// 4 card, 5 identity, 6 ssh, 7 passkey.
#[derive(Clone)]
struct FilterState {
    query: String,
    kind: i32,
    folder: String,
    travel_only: bool,
    fav_only: bool,
    show_trash: bool,
    /// Health metric filter from the scoreboard ("", breached/reused/weak/stale).
    health: String,
    /// Janitor review queue: unverified + never-filled logins only
    /// (fake/stale cleanup candidates). Pairs with select-mode bulk trash.
    janitor: bool,
    /// Paged window: first N matches render (Load More grows it).
    limit: usize,
}

impl Default for FilterState {
    fn default() -> Self {
        Self { query: String::new(), kind: 0, folder: "All".to_string(), travel_only: false, fav_only: false, show_trash: false, health: String::new(), janitor: false, limit: LIST_CAP }
    }
}

/// Janitor candidates over live logins: not verified AND never filled.
/// Pure over an injected filled-set (one sidecar read per list build, not
/// per row). Sorted weak/stale-flavored first? No — stable vault order;
/// the list's own health icons carry severity.
fn janitor_ids(vault: &Vault, filled: &std::collections::HashSet<String>) -> Vec<String> {
    vault
        .credentials
        .iter()
        .filter(|c| c.deleted_at.is_none() && !vault.is_verified(&c.id) && !filled.contains(&c.id))
        .map(|c| c.id.clone())
        .collect()
}

/// Ids ever filled (count>0 or stamped) — ONE sidecar read per call.
/// Best-effort IO: missing/corrupt file ⇒ empty set ⇒ janitor over-includes
/// (review queue fail-open; trash is soft + restorable, never data loss).
fn read_fill_keys() -> std::collections::HashSet<String> {    let mut out = std::collections::HashSet::new();
    let Ok(txt) = std::fs::read_to_string("pv_ext_stats.json") else {
        return out;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) else {
        return out;
    };
    if let Some(m) = v.get("fill_counts").and_then(|m| m.as_object()) {
        for (id, n) in m {
            if n.as_u64().unwrap_or(0) > 0 {
                out.insert(id.clone());
            }
        }
    }
    if let Some(m) = v.get("last_filled").and_then(|m| m.as_object()) {
        for (id, _) in m {
            out.insert(id.clone());
        }
    }
    out
}

/// Rotate every reused login password: each shared password is replaced by
/// a UNIQUE fresh one (20-char full charset), old → history (keep 5),
/// `last_changed` = now. One caller re-seal covers the batch. Pure shape
/// over `&mut Vault` (CSPRNG inside) — tests assert uniqueness + history,
/// never fixed values.
///
/// Honest scope: vault-side only. The operator must still update each
/// password ON ITS WEBSITE — the UI says so next to the button.
fn rotate_reused_passwords(vault: &mut Vault) -> usize {
    use secrecy::ExposeSecret;
    let mut freq: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for c in &vault.credentials {
        if c.deleted_at.is_none() && !c.password.is_empty() {
            *freq.entry(c.password.clone()).or_insert(0) += 1;
        }
    }
    if !freq.values().any(|&n| n > 1) {
        return 0;
    }
    let now = crate::models::current_timestamp();
    let mut used: std::collections::HashSet<String> =
        vault.credentials.iter().map(|c| c.password.clone()).collect();
    let policy = crate::core::generator::PasswordPolicy::default();
    let mut n = 0;
    for c in vault.credentials.iter_mut() {
        if c.deleted_at.is_some() || c.password.is_empty() {
            continue;
        }
        if freq.get(&c.password).copied().unwrap_or(0) < 2 {
            continue;
        }
        let mut fresh = String::new();
        for _ in 0..10 {
            let cand = crate::core::generator::PasswordGenerator::generate_complex(&policy)
                .map(|s| s.expose_secret().clone())
                .unwrap_or_default();
            if !cand.is_empty() && !used.contains(&cand) {
                fresh = cand;
                break;
            }
        }
        if fresh.is_empty() {
            continue;
        }
        crate::models::push_history(&mut c.password_history, &c.password, now);
        // NOTE: old password stays in `used` — a fresh candidate must never
        // re-issue a compromised shared password, even by chance.
        c.password = fresh.clone();
        used.insert(fresh);
        c.last_changed = now;
        n += 1;
    }
    n
}

/// Live login id with the same title + username (case-insensitive,
/// trimmed) — desktop manual-Add duplicate guard. Mirrors the bridge
/// upsert and importer `dedup_key` (without the password leg: same
/// account ⇒ update-in-place, never a second row). Trashed never blocks.
/// Pure — unit tested.
fn find_live_login_id(vault: &Vault, title: &str, username: &str) -> Option<String> {
    let t = title.trim().to_lowercase();
    let u = username.trim().to_lowercase();
    if t.is_empty() || u.is_empty() {
        return None;
    }
    vault
        .credentials
        .iter()
        .find(|c| {
            c.deleted_at.is_none()
                && c.title.trim().to_lowercase() == t
                && c.username.trim().to_lowercase() == u
        })
        .map(|c| c.id.clone())
}

fn eff_folder(folder: &str) -> &str {
    if folder.is_empty() {
        "General"
    } else {
        folder
    }
}

fn primary_url(urls: &[models::LoginUrl]) -> String {
    urls.first().map(|u| u.url().to_string()).unwrap_or_default()
}
fn custom_to_ui(fields: &[models::CustomField]) -> ModelRc<CustomFieldView> {
    ModelRc::new(VecModel::from(
        fields
            .iter()
            .map(|f| CustomFieldView {
                name: f.name.clone().into(),
                value: f.value.clone().into(),
                ftype: f.field_type.to_i32(),
            })
            .collect::<Vec<_>>(),
    ))
}

fn attachments_to_ui(files: &[models::EncryptedAttachment]) -> ModelRc<AttachmentView> {
    ModelRc::new(VecModel::from(
        files
            .iter()
            .map(|a| AttachmentView {
                id: a.id.clone().into(),
                filename: a.filename.clone().into(),
                size: human_bytes(a.size_bytes).into(),
            })
            .collect::<Vec<_>>(),
    ))
}

fn human_bytes(n: usize) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    }
}

fn guess_mime(filename: &str) -> String {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "txt" | "md" => "text/plain",
        "json" => "application/json",
        "pem" | "key" => "application/x-pem-file",
        "pfx" | "p12" => "application/x-pkcs12",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Push the vault's folder registry into both folder models (form + filter).
/// Keeps the active filter valid if its folder vanished.
fn sync_folders_to_ui(vault: &Vault, ui: &MainWindow) {
    let mut folders = vault.folders.clone();
    if folders.is_empty() {
        folders.push("General".to_string());
    }
    folders.sort();
    folders.dedup();
    let mut with_all = vec!["All".to_string()];
    with_all.extend(folders.clone());
    ui.set_folders_list(ModelRc::new(VecModel::from(
        folders.into_iter().map(slint::SharedString::from).collect::<Vec<_>>(),
    )));
    ui.set_filter_folders(ModelRc::new(VecModel::from(
        with_all.into_iter().map(slint::SharedString::from).collect::<Vec<_>>(),
    )));
    if ui.get_folder_filter() != "All"
        && !ui.get_filter_folders().iter().any(|f| ui.get_folder_filter() == f.as_str())
    {
        ui.set_folder_filter("All".into());
    }
}

#[allow(clippy::too_many_arguments)]
fn push_item(
    out: &mut Vec<CredentialView>,
    f: &FilterState,
    q: &str,
    id: &str,
    kind: i32,
    title: &str,
    user: &str,
    secret: &str,
    meta: &str,
    url: &str,
    notes: &str,
    folder: &str,
    totp: &str,
    travel_safe: bool,
    fav: bool,
    trashed: bool,
    verified: bool,
) {
    if f.kind != 0 && f.kind != kind {
        return;
    }
    // Travel Mode: only travel-safe items survive in list, QuickBar, search.
    if f.travel_only && !travel_safe {
        return;
    }
    // Sidebar ⭐ filter: only pinned items survive (QuickBar never sets it).
    if f.fav_only && !fav {
        return;
    }
    // Trash split: active views hide trashed items; the Trash view shows
    // ONLY them (QuickBar, pill, and autotype never set show_trash).
    if f.show_trash != trashed {
        return;
    }
    if f.folder != "All" && eff_folder(folder) != f.folder {
        return;
    }
    // Scoreboard metric filter: only audited-flagged ids survive.
    if !f.health.is_empty() && health_kind_for(id) != f.health {
        return;
    }
    if !q.is_empty() {
        let hay = format!("{title} {user} {notes}").to_lowercase();
        if !hay.contains(q) {
            return;
        }
    }
    out.push(CredentialView {
        id: id.into(),
        kind,
        title: title.into(),
        username: user.into(),
        password: secret.into(),
        meta: meta.into(),
        url: url.into(),
        notes: notes.into(),
        folder: eff_folder(folder).into(),
        totp: totp.into(),
        // Row icons compare against KIND strings ("breached"/"weak"/
        // "reused"/"stale") — the human-readable badge TEXT lives in the
        // detail pane (d_health), never in this field.
        health: health_kind_for(id).into(),
        fav,
        verified,
        sel: selection_contains(kind, id),
        has_icon: false,
        icon: slint::Image::default(),
    });
    // Favicons resolve after push (Image has no Default-dependent borrow):
    // kind-1 rows with a cached domain icon show the site logo (URL first,
    // domain-like title as fallback — imports often leave URL empty).
    if kind == 1 {
        if let Some(img) = favicon_for_item(title, url) {
            if let Some(row) = out.last_mut() {
                row.has_icon = true;
                row.icon = img;
            }
        }
    }
}

/// Bulk-select registry: "kind:id" set, read by every list build (same
/// zero-plumbing pattern as the health registry). Cleared on lock/exit and
/// after every bulk action. Pure selection state — never persisted.
fn selection_registry() -> &'static Mutex<std::collections::HashSet<String>> {
    static REGISTRY: std::sync::OnceLock<Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

fn selection_key(kind: i32, id: &str) -> String {
    format!("{kind}:{id}")
}

fn selection_contains(kind: i32, id: &str) -> bool {
    selection_registry()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains(&selection_key(kind, id))
}

fn selection_count() -> usize {
    selection_registry()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .len()
}

/// Staged import rows awaiting user Confirm (dry-run preview). RAM-only,
/// process-global like the selection registry so pick/confirm/cancel/lock
/// all reach it without threading handles. Dropped on cancel AND on lock.
struct PendingImport {
    raws: Vec<importer::RawItem>,
    source: String,
    path_str: String,
}

fn pending_import_store() -> &'static Mutex<Option<PendingImport>> {
    static PENDING: std::sync::OnceLock<Mutex<Option<PendingImport>>> = std::sync::OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(None))
}

/// Raw cached favicon PNGs by domain (bytes are Send+Sync; decoding to
/// `slint::Image` happens ONLY on the event-loop thread — Slint images are
/// neither Send nor Sync). Filled by the prefetch worker; list/detail builds
/// (always on the event loop) decode on demand.
/// A2-lite: RAM icon cap (100). Disk cache is unbounded (keyed by domain,
/// never by secret); RAM holds at most 100 decoded PNGs for the live list.
const FAVICON_RAM_CAP: usize = 100;

fn favicon_bytes() -> &'static Mutex<std::collections::HashMap<String, Vec<u8>>> {
    static ICONS: std::sync::OnceLock<Mutex<std::collections::HashMap<String, Vec<u8>>>> =
        std::sync::OnceLock::new();
    ICONS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn clear_favicon_bytes() {
    favicon_bytes().lock().unwrap_or_else(|p| p.into_inner()).clear();
    crate::core::favicon::clear_memory_cache();
}

/// Shared RAM→disk icon resolve. RAM miss (A2-lite 100-cap eviction) falls
/// back to the disk cache — custom override first, then fetched file.
/// Fail-closed: undecodable bytes yield None (letter icon), never a panic.
fn favicon_bytes_for_domain(domain: &str) -> Option<Vec<u8>> {
    if let Some(b) = favicon_bytes()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(domain)
        .cloned()
    {
        return Some(b);
    }
    let b = crate::core::favicon::custom_icon_bytes(domain).or_else(|| {
        std::fs::read(crate::core::favicon::icon_path(domain))
            .ok()
            .filter(|b| crate::core::favicon::valid_icon_bytes(b))
    })?;
    // Repopulate RAM (still under the cap — eviction policy lives at insert).
    let mut cache = favicon_bytes().lock().unwrap_or_else(|p| p.into_inner());
    if cache.len() >= FAVICON_RAM_CAP {
        if let Some(k) = cache.keys().next().cloned() {
            cache.remove(&k);
        }
    }
    cache.insert(domain.to_string(), b.clone());
    Some(b)
}

fn favicon_for_item(title: &str, url: &str) -> Option<slint::Image> {
    if !crate::core::favicon::show_favicons() {
        return None;
    }
    let domain = crate::core::favicon::icon_domain(title, url)?;
    let bytes = favicon_bytes_for_domain(&domain)?;
    png_bytes_to_image(&bytes)
}

/// PNG bytes → Slint image (QR grayscale, favicon color — `image` decodes
/// both; software buffer, safe to build on the event-loop thread).
fn png_bytes_to_image(png: &[u8]) -> Option<slint::Image> {
    let rgba = image::load_from_memory(png).ok()?.to_rgba8();
    let (w, h) = (rgba.width(), rgba.height());
    let buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
        rgba.as_raw(),
        w,
        h,
    );
    Some(slint::Image::from_rgba8(buf))
}

/// Background favicon pass: disk cache first, one DuckDuckGo batch for
/// misses (kill-switch + toggle gated), then rebuild the list so fresh
/// icons pop in. Fire-and-forget — never blocks the UI thread.
fn trigger_favicon_prefetch(
    vault_arc: Arc<Mutex<Vault>>,
    search_arc: Arc<Mutex<FilterState>>,
    main_weak: slint::Weak<MainWindow>,
) {
    std::thread::spawn(move || {
        if !crate::core::favicon::show_favicons() {
            return;
        }
        // Titles count too: imports often carry the host as the title with
        // an empty URL list (e.g. title `2captcha.com`, no urls).
        let pairs: Vec<(String, String)> = {
            let v = lock_vault(&vault_arc);
            v.credentials
                .iter()
                .map(|c| {
                    (
                        c.title.clone(),
                        c.urls.first().map(|u| u.url().to_string()).unwrap_or_default(),
                    )
                })
                .collect()
        };
        // Fix 3: rotating slice — 200+ domain vaults cover a new window
        // each unlock instead of re-fetching the same first 200 forever.
        let mut domains = crate::core::favicon::domains_for_items_rotating(&pairs);
        // 2FA issuers ride along (famous names + domain-like issuers), so
        // hub cards pop icons in on the same pass as the login list.
        {
            let v = lock_vault(&vault_arc);
            for a in &v.totp_accounts {
                let d = totp_icon_domain(&v, &a.issuer, &a.account_name);
                if let Some(d) = d {
                    if !domains.contains(&d) {
                        domains.push(d);
                    }
                }
            }
        }
        eprintln!("[favicon] {} candidate domains", domains.len());
        if domains.is_empty() {
            return;
        }
        let hits = crate::core::favicon::prefetch_blocking(&domains, net_allowed);
        eprintln!("[favicon] {} hits (disk + fetch)", hits.len());
        if hits.is_empty() {
            return;
        }
        let mut fresh = 0;
        {
            // Bytes validated upstream (fetch decode-checks before saving;
            // disk hits decode-checked on read). No Slint work here: images
            // are !Send, so decoding happens on the event-loop thread only.
            let mut cache = favicon_bytes().lock().unwrap_or_else(|p| p.into_inner());
            for (d, bytes) in hits {
                if cache.contains_key(&d) {
                    continue;
                }
                // A2-lite: cap 100 RAM icons. Evict one arbitrary entry when
                // full (true LRU needs a new dep — not worth it for icons;
                // disk cache refills on demand, keyed by domain not secret).
                if cache.len() >= FAVICON_RAM_CAP {
                    if let Some(k) = cache.keys().next().cloned() {
                        cache.remove(&k);
                    }
                }
                cache.insert(d, bytes);
                fresh += 1;
            }
        }
        if fresh == 0 {
            return;
        }
        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = main_weak.upgrade() else {
                return;
            };
            let f = search_arc.lock().unwrap().clone();
            let v = lock_vault(&vault_arc);
            set_paged_credentials(&ui, vault_to_items(&v, &f));
            // 2FA hub cards follow (icons may have arrived on this pass).
            ui.set_auth_accounts(rebuild_auth_list(&v));
            ui.set_auth_rows(rebuild_auth_rows(&v, ui.get_totp_search_query().as_str()));
            // Detail header follows if it shows a login.
            if ui.get_d_kind() == 1 {
                if let Some(c) = v.credentials.iter().find(|c| c.id == ui.get_d_id().as_str()) {
                    let first_url = c.urls.first().map(|u| u.url()).unwrap_or("");
                    match favicon_for_item(&c.title, first_url) {
                        Some(img) => {
                            ui.set_d_icon(img);
                            ui.set_d_has_icon(true);
                        }
                        None => ui.set_d_has_icon(false),
                    }
                }
            }
        });
    });
}

/// Process-wide health badges from the last audit (id → badge text).
/// Badge text carries counts only — never secrets. Written by the audit
/// worker, read by every list builder, cleared on lock/unlock.
fn health_registry() -> &'static Mutex<std::collections::HashMap<String, String>> {
    static REGISTRY: std::sync::OnceLock<Mutex<std::collections::HashMap<String, String>>> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn health_badge_for(id: &str) -> String {
    health_registry()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(id)
        .cloned()
        .unwrap_or_default()
}

/// Metric category registry (id → breached/reused/weak/stale), written by
/// the audit worker next to the badge registry. Drives scoreboard filtering.
fn health_kind_registry() -> &'static Mutex<std::collections::HashMap<String, String>> {
    static KINDS: std::sync::OnceLock<Mutex<std::collections::HashMap<String, String>>> =
        std::sync::OnceLock::new();
    KINDS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn health_kind_for(id: &str) -> String {
    health_kind_registry()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(id)
        .cloned()
        .unwrap_or_default()
}

/// Unified list builder: search query + type + folder over all 6 vectors.
/// Windowing diet: search filters the FULL vault first, then only the first
/// `f.limit` rows instantiate as Slint cards (482 items = ~90MB of
/// widget/GPU overhead). The pre-truncate total is recorded for the
/// Load-More footer — read it back with `total_matches()` on the same tick.
const LIST_CAP: usize = 50;
const LIST_PAGE: usize = 50;
fn vault_to_items(vault: &Vault, f: &FilterState) -> ModelRc<CredentialView> {
    let q = f.query.trim().to_lowercase();
    let mut items = Vec::new();
    // Janitor fast path: ONE sidecar read per build (not per row), then
    // only unverified + never-filled logins survive. Other kinds skip.
    let filled_set: std::collections::HashSet<String> = if f.janitor {
        read_fill_keys()
    } else {
        std::collections::HashSet::new()
    };
    for c in &vault.credentials {
        if f.janitor
            && (c.deleted_at.is_some() || vault.is_verified(&c.id) || filled_set.contains(&c.id))
        {
            continue;
        }
        push_item(&mut items, f, &q, &c.id, 1, &c.title, &c.username, &c.password, "", &primary_url(&c.urls), &c.notes, &c.folder, &c.totp_secret, c.travel_safe, c.favorite, c.deleted_at.is_some(), vault.is_verified(&c.id));
    }
    if f.janitor {
        // Janitor reviews logins only — other vectors skip the walk.
        // Same tail bookkeeping (truncate + total) so the footer works.
        let total = items.len();
        items.truncate(f.limit);
        *total_matches_registry()
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = total;
        return ModelRc::new(slint::VecModel::from(items));
    }
    for l in &vault.licenses {
        push_item(&mut items, f, &q, &l.id, 2, &l.app_name, "Software license",
            &l.license_key, &l.expiry_date.clone().unwrap_or_default(), "", "", &l.folder, "", l.travel_safe, l.favorite, l.deleted_at.is_some(), false);
    }
    for n in &vault.notes {
        let preview: String = n.content.lines().next().unwrap_or("").chars().take(48).collect();
        push_item(&mut items, f, &q, &n.id, 3, &n.title, &preview, &n.content, "", "", &n.content, &n.folder, "", n.travel_safe, n.favorite, n.deleted_at.is_some(), false);
    }
    for k in &vault.cards {
        let exp = format!("{:0>2}/{:0>2}", k.exp_month, k.exp_year);
        let meta = format!("exp {exp}  CVV {}", k.cvv);
        push_item(&mut items, f, &q, &k.id, 4, &k.title, &k.cardholder_name, &k.card_number, &meta, "", "", &k.folder, "", k.travel_safe, k.favorite, k.deleted_at.is_some(), false);
    }
    for i in &vault.identities {
        push_item(&mut items, f, &q, &i.id, 5, &i.title, &i.full_name, &i.nid_or_passport, &i.phone, &i.email, &i.address, &i.folder, "", i.travel_safe, i.favorite, i.deleted_at.is_some(), false);
    }
    for s in &vault.ssh_keys {
        push_item(&mut items, f, &q, &s.id, 6, &s.title, "SSH key", &s.private_key, &s.fingerprint, "", &s.public_key, &s.folder, "", s.travel_safe, s.favorite, s.deleted_at.is_some(), false);
    }
    // Standalone 2FA (kind 8): hub accounts also live in All items +
    // Favorites so the counts never desync. No secrets ride the list model
    // (password/totp stay empty — copy/type always re-derive the FRESH live
    // code by id). travel_safe=true: the 2FA Hub never travel-filters, so
    // the list must not either, or the two views would disagree again.
    for a in &vault.totp_accounts {
        let title = if a.issuer.trim().is_empty() { a.account_name.clone() } else { a.issuer.clone() };
        let meta = match a.otp_type.trim().to_lowercase().as_str() {
            "hotp" => "HOTP".to_string(),
            "steam" => "STEAM".to_string(),
            _ => "TOTP".to_string(),
        };
        push_item(&mut items, f, &q, &a.id, 8, &title, &a.account_name, "", &meta, "", "", "General", "", true, a.favorite, false, false);
    }
    let total = items.len();
    items.truncate(f.limit);
    *total_matches_registry()
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = total;
    ModelRc::new(VecModel::from(items))
}

/// Pre-truncate total from the last vault_to_items build (same tick).
/// Backed by a process-wide cell because vault_to_items returns only the
/// model (30+ call sites stay untouched).
fn total_matches_registry() -> &'static Mutex<usize> {
    static TOTAL: std::sync::OnceLock<Mutex<usize>> = std::sync::OnceLock::new();
    TOTAL.get_or_init(|| Mutex::new(0))
}

fn total_matches() -> usize {
    *total_matches_registry()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

fn restore_total(n: usize) {
    *total_matches_registry()
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = n;
}

/// Paged list paint: model + total-matches count for the Load-More footer.
/// Call with the model built on this tick (event-loop single-threaded —
/// the QuickBar feed preserves/restores around its own build).
fn set_paged_credentials(ui: &MainWindow, model: ModelRc<CredentialView>) {
    ui.set_credentials(model);
    ui.set_total_matches_count(total_matches() as i32);
}

/// QuickBar feed: logins only, optional query.
/// D6: Omni-Search QuickBar feed — ALL kinds (logins, cards, notes, licenses,
/// identities, ssh). Rows display title + subtitle only (numbers/keys stay
/// masked until Copy/Type), so screen-sharers see no secrets.
///
/// Moat #1: fuzzy rank — title-prefix beats word-prefix beats substring,
/// favorites float (stable sort keeps vault order inside equal scores).
/// QuickBar-only: the main list order is untouched.
fn qb_rank_score(q: &str, title: &str, username: &str, fav: bool) -> i32 {
    if q.is_empty() {
        return if fav { 15 } else { 0 };
    }
    let t = title.to_lowercase();
    let u = username.to_lowercase();
    let base = if t == q {
        100
    } else if t.starts_with(q) {
        60
    } else if t.split_whitespace().any(|w| w.starts_with(q)) {
        40
    } else if t.contains(q) {
        20
    } else if u.starts_with(q) {
        10
    } else if u.contains(q) {
        5
    } else {
        0
    };
    base + if fav { 15 } else { 0 }
}

fn vault_quickbar(vault: &Vault, query: &str, travel_only: bool) -> ModelRc<CredentialView> {
    // The feed must not disturb the main list's total: save/restore it.
    let prev = total_matches();
    let model = vault_to_items(
        vault,
        &FilterState { query: query.to_string(), kind: 0, folder: "All".to_string(), travel_only, fav_only: false, show_trash: false, health: String::new(), janitor: false, limit: LIST_CAP },
    );
    restore_total(prev);
    // Standalone 2FA stays out of the QuickBar: its copy/type flows dispatch
    // on secrets stored in the row, and kind-8 rows deliberately carry none
    // (fresh codes resolve by id in the main window only).
    let q = query.trim().to_lowercase();
    let mut rows: Vec<CredentialView> = model.iter().filter(|r| r.kind != 8).collect();
    // Stable: equal scores keep vault order (no reshuffle surprises).
    rows.sort_by(|a, b| {
        qb_rank_score(&q, &b.title, &b.username, b.fav)
            .cmp(&qb_rank_score(&q, &a.title, &a.username, a.fav))
    });
    ModelRc::new(VecModel::from(rows))
}

#[cfg(windows)]
fn bring_to_foreground(window: &slint::Window) {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows_sys::Win32::UI::WindowsAndMessaging::SetForegroundWindow;
    let handle_wrapper = window.window_handle();
    if let Ok(handle) = handle_wrapper.window_handle() {
        if let RawWindowHandle::Win32(win32) = handle.as_raw() {
            let hwnd = win32.hwnd.get() as *mut ::core::ffi::c_void;
            unsafe {
                SetForegroundWindow(hwnd as _);
            }
        }
    }
}

fn main() -> Result<(), slint::PlatformError> {
    // Zero-Footprint Portable Mode (rules Cat 7): PHANTOM_VAULT_DIR pins the
    // process working directory BEFORE anything touches disk, so every
    // relative data file (vault, DPAPI seals, decoy, sync sidecars,
    // crash.log) lives on the USB/RAM-disk. Absolute picker/CLI paths are
    // unaffected. Point it at a RAM-disk for zero SSD artifacts.
    // Portable badge source of truth: the USB/RAM-disk dir when the mode
    // actually engaged, else None (UI shows a 📦 badge, never the path —
    // shoulder-surfers don't need our drive layout).
    let mut portable_dir: Option<String> = None;
    if let Ok(dir) = std::env::var("PHANTOM_VAULT_DIR") {
        let dir = dir.trim().to_string();
        if !dir.is_empty() {
            let res: std::io::Result<()> =
                std::fs::create_dir_all(&dir).and_then(|()| std::env::set_current_dir(&dir));
            match res {
                Ok(()) => {
                    eprintln!("📦 Portable mode: data dir = {dir}");
                    portable_dir = Some(dir);
                }
                Err(e) => eprintln!("⚠️ Portable dir unusable ({dir}): {e} — using default."),
            }
        }
    }
    // Cat 8 process hardening, applied before any secret exists in RAM:
    // refuse injected DLLs, opt out of WER crash-dump uploads, probe admin.
    let dll_guarded = windows_native::process_guard::block_injected_dlls();
    let extra_hardened = windows_native::process_guard::harden_extra();
    let wer_excluded = windows_native::process_guard::exclude_from_crash_dumps();
    let elevated = windows_native::process_guard::is_elevated();
    // NOTE: stderr only — stdout belongs to the Native Messaging frame
    // protocol when Chromium launches us (any println here corrupts the
    // length-prefixed pipe and the popup hangs on "Loading…").
    if dll_guarded {
        eprintln!("🛡️ DLL-injection block active (Microsoft-only binaries).");
    }
    if extra_hardened > 0 {
        eprintln!("🛡️ Extra mitigations applied ({extra_hardened}/3: ext-point, fonts, handles).");
    }
    // M9: pagefile defense needs SeLockMemoryPrivilege — try once, warn loud.
    if !core::memory::acquire_lock_privilege() {
        eprintln!("⚠️ SeLockMemoryPrivilege unavailable — VirtualLock pagefile pinning will fail (see LockedBytes errors).");
    }
    if wer_excluded {
        eprintln!("🛡️ Crash-dump upload excluded (WER).");
    }
    if elevated {
        eprintln!("⚠️ Running as Administrator — larger blast radius. Prefer portable user mode.");
    }
    // Phase 16 (Option 2): headless CLI modes — exit before any GUI init.
    //   vault run -e TITLE=VAR ... -- <cmd>   (memory-only env injection)
    //   vault scan [path]                     (secret-leak check, exit 1 on hits)
    //   vault ssh-agent                       (named-pipe agent, foreground)
    //   vault shred <file>...                (DoD 3-pass shred + delete)
    //   vault native-host [--print-manifest <origin>]  (browser bridge: Hello-cached unlock, stdio framing)
    //   <exe> chrome-extension://<id>/ [...]  (Chromium launches the bridge
    //     with the origin URL as argv[1] — never the "native-host" word)
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() > 1 {
        let code = match argv[1].as_str() {
            "run" => developer::vault_run::run_cli(&argv[2..]),
            "scan" => developer::vault_run::scan_cli(&argv[2..]),
            "ssh-agent" => developer::ssh_agent::serve_cli(),
            origin if is_native_host_launch(origin) => {
                if let Some(pos) = argv.iter().position(|a| a == "--print-manifest") {
                    let origin = argv.get(pos + 1).cloned().unwrap_or_else(|| {
                        "chrome-extension://<YOUR-EXTENSION-ID>/".to_string()
                    });
                    windows_native::native_host::print_manifest(&origin);
                    0
                } else {
                    windows_native::native_host::serve_cli()
                }
            }
            "shred" => {
                if argv.len() < 3 {
                    eprintln!("usage: phantom_vault shred <file>...");
                    2
                } else {
                    let mut failed = 0;
                    for f in &argv[2..] {
                        match security::shredder::shred_file(std::path::Path::new(f)) {
                            Ok(()) => println!("shredded: {f}"),
                            Err(e) => {
                                eprintln!("shred failed {f}: {e}");
                                failed += 1;
                            }
                        }
                    }
                    if failed > 0 { 1 } else { 0 }
                }
            }
            "completions" => {
                let shell = argv.get(2).map(String::as_str).unwrap_or("powershell");
                match developer::shell_complete::render(shell) {
                    Ok(script) => {
                        print!("{script}");
                        0
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        2
                    }
                }
            }
            _ => {
                eprintln!("usage: phantom_vault [run|scan|ssh-agent|native-host|completions] ...");
                2
            }
        };
        std::process::exit(code);
    }
    // Crash recorder: persist panic details to crash.log so field
    // crashes can be diagnosed even when the console is lost.
    std::panic::set_hook(Box::new(|info| {
        let mut msg = format!("PANIC: {info}\n");
        let bt = std::backtrace::Backtrace::capture();
        msg.push_str(&format!("{bt}\n"));
        let _ = std::fs::write("crash.log", &msg);
        eprintln!("{msg}");
    }));
    let main_window = MainWindow::new()?;
    main_window.set_app_version(env!("CARGO_PKG_VERSION").into());
    main_window.set_favicons_enabled(crate::core::favicon::show_favicons());
    // App PIN button shows iff a sealed PIN exists on this machine.
    main_window.set_pin_available(security::app_pin::is_enrolled(std::path::Path::new(".")));
    main_window.set_ext_pin_set(security::ext_pin::is_set(std::path::Path::new(".")));
    main_window.set_portable_badge(
        portable_dir
            .map(|_| "📦 Portable".to_string())
            .unwrap_or_default()
            .into(),
    );
    main_window.set_has_vault_file(std::path::Path::new(VAULT_FILE).exists());
    // First-run onboarding: no vault on disk → 3-step wizard (zero-knowledge
    // explainer + master-password setup with live strength meter) instead of
    // the bare lock screen. Hidden on first successful unlock.
    if !std::path::Path::new(VAULT_FILE).exists() {
        main_window.set_show_onboarding(true);
        main_window.set_onboarding_step(1);
    }
    // Prefs painted before first frame (tray + backup).
    main_window.set_tray_minimize(windows_native::tray::load_tray_pref());
    main_window.set_chain_2fa(chain_2fa_enabled());
    {
        let bcfg = storage::backup_scheduler::load_config();
        main_window.set_backup_enabled(bcfg.enabled);
        main_window.set_backup_interval(bcfg.interval_days as i32);
        main_window.set_backup_dir(bcfg.backup_dir.clone().into());
        main_window.set_backup_status(format!(
            "Next: {} • keep {} • {}",
            if bcfg.enabled {
                if bcfg.last_backup_timestamp == 0 {
                    "on next heartbeat".to_string()
                } else {
                    format!("{}d cycle", bcfg.interval_days)
                }
            } else {
                "disabled".to_string()
            },
            bcfg.max_backups_retained,
            bcfg.backup_dir,
        ).into());
    }
    let quick_bar = QuickBarWindow::new()?;
    let capture_window = QuickCaptureWindow::new()?;
    let quickbar_visible = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Main-window visibility for the resource diet: background loops deep-
    // sleep while this is false (tray/minimized) or the vault is locked.
    // Flipped on the event loop at every show/hide transition below.
    let ui_visible = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let active_vault = Arc::new(Mutex::new(Vault::new()));
    // Store master password in RAM for re-encryption on add (wrapped in Arc/Mutex)
    let active_master_pw: Arc<Mutex<Option<SecretString>>> = Arc::new(Mutex::new(None));
    // Phase 7: shared search query for filtering after add/unlock
    let search_state: Arc<Mutex<FilterState>> = Arc::new(Mutex::new(FilterState::default()));
    // Pending custom fields for the open add/edit form (login kind).
    let pending_cf: Arc<Mutex<Vec<models::CustomField>>> = Arc::new(Mutex::new(Vec::new()));
    // Edit target: Some((kind, id)) when the form edits instead of creates.
    let editing_item: Arc<Mutex<Option<(i32, String)>>> = Arc::new(Mutex::new(None));
    // Travel Mode: when true, only travel_safe items are listed anywhere.
    let travel_mode: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    // System tray: icon + menu, alive from boot so close-to-tray always has
    // a restore path. Actions hop to the event loop (Slint is not thread-safe).
    let trayalive = {
        let w_main = main_window.as_weak();
        let w_qb = quick_bar.as_weak();
        let qb_vis = Arc::clone(&quickbar_visible);
        let t_vault = Arc::clone(&active_vault);
        let t_master = Arc::clone(&active_master_pw);
        let t_travel = Arc::clone(&travel_mode);
        let open = {
            let w = w_main.clone();
            let vis = Arc::clone(&ui_visible);
            Arc::new(move || {
                let w = w.clone();
                let vis = vis.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = w.upgrade() {
                        let hwnd = windows_native::ime_guard::hwnd_of(ui.window());
                        if !hwnd.is_null() {
                            use windows_sys::Win32::UI::WindowsAndMessaging::{
                                ShowWindow, SW_SHOW,
                            };
                            unsafe {
                                ShowWindow(hwnd, SW_SHOW);
                            }
                        }
                        ui.window().set_minimized(false);
                        ui.show().ok();
                        bring_to_foreground(ui.window());
                        vis.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }) as Arc<dyn Fn() + Send + Sync>
        };
        let quickbar = {
            let w_main = w_main.clone();
            let w_qb = w_qb.clone();
            Arc::new(move || {
                let (w_main, w_qb, t_vault, t_master, t_travel, qb_vis) = (
                    w_main.clone(), w_qb.clone(),
                    t_vault.clone(), t_master.clone(), t_travel.clone(),
                    qb_vis.clone(),
                );
                let _ = slint::invoke_from_event_loop(move || {
                    let is_unlocked = lock_master_pw(&t_master).is_some();
                    if !is_unlocked {
                        if let Some(main_ui) = w_main.upgrade() {
                            main_ui.show().ok();
                            bring_to_foreground(main_ui.window());
                        }
                        return;
                    }
                    if let Some(qb) = w_qb.upgrade() {
                        let vault = lock_vault(&t_vault);
                        let travel = *t_travel.lock().unwrap();
                        qb.set_quick_query("".into());
                        qb.set_filtered_results(vault_quickbar(&vault, "", travel));
                        qb.show().ok();
                        bring_to_foreground(qb.window());
                        qb_vis.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }) as Arc<dyn Fn() + Send + Sync>
        };
        let lock = {
            let t_vault = Arc::clone(&active_vault);
            let t_master = Arc::clone(&active_master_pw);
            Arc::new(move || {
                windows_native::clipboard::flush_now();
                panic_wipe(&t_vault, &t_master);
                security::access_log::log_event("lock", "tray exit");
                std::process::exit(0);
            }) as Arc<dyn Fn() + Send + Sync>
        };
        let exit = {
            let t_vault = Arc::clone(&active_vault);
            let t_master = Arc::clone(&active_master_pw);
            Arc::new(move || {
                windows_native::clipboard::flush_now();
                panic_wipe(&t_vault, &t_master);
                security::access_log::log_event("lock", "tray exit");
                std::process::exit(0);
            }) as Arc<dyn Fn() + Send + Sync>
        };
        match windows_native::tray::start(windows_native::tray::TrayActions {
            on_open: Some(open),
            on_quickbar: Some(quickbar),
            on_lock: Some(lock),
            on_exit: Some(exit),
        }) {
            Ok(_handle) => {
                eprintln!("📥 System tray icon live.");
                true
            }
            Err(e) => {
                eprintln!("⚠️ Tray unavailable ({e}) — close-to-tray falls back to exit.");
                // Console is invisible in release builds: mirror into the
                // access log so the user can SEE why X exits (Access Log viewer).
                security::access_log::log_event("tray", &format!("boot failed: {e}"));
                false
            }
        }
    };
    let tray_alive = Arc::new(std::sync::atomic::AtomicBool::new(trayalive));
    // X button: tray-minimize (hide + trim, loop survives — the callback runs
    // on the event loop, unlike the old worker-thread hide() crash). Tray
    // missing or pref OFF = secure exit (flush + log), never a linger.
    {
        let w = main_window.as_weak();
        let alive = Arc::clone(&tray_alive);
        let vis = Arc::clone(&ui_visible);
        main_window.window().on_close_requested(move || {
            eprintln!("PV_CLOSE requested pref={} alive={}",
                windows_native::tray::load_tray_pref(),
                alive.load(std::sync::atomic::Ordering::SeqCst));
            security::access_log::log_event("close", "requested");
            // Pref ON but pump dead (silent boot failure / later pump death)?
            // Rescue once via respawn instead of surprise-exiting the user.
            let minimize = windows_native::tray::load_tray_pref()
                && (alive.load(std::sync::atomic::Ordering::SeqCst)
                    || {
                        let ok = windows_native::tray::restart();
                        if ok {
                            alive.store(true, std::sync::atomic::Ordering::SeqCst);
                        } else {
                            security::access_log::log_event(
                                "tray",
                                "close-time respawn failed — exiting",
                            );
                        }
                        ok
                    });
            if minimize {
                windows_native::tray::trim_working_set();
                vis.store(false, std::sync::atomic::Ordering::SeqCst);
                // Diagnosis trail: with no console in release builds, the
                // access log is the only witness of which close path ran.
                security::access_log::log_event("tray", "minimize accepted");
                if let Some(ui) = w.upgrade() {
                    ui.set_notification_text("📥 Minimized to tray — right-click the tray icon to restore.".into());
                    ui.window().set_minimized(true);
                    // KeepWindowShown alone leaves a taskbar button; SW_HIDE
                    // removes it so only the tray icon remains (restore uses
                    // SW_SHOW + show() + foreground).
                    let hwnd = windows_native::ime_guard::hwnd_of(ui.window());
                    if !hwnd.is_null() {
                        use windows_sys::Win32::UI::WindowsAndMessaging::{
                            ShowWindow, SW_HIDE,
                        };
                        unsafe {
                            ShowWindow(hwnd, SW_HIDE);
                        }
                    }
                }
                slint::CloseRequestResponse::KeepWindowShown
            } else {
                windows_native::clipboard::flush_now();
                security::access_log::log_event("lock", "window close exit");
                // P1 fix: window-close exit must not leave bridge credentials.
                // (Tray-minimize path above keeps running unlocked — beats on.)
                stop_bridge_heartbeat();
                std::process::exit(0);
            }
        });
    }
    // Scheduled-backup heartbeat: ciphertext-only, needs no unlock.
    {
        let w = main_window.as_weak();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(
                storage::backup_scheduler::HEARTBEAT_SECS,
            ));
            let now = crate::models::current_timestamp();
            if let Some(msg) = storage::backup_scheduler::heartbeat_tick(now) {
                let w = w.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = w.upgrade() {
                        ui.set_backup_status(msg.clone().into());
                        ui.set_notification_text(msg.into());
                    }
                });
            }
        });
    }
    // Health badges keyed by credential id (audit results, cleared on lock).
    let _health_state: Arc<Mutex<std::collections::HashMap<String, String>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    // Wire-up #3: dynamic clipboard flush + auto-lock state.
    let clipboard_timeout_secs = Arc::new(std::sync::atomic::AtomicU64::new(15));
    let autolock_timeout_mins = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let last_activity = Arc::new(Mutex::new(std::time::Instant::now()));
    // Wire-up #4: last UIA-detected app for the autofill pill.
    let pill_app: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    // Phase 25: BLE proximity auto-lock state (config persisted to
    // proximity.json; monitor holds the debounce across heartbeats).
    let prox_config: Arc<Mutex<windows_native::proximity_lock::ProximityConfig>> =
        Arc::new(Mutex::new(windows_native::proximity_lock::ProximityConfig::load()));
    let prox_monitor: Arc<Mutex<windows_native::proximity_lock::ProximityMonitor>> =
        Arc::new(Mutex::new(windows_native::proximity_lock::ProximityMonitor::new()));
    {
        let cfg = prox_config.lock().map(|c| c.clone()).unwrap_or_default();
        main_window.set_prox_enabled(cfg.enabled);
        main_window.set_prox_device(cfg.device_name.into());
        main_window.set_prox_sensitivity(
            windows_native::proximity_lock::sensitivity_for_threshold(cfg.rssi_threshold),
        );
        if !cfg.enabled {
            main_window.set_prox_status("⚪ Proximity Inactive".into());
        }
    }

    // Surface the elevation warning where the user WILL see it: lock screen.
    if elevated {
        main_window.set_status_text(
            "Vault is locked. Enter Master Password:\n⚠️ Running as Administrator.".into(),
        );
    }
    // Cat 8 binary self-integrity: hash on a worker (large exes take ~0.5s),
    // banner on the lock screen only when the tripwire actually fires.
    {
        let weak = main_window.as_weak();
        std::thread::spawn(move || {
            if security::integrity::check() == security::integrity::Integrity::Tampered {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_integrity_warning("🚨 Binary Integrity Warning: Executable hash has changed since installation! Check for tampering.".into());
                    }
                });
            }
        });
    }

    // Wire-up #3: background auto-lock ticker (5s cadence). Wipes master +
    // decrypted vault from RAM and drops back to the lock screen on timeout.
    // Cat 8: the same tick also feeds the session-lock monitor (Win+L,
    // screensaver, RDP disconnect) — either trigger takes the shared path.
    {
        let main_weak_lock = main_window.as_weak();
        let cap_weak_lock = capture_window.as_weak();
        let vault_lock = Arc::clone(&active_vault);
        let master_lock = Arc::clone(&active_master_pw);
        let activity_lock = Arc::clone(&last_activity);
        let timeout_lock = Arc::clone(&autolock_timeout_mins);
        let pending_lock = Arc::clone(&pending_cf);
        let editing_lock = Arc::clone(&editing_item);
        let session_mon = Arc::new(Mutex::new(
            windows_native::session_lock::LockMonitor::new(2),
        ));
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(5));
            let still_unlocked = master_lock.lock().map(|m| m.is_some()).unwrap_or(false);
            if !still_unlocked {
                continue;
            }
            // Trigger A: session ended (Win+L / screensaver / RDP).
            let session_fired = session_mon
                .lock()
                .map(|mut m| {
                    m.observe(windows_native::session_lock::workstation_locked())
                })
                .unwrap_or(false);
            if session_fired {
                lock_vault_now(
                    main_weak_lock.clone(),
                    cap_weak_lock.clone(),
                    &vault_lock,
                    &master_lock,
                    &pending_lock,
                    &editing_lock,
                    "🔒 Locked: workstation session ended.",
                    "session-lock",
                );
                continue;
            }
            // Trigger B: inactivity timeout (0 = disabled).
            let mins = timeout_lock.load(std::sync::atomic::Ordering::SeqCst);
            if mins == 0 {
                continue;
            }
            let idle = activity_lock
                .lock()
                .map(|t| t.elapsed())
                .unwrap_or(Duration::from_secs(0));
            let limit = Duration::from_secs(mins * 60);
            if idle < limit {
                // 30s heads-up before the guillotine: interact (copy, type,
                // click) to stay awake. Re-arms whenever comfortably awake.
                static WARNED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if limit.saturating_sub(idle) > Duration::from_secs(30) {
                    WARNED.store(false, std::sync::atomic::Ordering::SeqCst);
                } else if !WARNED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    let weak = main_weak_lock.clone();
                    let secs = limit.saturating_sub(idle).as_secs().max(1);
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_notification_text(
                                format!("⏳ Auto-lock in ~{secs}s — interact to stay awake.").into(),
                            );
                        }
                    });
                }
                continue;
            }
            lock_vault_now(
                main_weak_lock.clone(),
                cap_weak_lock.clone(),
                &vault_lock,
                &master_lock,
                &pending_lock,
                &editing_lock,
                "🔒 Auto-locked due to inactivity.",
                "inactivity",
            );
            // Avoid repeat firing until next unlock touches activity.
            if let Ok(mut t) = activity_lock.lock() {
                *t = std::time::Instant::now();
            }
        });
    }

    // Wire-up #4: UIA password-field focus probe. Shows the pill when a
    // foreign app focuses a password box; hides it otherwise. Change-driven
    // to avoid spamming the event loop.
    // Cat 8 blur-on-focus-loss rides the same 1.5s tick: the moment NONE of
    // our three windows holds focus while unlocked, revealed secrets and the
    // detail modal mask themselves (Alt+Tab / shoulder-surfing defense).
    #[cfg(windows)]
    {
        let main_weak_pill = main_window.as_weak();
        let qb_weak_pill = quick_bar.as_weak();
        let cap_weak_pill = capture_window.as_weak();
        let master_pill = Arc::clone(&active_master_pw);
        let pill_app_probe = Arc::clone(&pill_app);
        let pill_visible = Arc::clone(&ui_visible);
        thread::spawn(move || {
            use windows_native::ime_guard::hwnd_of;
            let mut last_shown = String::new();
            let mut had_focus = true; // assume focused until proven otherwise
            let mut ours: Vec<isize> = vec![0, 0, 0];
            loop {
                // Diet cadence: locked vault or hidden main window → 10s
                // idle (pill still probes, just slower); active → 1.5s.
                // UIA COM probe is the hottest idle cost after the ticker.
                // Falls through to the existing locked/hidden handling below.
                let unlocked = master_pill.lock().map(|m| m.is_some()).unwrap_or(false);
                let hidden = !pill_visible.load(std::sync::atomic::Ordering::SeqCst);
                if !unlocked || hidden {
                    thread::sleep(Duration::from_secs(10));
                } else {
                    thread::sleep(Duration::from_millis(1500));
                }
                // Lazily resolve our HWNDs (valid only after first show).
                if ours.iter().all(|&h| h == 0) {
                    if let Some(ui) = main_weak_pill.upgrade() {
                        ours[0] = hwnd_of(ui.window()) as isize;
                    }
                    if let Some(qb) = qb_weak_pill.upgrade() {
                        ours[1] = hwnd_of(qb.window()) as isize;
                    }
                    if let Some(cap) = cap_weak_pill.upgrade() {
                        ours[2] = hwnd_of(cap.window()) as isize;
                    }
                }
                // Focus-blur tripwire (only meaningful while unlocked).
                if unlocked && ours.iter().any(|&h| h != 0) {
                    let fg =
                        unsafe { windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow() }
                            as isize;
                    let focused = ours.contains(&fg);
                    if had_focus && !focused {
                        let weak = main_weak_pill.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak.upgrade() {
                                ui.set_d_secret_visible(false);
                                ui.set_show_detail(false);
                                ui.set_notification_text(
                                    "👁️ Secrets masked (window lost focus).".into(),
                                );
                            }
                        });
                    }
                    had_focus = focused;
                } else if !unlocked {
                    had_focus = true; // re-arm for the next unlock
                }
                if !unlocked {
                    if !last_shown.is_empty() {
                        last_shown.clear();
                        if let Ok(mut a) = pill_app_probe.lock() {
                            a.clear();
                        }
                        let weak = main_weak_pill.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak.upgrade() {
                                ui.set_show_autofill_pill(false);
                            }
                        });
                    }
                    continue;
                }
                let ctx = windows_native::desktop_autofill::inspect_active_context()
                    .unwrap_or_default();
                // Spoofed host app → never offer the pill; warn once per app.
                if let Some(brand) =
                    windows_native::desktop_autofill::executable_spoof_brand(&ctx.exe_name)
                {
                    if last_shown != ctx.exe_name {
                        last_shown = ctx.exe_name.clone();
                        crate::security::access_log::log_event(
                            "pill-blocked-spoof",
                            &ctx.exe_name,
                        );
                        let weak = main_weak_pill.clone();
                        let exe = ctx.exe_name.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak.upgrade() {
                                ui.set_show_autofill_pill(false);
                                ui.set_notification_text(
                                    format!(
                                        "🚨 App-Spoof Hazard: Suspicious executable '{exe}' detected (impersonating {brand})! Autofill pill suppressed."
                                    )
                                    .into(),
                                );
                            }
                        });
                    }
                    continue;
                }
                let show = ctx.is_password_focused && !ctx.app_name.is_empty()
                    && !ctx.app_name.eq_ignore_ascii_case("phantom_vault");
                if show {
                    if last_shown != ctx.app_name {
                        last_shown = ctx.app_name.clone();
                        if let Ok(mut a) = pill_app_probe.lock() {
                            *a = ctx.app_name.clone();
                        }
                        let weak = main_weak_pill.clone();
                        let title = format!("⚡ Fill {}", ctx.app_name);
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak.upgrade() {
                                ui.set_pill_title(title.into());
                                ui.set_show_autofill_pill(true);
                            }
                        });
                    }
                } else if !last_shown.is_empty() {
                    last_shown.clear();
                    if let Ok(mut a) = pill_app_probe.lock() {
                        a.clear();
                    }
                    let weak = main_weak_pill.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_show_autofill_pill(false);
                        }
                    });
                }
            }
        });
    }

    // Blackout is OFF by default on startup (dev-friendly: screenshots work).
    // It only engages when the user toggles it ON in Settings, and the
    // persisted choice in blackout.pref is honored across restarts.
    #[cfg(windows)]
    {
        let main_weak_guard = main_window.as_weak();
        let qb_weak_guard = quick_bar.as_weak();
        let cap_weak_guard = capture_window.as_weak();
        // Delayed off-loop: DWM needs the top-level HWNDs fully adopted first.
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(250));
            let enabled = windows_native::display_guard::load_blackout_pref();
            let _ = slint::invoke_from_event_loop(move || {
                let mut guarded = 0;
                if enabled {
                    if let Some(ui) = main_weak_guard.upgrade() {
                        if windows_native::display_guard::guard_window(ui.window()) {
                            guarded += 1;
                        }
                    }
                    if let Some(qb) = qb_weak_guard.upgrade() {
                        if windows_native::display_guard::guard_window(qb.window()) {
                            guarded += 1;
                        }
                    }
                    if let Some(cap) = cap_weak_guard.upgrade() {
                        if windows_native::display_guard::guard_window(cap.window()) {
                            guarded += 1;
                        }
                    }
                } else if let Some(ui) = main_weak_guard.upgrade() {
                    // Mirror the persisted OFF state onto the toggle + HWNDs.
                    ui.set_blackout_enabled(false);
                    windows_native::display_guard::clear_window(ui.window());
                    if let Some(qb) = qb_weak_guard.upgrade() {
                        windows_native::display_guard::clear_window(qb.window());
                    }
                    if let Some(cap) = cap_weak_guard.upgrade() {
                        windows_native::display_guard::clear_window(cap.window());
                    }
                }
                if guarded > 0 {
                    println!("🛡️ DWM Anti-Capture Guard Active (WDA_MONITOR) on {guarded}/3 windows.");
                }
                // Cat 8 IME shield: the same three HWNDs go IME-deaf so cloud
                // IMEs can never compose (and upload) sensitive keystrokes.
                let mut deaf = 0;
                if let Some(ui) = main_weak_guard.upgrade() {
                    if windows_native::ime_guard::set_ime_detached(
                        windows_native::ime_guard::hwnd_of(ui.window()),
                        true,
                    ) {
                        deaf += 1;
                    }
                }
                if let Some(qb) = qb_weak_guard.upgrade() {
                    if windows_native::ime_guard::set_ime_detached(
                        windows_native::ime_guard::hwnd_of(qb.window()),
                        true,
                    ) {
                        deaf += 1;
                    }
                }
                if let Some(cap) = cap_weak_guard.upgrade() {
                    if windows_native::ime_guard::set_ime_detached(
                        windows_native::ime_guard::hwnd_of(cap.window()),
                        true,
                    ) {
                        deaf += 1;
                    }
                }
                if deaf > 0 {
                    println!("🛡️ IME shield active (cloud-IME deaf) on {deaf}/3 windows.");
                }
            });
        });
    }

    // Phase 9: QuickBarWindow callbacks — query filtering, copy + auto-clear, dismiss
    let qb_weak_query = quick_bar.as_weak();
    let vault_arc_qb_query = Arc::clone(&active_vault);
    let travel_qb_query = Arc::clone(&travel_mode);
    quick_bar.on_query_changed(move |query| {
        let q = query.as_str().to_string();
        let vault = lock_vault(&vault_arc_qb_query);
        let filtered = vault_quickbar(&vault, &q, *travel_qb_query.lock().unwrap());
        if let Some(ui) = qb_weak_query.upgrade() {
            ui.set_filtered_results(filtered);
        }
    });

    let qb_weak_select = quick_bar.as_weak();
    let main_weak_for_copy = main_window.as_weak();
    let qb_visible_select = Arc::clone(&quickbar_visible);
    let ct_select = Arc::clone(&clipboard_timeout_secs);
    let activity_select = Arc::clone(&last_activity);
    let vault_arc_select = Arc::clone(&active_vault);
    quick_bar.on_item_selected(move |kind, id, password| {
        if let Some(qb) = qb_weak_select.upgrade() {
            qb.hide().ok();
        }
        qb_visible_select.store(false, std::sync::atomic::Ordering::SeqCst);
        // Reprompt gate: armed logins detour through the MainWindow modal
        // (rp_action 1 = copy) instead of copying straight from QuickBar.
        if let Some(main_ui) = main_weak_for_copy.upgrade() {
            let gated = {
                let v = lock_vault(&vault_arc_select);
                reprompt_gate(&v, kind, id.as_str())
            };
            if let Some((g_user, g_secret)) = gated {
                main_ui.set_rp_action(1);
                main_ui.set_rp_kind(1);
                main_ui.set_rp_id(id.as_str().into());
                main_ui.set_rp_user(g_user.into());
                main_ui.set_rp_secret(g_secret.into());
                main_ui.set_rp_error(String::new().into());
                main_ui.set_rp_show(true);
                main_ui.set_notification_text("🔒 Master re-prompt required.".into());
                return;
            }
        }
        // Phase 20: masked copy (Win+V excluded) with guarded auto-clear.
        if let Some(main_ui) = main_weak_for_copy.upgrade() {
            if let Ok(mut t) = activity_select.lock() {
                *t = std::time::Instant::now();
            }
            let secs = ct_select.load(std::sync::atomic::Ordering::SeqCst);
            secure_copy_with_feedback(
                main_ui.as_weak(),
                password.as_str().to_string(),
                &format!("📋 Password copied! (Masked from Win+V, auto-clearing in {secs}s)"),
                secs,
            );
        }
    });

    // QuickBar live-TOTP copy: fresh code generated at click time (never a
    // stale row snapshot). Same reprompt gate as password copy for kind 1.
    let qb_weak_totp = quick_bar.as_weak();
    let main_weak_for_totp = main_window.as_weak();
    let qb_visible_totp = Arc::clone(&quickbar_visible);
    let ct_totp = Arc::clone(&clipboard_timeout_secs);
    let activity_totp = Arc::clone(&last_activity);
    let vault_arc_totp = Arc::clone(&active_vault);
    quick_bar.on_copy_totp_selected(move |kind, id| {
        if let Some(qb) = qb_weak_totp.upgrade() {
            qb.hide().ok();
        }
        qb_visible_totp.store(false, std::sync::atomic::Ordering::SeqCst);
        if let Some(main_ui) = main_weak_for_totp.upgrade() {
            let gated = {
                let v = lock_vault(&vault_arc_totp);
                if kind == 1 {
                    reprompt_gate(&v, kind, id.as_str())
                } else {
                    None
                }
            };
            if let Some((g_user, g_secret)) = gated {
                main_ui.set_rp_action(1);
                main_ui.set_rp_kind(1);
                main_ui.set_rp_id(id.as_str().into());
                main_ui.set_rp_user(g_user.into());
                main_ui.set_rp_secret(g_secret.into());
                main_ui.set_rp_error(String::new().into());
                main_ui.set_rp_show(true);
                main_ui.set_notification_text("🔒 Master re-prompt required.".into());
                return;
            }
        }
        if let Some(main_ui) = main_weak_for_totp.upgrade() {
            if let Ok(mut t) = activity_totp.lock() {
                *t = std::time::Instant::now();
            }
            let code: Option<String> = {
                let v = lock_vault(&vault_arc_totp);
                if kind == 1 {
                    v.credentials
                        .iter()
                        .find(|c| c.id == id.as_str())
                        .and_then(|c| {
                            crate::totp_engine::generate_live_code(&c.totp_secret).ok()
                        })
                        .map(|(c, _)| c)
                } else if kind == 8 {
                    v.totp_accounts
                        .iter()
                        .find(|a| a.id == id.as_str())
                        .and_then(|a| {
                            crate::totp_engine::generate_code_for_account(a).ok()
                        })
                        .map(|(c, _)| c)
                } else {
                    None
                }
            };
            let Some(code) = code else {
                main_ui.set_notification_text("⚠️ No live TOTP code for this item.".into());
                return;
            };
            let secs = ct_totp.load(std::sync::atomic::Ordering::SeqCst);
            secure_copy_with_feedback(
                main_ui.as_weak(),
                code,
                &format!("⏱️ TOTP copied! (Masked from Win+V, auto-clearing in {secs}s)"),
                secs,
            );
        }
    });

    // QuickBar open-URL (Moat #1 action-mode): same guarded launcher as the
    // main list — QuickBar stays open so the user keeps context.
    let main_weak_for_url = main_window.as_weak();
    quick_bar.on_qb_open_url(move |url| {
        if let Some(main_ui) = main_weak_for_url.upgrade() {
            launch_url(&main_ui, url.as_str());
        }
    });

    // Phase 13: Auto-Type from QuickBar (username + password keystroke fill)
    let type_qb_main = main_window.as_weak();
    let type_qb_self = quick_bar.as_weak();
    let type_qb_vis = Arc::clone(&quickbar_visible);
    let type_qb_vault = Arc::clone(&active_vault);
    let type_qb_uvis = Arc::clone(&ui_visible);
    quick_bar.on_type_selected(move |kind, id, username, password, totp| {
        if let Some(title) =
            check_canary_trip(&type_qb_vault, password.as_str(), "autotype-quickbar")
        {
            if let Some(ui) = type_qb_main.upgrade() {
                ui.set_notification_text(
                    format!("🚨 CANARY TRIPPED: '{title}' — logged!").into(),
                );
            }
        }
        // Reprompt gate: armed logins detour through the MainWindow modal
        // (rp_action 2 = type) instead of keystroking straight from QuickBar.
        if let Some(main_ui) = type_qb_main.upgrade() {
            let gated = {
                let v = lock_vault(&type_qb_vault);
                reprompt_gate(&v, kind, id.as_str())
            };
            if let Some((g_user, g_secret)) = gated {
                main_ui.set_rp_action(2);
                main_ui.set_rp_kind(1);
                main_ui.set_rp_id(id.as_str().into());
                main_ui.set_rp_user(g_user.into());
                main_ui.set_rp_secret(g_secret.into());
                main_ui.set_rp_error(String::new().into());
                main_ui.set_rp_show(true);
                main_ui.set_notification_text("🔒 Master re-prompt required.".into());
                return;
            }
        }
        trigger_autotype(
            type_qb_main.clone(),
            type_qb_self.clone(),
            Arc::clone(&type_qb_vis),
            Arc::clone(&type_qb_uvis),
            {
                let v = lock_vault(&type_qb_vault);
                type_request_for(&v, kind, id.as_str()).unwrap_or_else(|| {
                    login_type_request(
                        &v,
                        id.as_str(),
                        username.as_str(),
                        password.as_str(),
                        totp.as_str(),
                    )
                })
            },
        );
    });

    let qb_weak_dismiss = quick_bar.as_weak();
    let qb_visible_dismiss = Arc::clone(&quickbar_visible);
    quick_bar.on_dismiss(move || {
        if let Some(qb) = qb_weak_dismiss.upgrade() {
            qb.hide().ok();
        }
        qb_visible_dismiss.store(false, std::sync::atomic::Ordering::SeqCst);
    });

    // Phase 9: Global Hotkey Alt+Space — toggle QuickBarWindow
    #[cfg(windows)]
    {
        // Initialize GlobalHotKeyManager and register Alt+Space
        use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager};
        use global_hotkey::hotkey::{Code, HotKey, Modifiers};
        // Keep manager alive for lifetime of app.
        // NOTE: never .expect() here — a second app instance (or another tool
        // holding Alt+Space) must degrade gracefully, not kill the vault.
        let hotkey_ready = match GlobalHotKeyManager::new() {
            Ok(manager) => {
                let quickbar_hk = HotKey::new(Some(Modifiers::ALT), Code::Space);
                let autotype_hk = HotKey::new(
                    Some(Modifiers::CONTROL | Modifiers::ALT),
                    Code::KeyA,
                );
                // Panic Nuke: wipe RAM + die instantly. No confirm, no second chance.
                let panic_hk = HotKey::new(
                    Some(
                        Modifiers::CONTROL
                            | Modifiers::SHIFT
                            | Modifiers::ALT,
                    ),
                    Code::KeyQ,
                );
                let quick_id = quickbar_hk.id();
                let auto_id = autotype_hk.id();
                let panic_id = panic_hk.id();
                // Phase 22: Smart-Grab capture entry.
                let capture_hk = HotKey::new(Some(Modifiers::ALT), Code::KeyS);
                let capture_id = capture_hk.id();
                let mut ids = Vec::new();
                if manager.register(quickbar_hk).is_ok() {
                    ids.push(quick_id);
                }
                // Ctrl+Alt+A opens the Quick Bar straight into Type flow.
                // Independent registration: Alt+Space may be taken while this is free.
                let auto_armed = if manager.register(autotype_hk).is_ok() {
                    ids.push(auto_id);
                    Some(auto_id)
                } else {
                    None
                };
                let panic_armed = manager.register(panic_hk).is_ok();
                let capture_armed = manager.register(capture_hk).is_ok();
                // Prevent manager drop — leak for app lifetime.
                std::mem::forget(manager);
                if ids.is_empty() && !panic_armed && !capture_armed {
                    main_window.set_notification_text(
                        "⚠️ Hotkeys taken (another instance?) — in-app buttons still work.".into(),
                    );
                    None
                } else {
                    Some((ids, panic_armed.then_some(panic_id), capture_armed.then_some(capture_id), auto_armed))
                }
            }
            Err(_) => {
                main_window.set_notification_text(
                    "⚠️ Global hotkey unavailable — Quick Bar via in-app buttons only.".into(),
                );
                None
            }
        };
        if let Some((hotkey_ids, panic_id, capture_id, auto_id)) = hotkey_ready {
            let main_weak_hk = main_window.as_weak();
            let qb_weak_hk = quick_bar.as_weak();
            let vault_arc_hk = Arc::clone(&active_vault);
            let vault_arc_travel_hk = Arc::clone(&travel_mode);
            let master_pw_hk = Arc::clone(&active_master_pw);
            let qb_visible_hk = Arc::clone(&quickbar_visible);
            let vault_arc_nuke = Arc::clone(&active_vault);
            let master_pw_nuke = Arc::clone(&active_master_pw);
            let cap_weak_hk = capture_window.as_weak();
            let main_weak_cap = main_window.as_weak();
            let master_pw_cap = Arc::clone(&active_master_pw);
            thread::spawn(move || {
            let receiver = GlobalHotKeyEvent::receiver();
            loop {
                if let Ok(event) = receiver.recv() {
                    // Panic Nuke first: wipe RAM, flush clipboard residue, die.
                    // No UI round-trip, no log line — the nuke itself leaves
                    // no trace by design.
                    if Some(event.id) == panic_id {
                        panic_wipe(&vault_arc_nuke, &master_pw_nuke);
                        windows_native::clipboard::flush_now();
                        std::process::exit(0x1AFE);
                    }
                    // Phase 22: Smart-Grab — inspect foreground app, open capture.
                    if Some(event.id) == capture_id {
                        let main_weak = main_weak_cap.clone();
                        let cap_weak = cap_weak_hk.clone();
                        let master_clone = Arc::clone(&master_pw_cap);
                        thread::spawn(move || {
                            let unlocked = lock_master_pw(&master_clone).is_some();
                            if !unlocked {
                                let _ = slint::invoke_from_event_loop(move || {
                                    if let Some(main_ui) = main_weak.upgrade() {
                                        main_ui.show().ok();
                                        main_ui.set_notification_text(
                                            "🔓 Unlock first — then Alt+S captures the app.".into(),
                                        );
                                        #[cfg(windows)]
                                        bring_to_foreground(main_ui.window());
                                    }
                                });
                                return;
                            }
                            // UIA/COM inspection on THIS worker (MTA via ComGuard).
                            let ctx = windows_native::desktop_autofill::inspect_active_context()
                                .unwrap_or_default();
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Some(cap) = cap_weak.upgrade() {
                                    cap.set_cap_title(ctx.app_name.clone().into());
                                    cap.set_cap_user(ctx.detected_username.clone().into());
                                    cap.set_cap_pass("".into());
                                    cap.set_cap_totp("".into());
                                    cap.set_cap_hint(
                                        if ctx.is_password_focused {
                                            format!("🔑 Password field focused in {}", ctx.app_name).into()
                                        } else if ctx.window_title.is_empty() {
                                            "Alt+S grabbed this app".into()
                                        } else {
                                            format!("from {}", ctx.window_title.chars().take(48).collect::<String>()).into()
                                        },
                                    );
                                    cap.show().ok();
                                    #[cfg(windows)]
                                    bring_to_foreground(cap.window());
                                }
                            });
                        });
                        continue;
                    }
                    // Either Alt+Space (Quick Bar) or Ctrl+Alt+A (Type flow entry).
                    if !hotkey_ids.contains(&event.id) {
                        continue;
                    }
                    // Phase 23: Ctrl+Alt+A pre-filters by the focused app —
                    // the Quick Bar opens already matching (e.g. "Discord").
                    // Self-focus (our own window) yields no filter.
                    let mut app_prefilter = if Some(event.id) == auto_id {
                        windows_native::desktop_autofill::inspect_active_context()
                            .map(|c| c.app_name)
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    if app_prefilter.eq_ignore_ascii_case("phantom_vault") {
                        app_prefilter.clear();
                    }
                    let main_weak = main_weak_hk.clone();
                    let qb_weak = qb_weak_hk.clone();
                    let vault_clone = Arc::clone(&vault_arc_hk);
                    let master_clone = Arc::clone(&master_pw_hk);
                    let qb_visible = Arc::clone(&qb_visible_hk);
                    let travel_clone = Arc::clone(&vault_arc_travel_hk);
                    let _ = slint::invoke_from_event_loop(move || {
                        // Toggle visibility: if visible -> hide
                        if qb_visible.load(std::sync::atomic::Ordering::SeqCst) {
                            if let Some(qb) = qb_weak.upgrade() {
                                qb.hide().ok();
                            }
                            qb_visible.store(false, std::sync::atomic::Ordering::SeqCst);
                            return;
                        }
                        // Not visible: check vault locked
                        let is_unlocked = lock_master_pw(&master_clone).is_some();
                        if !is_unlocked {
                            if let Some(main_ui) = main_weak.upgrade() {
                                main_ui.show().ok();
                                bring_to_foreground(main_ui.window());
                            }
                            return;
                        }
                        // Vault unlocked: populate QuickBarWindow and show.
                        // Ctrl+Alt+A arrives pre-filtered by app; Alt+Space is blank.
                        if let Some(qb) = qb_weak.upgrade() {
                            let vault = lock_vault(&vault_clone);
                            let travel = *travel_clone.lock().unwrap();
                            let filtered = vault_quickbar(&vault, &app_prefilter, travel);
                            qb.set_quick_query(app_prefilter.into());
                            qb.set_filtered_results(filtered);
                            qb.show().ok();
                            bring_to_foreground(qb.window());
                            qb_visible.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                    });
                }
            }
            });
        }
    }
    #[cfg(not(windows))]
    {
        // Non-Windows: keep quick_bar logic but hotkey disabled
        let _ = &quick_bar;
        let _ = &capture_window;
    }

    // Phase 22: QuickCapture save/cancel.
    let cap_weak_save = capture_window.as_weak();
    let cap_vault_save = Arc::clone(&active_vault);
    let cap_master_save = Arc::clone(&active_master_pw);
    let cap_search_save = Arc::clone(&search_state);
    let cap_qb_save = quick_bar.as_weak();
    let cap_main_save = main_window.as_weak();
    capture_window.on_capture_save(move |title, user, pass, totp| {
        // Decoy MUST NOT capture here: the push below re-seals VAULT_FILE,
        // which would overwrite the real vault with decoy content.
        if let Some(main_ui) = cap_main_save.upgrade() {
            if main_ui.get_is_decoy() {
                if let Some(cap) = cap_weak_save.upgrade() {
                    cap.set_cap_hint("⛔ Decoy mode is read-only.".into());
                }
                return;
            }
        }
        let title = title.as_str().trim().to_string();
        let user = user.as_str().trim().to_string();
        let pass = pass.as_str().to_string();
        let totp = totp.as_str().trim().replace([' ', '-'], "");
        if title.is_empty() || user.is_empty() || pass.trim().is_empty() {
            if let Some(cap) = cap_weak_save.upgrade() {
                cap.set_cap_hint("⚠️ Title + username + password required.".into());
            }
            return;
        }
        if let Some(cap) = cap_weak_save.upgrade() {
            cap.hide().ok();
        }
        let weak = cap_main_save.clone();
        let vault_clone = Arc::clone(&cap_vault_save);
        let master_clone = Arc::clone(&cap_master_save);
        let search_clone = Arc::clone(&cap_search_save);
        let qb_clone = cap_qb_save.clone();
        std::thread::spawn(move || {
            let master_opt = lock_master_pw(&master_clone).clone();
            let Some(master_pw) = master_opt else {
                return;
            };
            let new_id = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| format!("cap{}", d.as_millis()))
                .unwrap_or_else(|_| "cap0".to_string());
            let res: Result<Vault, String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                vault.credentials.push(Credential {
                    id: new_id,
                    title: title.clone(),
                    username: user.clone(),
                    password: pass.clone(),
                    totp_secret: totp.clone(),
                    urls: Vec::new(),
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
                match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                    Ok(()) => Ok(vault.clone()),
                    Err(e) => {
                        *vault = snapshot;
                        Err(e)
                    }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    match res {
                        Ok(v) => {
                            let f = search_clone.lock().unwrap().clone();
                            set_paged_credentials(&ui, vault_to_items(&v, &f));
                            sync_folders_to_ui(&v, &ui);
                            if let Some(qb) = qb_clone.upgrade() {
                                qb.set_filtered_results(vault_quickbar(&v, "", search_clone.lock().unwrap().travel_only));
                            }
                            ui.set_notification_text(
                                "✅ Captured & encrypted login!".into(),
                            );
                            trigger_sync_push(ui.as_weak());
                        }
                        Err(e) => {
                            ui.set_notification_text(format!("❌ Capture save failed: {e}").into());
                        }
                    }
                }
            });
        });
    });

    let cap_weak_cancel = capture_window.as_weak();
    capture_window.on_capture_cancel(move || {
        if let Some(cap) = cap_weak_cancel.upgrade() {
            cap.hide().ok();
        }
    });

    // Phase 23: capture password quick-generate (strong default policy).
    let cap_weak_gen = capture_window.as_weak();
    capture_window.on_capture_generate(move || {
        let policy = PasswordPolicy::default();
        if let Ok(secret) =
            PasswordGenerator::generate_complex(&policy)
        {
            if let Some(cap) = cap_weak_gen.upgrade() {
                cap.set_cap_pass(secret.expose_secret().to_owned().into());
            }
        }
    });

    // Onboarding strength meter: charset-pool entropy for the typed master
    // password. Weak <28b, Good <50b, Strong <80b, else Unbreakable.
    // Pure estimate — the password itself never leaves the UI thread.
    let ob_weak = main_window.as_weak();
    main_window.on_ob_pw_changed(move |pw| {
        let Some(ui) = ob_weak.upgrade() else {
            return;
        };
        let s = pw.as_str();
        if s.is_empty() {
            ui.set_ob_strength_label(String::new().into());
            ui.set_ob_strength_frac(0.0);
            return;
        }
        let (mut pool, mut classes) = (0u32, 0u32);
        if s.bytes().any(|c| c.is_ascii_lowercase()) {
            pool += 26;
            classes += 1;
        }
        if s.bytes().any(|c| c.is_ascii_uppercase()) {
            pool += 26;
            classes += 1;
        }
        if s.bytes().any(|c| c.is_ascii_digit()) {
            pool += 10;
            classes += 1;
        }
        if s.bytes().any(|c| !c.is_ascii_alphanumeric()) {
            pool += 32;
            classes += 1;
        }
        // Single-class input is weaker than the pool suggests (keyboard walks,
        // dictionary words) — discount to 60%.
        let mut bits = s.len() as f64 * (pool.max(2) as f64).log2();
        if classes < 2 {
            bits *= 0.6;
        }
        let label = if bits < 28.0 {
            "Weak"
        } else if bits < 50.0 {
            "Good"
        } else if bits < 80.0 {
            "Strong"
        } else {
            "Unbreakable"
        };
        ui.set_ob_strength_label(format!("{} (~{:.0} bits)", label, bits).into());
        ui.set_ob_strength_frac((bits / 100.0).clamp(0.0, 1.0) as f32);
    });

    // 1. Unlock handler — delegates to the shared unlock pipeline
    let window_weak = main_window.as_weak();
    let vault_arc = Arc::clone(&active_vault);
    let master_pw_arc = Arc::clone(&active_master_pw);
    let search_state_unlock = Arc::clone(&search_state);
    let qb_weak_unlock = quick_bar.as_weak();
    let travel_off = Arc::clone(&travel_mode);
    let activity_unlock = Arc::clone(&last_activity);
    let unlock_uvis = Arc::clone(&ui_visible);
    main_window.on_unlock_requested(move |entered_password| {
        if let Ok(mut t) = activity_unlock.lock() {
            *t = std::time::Instant::now();
        }
        let pass = SecretString::new(entered_password.as_str().trim().to_string());
        // Fresh unlock always starts with Travel Mode OFF.
        *travel_off.lock().unwrap() = false;
        if let Some(ui) = window_weak.upgrade() {
            ui.set_is_travel_mode(false);
        }
        // Cat 8 AND-mode is read on the UI thread and enforced in the worker.
        let and_mode = window_weak
            .upgrade()
            .map(|ui| ui.get_and_mode())
            .unwrap_or(false);
        unlock_with_password(
            pass,
            window_weak.clone(),
            Arc::clone(&vault_arc),
            Arc::clone(&master_pw_arc),
            Arc::clone(&search_state_unlock),
            qb_weak_unlock.clone(),
            Arc::clone(&unlock_uvis),
            true,
            and_mode,
        );
    });

    // Phase 11: Windows Hello — availability probe on startup
    let hello_weak = main_window.as_weak();
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(_) => return,
        };
        let available =
            matches!(runtime.block_on(windows_native::hello::WindowsHello::check_availability()), Ok(
                windows_native::hello::BiometricAvailability::Available,
            ));
        // Hello status row (Settings): availability + enrollment in one line.
        let status = if available {
            "Available — unlock once with password to enroll Hello.".to_string()
        } else {
            "Not available on this device.".to_string()
        };
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = hello_weak.upgrade() {
                if available {
                    ui.set_hello_available(true);
                }
                ui.set_hello_status(status.into());
            }
        });
    });

    // Phase 27: optional vault-unlock TOTP gate (DEFAULT OFF).
    // Pending setup secret lives here between [Enable] and [Confirm] —
    // never in a Slint prop, never on disk until the user proves enrollment.
    let pending_totp_secret: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    // Verify path: password already proven + vault stashed; a matching live
    // code completes the SAME publish pipeline (no second KDF, no dup logic).
    let verify_weak = main_window.as_weak();
    let verify_vault = Arc::clone(&active_vault);
    let verify_master = Arc::clone(&active_master_pw);
    let verify_search = Arc::clone(&search_state);
    let verify_qb = quick_bar.as_weak();
    let verify_uvis = Arc::clone(&ui_visible);
    main_window.on_verify_totp_unlock(move |code| {
        let Some(ui) = verify_weak.upgrade() else {
            return;
        };
        if ui.get_is_unlocked() || !ui.get_show_totp_step() {
            return;
        }
        let code = code.trim().replace([' ', '-'], "");
        if code.is_empty() {
            ui.set_totp_step_error("Enter the 6-digit code.".into());
            return;
        }
        let expected = {
            let vault = lock_vault(&verify_vault);
            if !vault.totp_unlock_enabled || vault.totp_unlock_secret.trim().is_empty() {
                None
            } else {
                let probe = TotpAccount {
                    id: "unlock-gate".into(),
                    account_name: "vault-unlock".into(),
                    issuer: "PhantomVault".into(),
                    secret: vault.totp_unlock_secret.clone(),
                    digits: 6,
                    period: 30,
                    algorithm: "SHA1".into(),
                    otp_type: "totp".into(),
                    counter: 0,
                    favorite: false,
                };
                totp_engine::generate_code_for_account(&probe).ok().map(|(c, _)| c)
            }
        };
        let Some(expected) = expected else {
            // Gate misconfigured mid-flight — fail closed, full reset.
            *lock_vault(&verify_vault) = Vault::new();
            *lock_master_pw(&verify_master) = None;
            ui.set_show_totp_step(false);
            ui.set_totp_step_error("Unlock 2FA misconfigured — signed out.".into());
            ui.set_status_text("Vault is locked. Enter Master Password:".into());
            return;
        };
        // Constant-time-ish compare (length gate + OR-fold, no early exit).
        let ok = expected.len() == code.len()
            && expected
                .as_bytes()
                .iter()
                .zip(code.as_bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0;
        if !ok {
            ui.set_totp_step_error("❌ Wrong code — try the current one.".into());
            return;
        }
        let vault = std::mem::replace(&mut *lock_vault(&verify_vault), Vault::new());
        publish_unlocked_vault(
            &ui,
            &verify_qb,
            &verify_vault,
            &verify_master,
            &verify_search,
            &verify_uvis,
            vault,
            None,
            0,
            false,
        );
    });

    // Gate cancelled: scrub the stashed vault + master, back to password.
    let cancel_weak = main_window.as_weak();
    let cancel_vault = Arc::clone(&active_vault);
    let cancel_master = Arc::clone(&active_master_pw);
    main_window.on_cancel_totp_step(move || {
        *lock_vault(&cancel_vault) = Vault::new();
        *lock_master_pw(&cancel_master) = None;
        if let Some(ui) = cancel_weak.upgrade() {
            ui.set_show_totp_step(false);
            ui.set_totp_step_error("".into());
            ui.set_status_text("Vault is locked. Enter Master Password:".into());
        }
    });

    // Setup step 1 [Enable]: mint a fresh secret, show it ONCE for enrollment.
    let setup_weak = main_window.as_weak();
    let setup_pending = Arc::clone(&pending_totp_secret);
    main_window.on_setup_totp_unlock(move || {
        let Some(ui) = setup_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let mut raw = [0u8; 20];
        OsRng.fill_bytes(&mut raw);
        let secret = BASE32_NOPAD.encode(&raw);
        raw.zeroize();
        *setup_pending.lock().unwrap() = Some(secret.clone());
        ui.set_totp2fa_secret(secret.into());
        ui.set_notification_text(
            "📱 Scan/type this secret into your authenticator, then Confirm.".into(),
        );
    });

    // Setup step 2 [Confirm]: code must verify before anything is persisted.
    let confirm_weak = main_window.as_weak();
    let confirm_vault = Arc::clone(&active_vault);
    let confirm_master = Arc::clone(&active_master_pw);
    let confirm_pending = Arc::clone(&pending_totp_secret);
    main_window.on_confirm_totp_unlock(move |code| {
        let Some(ui) = confirm_weak.upgrade() else {
            return;
        };
        let pending = confirm_pending.lock().unwrap().clone();
        let Some(secret) = pending else {
            ui.set_notification_text("⚠️ Press Enable first.".into());
            return;
        };
        let probe = TotpAccount {
            id: "unlock-gate".into(),
            account_name: "vault-unlock".into(),
            issuer: "PhantomVault".into(),
            secret: secret.clone(),
            digits: 6,
            period: 30,
            algorithm: "SHA1".into(),
            otp_type: "totp".into(),
            counter: 0,
            favorite: false,
        };
        let ok = totp_engine::generate_code_for_account(&probe)
            .map(|(c, _)| {
                let entered = code.trim().replace([' ', '-'], "");
                c.len() == entered.len()
                    && c.as_bytes()
                        .iter()
                        .zip(entered.as_bytes())
                        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                        == 0
            })
            .unwrap_or(false);
        if !ok {
            ui.set_notification_text("❌ Code doesn't match — check the secret + clock.".into());
            return;
        }
        let master_opt = lock_master_pw(&confirm_master).clone();
        let Some(master_pw) = master_opt else {
            ui.set_notification_text("⚠️ Vault not unlocked.".into());
            return;
        };
        let weak = confirm_weak.clone();
        let vault_clone = Arc::clone(&confirm_vault);
        let pending_done = Arc::clone(&confirm_pending);
        std::thread::spawn(move || {            let res: Result<Vault, String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                vault.totp_unlock_enabled = true;
                vault.totp_unlock_secret = secret.clone();
                match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                    Ok(()) => Ok(vault.clone()),
                    Err(e) => {
                        *vault = snapshot;
                        Err(e)
                    }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    match res {
                        Ok(_) => {
                            *pending_done.lock().unwrap() = None;
                            ui.set_totp2fa_on(true);
                            ui.set_totp2fa_secret("".into());
                            ui.set_notification_text(
                                "🔐 Unlock 2FA armed — password + code from now on.".into(),
                            );
                            trigger_sync_push(ui.as_weak());
                        }
                        Err(e) => {
                            ui.set_notification_text(format!("❌ Enable failed: {e}").into());
                        }
                    }
                }
            });
        });
    });

    // Disarm: wipe secret + flag, re-seal, mirror OFF.
    let disable_weak = main_window.as_weak();
    let disable_vault = Arc::clone(&active_vault);
    let disable_master = Arc::clone(&active_master_pw);
    let disable_pending = Arc::clone(&pending_totp_secret);
    main_window.on_disable_totp_unlock(move || {
        let Some(ui) = disable_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let master_opt = lock_master_pw(&disable_master).clone();
        let Some(master_pw) = master_opt else {
            ui.set_notification_text("⚠️ Vault not unlocked.".into());
            return;
        };
        let weak = disable_weak.clone();
        let vault_clone = Arc::clone(&disable_vault);
        let pending_done = Arc::clone(&disable_pending);
        std::thread::spawn(move || {
            let res: Result<Vault, String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                vault.totp_unlock_enabled = false;
                vault.totp_unlock_secret.zeroize();
                vault.totp_unlock_secret = String::new();
                match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                    Ok(()) => Ok(vault.clone()),
                    Err(e) => {
                        *vault = snapshot;
                        Err(e)
                    }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    match res {
                        Ok(_) => {
                            *pending_done.lock().unwrap() = None;
                            ui.set_totp2fa_on(false);
                            ui.set_totp2fa_secret("".into());
                            ui.set_notification_text("Unlock 2FA disarmed.".into());
                            trigger_sync_push(ui.as_weak());
                        }
                        Err(e) => {
                            ui.set_notification_text(format!("❌ Disarm failed: {e}").into());
                        }
                    }
                }
            });
        });
    });

    // Phase 11: Windows Hello — biometric unlock request
    let bio_weak = main_window.as_weak();    let bio_vault = Arc::clone(&active_vault);
    let bio_master = Arc::clone(&active_master_pw);
    let bio_search = Arc::clone(&search_state);
    let bio_qb = quick_bar.as_weak();
    let bio_uvis = Arc::clone(&ui_visible);
    main_window.on_request_biometric_unlock(move || {
        // Cat 8 AND-mode is password-FIRST: a Hello-first attempt would skip
        // factor one, so refuse loudly instead of half-unlocking.
        if let Some(ui) = bio_weak.upgrade() {
            if ui.get_and_mode() {
                ui.set_unlock_error_message(
                    "Two-factor unlock is ON — enter your master password first.".into(),
                );
                return;
            }
            ui.set_unlock_error_message("".into());
            ui.set_status_text("🖐 Waiting for Windows Hello…".into());
        }
        let weak = bio_weak.clone();
        let vault_clone = Arc::clone(&bio_vault);
        let master_clone = Arc::clone(&bio_master);
        let search_clone = Arc::clone(&bio_search);
        let qb_clone = bio_qb.clone();
        let uvis_clone = Arc::clone(&bio_uvis);
        std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_unlock_error_message(
                                "Could not start biometric service.".into(),
                            );
                            ui.set_status_text("Vault is locked. Enter Master Password:".into());
                        }
                    });
                    return;
                }
            };
            let auth =
                runtime.block_on(windows_native::hello::WindowsHello::authenticate(
                    "Unlock PHANTOM_VAULT",
                ));
            match auth {
                Ok(true) => {
                    // Verified — unseal the DPAPI-cached passphrase (never stored plaintext).
                    let blob = std::fs::read(HELLO_TOKEN_FILE).unwrap_or_default();
                    let secret = match core::memory::DpapiGuard::unprotect(&blob) {
                        Ok(s) => s,
                        Err(e) => {
                            let msg = e.to_string();
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Some(ui) = weak.upgrade() {
                                    ui.set_unlock_error_message(msg.into());
                                    ui.set_status_text(
                                        "Vault is locked. Enter Master Password:".into(),
                                    );
                                }
                            });
                            return;
                        }
                    };
                    let pass = String::from_utf8_lossy(secret.expose()).into_owned();
                    drop(secret);
    if pass.is_empty() {
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak.upgrade() {
                                ui.set_unlock_error_message(
                                    "No cached Hello credential — unlock with password once first.".into(),
                                );
                                ui.set_status_text("Vault is locked. Enter Master Password:".into());
                            }
                        });
                        return;
                    }
                    unlock_with_password(
                        SecretString::new(pass), weak, vault_clone, master_clone, search_clone, qb_clone, Arc::clone(&uvis_clone), false,
                        false,
                    );
                }
                Ok(false) => {
                    // User canceled — stay safely locked.
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_status_text("Vault is locked. Enter Master Password:".into());
                        }
                    });
                }
                Err(e) => {
                    let msg = e.to_string();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_unlock_error_message(msg.into());
                        }
                    });
                }
            }
        });
    });

    // PR-1: New-device explicit re-enroll. Unlocked + non-decoy only.
    // Runs Hello auth off-thread, then seals via the single `seal_hello_token`
    // choke point. Modal stays open on failure/cancel; [Later] just hides it
    // (it re-shows on next unlock until enrolled).
    let reenroll_weak = main_window.as_weak();
    let reenroll_master = Arc::clone(&active_master_pw);
    main_window.on_reenroll_hello_requested(move || {
        let Some(ui) = reenroll_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_new_device_error("⛔ Decoy mode is read-only.".into());
            return;
        }
        let master_opt = lock_master_pw(&reenroll_master).clone();
        let Some(master_pw) = master_opt else {
            ui.set_new_device_error("❌ Vault not unlocked!".into());
            return;
        };
        // SecretString clone: zeroizing buffer, no plaintext String anywhere.
        let master_copy = master_pw.clone();
        drop(master_pw);
        ui.set_new_device_error("".into());
        ui.set_status_text("🖐 Confirm Windows Hello to enroll this PC…".into());
        let weak = reenroll_weak.clone();
        std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_new_device_error(
                                "Could not start biometric service.".into(),
                            );
                        }
                    });
                    return;
                }
            };
            let auth = runtime.block_on(windows_native::hello::WindowsHello::authenticate(
                "Enroll Windows Hello on this PC",
            ));
            match auth {
                Ok(true) => {
                    if seal_hello_token(&master_copy) {
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak.upgrade() {
                                ui.set_show_new_device_modal(false);
                                ui.set_new_device_error("".into());
                                ui.set_status_text("✅ Hello enrolled on this PC.".into());
                            }
                        });
                    } else {
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak.upgrade() {
                                ui.set_new_device_error(
                                    "⚠️ Hello verified but seal failed.".into(),
                                );
                            }
                        });
                    }
                }
                Ok(false) => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_new_device_error("Canceled — Hello not enrolled.".into());
                        }
                    });
                }
                Err(e) => {
                    let msg = e.to_string();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_new_device_error(msg.into());
                        }
                    });
                }
            }
        });
    });
    let dismiss_weak = main_window.as_weak();
    main_window.on_dismiss_new_device_modal(move || {
        if let Some(ui) = dismiss_weak.upgrade() {
            ui.set_show_new_device_modal(false);
        }
    });

    // App PIN quick-unlock (DPAPI-bound, device-local). Mirrors the Hello
    // path: verify off-thread, then funnel into the SAME unlock pipeline
    // (backoff, migration, AND-mode/TOTP gates all apply downstream).
    let pin_weak = main_window.as_weak();
    let pin_vault = Arc::clone(&active_vault);
    let pin_master = Arc::clone(&active_master_pw);
    let pin_search = Arc::clone(&search_state);
    let pin_qb = quick_bar.as_weak();
    let pin_uvis = Arc::clone(&ui_visible);
    main_window.on_request_pin_unlock(move |pin| {
        // Cat 8 AND-mode is password-FIRST, same as Hello-first: refuse.
        if let Some(ui) = pin_weak.upgrade() {
            if ui.get_and_mode() {
                ui.set_pin_error(
                    "Two-factor unlock is ON — enter your master password first.".into(),
                );
                return;
            }
            ui.set_pin_error("".into());
            ui.set_status_text("🔢 Checking PIN…".into());
        }
        let pin = pin.as_str().trim().to_string();
        let weak = pin_weak.clone();
        let vault_clone = Arc::clone(&pin_vault);
        let master_clone = Arc::clone(&pin_master);
        let search_clone = Arc::clone(&pin_search);
        let qb_clone = pin_qb.clone();
        let uvis_clone = Arc::clone(&pin_uvis);
        std::thread::spawn(move || {
            // Argon2id + DPAPI happen here (never on the Slint thread).
            match security::app_pin::verify_and_recover(Path::new("."), &pin) {
                Ok(master) => {
                    unlock_with_password(
                        master, weak, vault_clone, master_clone, search_clone, qb_clone,
                        Arc::clone(&uvis_clone), false, false,
                    );
                }
                Err(security::app_pin::PinError::Wiped) => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_pin_available(false);
                            ui.set_show_pin_pad(false);
                            ui.set_pin_error("Too many wrong PINs — PIN login wiped. Unlock with your master password to set a new PIN.".into());
                            ui.set_status_text("Vault is locked. Enter Master Password:".into());
                        }
                    });
                }
                Err(e) => {
                    let msg = e.to_string();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_pin_error(msg.into());
                            ui.set_status_text("Vault is locked. Enter Master Password:".into());
                        }
                    });
                }
            }
        });
    });


// NOTE: push_new_item + replace_item used to live nested inside a setup
// closure (untestable). Moved to crate root verbatim — pure field-mapping,
// zero behavior change. See above the test module for the bodies.


    // Bitwarden-parity: one generic saver for all 6 item kinds.
    // kind: 1 login(a=user,b=pass,c=url) 2 license(a=key,b=expiry)
    // 3 note(a=content) 4 card(a=holder,b=number,c=exp,d=cvv)
    // 5 identity(a=name,b=nid,c=email,d=phone,e=address)
    // 6 ssh(a=public,b=private,c=fingerprint)
    let window_weak_add = main_window.as_weak();
    let vault_arc_add = Arc::clone(&active_vault);
    let master_pw_add = Arc::clone(&active_master_pw);
    let search_state_add = Arc::clone(&search_state);
    let qb_weak_add = quick_bar.as_weak();
    let pending_cf_add = Arc::clone(&pending_cf);
    let editing_add = Arc::clone(&editing_item);
    main_window.on_add_item_requested(
        move |kind, title, a, b, c, d, e, notes, folder, totp, backup, company, city, state, zip, country, reprompt, fav, travel| {
            if let Some(ui) = window_weak_add.upgrade() {
                // Decoy vaults are read-mostly cover: never write through them.
                if ui.get_is_decoy() {
                    ui.set_notification_text("⛔ Decoy mode is read-only.".into());
                    return;
                }
            }
            let title = title.trim().to_string();
            let a = a.as_str().to_string();
            let b = b.as_str().to_string();
            let mut cc = c.as_str().to_string();
            // Secondary website rows (AUTOFILL + Add website) merge into the
            // primary box: trimmed, de-duplicated, empties dropped.
            // Their per-URL match rules ride a SEPARATE Vec<LoginUrl> (a plain
            // string merge would destroy rules); primary-box lines stay Plain.
            let mut url_rules: Vec<models::LoginUrl> = Vec::new();
            if let Some(ui) = window_weak_add.upgrade() {
                let rules: Vec<i32> = ui.get_f_url_rules().iter().collect();
                for (ri, extra) in ui.get_f_urls().iter().enumerate() {
                    let t = extra.trim().to_string();
                    if !t.is_empty()
                        && cc.lines().map(str::trim).all(|l| l != t)
                    {
                        if !cc.trim().is_empty() {
                            cc.push('\n');
                        }
                        cc.push_str(&t);
                        let rule = rules.get(ri).copied().unwrap_or(0).clamp(0, 5) as u8;
                        url_rules.push(models::LoginUrl::new(t, rule));
                    }
                }
            }
            let dd = d.as_str().to_string();
            let ee = e.as_str().to_string();
            let notes = notes.as_str().to_string();
            let mut folder = folder.as_str().trim().to_string();
            if folder.is_empty() {
                folder = "General".to_string();
            }
            let totp_for_cb = totp.as_str().trim().to_string();
            let backup_for_cb = backup.as_str().to_string();

            // Per-kind validation (kind label for messages).
            let kind_name = match kind {
                1 => "Login",
                2 => "License",
                3 => "Note",
                4 => "Card",
                5 => "Identity",
                6 => "SSH key",
                _ => "",
            };
            let valid = !title.is_empty()
                && match kind {
                    1 => !a.trim().is_empty() && !b.trim().is_empty(),
                    2 => !a.trim().is_empty(),
                    3 => !a.trim().is_empty(),
                    4 => !a.trim().is_empty() && !b.trim().is_empty(),
                    5 => !a.trim().is_empty(),
                    6 => !b.trim().is_empty(),
                    _ => false,
                };
            if !valid {
                if let Some(ui) = window_weak_add.upgrade() {
                    if kind_name.is_empty() {
                        ui.set_notification_text("⚠️ Unknown item type!".into());
                    } else {
                        ui.set_notification_text(
                            format!("⚠️ {kind_name} needs a title + key fields!").into(),
                        );
                    }
                }
                return;
            }
            // Luhn flag rides into the worker: the success notification below
            // appends the typo warning (a warn here would be overwritten by
            // the Encrypting/Saved messages). Never blocks — exotic cards save.
            let luhn_warn_for_thread =
                kind == 4 && !b.trim().is_empty() && !luhn_valid(&b);
            // Card expiry gate: refuse garbage LOUD (never store month 13).
            // Empty stays optional; push/replace re-validate defensively.
            if kind == 4 && parse_card_expiry(&cc).is_none() {
                if let Some(ui) = window_weak_add.upgrade() {
                    ui.set_notification_text(
                        "⚠️ Card expiry must be MM/YY with month 01–12.".into(),
                    );
                }
                return;
            }

            if let Some(ui) = window_weak_add.upgrade() {
                ui.set_notification_text("⏳ Encrypting to disk (Argon2id)…".into());
            }

            let weak = window_weak_add.clone();
            let vault_clone = Arc::clone(&vault_arc_add);
            let master_clone = Arc::clone(&master_pw_add);
            let search_clone = Arc::clone(&search_state_add);
            let qb_weak = qb_weak_add.clone();
            // Favorite arrives as an explicit callback arg (form checkbox).
            let fav_for_thread = fav;
            // Identity structured parts ride the same way (kind 5 only reads).
            let company_for_thread = company.as_str().trim().to_string();
            let city_for_thread = city.as_str().trim().to_string();
            let state_for_thread = state.as_str().trim().to_string();
            let zip_for_thread = zip.as_str().trim().to_string();
            let country_for_thread = country.as_str().trim().to_string();
            let mut url_rules_for_thread = url_rules;
            let title_for_thread = title.clone();
            let backup_for_thread = backup_for_cb.clone();
            let totp_for_thread = totp_for_cb.clone();
            let reprompt_for_thread = reprompt;
            let travel_for_thread = travel;
            let custom_for_thread = pending_cf_add.lock().unwrap().clone();
            let editing_for_thread = editing_add.lock().unwrap().clone();
            let editing_done = Arc::clone(&editing_add);
            let pending_done = Arc::clone(&pending_cf_add);

            std::thread::spawn(move || {
                let master_opt = lock_master_pw(&master_clone).clone();
                let Some(master_pw) = master_opt else {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_notification_text("❌ Vault not unlocked!".into());
                        }
                    });
                    return;
                };

                // Unique id via millis since epoch
                let new_id = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| format!("i{}", d.as_millis()))
                    .unwrap_or_else(|_| "i0".to_string());

                // Critical section + heavy crypto: push/replace + save_vault inside worker thread.
                // Roll back the in-memory mutation if the disk write fails.
                let mut updated_existing = false;
                let save_result: Result<Vault, String> = {
                    let mut vault = lock_vault(&vault_clone);
                    // Snapshot for rollback (cheap, in-RAM vaults are small).
                    let snapshot = vault.clone();
                    // Primary-box lines are always Default-rule; row rules
                    // arrived above with their URLs (deduped there too).
                    let mut urls: Vec<models::LoginUrl> = cc
                        .lines()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(|s| models::LoginUrl::new(s.to_string(), 0))
                        .collect();
                    for r in url_rules_for_thread.drain(..) {
                        if !urls.iter().any(|u| u.url().eq_ignore_ascii_case(r.url())) {
                            urls.push(r);
                        }
                    }
                    let backup: Vec<String> = backup_for_thread
                        .lines()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect();
                    let custom = custom_for_thread.clone();
                    let editing = editing_for_thread.clone();
                    let replaced = if let Some((ekind, eid)) = editing {
                        replace_item(
                            &mut vault, ekind, &eid, &title_for_thread,
                            &a, &b, &cc, &dd, &ee, &notes, &folder,
                            &urls, &backup, &custom, &totp_for_thread, reprompt_for_thread,
                            fav_for_thread, travel_for_thread,
                            &company_for_thread, &city_for_thread, &state_for_thread,
                            &zip_for_thread, &country_for_thread,
                        )
                    } else {
                        false
                    };
                    if !replaced {
                        // Duplicate guard (logins only, bridge upsert
                        // semantics): same title+username ⇒ identical ?
                        // block : update in place with history. Editing
                        // mode (replaced) skips this — it owns its id.
                        if kind == 1 {
                            if let Some(eid) = find_live_login_id(&vault, &title_for_thread, &a) {
                                let same = vault
                                    .credentials
                                    .iter()
                                    .find(|c| c.id == eid)
                                    .map(|c| c.password == b)
                                    .unwrap_or(false);
                                if same {
                                    // Identical entry live: notify + return
                                    // (guard drops here, nothing saved).
                                    let w2 = weak.clone();
                                    let _ = slint::invoke_from_event_loop(move || {
                                        if let Some(ui) = w2.upgrade() {
                                            ui.set_notification_text(
                                                "⚠️ Identical login already exists — no duplicate created.".into(),
                                            );
                                        }
                                    });
                                    return;
                                }
                                let now = crate::models::current_timestamp();
                                if let Some(c) =
                                    vault.credentials.iter_mut().find(|c| c.id == eid)
                                {
                                    let old = c.password.clone();
                                    crate::models::push_history(&mut c.password_history, &old, now);
                                    c.password = b.clone();
                                    c.last_changed = now;
                                    for u in &urls {
                                        if !c.urls.iter().any(|x| {
                                            x.url().to_lowercase() == u.url().to_lowercase()
                                        }) {
                                            c.urls.push(u.clone());
                                        }
                                    }
                                    updated_existing = true;
                                }
                            } else {
                                push_new_item(
                                    &mut vault, kind, new_id, &title_for_thread,
                                    &a, &b, &cc, &dd, &ee, &notes, &folder,
                                    urls, backup, custom, &totp_for_thread, reprompt_for_thread,
                                    fav_for_thread, travel_for_thread,
                                    &company_for_thread, &city_for_thread, &state_for_thread,
                                    &zip_for_thread, &country_for_thread,
                                );
                            }
                        } else {
                            push_new_item(
                                &mut vault, kind, new_id, &title_for_thread,
                                &a, &b, &cc, &dd, &ee, &notes, &folder,
                                urls, backup, custom, &totp_for_thread, reprompt_for_thread,
                                fav_for_thread, travel_for_thread,
                                &company_for_thread, &city_for_thread, &state_for_thread,
                                &zip_for_thread, &country_for_thread,
                            );
                        }
                    }

                    match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                        Ok(()) => Ok(vault.clone()),
                        Err(e) => {
                            *vault = snapshot;
                            Err(e)
                        }
                    }
                };

                let fav_vc = Arc::clone(&vault_clone);
                let fav_sc = Arc::clone(&search_clone);
                let fav_w = weak.clone();
                // Live breach gate (logins only): k-anonymity check AFTER the
                // save lands, warn-only (never blocks). Decoy saves return
                // earlier, so this path is always the real vault.
                let hibp_pw: Option<String> =
                    if kind == 1 && !b.trim().is_empty() { Some(b.clone()) } else { None };
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = weak.upgrade() else {
                        return;
                    };
                    match save_result {
                        Ok(vault_snapshot) => {
                            // Re-apply current filters so the list stays consistent
                            let f = search_clone.lock().unwrap().clone();
                            let items = vault_to_items(&vault_snapshot, &f);
                            ui.set_credentials(items.clone());
                            ui.set_total_matches_count(total_matches() as i32);
                            if let Some(qb) = qb_weak.upgrade() {
                                qb.set_filtered_results(vault_quickbar(&vault_snapshot, "", search_clone.lock().unwrap().travel_only));
                            }
                            ui.set_notification_text(
                                if updated_existing {
                                    "🔄 Updated the existing login (old password kept in history).".into()
                                } else if luhn_warn_for_thread {
                                    "✅ Saved — ⚠️ card number fails Luhn check, verify digits.".into()
                                } else {
                                    "✅ Item encrypted to disk!".into()
                                },
                            );
                            // Fire-and-forget breach check: offline toggle or
                            // global kill-switch ⇒ silent skip (zero packets).
                            if let Some(pw) = hibp_pw {
                                let offline = ui.get_offline_audit() || !net_allowed();
                                if !offline {
                                    let w2 = weak.clone();
                                    std::thread::spawn(move || {
                                        let Some(rt) = tokio_rt() else {
                                            return;
                                        };
                                        if let Ok(Some(n)) =
                                            rt.block_on(security::breach_check::check_password(&pw))
                                        {
                                            let _ = slint::invoke_from_event_loop(move || {
                                                if let Some(ui) = w2.upgrade() {
                                                    ui.set_notification_text(
                                                        format!("🚨 Saved, but this password appeared in {n} breaches — consider rotating it.").into(),
                                                    );
                                                }
                                            });
                                        }
                                    });
                                }
                            }
                            // Clear form, exit edit mode, drop pending custom fields
                            ui.set_f_title("".into());
                            ui.set_f_a("".into());
                            ui.set_f_b("".into());
                            ui.set_f_c("".into());
                            ui.set_f_urls(ModelRc::new(VecModel::from(Vec::<slint::SharedString>::new())));
                            ui.set_f_d("".into());
                            ui.set_f_e("".into());
                            ui.set_f_notes("".into());
                            ui.set_f_totp("".into());
                            ui.set_f_backup("".into());
                            ui.set_f_reprompt(false);
                            ui.set_f_fav(false);
                            ui.set_f_travel(false);
                            ui.set_show_add_form(false);
                            *editing_done.lock().unwrap() = None;
                            *pending_done.lock().unwrap() = Vec::new();
                            ui.set_custom_fields(ModelRc::new(VecModel::from(Vec::<CustomFieldView>::new())));
                            sync_folders_to_ui(&vault_snapshot, &ui);
                            trigger_sync_push(ui.as_weak());
                            // New URLs may need icons — background pass only.
                            trigger_favicon_prefetch(fav_vc, fav_sc, fav_w);
                        }
                        Err(e) => {
                            ui.set_notification_text(format!("❌ Save failed: {}", e).into());
                        }
                    }
                });
            });
        },
    );

    // Bitwarden-parity: delete any item by (kind, id), worker-threaded.
    let window_weak_del = main_window.as_weak();
    let vault_arc_del = Arc::clone(&active_vault);
    let master_pw_del = Arc::clone(&active_master_pw);
    let search_state_del = Arc::clone(&search_state);
    let qb_weak_del = quick_bar.as_weak();
    main_window.on_delete_item_requested(move |kind, id| {
        if let Some(ui) = window_weak_del.upgrade() {
            if ui.get_is_decoy() {
                ui.set_notification_text("⛔ Decoy mode is read-only.".into());
                return;
            }
            ui.set_notification_text("⏳ Deleting…".into());
        }
        let id = id.as_str().to_string();
        let weak = window_weak_del.clone();
        let vault_clone = Arc::clone(&vault_arc_del);
        let master_clone = Arc::clone(&master_pw_del);
        let search_clone = Arc::clone(&search_state_del);
        let qb_weak = qb_weak_del.clone();
        std::thread::spawn(move || {
            let master_opt = lock_master_pw(&master_clone).clone();
            let Some(master_pw) = master_opt else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_notification_text("❌ Vault not unlocked!".into());
                    }
                });
                return;
            };
            // Two-phase delete: active → Trash (stamp), Trash → shred.
            // Disk failure rolls the RAM mutation back via snapshot.
            let save_result: Result<(Vault, bool), String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                if kind == 8 {
                    // Standalone 2FA has no trash generation: permanent
                    // remove, same as the hub 🗑️ button.
                    if !remove_totp_account(&mut vault, &id) {
                        Err("Authenticator account not found (already deleted?)".to_string())
                    } else {
                        match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                            Ok(()) => Ok((vault.clone(), true)),
                            Err(e) => {
                                *vault = snapshot;
                                Err(e)
                            }
                        }
                    }
                } else {
                let already = vault.is_trashed(kind, &id).unwrap_or(false);
                let ok = if already {
                    vault.delete_item(kind, &id)
                } else {
                    vault.trash_item(kind, &id, crate::models::current_timestamp())
                };
                if !ok {
                    Err("Item not found (already deleted?)".to_string())
                } else {
                    match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                        Ok(()) => Ok((vault.clone(), already)),
                        Err(e) => {
                            *vault = snapshot;
                            Err(e)
                        }
                    }
                }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match save_result {
                    Ok((vault_snapshot, permanent)) => {
                        let f = search_clone.lock().unwrap().clone();
                        set_paged_credentials(&ui, vault_to_items(&vault_snapshot, &f));
                        set_trash_label(&ui, &vault_snapshot);
                        if kind == 8 {
                            // Keep the 2FA Hub in sync with list-side deletes.
                            ui.set_auth_accounts(rebuild_auth_list(&vault_snapshot));
                            ui.set_auth_rows(rebuild_auth_rows(&vault_snapshot, ui.get_totp_search_query().as_str()));
                        }
                        if let Some(qb) = qb_weak.upgrade() {
                            qb.set_filtered_results(vault_quickbar(&vault_snapshot, "", search_clone.lock().unwrap().travel_only));
                        }
                        if permanent {
                            ui.set_notification_text("🔥 Item permanently shredded.".into());
                            security::access_log::log_event("delete", "permanent");
                        } else {
                            ui.set_notification_text("🗑️ Moved to Trash (restorable 30 days).".into());
                            security::access_log::log_event("delete", "trash");
                        }
                        ui.set_show_detail(false);
                        ui.set_d_id(String::new().into());
                        trigger_sync_push(ui.as_weak());
                    }
                    Err(e) => {
                        ui.set_notification_text(format!("❌ Delete failed: {}", e).into());
                    }
                }
            });
        });
    });

    // Trash second phase: restore one item (clears deleted_at) + re-seal.
    let window_weak_restore = main_window.as_weak();
    let vault_arc_restore = Arc::clone(&active_vault);
    let master_pw_restore = Arc::clone(&active_master_pw);
    let search_state_restore = Arc::clone(&search_state);
    let qb_weak_restore = quick_bar.as_weak();
    main_window.on_restore_item(move |kind, id| {
        let Some(ui) = window_weak_restore.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let weak = window_weak_restore.clone();
        let vault_clone = Arc::clone(&vault_arc_restore);
        let master_clone = Arc::clone(&master_pw_restore);
        let search_clone = Arc::clone(&search_state_restore);
        let qb_weak = qb_weak_restore.clone();
        let (kind, id) = (kind, id.as_str().to_string());
        std::thread::spawn(move || {
            let master_opt = lock_master_pw(&master_clone).clone();
            let Some(master_pw) = master_opt else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_notification_text("❌ Vault not unlocked!".into());
                    }
                });
                return;
            };
            let save_result: Result<Vault, String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                if !vault.restore_item(kind, &id) {
                    Err("Item is not in Trash (already active?)".to_string())
                } else {
                    match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                        Ok(()) => Ok(vault.clone()),
                        Err(e) => {
                            *vault = snapshot;
                            Err(e)
                        }
                    }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match save_result {
                    Ok(vault_snapshot) => {
                        let f = search_clone.lock().unwrap().clone();
                        set_paged_credentials(&ui, vault_to_items(&vault_snapshot, &f));
                        set_trash_label(&ui, &vault_snapshot);
                        if let Some(qb) = qb_weak.upgrade() {
                            qb.set_filtered_results(vault_quickbar(&vault_snapshot, "", search_clone.lock().unwrap().travel_only));
                        }
                        // Reopen the detail on the restored item (banner gone).
                        ui.set_d_trashed(false);
                        ui.set_notification_text("♻️ Restored to active vault.".into());
                        security::access_log::log_event("restore", "trash");
                        trigger_sync_push(ui.as_weak());
                    }
                    Err(e) => {
                        ui.set_notification_text(format!("❌ Restore failed: {}", e).into());
                    }
                }
            });
        });
    });

    // Factory Reset triple-gate: master password + typed DELETE + 5s
    // countdown → DoD-shred vault + generations + DPAPI seals, RAM purge,
    // back to onboarding. Decoy mode is strictly read-only.
    fn factory_gen() -> &'static std::sync::atomic::AtomicU64 {
        static GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        &GEN
    }
    let fr_weak = main_window.as_weak();
    let fr_vault = Arc::clone(&active_vault);
    main_window.on_factory_reset_start(move || {
        let Some(ui) = fr_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        ui.set_fr_password(String::new().into());
        ui.set_fr_delete_text(String::new().into());
        ui.set_fr_error(String::new().into());
        ui.set_fr_armed(false);
        ui.set_fr_countdown(0);
        // Danger preview: live counts so the user sees the blast radius.
        {
            let v = lock_vault(&fr_vault);
            let items = v.credentials.len()
                + v.cards.len()
                + v.identities.len()
                + v.ssh_keys.len()
                + v.totp_accounts.len()
                + v.licenses.len()
                + v.notes.len();
            let vault_path = std::path::Path::new(developer::vault_run::VAULT_FILE);
            let mut gens = 0;
            for g in 1..=storage::BACKUP_KEEP {
                if storage::backup_name(vault_path, g).exists() {
                    gens += 1;
                }
            }
            let decoy = if security::decoy::decoy_exists() {
                " + decoy"
            } else {
                ""
            };
            ui.set_fr_preview(
                format!("⚠️ Will shred: {items} items, {gens} backup generations{decoy}.").into(),
            );
        }
        ui.set_show_factory_reset(true);
    });
    let frc_weak = main_window.as_weak();
    main_window.on_factory_reset_cancel(move || {
        use std::sync::atomic::Ordering::SeqCst;
        factory_gen().fetch_add(1, SeqCst);
        if let Some(ui) = frc_weak.upgrade() {
            ui.set_show_factory_reset(false);
            ui.set_fr_password(String::new().into());
            ui.set_fr_delete_text(String::new().into());
            ui.set_fr_error(String::new().into());
            ui.set_fr_armed(false);
            ui.set_fr_countdown(0);
        }
    });
    let fra_weak = main_window.as_weak();
    main_window.on_factory_reset_arm(move || {
        use std::sync::atomic::Ordering::SeqCst;
        let Some(ui) = fra_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_fr_error("⛔ Decoy mode is read-only.".into());
            return;
        }
        let pw = ui.get_fr_password().to_string();
        if pw.is_empty() {
            ui.set_fr_error("⚠️ Enter your master password first.".into());
            return;
        }
        if ui.get_fr_delete_text().to_string().trim() != "DELETE" {
            ui.set_fr_error("⚠️ Type DELETE in the box to continue.".into());
            return;
        }
        ui.set_fr_error("⏳ Verifying master password…".into());
        ui.set_fr_armed(false);
        let gen = factory_gen().fetch_add(1, SeqCst) + 1;
        let weak = fra_weak.clone();
        std::thread::spawn(move || {
            // Trial decrypt proves the password WITHOUT unlocking anything.
            if storage::load_vault_versioned_secret(&SecretString::new(pw), VAULT_FILE).is_err() {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_fr_error("❌ Wrong master password.".into());
                    }
                });
                return;
            }
            // Deliberate 5s countdown — no click-through deletes.
            for n in (1..=5).rev() {
                if factory_gen().load(SeqCst) != gen {
                    return; // cancelled / re-armed
                }
                let weak_n = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak_n.upgrade() {
                        ui.set_fr_countdown(n);
                        ui.set_fr_error(String::new().into());
                    }
                });
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            if factory_gen().load(SeqCst) != gen {
                return;
            }
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    ui.set_fr_countdown(0);
                    ui.set_fr_armed(true);
                    ui.set_fr_error("🔥 Armed. This is your last chance.".into());
                }
            });
        });
    });
    let frc2_weak = main_window.as_weak();
    let frc2_vault = Arc::clone(&active_vault);
    let frc2_master = Arc::clone(&active_master_pw);
    let frc2_qb = quick_bar.as_weak();
    main_window.on_factory_reset_confirm(move || {
        let Some(ui) = frc2_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_fr_error("⛔ Decoy mode is read-only.".into());
            return;
        }
        if !ui.get_fr_armed() {
            ui.set_fr_error("⚠️ Arm the countdown first.".into());
            return;
        }
        let pw = ui.get_fr_password().to_string();
        if pw.is_empty() {
            ui.set_fr_error("⚠️ Master password required.".into());
            return;
        }
        ui.set_fr_error("🔥 Shredding…".into());
        ui.set_fr_armed(false);
        let weak = frc2_weak.clone();
        let vault_clone = Arc::clone(&frc2_vault);
        let master_clone = Arc::clone(&frc2_master);
        let qb_clone = frc2_qb.clone();
        std::thread::spawn(move || {
            // Re-verify at execution time (seconds may have passed).
            if storage::load_vault_versioned_secret(&SecretString::new(pw), VAULT_FILE).is_err() {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_fr_error("❌ Wrong master password.".into());
                    }
                });
                return;
            }
            let mut targets = collect_factory_targets_in(std::path::Path::new("."));
            // C10: scheduled Documents backups + scheduler config + metadata
            // sidecars survived Factory Reset. Shred them too.
            let backup_dir = std::path::PathBuf::from(
                storage::backup_scheduler::default_backup_dir(),
            );
            if backup_dir.is_dir() {
                if let Ok(rd) = std::fs::read_dir(&backup_dir) {
                    for e in rd.flatten() {
                        let p = e.path();
                        if p.is_file() {
                            targets.push(p);
                        }
                    }
                }
                // Remove the (now empty) backup tree + schedule + audit trails.
                for extra in [
                    std::path::PathBuf::from(storage::backup_scheduler::SCHEDULE_FILE),
                    std::path::PathBuf::from("access.log"),
                    std::path::PathBuf::from("access.log.head"),
                    std::path::PathBuf::from("pv_ext_stats.json"),
                ] {
                    if extra.is_file() {
                        targets.push(extra);
                    }
                }
            }
            // Metadata sidecars must die on reset EVEN when no backup dir was
            // ever created (the block above gates on is_dir): trails,
            // schedule, and fill-audit are local state, not backups.
            for extra in [
                std::path::PathBuf::from(storage::backup_scheduler::SCHEDULE_FILE),
                std::path::PathBuf::from("access.log"),
                std::path::PathBuf::from("access.log.head"),
                std::path::PathBuf::from("pv_ext_stats.json"),
            ] {
                if extra.is_file() && !targets.contains(&extra) {
                    targets.push(extra);
                }
            }
            let mut failed = Vec::new();
            for t in &targets {
                if let Err(e) = security::shredder::shred_file(t) {
                    failed.push(format!("{}: {e}", t.display()));
                }
            }
            let _ = std::fs::remove_dir_all(&backup_dir);
            // RAM purge: vault, master, session registries, clipboard.
            // (SecretString zeroizes on drop; the guard assignment below
            // drops the old master here.)
            *lock_vault(&vault_clone) = Vault::new();
            *lock_master_pw(&master_clone) = None;
            selection_registry().lock().unwrap_or_else(|p| p.into_inner()).clear();
            // Staged import rows are plaintext-adjacent — must not survive.
            // H8: poison-recovering (see lock_vault_now).
            *pending_import_store().lock().unwrap_or_else(|p| p.into_inner()) = None;
            // Fresh vault deserves a fresh one-shot shard nudge.
            let _ = std::fs::remove_file("shards_nudged.pref");
            clear_favicon_bytes();
            if let Ok(mut reg) = health_registry().lock() {
                reg.clear();
            }
            windows_native::clipboard::flush_now();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                finish_factory_reset_ui(&ui, &qb_clone);
                if failed.is_empty() {
                    ui.set_status_text(
                        format!("🔥 Vault shredded ({} files). Create a new master password.", targets.len()).into(),
                    );
                } else {
                    ui.set_status_text(
                        format!("⚠️ Reset partial — {} failed: {}", failed.len(), failed.join("; ")).into(),
                    );
                }
            });
        });
    });

    // Trash third phase: shred EVERYTHING trashed (DoD re-seal) + push.
    let window_weak_empty = main_window.as_weak();
    let vault_arc_empty = Arc::clone(&active_vault);
    let master_pw_empty = Arc::clone(&active_master_pw);
    let search_state_empty = Arc::clone(&search_state);
    let qb_weak_empty = quick_bar.as_weak();
    main_window.on_empty_trash(move || {
        let Some(ui) = window_weak_empty.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let weak = window_weak_empty.clone();
        let vault_clone = Arc::clone(&vault_arc_empty);
        let master_clone = Arc::clone(&master_pw_empty);
        let search_clone = Arc::clone(&search_state_empty);
        let qb_weak = qb_weak_empty.clone();
        std::thread::spawn(move || {
            let master_opt = lock_master_pw(&master_clone).clone();
            let Some(master_pw) = master_opt else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_notification_text("❌ Vault not unlocked!".into());
                    }
                });
                return;
            };
            // The re-seal below runs through the DoD-guarded writer, so the
            // shredded bytes are overwritten on disk, not merely unlinked.
            let save_result: Result<(Vault, usize), String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                let n = vault.empty_trash();
                if n == 0 {
                    Err("Trash is already empty.".to_string())
                } else {
                    match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                        Ok(()) => Ok((vault.clone(), n)),
                        Err(e) => {
                            *vault = snapshot;
                            Err(e)
                        }
                    }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match save_result {
                    Ok((vault_snapshot, n)) => {
                        let f = search_clone.lock().unwrap().clone();
                        set_paged_credentials(&ui, vault_to_items(&vault_snapshot, &f));
                        set_trash_label(&ui, &vault_snapshot);
                        if let Some(qb) = qb_weak.upgrade() {
                            qb.set_filtered_results(vault_quickbar(&vault_snapshot, "", search_clone.lock().unwrap().travel_only));
                        }
                        ui.set_show_empty_confirm(false);
                        ui.set_show_detail(false);
                        ui.set_d_id(String::new().into());
                        ui.set_notification_text(
                            format!("🔥 Emptied Trash — {n} items shredded.").into(),
                        );
                        security::access_log::log_event("trash", "emptied");
                        trigger_sync_push(ui.as_weak());
                    }
                    Err(e) => {
                        ui.set_notification_text(format!("⚠️ {e}").into());
                    }
                }
            });
        });
    });

    // Unified list filtering: search query + type + folder (all Rust-side).
    let window_weak_search = main_window.as_weak();
    let vault_arc_search = Arc::clone(&active_vault);
    let search_state_search = Arc::clone(&search_state);
    main_window.on_search_changed(move |query| {
        let mut f = search_state_search.lock().unwrap().clone();
        f.query = query.as_str().to_string();
        // New search starts fast at the first page.
        f.limit = LIST_CAP;
        // Search stays inside the current view (vault or Trash).
        *search_state_search.lock().unwrap() = f.clone();
        let vault = lock_vault(&vault_arc_search);
        if let Some(ui) = window_weak_search.upgrade() {
            set_paged_credentials(&ui, vault_to_items(&vault, &f));
        }
    });

    // Isolated 2FA Hub search: filters ONLY the authenticator grid.
    // The vault `search_query`, list, and filters are never touched here
    // (and vice versa) — the 1s ticker re-applies this same query.
    let window_weak_totp = main_window.as_weak();
    let vault_arc_totp = Arc::clone(&active_vault);
    main_window.on_totp_search_changed(move |query| {
        let vault = lock_vault(&vault_arc_totp);
        if let Some(ui) = window_weak_totp.upgrade() {
            ui.set_auth_rows(rebuild_auth_rows(&vault, query.as_str()));
        }
    });

    let window_weak_type = main_window.as_weak();
    let vault_arc_type = Arc::clone(&active_vault);
    let search_state_type = Arc::clone(&search_state);
    main_window.on_type_filter_changed(move |kind| {
        let mut f = search_state_type.lock().unwrap().clone();
        f.kind = kind;
        f.limit = LIST_CAP;
        // Leaving any view always exits Trash (prop mirrors the state).
        f.show_trash = false;
        *search_state_type.lock().unwrap() = f.clone();
        let vault = lock_vault(&vault_arc_type);
        if let Some(ui) = window_weak_type.upgrade() {
            ui.set_showing_trash(false);
            set_paged_credentials(&ui, vault_to_items(&vault, &f));
        }
    });

    let window_weak_folder = main_window.as_weak();
    let vault_arc_folder = Arc::clone(&active_vault);
    let search_state_folder = Arc::clone(&search_state);
    // Paged window: Load More grows the slice by one page per tap.
    let window_weak_more = main_window.as_weak();
    let vault_arc_more = Arc::clone(&active_vault);
    let search_state_more = Arc::clone(&search_state);
    main_window.on_load_more_items(move || {
        let Some(ui) = window_weak_more.upgrade() else {
            return;
        };
        let mut f = search_state_more.lock().unwrap().clone();
        f.limit = f.limit.saturating_add(LIST_PAGE);
        *search_state_more.lock().unwrap() = f.clone();
        let vault = lock_vault(&vault_arc_more);
        set_paged_credentials(&ui, vault_to_items(&vault, &f));
    });
    main_window.on_folder_filter_changed(move |folder| {
        let mut f = search_state_folder.lock().unwrap().clone();
        f.folder = folder.as_str().to_string();
        f.limit = LIST_CAP;
        f.show_trash = false;
        *search_state_folder.lock().unwrap() = f.clone();
        let vault = lock_vault(&vault_arc_folder);
        if let Some(ui) = window_weak_folder.upgrade() {
            ui.set_showing_trash(false);
            set_paged_credentials(&ui, vault_to_items(&vault, &f));
        }
    });

    // Sidebar ⭐ filter: same refresh pattern, kind stays untouched.
    let window_weak_favf = main_window.as_weak();
    let vault_arc_favf = Arc::clone(&active_vault);
    let search_state_favf = Arc::clone(&search_state);
    main_window.on_fav_filter_changed(move |only| {
        let mut f = search_state_favf.lock().unwrap().clone();
        f.fav_only = only;
        f.limit = LIST_CAP;
        if only {
            f.show_trash = false;
        }
        *search_state_favf.lock().unwrap() = f.clone();
        let vault = lock_vault(&vault_arc_favf);
        if let Some(ui) = window_weak_favf.upgrade() {
            ui.set_show_fav_only(only);
            if only {
                ui.set_showing_trash(false);
            }
            set_paged_credentials(&ui, vault_to_items(&vault, &f));
            // Hub parity: the passkey list honors the same ⭐ filter.
            ui.set_passkeys(rebuild_passkeys(&vault, f.fav_only));
        }
    });

    // Sidebar 🗑️ Trash: all kinds + folders, trashed items only.
    let window_weak_trash = main_window.as_weak();
    let vault_arc_trash = Arc::clone(&active_vault);
    let search_state_trash = Arc::clone(&search_state);
    main_window.on_show_trash_view(move || {
        let mut f = search_state_trash.lock().unwrap().clone();
        f.kind = 0;
        f.folder = "All".to_string();
        f.fav_only = false;
        f.show_trash = true;
        f.limit = LIST_CAP;
        *search_state_trash.lock().unwrap() = f.clone();
        let vault = lock_vault(&vault_arc_trash);
        if let Some(ui) = window_weak_trash.upgrade() {
            ui.set_type_filter(0);
            ui.set_folder_filter("All".into());
            ui.set_show_fav_only(false);
            ui.set_showing_trash(true);
            ui.set_show_empty_confirm(false);
            set_paged_credentials(&ui, vault_to_items(&vault, &f));
        }
    });

    // ⭐ toggle on any of the 6 kinds: flip, re-seal, refresh list + detail.
    let window_weak_fav = main_window.as_weak();
    let vault_arc_fav = Arc::clone(&active_vault);
    let master_pw_fav = Arc::clone(&active_master_pw);
    let search_state_fav = Arc::clone(&search_state);
    main_window.on_toggle_favorite(move |kind, id| {
        let Some(ui) = window_weak_fav.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let master_opt = lock_master_pw(&master_pw_fav).clone();
        let Some(master_pw) = master_opt else {
            ui.set_notification_text("❌ Vault not unlocked!".into());
            return;
        };
        let weak = window_weak_fav.clone();
        let vault_clone = Arc::clone(&vault_arc_fav);
        let search_clone = Arc::clone(&search_state_fav);
        let (kind, id) = (kind, id.as_str().to_string());
        std::thread::spawn(move || {
            // Scoped borrows: the flip borrow ends before the re-seal reads
            // the vault, and the rollback re-borrows after a failed write.
            let flipped: Option<bool> = (|| {
                let mut vault = lock_vault(&vault_clone);
                let state = match fav_flag_mut(&mut vault, kind, &id) {
                    Some(f) => {
                        *f = !*f;
                        *f
                    }
                    None => return None,
                };
                if save_vault_secret(&vault, &master_pw, VAULT_FILE).is_err() {
                    if let Some(f) = fav_flag_mut(&mut vault, kind, &id) {
                        *f = !*f; // roll back the flip on disk failure
                    }
                    return None;
                }
                Some(state)
            })();
            // NOTE: borrow ends before this invoke (no lock held across threads).
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                // Re-read the toggled item to refresh the open detail star.
                let (fav_now, hist) = {
                    let v = lock_vault(&vault_clone);
                    let fav_now = fav_flag(&v, kind, &id);
                    let hist = if kind == 1 {
                        v.credentials
                            .iter()
                            .find(|c| c.id == id)
                            .map(rebuild_history)
                            .unwrap_or_else(|| {
                                ModelRc::new(VecModel::from(Vec::<HistoryView>::new()))
                            })
                    } else {
                        ModelRc::new(VecModel::from(Vec::<HistoryView>::new()))
                    };
                    (fav_now, hist)
                };
                if ui.get_d_id() == id.as_str() {
                    if let Some(f) = fav_now {
                        ui.set_d_fav(f);
                    }
                    ui.set_d_history(hist);
                }
                let f = search_clone.lock().unwrap().clone();
                let v = lock_vault(&vault_clone);
                set_paged_credentials(&ui, vault_to_items(&v, &f));
                ui.set_notification_text(
                    match flipped {
                        Some(true) => "⭐ Pinned to Favorites.".into(),
                        Some(false) => "☆ Unpinned.".into(),
                        // Missing item OR rolled-back save failure — one honest line.
                        None => "⚠️ Toggle failed (missing item or save error).".into(),
                    }
                );
            });
        });
    });

    // Verified-working toggle (logins only): flips Vault.verified_ids with
    // the same save + rollback + refresh + sync discipline as favorites.
    let ver_weak = main_window.as_weak();
    let ver_vault = Arc::clone(&active_vault);
    let ver_master = Arc::clone(&active_master_pw);
    let ver_search = Arc::clone(&search_state);
    main_window.on_toggle_verified(move |kind, id| {
        let Some(ui) = ver_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        if kind != 1 {
            ui.set_notification_text("⚠️ Only logins can be marked verified.".into());
            return;
        }
        let master_opt = lock_master_pw(&ver_master).clone();
        let Some(master_pw) = master_opt else {
            ui.set_notification_text("❌ Vault not unlocked!".into());
            return;
        };
        let weak = ver_weak.clone();
        let vault_clone = Arc::clone(&ver_vault);
        let search_clone = Arc::clone(&ver_search);
        let id = id.as_str().to_string();
        std::thread::spawn(move || {
            let flipped: Option<bool> = (|| {
                let mut vault = lock_vault(&vault_clone);
                let cur = vault.is_verified(&id);
                if !vault.set_verified(&id, !cur) {
                    return None;
                }
                if save_vault_secret(&vault, &master_pw, VAULT_FILE).is_err() {
                    // Roll back the flip on disk failure.
                    vault.set_verified(&id, cur);
                    let _ = save_vault_secret(&vault, &master_pw, VAULT_FILE);
                    return None;
                }
                Some(!cur)
            })();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                {
                    let v = lock_vault(&vault_clone);
                    if ui.get_d_id() == id.as_str() {
                        ui.set_d_verified(v.is_verified(&id));
                    }
                }
                let f = search_clone.lock().unwrap().clone();
                let v = lock_vault(&vault_clone);
                set_paged_credentials(&ui, vault_to_items(&v, &f));
                ui.set_notification_text(
                    match flipped {
                        Some(true) => "✅ Marked as verified working.".into(),
                        Some(false) => "Verification mark removed.".into(),
                        None => "⚠️ Toggle failed (missing item or save error).".into(),
                    }
                );
                trigger_sync_push(ui.as_weak());
            });
        });
    });

    // Bulk-select (Column 2 ☑️ mode): toggle / clear are RAM-only; the
    // three batch actions run one lock + one DoD re-seal + one sync push.
    fn refresh_selection_ui(ui: &MainWindow, vault: &Vault, search: &FilterState) {
        let n = selection_count();
        ui.set_selected_count(n as i32);
        ui.set_selected_label(
            if n == 0 {
                String::new()
            } else {
                format!("{n} item{} selected", if n == 1 { "" } else { "s" })
            }
            .into(),
        );
        set_paged_credentials(ui, vault_to_items(vault, search));
    }
    let sel_weak = main_window.as_weak();
    let sel_vault = Arc::clone(&active_vault);
    let sel_search = Arc::clone(&search_state);
    main_window.on_toggle_select(move |kind, id| {
        let Some(ui) = sel_weak.upgrade() else {
            return;
        };
        {
            let mut reg = selection_registry().lock().unwrap_or_else(|p| p.into_inner());
            let k = selection_key(kind, id.as_str());
            if !reg.remove(&k) {
                reg.insert(k);
            }
        }
        let f = sel_search.lock().unwrap().clone();
        let v = lock_vault(&sel_vault);
        refresh_selection_ui(&ui, &v, &f);
    });
    let clr_weak = main_window.as_weak();
    let clr_vault = Arc::clone(&active_vault);
    let clr_search = Arc::clone(&search_state);
    main_window.on_clear_selection(move || {
        let Some(ui) = clr_weak.upgrade() else {
            return;
        };
        selection_registry().lock().unwrap_or_else(|p| p.into_inner()).clear();
        let f = clr_search.lock().unwrap().clone();
        let v = lock_vault(&clr_vault);
        refresh_selection_ui(&ui, &v, &f);
    });
    // Shared batch runner: snapshot-rollback re-seal, list + hub + QuickBar
    // refresh, selection cleared, single sync push. Returns affected count.
    #[allow(clippy::too_many_arguments)]
    fn run_bulk_op(
        weak: slint::Weak<MainWindow>,
        vault_clone: Arc<Mutex<Vault>>,
        master_clone: Arc<Mutex<Option<SecretString>>>,
        search_clone: Arc<Mutex<FilterState>>,
        qb_clone: slint::Weak<QuickBarWindow>,
        verb: &'static str,
        // Optional success-note suffix (e.g. rotate's "update each site").
        note: Option<&'static str>,
        op: impl FnOnce(&mut Vault) -> usize + Send + 'static,
    ) {
        std::thread::spawn(move || {
            let master_opt = lock_master_pw(&master_clone).clone();
            let Some(master_pw) = master_opt else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_notification_text("❌ Vault not unlocked!".into());
                    }
                });
                return;
            };
            let saved: Result<(Vault, usize), String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                let n = op(&mut vault);
                if n == 0 {
                    Err("No selected items found (already moved?).".to_string())
                } else {
                    match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                        Ok(()) => Ok((vault.clone(), n)),
                        Err(e) => {
                            *vault = snapshot;
                            Err(e)
                        }
                    }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match saved {
                    Ok((v, n)) => {
                        selection_registry().lock().unwrap_or_else(|p| p.into_inner()).clear();
                        let f = search_clone.lock().unwrap().clone();
                        refresh_selection_ui(&ui, &v, &f);
                        sync_folders_to_ui(&v, &ui);
                        set_trash_label(&ui, &v);
                        ui.set_auth_accounts(rebuild_auth_list(&v));
                        ui.set_auth_rows(rebuild_auth_rows(&v, ui.get_totp_search_query().as_str()));
                        if let Some(qb) = qb_clone.upgrade() {
                            qb.set_filtered_results(vault_quickbar(&v, "", search_clone.lock().unwrap().travel_only));
                        }
                        ui.set_notification_text(
                            match note {
                                Some(extra) => format!(
                                    "✅ Bulk {verb}: {n} item{}. {extra}",
                                    if n == 1 { "" } else { "s" }
                                ),
                                None => format!(
                                    "✅ Bulk {verb}: {n} item{}.",
                                    if n == 1 { "" } else { "s" }
                                ),
                            }
                            .into(),
                        );
                        security::access_log::log_event("bulk", verb);
                        trigger_sync_push(ui.as_weak());
                    }
                    Err(e) => {
                        ui.set_notification_text(format!("❌ Bulk {verb} failed: {e}").into());
                    }
                }
            });
        });
    }
    let bulk_weak = main_window.as_weak();
    let bulk_vault = Arc::clone(&active_vault);
    let bulk_master = Arc::clone(&active_master_pw);
    let bulk_search = Arc::clone(&search_state);
    let bulk_qb = quick_bar.as_weak();
    let parse_sel = || -> Vec<(i32, String)> {
        selection_registry()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter_map(|k| {
                let (ks, id) = k.split_once(':')?;
                Some((ks.parse::<i32>().ok()?, id.to_string()))
            })
            .collect()
    };
    main_window.on_bulk_favorite({
        let weak = bulk_weak.clone();
        let vault_clone = Arc::clone(&bulk_vault);
        let master_clone = Arc::clone(&bulk_master);
        let search_clone = Arc::clone(&bulk_search);
        let qb_clone = bulk_qb.clone();
        move || {
            if weak.upgrade().map(|ui| ui.get_is_decoy()).unwrap_or(false) {
                if let Some(ui) = weak.upgrade() {
                    ui.set_notification_text("⛔ Decoy mode is read-only.".into());
                }
                return;
            }
            let targets = parse_sel();
            run_bulk_op(weak.clone(), Arc::clone(&vault_clone), Arc::clone(&master_clone), Arc::clone(&search_clone), qb_clone.clone(), "favorite", None, move |vault| {
                let mut n = 0;
                for (kind, id) in &targets {
                    if let Some(f) = fav_flag_mut(vault, *kind, id) {
                        if !*f {
                            *f = true;
                            n += 1;
                        }
                    }
                }
                n
            });
        }
    });
    main_window.on_bulk_move({
        let weak = bulk_weak.clone();
        let vault_clone = Arc::clone(&bulk_vault);
        let master_clone = Arc::clone(&bulk_master);
        let search_clone = Arc::clone(&bulk_search);
        let qb_clone = bulk_qb.clone();
        move |folder| {
            if weak.upgrade().map(|ui| ui.get_is_decoy()).unwrap_or(false) {
                if let Some(ui) = weak.upgrade() {
                    ui.set_notification_text("⛔ Decoy mode is read-only.".into());
                }
                return;
            }
            let dest = folder.as_str().trim().to_string();
            if dest.is_empty() || dest == "All" {
                if let Some(ui) = weak.upgrade() {
                    ui.set_notification_text("⚠️ Pick a destination folder first.".into());
                }
                return;
            }
            let targets = parse_sel();
            run_bulk_op(weak.clone(), Arc::clone(&vault_clone), Arc::clone(&master_clone), Arc::clone(&search_clone), qb_clone.clone(), "move", None, move |vault| {
                let mut n = 0;
                for (kind, id) in &targets {
                    let slot: Option<&mut String> = match *kind {
                        1 => vault.credentials.iter_mut().find(|c| &c.id == id).map(|c| &mut c.folder),
                        2 => vault.licenses.iter_mut().find(|l| &l.id == id).map(|l| &mut l.folder),
                        3 => vault.notes.iter_mut().find(|n| &n.id == id).map(|n| &mut n.folder),
                        4 => vault.cards.iter_mut().find(|k| &k.id == id).map(|k| &mut k.folder),
                        5 => vault.identities.iter_mut().find(|i| &i.id == id).map(|i| &mut i.folder),
                        6 => vault.ssh_keys.iter_mut().find(|s| &s.id == id).map(|s| &mut s.folder),
                        _ => None, // standalone 2FA / passkeys carry no folder
                    };
                    if let Some(f) = slot {
                        if *f != dest {
                            *f = dest.clone();
                            n += 1;
                        }
                    }
                }
                if !vault.folders.iter().any(|f| f == &dest) {
                    vault.folders.push(dest);
                }
                n
            });
        }
    });
    main_window.on_bulk_trash({
        let weak = bulk_weak.clone();
        let vault_clone = Arc::clone(&bulk_vault);
        let master_clone = Arc::clone(&bulk_master);
        let search_clone = Arc::clone(&bulk_search);
        let qb_clone = bulk_qb.clone();
        move || {
            if weak.upgrade().map(|ui| ui.get_is_decoy()).unwrap_or(false) {
                if let Some(ui) = weak.upgrade() {
                    ui.set_notification_text("⛔ Decoy mode is read-only.".into());
                }
                return;
            }
            let targets = parse_sel();
            run_bulk_op(weak.clone(), Arc::clone(&vault_clone), Arc::clone(&master_clone), Arc::clone(&search_clone), qb_clone.clone(), "trash", None, move |vault| {
                let mut n = 0;
                let now = crate::models::current_timestamp();
                for (kind, id) in &targets {
                    let ok = if *kind == 8 {
                        // Standalone 2FA has no trash generation (same as
                        // single delete): permanent remove.
                        remove_totp_account(vault, id)
                    } else if vault.is_trashed(*kind, id).unwrap_or(false) {
                        vault.delete_item(*kind, id)
                    } else {
                        vault.trash_item(*kind, id, now)
                    };
                    if ok {
                        n += 1;
                    }
                }
                n
            });
        }
    });

    // One-click reused rotation: every shared login password becomes unique
    // (history kept, one re-seal). Vault-side only — the notification says
    // the website updates out loud. Decoy refused up front like bulk trash.
    main_window.on_rotate_reused({
        let weak = bulk_weak.clone();
        let vault_clone = Arc::clone(&bulk_vault);
        let master_clone = Arc::clone(&bulk_master);
        let search_clone = Arc::clone(&bulk_search);
        let qb_clone = bulk_qb.clone();
        move || {
            if weak.upgrade().map(|ui| ui.get_is_decoy()).unwrap_or(false) {
                if let Some(ui) = weak.upgrade() {
                    ui.set_notification_text("⛔ Decoy mode is read-only.".into());
                }
                return;
            }
            run_bulk_op(weak.clone(), Arc::clone(&vault_clone), Arc::clone(&master_clone), Arc::clone(&search_clone), qb_clone.clone(), "rotate", Some("History kept — now update each password ON ITS WEBSITE."), move |vault| {
                rotate_reused_passwords(vault)
            });
        }
    });
/// Zero-lockin: one rendered GA migration page (URI + PNG bytes).
struct GaPage {
    uri: String,
    png: Vec<u8>,
}

fn ga_warn_text(skipped: &[String], lossy: &[String], capped: usize) -> String {
    let mut parts = Vec::new();
    if !lossy.is_empty() {
        parts.push(format!(
            "⚠️ {} transfer as standard TOTP (Steam alphabet / custom period won't match on phone): {}",
            lossy.len(),
            lossy.join(", ")
        ));
    }
    if !skipped.is_empty() {
        parts.push(format!(
            "⏭️ {} skipped (undecodable secrets — re-enroll these): {}",
            skipped.len(),
            skipped.join(", ")
        ));
    }
    if capped > 0 {
        parts.push(format!("✂️ Capped at 100 accounts ({capped} left out) — export again after moving these."));
    }
    parts.join("\n")
}

fn ga_show_page(ui: &MainWindow, pages: &[GaPage], idx: usize) {
    let Some(p) = pages.get(idx) else {
        return;
    };
    if let Some(img) = png_bytes_to_image(&p.png) {
        ui.set_ga_image(img);
    }
    ui.set_ga_page(format!("Page {} of {}", idx + 1, pages.len()).into());
    ui.set_ga_show(true);
}

    // 8a: Universal 2FA ingestion (multi-line URIs + every JSON schema).
    // Shared save path: smart-dedup merge, rollback on disk failure, hub
    // repaint, result card. Used by paste, file browse, and (unchanged)
    // single-QR scan paths below.
    fn save_2fa_accounts(
        weak: slint::Weak<MainWindow>,
        vault_arc: Arc<Mutex<Vault>>,
        master_arc: Arc<Mutex<Option<SecretString>>>,
        search_arc: Arc<Mutex<FilterState>>,
        source_label: String,
        accounts: Vec<models::TotpAccount>,
        warnings: Vec<String>,
    ) {
        std::thread::spawn(move || {
            let master_opt = lock_master_pw(&master_arc).clone();
            let Some(master_pw) = master_opt else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_notification_text("❌ Vault not unlocked!".into());
                    }
                });
                return;
            };
            // Phase 28: this path merged blindly. A same-name/different-secret
            // account was silently added as a second card, which is exactly how
            // the user ended up with two Facebook cards and no idea which one
            // worked. Ask BEFORE any write; nothing is sealed on this branch.
            let conflicts = {
                let v = lock_vault(&vault_arc);
                dup_conflicts_against(&v, &accounts)
            };
            if !conflicts.is_empty() {
                let dup_ui = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = dup_ui.upgrade() {
                        park_twofa_for_dup(&ui, accounts, conflicts);
                    }
                });
                return;
            }
            let save_result: Result<authenticator::universal_2fa::Import2faSummary, String> = {
                let mut vault = lock_vault(&vault_arc);
                let snapshot = vault.clone();
                let report: MergeReport =
                    merge_2fa_with_policy(&mut vault, accounts, DupPolicy::KeepBoth);
                let imported = report.imported + report.replaced;
                match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                    Ok(()) => Ok(authenticator::universal_2fa::Import2faSummary {
                        accounts_imported: imported,
                        duplicates_skipped: report.skipped,
                        source_detected: source_label,
                        warnings,
                    }),
                    Err(e) => {
                        *vault = snapshot;
                        Err(e)
                    }
                }
            };
            let vault_for_list = Arc::clone(&vault_arc);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    match save_result {
                        Ok(s) => {
                            let mut msg = format!(
                                "✅ {}: {} imported, {} dupes skipped",
                                s.source_detected, s.accounts_imported, s.duplicates_skipped
                            );
                            if !s.warnings.is_empty() {
                                msg.push_str(&format!(" | ⚠️ {}", s.warnings.join(" | ")));
                            }
                            ui.set_notification_text(format!("✅ Imported {} 2FA accounts!", s.accounts_imported).into());
                            ui.set_import_2fa_status(msg.into());
                            ui.set_import_input("".into());
                            {
                                let v = lock_vault(&vault_for_list);
                                ui.set_auth_accounts(rebuild_auth_list(&v));
                                ui.set_auth_rows(rebuild_auth_rows(&v, ui.get_totp_search_query().as_str()));
                                // Standalone 2FA also lives in All items / Favorites.
                                let f = search_arc.lock().unwrap().clone();
                                set_paged_credentials(&ui, vault_to_items(&v, &f));
                            }
                            trigger_sync_push(ui.as_weak());
                        }
                        Err(e) => {
                            ui.set_notification_text(format!("❌ Import save failed: {e}").into());
                            ui.set_import_2fa_status(format!("❌ Save failed: {e}").into());
                        }
                    }
                }
            });
        });
    }
    let window_weak_url = main_window.as_weak();
    let vault_arc_url = Arc::clone(&active_vault);
    let master_pw_url = Arc::clone(&active_master_pw);
    let url_search = Arc::clone(&search_state);
    main_window.on_import_url_requested(move |url_text| {
        if let Some(ui) = window_weak_url.upgrade() {
            if ui.get_is_decoy() {
                ui.set_notification_text("⛔ Decoy mode is read-only.".into());
                return;
            }
        }
        let input = url_text.as_str().trim().to_string();
        if input.is_empty() {
            if let Some(ui) = window_weak_url.upgrade() {
                ui.set_notification_text("⚠️ Paste a migration URL first".into());
            }
            return;
        }
        if let Some(ui) = window_weak_url.upgrade() {
            ui.set_notification_text("⏳ Decoding & encrypting 2FA…".into());
        }
        let weak = window_weak_url.clone();
        // Universal pipeline: multi-line URIs + 2FAS/Aegis/Steam/andOTP/FreeOTP JSON.
        match authenticator::universal_2fa::sniff_and_parse_text(&input) {
            Ok((source, accounts, warnings)) => {
                save_2fa_accounts(
                    weak,
                    Arc::clone(&vault_arc_url),
                    Arc::clone(&master_pw_url),
                    Arc::clone(&url_search),
                    source.label().to_string(),
                    accounts,
                    warnings,
                );
            }
            Err(e) => {
                if let Some(ui) = window_weak_url.upgrade() {
                    ui.set_notification_text(format!("❌ Import failed: {e}").into());
                    ui.set_import_2fa_status(format!("❌ {e}").into());
                }
            }
        }
    });

    // 8a2: Browse & import 2FA file (json/2fas/maFile/txt/png/jpg).
    let window_weak_2faf = main_window.as_weak();
    let vault_arc_2faf = Arc::clone(&active_vault);
    let master_pw_2faf = Arc::clone(&active_master_pw);
    let f2_search = Arc::clone(&search_state);
    main_window.on_import_2fa_file(move || {
        if let Some(ui) = window_weak_2faf.upgrade() {
            if ui.get_is_decoy() {
                ui.set_notification_text("⛔ Decoy mode is read-only.".into());
                return;
            }
            ui.set_import_2fa_status("⏳ Waiting for file picker…".into());
        }
        let weak = window_weak_2faf.clone();
        let vault_clone = Arc::clone(&vault_arc_2faf);
        let master_clone = Arc::clone(&master_pw_2faf);
        let search_clone = Arc::clone(&f2_search);
        std::thread::spawn(move || {
            let picked = rfd::FileDialog::new()
                .set_title("Import 2FA file")
                .add_filter("2FA exports", &["json", "2fas", "maFile", "txt", "png", "jpg", "jpeg"])
                .add_filter("all files", &["*"])
                .pick_file();
            let Some(path) = picked else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_import_2fa_status("No file chosen.".into());
                    }
                });
                return;
            };
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_string();
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    let msg = format!("❌ Cannot read file: {e}");
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_import_2fa_status(msg.into());
                        }
                    });
                    return;
                }
            };
            match authenticator::universal_2fa::parse_file_bytes(&bytes, &ext) {
                Ok((source, accounts, warnings)) => {
                    save_2fa_accounts(
                        weak,
                        vault_clone,
                        master_clone,
                        search_clone,
                        format!("{} ({})", source.label(), path.file_name().and_then(|n| n.to_str()).unwrap_or("file")),
                        accounts,
                        warnings,
                    );
                }
                Err(e) => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_import_2fa_status(format!("❌ {e}").into());
                            ui.set_notification_text(format!("❌ 2FA import failed: {e}").into());
                        }
                    });
                }
            }
        });
    });

    // 8b: Clipboard QR scan (Win+Shift+S)
    let window_weak_qr = main_window.as_weak();
    let vault_arc_qr = Arc::clone(&active_vault);
    let master_pw_qr = Arc::clone(&active_master_pw);
    let search_qr = Arc::clone(&search_state);
    main_window.on_scan_qr_requested(move || {
        if let Some(ui) = window_weak_qr.upgrade() {
            if ui.get_is_decoy() {
                ui.set_notification_text("⛔ Decoy mode is read-only.".into());
                return;
            }
            ui.set_notification_text("⏳ Scanning clipboard QR…".into());
        }
        let weak = window_weak_qr.clone();
        let vault_clone = Arc::clone(&vault_arc_qr);
        let master_clone = Arc::clone(&master_pw_qr);
        let search_clone = Arc::clone(&search_qr);
        std::thread::spawn(move || {
            // Decode QR from clipboard image (rqrr) — background to avoid UI freeze
            let qr_content = match authenticator::qr_scanner::decode_qr_from_clipboard() {
                Ok(s) => s,
                Err(e) => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_notification_text(format!("❌ QR scan failed: {}", e).into());
                        }
                    });
                    return;
                }
            };
            // Parse the decoded QR string (could be migration or otpauth)
            let (accounts, batch_suffix) = match authenticator::parse_google_migration_url(&qr_content) {
                Ok((a, batch)) => {
                        let suffix = batch.display().map(|s| format!(" ({s})")).unwrap_or_default();
                        (a, suffix)
                    },
                Err(e) => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_notification_text(format!("❌ QR parse failed: {}", e).into());
                        }
                    });
                    return;
                }
            };
            // Phase 28: this path used to call `totp_accounts.extend()`
            // directly — NO dedup at all. That is the precise mechanism behind
            // the duplicate cards the user hit: re-scanning a QR for an account
            // already in the vault appended a second copy every time. It now
            // asks first, then merges under the explicit policy.
            let conflicts = {
                let v = lock_vault(&vault_clone);
                dup_conflicts_against(&v, &accounts)
            };
            if !conflicts.is_empty() {
                let dup_ui = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = dup_ui.upgrade() {
                        park_twofa_for_dup(&ui, accounts, conflicts);
                    }
                });
                return;
            }
            let master_opt = lock_master_pw(&master_clone).clone();
            let Some(master_pw) = master_opt else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_notification_text("❌ Vault not unlocked!".into());
                    }
                });
                return;
            };
            let save_result: Result<usize, String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                let report: MergeReport =
                    merge_2fa_with_policy(&mut vault, accounts, DupPolicy::KeepBoth);
                let imported = report.imported + report.replaced;
                match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                    Ok(()) => Ok(imported),
                    Err(e) => {
                        // Roll back to the pre-import snapshot rather than
                        // popping N entries: `pop` cannot undo a ReplaceExisting,
                        // which edits in place.
                        *vault = snapshot;
                        Err(e)
                    }
                }
            };
            let vault_for_list_qr = Arc::clone(&vault_clone);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    match save_result {
                        Ok(imported) => {
                            ui.set_notification_text(
                                format!("✅ Imported {imported} 2FA accounts successfully!{}", batch_suffix).into(),
                            );
                            ui.set_show_2fa_import(false);
                            {
                                let v = lock_vault(&vault_for_list_qr);
                                ui.set_auth_accounts(rebuild_auth_list(&v));
                                ui.set_auth_rows(rebuild_auth_rows(&v, ui.get_totp_search_query().as_str()));
                                // Standalone 2FA also lives in All items / Favorites.
                                let f = search_clone.lock().unwrap().clone();
                                set_paged_credentials(&ui, vault_to_items(&v, &f));
                            }
                            trigger_sync_push(ui.as_weak());
                        }
                        Err(e) => {
                            ui.set_notification_text(format!("❌ Import save failed: {}", e).into());
                        }
                    }
                }
            });
        });
    });

    // Webcam camera list (driver index, display name), refreshed on every
    // scan open. The picker handler resolves a display name back through it.
    fn webcam_cam_list() -> &'static Mutex<Vec<(u32, String)>> {
        static CAMS: std::sync::OnceLock<Mutex<Vec<(u32, String)>>> =
            std::sync::OnceLock::new();
        CAMS.get_or_init(|| Mutex::new(Vec::new()))
    }

    // Batch-4: live webcam QR → same import pipeline as clipboard QR.
    // Worker mother-fn: the capture callback runs on the camera worker thread
    // and owns the parse → re-seal → UI-refresh flow end to end (no dead arms).
    // Spawned per scan AND per camera switch; stale generations die via the
    // scanner's SCAN_GEN (no resurrection, no double-serve).
    /// Spawn generation: only the NEWEST worker may touch the modal. A stale
    /// worker (double-click spawn, rapid camera switch) exits silently —
    /// otherwise the loser closes the modal out from under the winner
    /// ("camera flashes then vanishes").
    static WEBCAM_SPAWN_GEN: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    fn spawn_webcam_worker(
        main_weak: slint::Weak<MainWindow>,
        vault_arc: Arc<Mutex<Vault>>,
        master_pw_arc: Arc<Mutex<Option<SecretString>>>,
        search_arc: Arc<Mutex<FilterState>>,
        camera_index: u32,
    ) {
        let my_gen = WEBCAM_SPAWN_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let weak = main_weak.clone();
        let vault_clone = Arc::clone(&vault_arc);
        let master_clone = Arc::clone(&master_pw_arc);
        let search_clone_cam = Arc::clone(&search_arc);
        std::thread::spawn(move || {
            let weak_cb = weak.clone();
            let weak_frame = weak.clone();
            // Live preview: every camera frame becomes the modal image.
            // Runs on this worker thread — hop to the event loop per frame.
            // Lens-cover hint: sustained near-black frames mean a covered lens
            // (a dead camera never reaches on_frame at all). The hint prop
            // updates only on dark↔light transitions, never per frame.
            let dark_state =
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let dark_state_cb = std::sync::Arc::clone(&dark_state);
            let on_frame = move |rgba: Vec<u8>, w: u32, h: u32| {
                // Sampled mean red (~luma proxy): sustained near-black means
                // a covered lens. Threshold compare is branchless-safe here.
                let mut sum: u64 = 0;
                let mut count: u64 = 0;
                for b in rgba.iter().step_by(16) {
                    sum += *b as u64;
                    count += 1;
                }
                let dark_now = count > 0 && sum / count < 6;
                if dark_state_cb.swap(dark_now, std::sync::atomic::Ordering::SeqCst)
                    != dark_now
                {
                    let weak_hint = weak_frame.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak_hint.upgrade() {
                            ui.set_webcam_hint(if dark_now {
                                "🌑 Very dark — lens covered?".into()
                            } else {
                                String::new().into()
                            });
                        }
                    });
                }
                let weak_frame = weak_frame.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak_frame.upgrade() {
                        let buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
                            &rgba, w, h,
                        );
                        ui.set_webcam_frame(slint::Image::from_rgba8(buf));
                    }
                });
            };
            let res = authenticator::camera_scanner::capture_and_scan_frame(
                camera_index,
                on_frame,
                move |qr_content| {
                    let weak_in = weak_cb.clone();
                    // Stale generation: a newer spawn owns the modal — never
                    // import/notify from a superseded worker.
                    if my_gen
                        != WEBCAM_SPAWN_GEN.load(std::sync::atomic::Ordering::SeqCst)
                    {
                        return;
                    }
                    // Parse the decoded QR string (migration or plain otpauth).
                    let (accounts, batch_suffix) = match authenticator::parse_google_migration_url(&qr_content) {
                        Ok((a, batch)) => {
                            let suffix = batch.display().map(|s| format!(" ({s})")).unwrap_or_default();
                            (a, suffix)
                        },
                        Err(e) => {
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Some(ui) = weak_in.upgrade() {
                                    ui.set_show_webcam_scan(false);
                                    ui.set_notification_text(format!("❌ QR parse failed: {}", e).into());
                                }
                            });
                            return;
                        }
                    };
                    // Phase 28: same blind `extend()` as the clipboard QR path, same
                    // fix — park the collision and let the user decide.
                    let conflicts = {
                        let v = lock_vault(&vault_clone);
                        dup_conflicts_against(&v, &accounts)
                    };
                    if !conflicts.is_empty() {
                        let dup_ui = weak_in.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = dup_ui.upgrade() {
                                ui.set_show_webcam_scan(false);
                                park_twofa_for_dup(&ui, accounts, conflicts);
                            }
                        });
                        return;
                    }
                    let master_opt = lock_master_pw(&master_clone).clone();
                    let Some(master_pw) = master_opt else {
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak_in.upgrade() {
                                ui.set_show_webcam_scan(false);
                                ui.set_notification_text("❌ Vault not unlocked!".into());
                            }
                        });
                        return;
                    };
                    let save_result: Result<usize, String> = {
                        let mut vault = lock_vault(&vault_clone);
                        let snapshot = vault.clone();
                        let report: MergeReport =
                            merge_2fa_with_policy(&mut vault, accounts, DupPolicy::KeepBoth);
                        let imported = report.imported + report.replaced;
                        match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                            Ok(()) => Ok(imported),
                            Err(e) => {
                                *vault = snapshot;
                                Err(e.to_string())
                            }
                        }
                    };
                    let vault_for_list = Arc::clone(&vault_clone);
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak_in.upgrade() {
                            ui.set_show_webcam_scan(false);
                            match save_result {
                                Ok(imported) => {
                                    ui.set_notification_text(
                                        format!("✅ Webcam imported {imported} 2FA accounts!{}", batch_suffix).into(),
                                    );
                                    {
                                        let v = lock_vault(&vault_for_list);
                                        ui.set_auth_accounts(rebuild_auth_list(&v));
                                    ui.set_auth_rows(rebuild_auth_rows(&v, ui.get_totp_search_query().as_str()));
                                        // Standalone 2FA also lives in All items / Favorites.
                                        let f = search_clone_cam.lock().unwrap().clone();
                                        set_paged_credentials(&ui, vault_to_items(&v, &f));
                                    }
                                    trigger_sync_push(ui.as_weak());
                                }
                                Err(e) => {
                                    ui.set_notification_text(format!("❌ Import save failed: {}", e).into());
                                }
                            }
                        }
                    });
                },
            );
            // Camera-level failure (no device / timeout / cancel): the modal
            // closes here; per-account outcomes were already reported above.
            // STALE workers (superseded by a newer spawn) exit SILENTLY —
            // only the newest generation may close the modal or notify.
            if let Err(e) = res {
                if my_gen
                    != WEBCAM_SPAWN_GEN.load(std::sync::atomic::Ordering::SeqCst)
                {
                    return;
                }
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_show_webcam_scan(false);
                        ui.set_notification_text(format!("❌ Webcam scan: {}", e).into());
                    }
                });
            }
        });
    }

    let window_weak_cam = main_window.as_weak();
    let vault_arc_cam = Arc::clone(&active_vault);
    let master_pw_cam = Arc::clone(&active_master_pw);
    let cam_search = Arc::clone(&search_state);
    main_window.on_scan_webcam_requested(move || {
        // Debounce: a scan already showing ignores re-entry (double-click
        // would spawn a loser worker whose death-flash closes the modal).
        if let Some(ui) = window_weak_cam.upgrade() {
            if ui.get_show_webcam_scan() {
                return;
            }
        }
        // Enumerate FIRST: no visible camera = guidance, never a black modal.
        // (Slim builds: list is always empty → same guidance path.)
        let cams = authenticator::camera_scanner::list_cameras();
        if let Some(ui) = window_weak_cam.upgrade() {
            if ui.get_is_decoy() {
                ui.set_notification_text("⛔ Decoy mode is read-only.".into());
                return;
            }
            if cams.is_empty() {
                ui.set_notification_text(
                    "📷 No camera found — check Windows Privacy → Camera, or close apps using it.".into(),
                );
                return;
            }
            {
                let mut stored = webcam_cam_list().lock().unwrap_or_else(|p| p.into_inner());
                *stored = cams.clone();
            }
            let names: Vec<slint::SharedString> =
                cams.iter().map(|(_, n)| n.as_str().into()).collect();
            ui.set_webcam_cams(slint::ModelRc::new(slint::VecModel::from_slice(
                &names,
            )));
            ui.set_webcam_cam_current(names[0].clone());
            ui.set_webcam_hint(String::new().into());
            ui.set_show_webcam_scan(true);
            ui.set_notification_text(
                format!("📷 Point the QR at {}…", cams[0].1).into(),
            );
        }
        spawn_webcam_worker(
            window_weak_cam.clone(),
            Arc::clone(&vault_arc_cam),
            Arc::clone(&master_pw_cam),
            Arc::clone(&cam_search),
            cams.first().map(|(i, _)| *i).unwrap_or(0),
        );
    });
    // Camera switch: cancel the running worker (generation-guarded, no
    // resurrection) and respawn on the chosen driver index.
    let pick_weak = main_window.as_weak();
    let pick_vault = Arc::clone(&active_vault);
    let pick_master = Arc::clone(&active_master_pw);
    let pick_search = Arc::clone(&search_state);
    main_window.on_webcam_camera_picked(move |name| {
        let wanted = name.to_string();
        let idx = webcam_cam_list()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|(_, n)| n == &wanted)
            .map(|(i, _)| *i);
        let Some(idx) = idx else {
            return;
        };
        authenticator::camera_scanner::cancel_webcam_scan();
        if let Some(ui) = pick_weak.upgrade() {
            ui.set_webcam_cam_current(wanted.into());
            ui.set_webcam_hint(String::new().into());
            ui.set_notification_text("📷 Switched camera — point the QR…".into());
        }
        spawn_webcam_worker(
            pick_weak.clone(),
            Arc::clone(&pick_vault),
            Arc::clone(&pick_master),
            Arc::clone(&pick_search),
            idx,
        );
    });
    let window_weak_cam_cancel = main_window.as_weak();
    main_window.on_cancel_webcam_scan(move || {
        authenticator::camera_scanner::cancel_webcam_scan();
        if let Some(ui) = window_weak_cam_cancel.upgrade() {
            ui.set_show_webcam_scan(false);
            ui.set_notification_text("Webcam scan cancelled.".into());
        }
    });

    // Phase 13: Auto-Type from the main credential list
    let type_main = main_window.as_weak();
    let type_main_qb = quick_bar.as_weak();
    let type_main_vis = Arc::clone(&quickbar_visible);
    let type_main_uvis = Arc::clone(&ui_visible);
    let type_main_vault = Arc::clone(&active_vault);
    main_window.on_type_credential_requested(move |username, password, totp| {
        if let Some(title) =
            check_canary_trip(&type_main_vault, password.as_str(), "autotype-list")
        {
            if let Some(ui) = type_main.upgrade() {
                ui.set_notification_text(
                    format!("🚨 CANARY TRIPPED: '{title}' — logged!").into(),
                );
            }
        }
        // Legacy login path (no id): metadata unknown, audit still records
        // the (empty) id sidecar-side only when present — see handler below.
        let req = {
            let v = lock_vault(&type_main_vault);
            // Best-effort id recovery for audit: match the exact password.
            let found = v.credentials.iter().find(|c| {
                c.deleted_at.is_none()
                    && c.username == username.as_str()
                    && c.password == password.as_str()
            });
            match found {
                Some(c) => type_request_for(&v, 1, &c.id).unwrap_or_else(|| TypeRequest {
                    kind: 1,
                    fields: vec![username.as_str().to_string(), password.as_str().to_string()],
                    press_enter: true,
                    item_id: String::new(),
                    item_title: String::new(),
                    last_changed: 0,
                    totp_secret: totp.as_str().to_string(),
                }),
                None => TypeRequest {
                    kind: 1,
                    fields: vec![username.as_str().to_string(), password.as_str().to_string()],
                    press_enter: true,
                    item_id: String::new(),
                    item_title: String::new(),
                    last_changed: 0,
                    totp_secret: totp.as_str().to_string(),
                },
            }
        };
        trigger_autotype(
            type_main.clone(),
            type_main_qb.clone(),
            Arc::clone(&type_main_vis),
            Arc::clone(&type_main_uvis),
            req,
        );
    });

    // Bitwarden-parity: type ANY item kind by (kind, id) — cards type
    // number{TAB}MM/YY{TAB}CVV, identities type name{TAB}email{TAB}phone{TAB}address.
    let type_item_main = main_window.as_weak();
    let type_item_qb = quick_bar.as_weak();
    let type_item_vis = Arc::clone(&quickbar_visible);
    let type_item_uvis = Arc::clone(&ui_visible);
    let type_item_vault = Arc::clone(&active_vault);
    main_window.on_type_item_requested(move |kind, id| {
        let req = {
            let v = lock_vault(&type_item_vault);
            type_request_for(&v, kind, id.as_str())
        };
        let Some(req) = req else {
            if let Some(ui) = type_item_main.upgrade() {
                ui.set_notification_text("⚠️ Item not found (or in Trash) — cannot type.".into());
            }
            return;
        };
        // Canary tripwire across every typed field (passwords AND card/
        // identity material — honeytokens can hide in any kind).
        let tripped = req
            .fields
            .iter()
            .filter(|f| !f.trim().is_empty())
            .find_map(|f| check_canary_trip(&type_item_vault, f, "autotype-item"));
        if let Some(title) = tripped {
            if let Some(ui) = type_item_main.upgrade() {
                ui.set_notification_text(
                    format!("🚨 CANARY TRIPPED: '{title}' — logged!").into(),
                );
            }
        }
        // Reprompt gate: armed items detour through the modal (rp_action 2).
        if let Some(main_ui) = type_item_main.upgrade() {
            let gated = {
                let v = lock_vault(&type_item_vault);
                reprompt_gate(&v, kind, id.as_str())
            };
            if let Some((g_user, g_secret)) = gated {
                main_ui.set_rp_action(2);
                main_ui.set_rp_kind(kind);
                main_ui.set_rp_id(id.clone());
                main_ui.set_rp_user(g_user.into());
                main_ui.set_rp_secret(g_secret.into());
                main_ui.set_rp_error(String::new().into());
                main_ui.set_rp_show(true);
                main_ui.set_notification_text("🔒 Master re-prompt required.".into());
                return;
            }
        }
        trigger_autotype(
            type_item_main.clone(),
            type_item_qb.clone(),
            Arc::clone(&type_item_vis),
            Arc::clone(&type_item_uvis),
            req,
        );
    });

    // 3. Secret copy — Phase 20 masked path (canary alert preserved).
    let window_weak_copy = main_window.as_weak();
    let vault_arc_copy = Arc::clone(&active_vault);
    let ct_copy = Arc::clone(&clipboard_timeout_secs);
    let activity_copy = Arc::clone(&last_activity);
    main_window.on_copy_password_requested(move |password_to_copy| {
        let Some(ui) = window_weak_copy.upgrade() else {
            return;
        };
        if let Ok(mut t) = activity_copy.lock() {
            *t = std::time::Instant::now();
        }

        // Phase 15 (Option 1): honeytoken tripwire — loud alert + log, copy proceeds.
        // The alert doubles as the copy confirmation so it isn't clobbered.
        let secs = ct_copy.load(std::sync::atomic::Ordering::SeqCst);
        let copied_msg = match check_canary_trip(
            &vault_arc_copy,
            password_to_copy.as_str(),
            "copy",
        ) {
            Some(title) => {
                format!("🚨 CANARY TRIPPED: '{title}' — copied + ransack logged!")
            }
            None => format!("📋 Password copied! (Masked from Win+V, auto-clearing in {secs}s)"),
        };
        secure_copy_with_feedback(
            ui.as_weak(),
            password_to_copy.as_str().to_string(),
            &copied_msg,
            secs,
        );
        mark_copied(ui.as_weak(), password_to_copy.as_str().to_string(), String::new());
    });

    // Middle-list 1-click copy: resolves the secret by (kind, id) so the row
    // model never carries secrets. Logins honor the master-reprompt gate;
    // 2FA copies the FRESH live code (never a stale list snapshot).
    let qc_weak = main_window.as_weak();
    let qc_vault = Arc::clone(&active_vault);
    let qc_ct = Arc::clone(&clipboard_timeout_secs);
    let qc_activity = Arc::clone(&last_activity);
    main_window.on_quick_copy(move |kind, id| {
        let Some(ui) = qc_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        if let Ok(mut t) = qc_activity.lock() {
            *t = std::time::Instant::now();
        }
        let id = id.as_str().to_string();
        let secs = qc_ct.load(std::sync::atomic::Ordering::SeqCst);
        if kind == 1 {
            // Armed logins detour through the master-reprompt modal first.
            let gated = {
                let v = lock_vault(&qc_vault);
                reprompt_gate(&v, kind, &id)
            };
            if let Some((g_user, g_secret)) = gated {
                ui.set_rp_action(1);
                ui.set_rp_kind(kind);
                ui.set_rp_id(id.into());
                ui.set_rp_user(g_user.into());
                ui.set_rp_secret(g_secret.into());
                ui.set_rp_error(String::new().into());
                ui.set_rp_show(true);
                ui.set_notification_text("🔒 Master re-prompt required.".into());
                return;
            }
        }
        let found: Option<(String, String)> = {
            let v = lock_vault(&qc_vault);
            match kind {
                1 => v.credentials.iter().find(|c| c.id == id)
                    .map(|c| (c.password.clone(), format!("📋 Password copied! (Masked from Win+V, auto-clearing in {secs}s)"))),
                4 => v.cards.iter().find(|k| k.id == id)
                    .map(|k| (k.card_number.clone(), format!("💳 Card number copied! (auto-clearing in {secs}s)"))),
                8 => v.totp_accounts.iter().find(|a| a.id == id).and_then(|a| {
                    crate::totp_engine::generate_code_for_account(a)
                        .map(|(c, _)| (c, format!("⏱️ TOTP code copied! (auto-clearing in {secs}s)")))
                        .ok()
                }),
                _ => None,
            }
        };
        let Some((text, copied_msg)) = found else {
            ui.set_notification_text("⚠️ Quick copy not available for this item.".into());
            return;
        };
        let copied_msg = match check_canary_trip(&qc_vault, text.as_str(), "copy") {
            Some(title) => format!("🚨 CANARY TRIPPED: '{title}' — copied + ransack logged!"),
            None => copied_msg,
        };
        secure_copy_with_feedback(ui.as_weak(), text.clone(), &copied_msg, secs);
        mark_copied(ui.as_weak(), text, id);
    });

    // Website launch: http(s) only (never file://, javascript:, or bare
    // commands) + quoted arg, so a hostile stored URL cannot escape into
    // command execution. Best-effort: failure is a toast, never a panic.
    let window_weak_url = main_window.as_weak();
/// Shared URL launcher (main list + QuickBar): http(s) only, length +
/// control-char guards, access-logged. Pure UI helper — unit-tested shape.
fn launch_url(ui: &MainWindow, url: &str) {
    let target = url.trim().to_string();
    let lower = target.to_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        ui.set_notification_text("⚠️ Only http(s) links can be launched.".into());
        return;
    }
    if target.len() > 2048 || target.chars().any(|c| c.is_control()) {
        ui.set_notification_text("⚠️ Link looks malformed — not launched.".into());
        return;
    }
    match std::process::Command::new("cmd")
        .args(["/C", "start", "", &target])
        .spawn()
    {
        Ok(_) => {
            ui.set_notification_text("↗ Opened in browser.".into());
            security::access_log::log_event("open-url", "website");
        }
        Err(e) => {
            ui.set_notification_text(format!("⚠️ Could not open link: {e}").into());
        }
    }
}

    main_window.on_open_url(move |url| {
        let Some(ui) = window_weak_url.upgrade() else {
            return;
        };
        launch_url(&ui, url.as_str());
    });
    // Moat #3 breach-rotate loop, step 1: per-row Open-site (vault-side
    // rotation already exists via bulk rotate; the site-side change starts
    // here — change it there, then rotate here).
    let health_url_weak = main_window.as_weak();
    let health_url_vault = Arc::clone(&active_vault);
    main_window.on_open_health_url(move |id| {
        let Some(ui) = health_url_weak.upgrade() else {
            return;
        };
        let v = lock_vault(&health_url_vault);
        let url = v
            .credentials
            .iter()
            .find(|c| c.id == id.as_str())
            .map(|c| primary_url(&c.urls));
        match url {
            Some(u) if !u.is_empty() => launch_url(&ui, &u),
            _ => ui.set_notification_text("⚠️ No saved website for this item.".into()),
        }
    });

    // Phase 10: Password & Diceware Generator callbacks
    let gen_weak_regen = main_window.as_weak();
    main_window.on_regenerate(move || {
        let Some(ui) = gen_weak_regen.upgrade() else { return; };
        let result: Option<(String, f64)> = if ui.get_gen_diceware_mode() {
            if ui.get_gen_dice_lang() == 1 {
                let wc = ui.get_gen_word_count().clamp(4, 8) as usize;
                let bits = PasswordGenerator::entropy_bits_diceware_bn(wc);
                PasswordGenerator::generate_diceware_bn(wc, '-')
                    .map(|s| (s.expose_secret().to_owned(), bits))
                    .ok()
            } else {
                let wc = ui.get_gen_word_count().clamp(4, 12) as usize;
                let bits = PasswordGenerator::entropy_bits_diceware(wc);
                PasswordGenerator::generate_diceware(wc, '-')
                    .map(|s| (s.expose_secret().to_owned(), bits))
                    .ok()
            }
        } else {
            let policy = PasswordPolicy {
                length: ui.get_gen_length().clamp(8, 128) as usize,
                uppercase: ui.get_gen_uppercase(),
                lowercase: ui.get_gen_lowercase(),
                digits: ui.get_gen_digits(),
                symbols: ui.get_gen_symbols(),
                exclude_ambiguous: ui.get_gen_exclude_ambiguous(),
            };
            let bits = PasswordGenerator::entropy_bits_complex(&policy);
            PasswordGenerator::generate_complex(&policy)
                .map(|s| (s.expose_secret().to_owned(), bits))
                .ok()
        };
        match result {
            Some((plain, bits)) => {
                ui.set_gen_output(plain.into());
                ui.set_gen_entropy_bits(bits as f32);
            }
            None => {
                ui.set_gen_output("⚠ Invalid parameters".into());
                ui.set_gen_entropy_bits(0.0);
            }
        }
    });

    let gen_weak_use = main_window.as_weak();
    let ct_gen = Arc::clone(&clipboard_timeout_secs);
    main_window.on_use_password(move |generated| {
        let Some(ui) = gen_weak_use.upgrade() else { return; };
        let pwd = generated.as_str();
        if pwd.is_empty() || pwd.starts_with('⚠') {
            return;
        }
        if ui.get_show_add_form() {
            // Login form open: fill its password field
            ui.set_new_kind(1);
            ui.set_f_b(pwd.into());
            ui.set_notification_text("✅ Generated password filled into form!".into());
        } else {
            // Standalone use: masked copy with guarded auto-clear
            let secs = ct_gen.load(std::sync::atomic::Ordering::SeqCst);
            secure_copy_with_feedback(
                ui.as_weak(),
                pwd.to_string(),
                &format!("📋 Generated password copied! (Masked from Win+V, auto-clearing in {secs}s)"),
                secs,
            );
        }
        ui.set_gen_output("".into());
        ui.set_gen_entropy_bits(0.0);
        ui.set_show_generator(false);
    });

    let gen_weak_close = main_window.as_weak();
    main_window.on_close_panel(move || {
        if let Some(ui) = gen_weak_close.upgrade() {
            ui.set_gen_output("".into());
            ui.set_gen_entropy_bits(0.0);
            ui.set_show_generator(false);
        }
    });

    // Phase 12: save repo + DPAPI-sealed token (token field cleared after save)
    let sync_weak_save = main_window.as_weak();
    main_window.on_save_sync_config(move |owner, repo, token| {
        let Some(ui) = sync_weak_save.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_sync_status("⛔ Decoy mode is read-only.".into());
            return;
        }
        let owner = owner.as_str().trim().to_string();
        let repo = repo.as_str().trim().to_string();
        let token_in = token.as_str().trim().to_string();
        if owner.is_empty() || repo.is_empty() {
            ui.set_sync_status("⚠️ Owner and repo are required.".into());
            return;
        }
        if let Err(e) = sync::github_sync::save_repo(&owner, &repo) {
            ui.set_sync_status(format!("⚠️ {e}").into());
            return;
        }
        if !token_in.is_empty() {
            if let Err(e) = sync::github_sync::store_token(&token_in) {
                ui.set_sync_status(format!("⚠️ {e}").into());
                return;
            }
        } else if !sync::github_sync::is_configured() {
            ui.set_sync_status("⚠️ Paste a token once — it is DPAPI-sealed on save.".into());
            return;
        }
        ui.set_sync_token_input("".into());
        // Presence only — the URL itself may embed proxy credentials.
        let via = if sync::github_sync::effective_proxy().is_some() {
            " (ciphertext only, via proxy)."
        } else {
            " (ciphertext only, direct)."
        };
        ui.set_sync_status(format!("✅ Connected to {owner}/{repo}{via}").into());
        trigger_sync_push(ui.as_weak());
    });

    // Phase 12: manual sync now (push local head)
    let sync_weak_now = main_window.as_weak();
    main_window.on_sync_now(move || {
        let Some(ui) = sync_weak_now.upgrade() else {
            return;
        };
        ui.set_sync_status("⏳ Syncing…".into());
        trigger_sync_push(ui.as_weak());
    });

    // Local Wi-Fi P2P sync (offline LAN): toggle, scan, per-peer sync.
    // Listener + beacon + responder threads are detached; the shared stop
    // flag retires them on toggle-off (re-enable flips it back + respawns).
    let p2p_stop = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let p2p_weak = main_window.as_weak();
    main_window.on_set_p2p(move |on| {
        let Some(ui) = p2p_weak.upgrade() else {
            return;
        };
        ui.set_p2p_enabled(on);
        if on {
            p2p_stop.store(false, std::sync::atomic::Ordering::SeqCst);
            for runner in [
                sync::p2p_local::run_listener as fn(Arc<std::sync::atomic::AtomicBool>),
                sync::p2p_local::run_beacon,
                sync::p2p_local::run_discover_responder,
            ] {
                let stop = Arc::clone(&p2p_stop);
                std::thread::spawn(move || runner(stop));
            }
            // Pairing PIN is created lazily and shown for cross-device entry.
            match sync::p2p_local::get_or_create_pin() {
                Ok(pin) => ui.set_p2p_pin(pin.into()),
                Err(e) => ui.set_p2p_status(format!("⚠️ PIN unavailable: {e}").into()),
            }
            ui.set_p2p_status("📡 Discovery ON — port 52199. Scan to find peers.".into());
            security::access_log::log_event("p2p", "discovery enabled");
        } else {
            p2p_stop.store(true, std::sync::atomic::Ordering::SeqCst);
            ui.set_p2p_peers(ModelRc::new(VecModel::from(Vec::<PeerView>::new())));
            ui.set_p2p_status("P2P discovery is OFF — enable to find LAN devices.".into());
            security::access_log::log_event("p2p", "discovery disabled");
        }
    });
    let scan_weak = main_window.as_weak();
    main_window.on_scan_p2p(move || {
        let Some(ui) = scan_weak.upgrade() else {
            return;
        };
        if !ui.get_p2p_enabled() {
            ui.set_p2p_status("⚠️ Enable discovery first.".into());
            return;
        }
        ui.set_p2p_status("🔍 Scanning LAN…".into());
        let weak = scan_weak.clone();
        std::thread::spawn(move || {
            let peers = sync::p2p_local::scan_peers(Duration::from_secs(4));
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                let rows: Vec<PeerView> = peers
                    .iter()
                    .map(|p| PeerView {
                        name: p.name.clone().into(),
                        ip: p.ip.clone().into(),
                        detail: format!("v{} • {}{}", p.version, p.head_sha.chars().take(8).collect::<String>(), if p.pin_required { " • 🔒 PIN" } else { "" }).into(),
                    })
                    .collect();
                ui.set_p2p_peers(ModelRc::new(VecModel::from(rows)));
                ui.set_p2p_status(if peers.is_empty() {
                    "No peers found — same Wi-Fi? Discovery ON on both?".into()
                } else {
                    format!("Found {} peer(s).", peers.len()).into()
                });
            });
        });
    });
    let regen_weak = main_window.as_weak();
    main_window.on_regen_p2p_pin(move || {
        let Some(ui) = regen_weak.upgrade() else {
            return;
        };
        match sync::p2p_local::regenerate_pin() {
            Ok(pin) => {
                ui.set_p2p_pin(pin.into());
                ui.set_p2p_status("🔑 New pairing PIN — re-pair your devices.".into());
                security::access_log::log_event("p2p", "pin regenerated");
            }
            Err(e) => ui.set_p2p_status(format!("⚠️ PIN regen failed: {e}").into()),
        }
    });
    let syncpeer_weak = main_window.as_weak();
    let syncpeer_vault = Arc::clone(&active_vault);
    let syncpeer_master = Arc::clone(&active_master_pw);
    let syncpeer_search = Arc::clone(&search_state);
    let syncpeer_qb = quick_bar.as_weak();
    main_window.on_sync_peer(move |ip, pin| {
        let Some(ui) = syncpeer_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_p2p_status("⛔ Decoy mode is read-only.".into());
            return;
        }
        ui.set_p2p_status(format!("⏳ Syncing with {ip}…").into());
        let weak = syncpeer_weak.clone();
        let vault_clone = Arc::clone(&syncpeer_vault);
        let master_clone = Arc::clone(&syncpeer_master);
        let search_clone = Arc::clone(&syncpeer_search);
        let qb_clone = syncpeer_qb.clone();
        let target = ip.as_str().to_string();
        let pin = pin.as_str().trim().to_string();
        std::thread::spawn(move || {
            let mut adopt = |blob: Vec<u8>| {
                crate::security::shredder::secure_write(
                    std::path::Path::new(VAULT_FILE),
                    &blob,
                )
                .map_err(|e| e.to_string())
            };
            let outcome = sync::p2p_local::sync_with_peer(&target, &pin, &mut adopt);
            // Adopted a remote head → reload memory + repaint everywhere.
            let reloaded: Option<Vault> = match &outcome {
                Ok(msg) if msg.contains("adopted") => {
                    let master_opt = lock_master_pw(&master_clone).clone();
                    master_opt.and_then(|master_pw| {
                        crate::storage::load_vault_versioned_secret(&master_pw, VAULT_FILE)
                            .ok()
                            .map(|(v, _)| {
                                *lock_vault(&vault_clone) = v.clone();
                                v
                            })
                    })
                }
                _ => None,
            };
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match outcome {
                    Ok(msg) => {
                        if let Some(v) = reloaded {
                            let f = search_clone.lock().unwrap().clone();
                            set_paged_credentials(&ui, vault_to_items(&v, &f));
                            sync_folders_to_ui(&v, &ui);
                            ui.set_d_id(String::new().into());
                            trigger_sync_push(ui.as_weak());
                        }
                        if let Some(qb) = qb_clone.upgrade() {
                            let vv = lock_vault(&vault_clone);
                            qb.set_filtered_results(vault_quickbar(&vv, "", search_clone.lock().unwrap().travel_only));
                        }
                        ui.set_p2p_status(msg.into());
                        let now_s = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        ui.set_p2p_last_sync(
                            format!("{ip} · {:02}:{:02} UTC", (now_s / 3600) % 24, (now_s / 60) % 60).into(),
                        );
                        ui.set_notification_text("📡 LAN sync complete.".into());
                    }
                    Err(e) => ui.set_p2p_status(e.into()),
                }
            });
        });
    });

    // GitHub Releases auto-updater: check → stage → restart-to-apply.
    let upd_weak = main_window.as_weak();
    let upd_info: Arc<Mutex<Option<sync::updater::ReleaseInfo>>> = Arc::new(Mutex::new(None));
    let upd_bat: Arc<Mutex<Option<std::path::PathBuf>>> = Arc::new(Mutex::new(None));
    let upd_info0 = Arc::clone(&upd_info);
    main_window.on_check_updates(move || {
        let Some(ui) = upd_weak.upgrade() else {
            return;
        };
        ui.set_update_status("⏳ Checking GitHub releases…".into());
        let weak = upd_weak.clone();
        let info_arc = Arc::clone(&upd_info0);
        std::thread::spawn(move || {
            let res = sync::updater::check_latest();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match res {
                    Err(e) => ui.set_update_status(format!("⚠️ Update check failed: {e}").into()),
                    Ok(None) => {
                        ui.set_update_tag(String::new().into());
                        ui.set_update_ready(false);
                        ui.set_update_notes(String::new().into());
                        ui.set_show_changelog(false);
                        ui.set_update_status(format!("✅ Already on latest (v{}).", env!("CARGO_PKG_VERSION")).into());
                    }
                    Ok(Some(info)) => {
                        ui.set_update_tag(info.tag.clone().into());
                        ui.set_update_ready(false);
                        ui.set_update_notes(if info.notes.trim().is_empty() {
                            "No release notes shipped with this version.".into()
                        } else {
                            info.notes.clone().into()
                        });
                        ui.set_update_status(
                            format!("🎉 {} available — {} ({} bytes). Download, then restart.", info.tag, info.asset_name, info.asset_size).into(),
                        );
                        if let Ok(mut g) = info_arc.lock() {
                            *g = Some(info);
                        }
                    }
                }
            });
        });
    });
    let dl_weak = main_window.as_weak();
    let dl_info = Arc::clone(&upd_info);
    let dl_bat = Arc::clone(&upd_bat);
    main_window.on_download_update(move || {
        let Some(ui) = dl_weak.upgrade() else {
            return;
        };
        let info = dl_info.lock().ok().and_then(|g| g.clone());
        let Some(info) = info else {
            ui.set_update_status("⚠️ Check for updates first.".into());
            return;
        };
        ui.set_update_status(format!("⏳ Downloading {}…", info.asset_name).into());
        let weak = dl_weak.clone();
        let bat_arc = Arc::clone(&dl_bat);
        std::thread::spawn(move || {
            let res: Result<std::path::PathBuf, String> = (|| {
                let staged = sync::updater::download_asset(&info).map_err(|e| e.to_string())?;
                sync::updater::stage_swap_script(&staged, &info.tag).map_err(|e| e.to_string())
            })();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match res {
                    Err(e) => ui.set_update_status(format!("⚠️ Update failed: {e}").into()),
                    Ok(bat) => {
                        if let Ok(mut g) = bat_arc.lock() {
                            *g = Some(bat);
                        }
                        ui.set_update_ready(true);
                        ui.set_update_status("✅ Staged! Click “Restart to Update” — the app swaps itself after exit.".into());
                        security::access_log::log_event("update", &format!("staged {}", info.tag));
                    }
                }
            });
        });
    });
    let rt_weak = main_window.as_weak();
    let rt_bat = Arc::clone(&upd_bat);
    main_window.on_restart_update(move || {
        let bat = rt_bat.lock().ok().and_then(|g| g.clone());
        let Some(bat) = bat else {
            if let Some(ui) = rt_weak.upgrade() {
                ui.set_update_status("⚠️ Download an update first.".into());
            }
            return;
        };
        security::access_log::log_event("update", "restart-to-apply");
        // Detached console-less launch, then exit so the script can swap us.
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", "/MIN", &bat.to_string_lossy()])
            .spawn();
        std::process::exit(0);
    });

    // Batch-4: registry-install the browser native host (HKCU, both browsers).
    let host_weak = main_window.as_weak();
    main_window.on_install_browser_host(move |ext_id| {
        let Some(ui) = host_weak.upgrade() else {
            return;
        };
        let id = ext_id.as_str().trim().to_string();
        // L5: Chrome/Edge/Brave IDs are 32 lowercase chars — reject
        // `*`/short/prefixed paste before it becomes a wildcard manifest.
        if !(id.len() == 32 && id.bytes().all(|b| b.is_ascii_lowercase())) {
            ui.set_bridge_status("⚠️ Extension ID must be 32 lowercase letters (chrome://extensions → Developer mode).".into());
            return;
        }
        let origin = format!("chrome-extension://{id}/");
        ui.set_bridge_status("⏳ Installing browser extension host…".into());
        let weak = host_weak.clone();
        std::thread::spawn(move || {
            // Registry writes are milliseconds; kept off-thread for uniformity.
            let res = windows_native::native_host::register_native_host(&origin);
            if res.is_ok() {
                security::access_log::log_event("bridge", "host installed");
            }
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    ui.set_bridge_status(match res {
                        Ok(path) => format!("🌐 Host installed → {path} (locked to {origin}). Reload the extension and retry.").into(),
                        Err(e) => format!("⚠️ Host install failed: {e}").into(),
                    });
                }
            });
        });
    });

    // Firefox bridge: pinned add-on ID (manifest.firefox.json gecko.id) —
    // nothing to paste, nothing to validate beyond the pin itself.
    let ffhost_weak = main_window.as_weak();
    main_window.on_install_firefox_host(move || {
        let Some(ui) = ffhost_weak.upgrade() else {
            return;
        };
        ui.set_bridge_status("🦊 Installing Firefox extension host…".into());
        let weak = ffhost_weak.clone();
        std::thread::spawn(move || {
            let res = windows_native::native_host::register_firefox_host(
                windows_native::native_host::FIREFOX_ADDON_ID,
            );
            if res.is_ok() {
                security::access_log::log_event("bridge", "firefox host installed");
            }
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    ui.set_bridge_status(match res {
                        Ok(path) => format!("✅ Firefox host installed — {path} (locked to {}). Load dist/firefox/ via about:debugging.", windows_native::native_host::FIREFOX_ADDON_ID).into(),
                        Err(e) => format!("⚠️ Firefox host install failed: {e}").into(),
                    });
                }
            });
        });
    });

    // Batch-4: privacy alias config (DPAPI-sealed token) + one-click generation.
    let alias_weak = main_window.as_weak();
    main_window.on_save_alias_config(move |provider_int, domain, token| {
        let Some(ui) = alias_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        // Synchronous: one DPAPI seal + two tiny file writes.
        match core::email_alias::save_config(
            core::email_alias::Provider::from_i32(provider_int),
            domain.as_str(),
            token.as_str(),
        ) {
            Ok(()) => {
                ui.set_alias_provider(provider_int);
                ui.set_alias_domain(domain.as_str().into());
                ui.set_alias_token("".into());
                ui.set_notification_text("🎭 Alias provider saved (token sealed).".into());
                security::access_log::log_event("alias", "config saved");
            }
            Err(e) => {
                ui.set_notification_text(format!("⚠️ Alias save failed: {e}").into());
            }
        }
    });

    let alias_gen_weak = main_window.as_weak();
    main_window.on_generate_alias_for_form(move || {
        let Some(ui) = alias_gen_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        ui.set_notification_text("🎭 Requesting alias…".into());
        let weak = alias_gen_weak.clone();
        std::thread::spawn(move || {
            let (provider, domain, token) = match core::email_alias::load_config() {
                Ok(c) => c,
                Err(e) => {
                    let msg = format!("⚠️ Alias not configured: {e}");
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_notification_text(msg.into());
                        }
                    });
                    return;
                }
            };
            let Some(rt) = tokio_rt() else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_notification_text("⚠️ Could not start network runtime.".into());
                    }
                });
                return;
            };
            let base = match provider {
                core::email_alias::Provider::AddyIo => "https://app.addy.io",
                core::email_alias::Provider::SimpleLogin => "https://app.simplelogin.io",
            };
            let client = reqwest::Client::new();
            let res = rt.block_on(core::email_alias::create_alias(
                &client,
                provider,
                base,
                &token,
                &domain,
                "phantom-vault",
            ));
            {
                use zeroize::Zeroize;
                let mut t = token;
                t.zeroize();
            }
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    match res {
                        Ok(email) => {
                            ui.set_f_a(email.into());
                            ui.set_notification_text("🎭 Alias generated into username.".into());
                            security::access_log::log_event("alias", "generated");
                        }
                        Err(e) => {
                            ui.set_notification_text(format!("⚠️ Alias failed: {e}").into());
                        }
                    }
                }
            });
        });
    });

    // Phase 15 (Option 1): duress provisioning + canary planting.
    let paranoia_weak = main_window.as_weak();
    main_window.on_set_duress_password(move |duress| {
        let Some(ui) = paranoia_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_sync_status("⛔ Decoy mode is read-only.".into());
            return;
        }
        match security::decoy::provision_decoy(duress.as_str()) {
            Ok(()) => ui.set_sync_status(
                "🕊️ Decoy vault provisioned. Memorize the duress password separately.".into(),
            ),
            Err(e) => ui.set_sync_status(format!("⚠️ {e}").into()),
        }
        // The duress password must not linger in UI-layer RAM afterwards.
        ui.set_duress_input(String::new().into());
    });

    let plant_weak = main_window.as_weak();
    let plant_vault = Arc::clone(&active_vault);
    let plant_master = Arc::clone(&active_master_pw);
    let plant_search = Arc::clone(&search_state);
    let plant_qb = quick_bar.as_weak();
    main_window.on_plant_canary(move || {
        let Some(ui) = plant_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_sync_status("⛔ Decoy mode is read-only.".into());
            return;
        }
        let master_opt = lock_master_pw(&plant_master).clone();
        let Some(master_pw) = master_opt else {
            ui.set_sync_status("⚠️ Vault not unlocked.".into());
            return;
        };
        let weak = plant_weak.clone();
        let search_clone = Arc::clone(&plant_search);
        let qb_clone = plant_qb.clone();
        let vault_clone = Arc::clone(&plant_vault);
        std::thread::spawn(move || {
            // Plant + persist under ONE lock scope with a snapshot: a disk
            // failure restores the exact prior vault (no pop() guessing).
            let (title, saved): (String, Result<(), String>) = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                let title = security::canary::plant_canary(&mut vault);
                match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                    Ok(()) => (title, Ok(())),
                    Err(e) => {
                        *vault = snapshot;
                        (title, Err(e))
                    }
                }
            };
            let saved_ok = saved.is_ok();
            let canaries = lock_vault(&vault_clone)
                .credentials
                .iter()
                .filter(|c| security::canary::is_canary(c))
                .count() as i32;
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    if saved_ok {
                        ui.set_canary_count(canaries);
                        let vault = lock_vault(&vault_clone);
                        let f = search_clone.lock().unwrap().clone();
                        let items = vault_to_items(&vault, &f);
                        ui.set_credentials(items.clone());
                        ui.set_total_matches_count(total_matches() as i32);
                        if let Some(qb) = qb_clone.upgrade() {
                            qb.set_filtered_results(vault_quickbar(&vault, "", search_clone.lock().unwrap().travel_only));
                        }
                        ui.set_sync_status(
                            format!("🐤 Honeytoken '{title}' planted — never touch it yourself.").into(),
                        );
                    } else {
                        ui.set_sync_status("⚠️ Canary save failed.".into());
                    }
                }
            });
        });
    });

    // Resident passkeys: register / delete / copy-pub, all re-sealed to disk.
    let pk_reg_weak = main_window.as_weak();
    let pk_reg_vault = Arc::clone(&active_vault);
    let pk_reg_master = Arc::clone(&active_master_pw);
    main_window.on_register_passkey(move |rp, user| {
        let Some(ui) = pk_reg_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let rp_id = rp.as_str().trim().to_lowercase();
        let user_name = user.as_str().trim().to_string();
        if rp_id.is_empty() || user_name.is_empty() {
            ui.set_notification_text("⚠️ Relying party + username required.".into());
            return;
        }
        if rp_id.contains(char::is_whitespace) || !rp_id.contains('.') {
            ui.set_notification_text("⚠️ rp_id must look like a domain (e.g. github.com).".into());
            return;
        }
        let master_opt = lock_master_pw(&pk_reg_master).clone();
        let Some(master_pw) = master_opt else {
            ui.set_notification_text("❌ Vault not unlocked!".into());
            return;
        };
        ui.set_notification_text("⏳ Generating Ed25519 passkey…".into());
        let weak = pk_reg_weak.clone();
        let vault_clone = Arc::clone(&pk_reg_vault);
        std::thread::spawn(move || {
            let item = core::passkey::register(&rp_id, &user_name, models::current_timestamp());
            let title = format!("{} / {}", item.rp_id, item.user_name);
            let saved = {
                let mut vault = lock_vault(&vault_clone);
                vault.passkeys.push(item);
                match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                    Ok(()) => Ok(vault.clone()),
                    Err(e) => {
                        vault.passkeys.pop();
                        Err(e)
                    }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match saved {
                    Ok(v) => {
                        ui.set_passkeys(rebuild_passkeys(&v, ui.get_show_fav_only()));
                        ui.set_passkeys_trash(rebuild_trashed_passkeys(&v));
                        ui.set_pk_rp("".into());
                        ui.set_pk_user("".into());
                        ui.set_notification_text(
                            format!("🔑 Passkey registered for '{title}'.").into(),
                        );
                        security::access_log::log_event("passkey", "register");
                    }
                    Err(e) => {
                        ui.set_notification_text(format!("❌ Register failed: {e}").into());
                    }
                }
            });
        });
    });

    let pk_del_weak = main_window.as_weak();
    let pk_del_vault = Arc::clone(&active_vault);
    let pk_del_master = Arc::clone(&active_master_pw);
    let pk_del_search = Arc::clone(&search_state);
    main_window.on_delete_passkey(move |id| {
        let Some(ui) = pk_del_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let master_opt = lock_master_pw(&pk_del_master).clone();
        let Some(master_pw) = master_opt else {
            ui.set_notification_text("❌ Vault not unlocked!".into());
            return;
        };
        let weak = pk_del_weak.clone();
        let vault_clone = Arc::clone(&pk_del_vault);
        let search_clone = Arc::clone(&pk_del_search);
        let target = id.as_str().to_string();
        std::thread::spawn(move || {
            // Two-phase delete like the other 6 kinds: active → Trash stamp,
            // Trash → permanent shred. Disk failure rolls RAM back.
            let saved: Result<(Vault, bool), String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                let already = vault.is_trashed(7, &target).unwrap_or(false);
                let ok = if already {
                    vault.delete_item(7, &target)
                } else {
                    vault.trash_item(7, &target, crate::models::current_timestamp())
                };
                if !ok {
                    Err("passkey not found".to_string())
                } else {
                    match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                        Ok(()) => Ok((vault.clone(), already)),
                        Err(e) => {
                            *vault = snapshot;
                            Err(e)
                        }
                    }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match saved {
                    Ok((v, permanent)) => {
                        let f = search_clone.lock().unwrap().clone();
                        ui.set_passkeys(rebuild_passkeys(&v, f.fav_only));
                        ui.set_passkeys_trash(rebuild_trashed_passkeys(&v));
                        set_trash_label(&ui, &v);
                        if permanent {
                            ui.set_notification_text("🔥 Passkey permanently shredded.".into());
                            security::access_log::log_event("passkey", "delete");
                        } else {
                            ui.set_notification_text(
                                "🗑️ Passkey moved to Trash (restorable 30 days).".into(),
                            );
                            security::access_log::log_event("passkey", "trash");
                        }
                        trigger_sync_push(ui.as_weak());
                    }
                    Err(e) => {
                        ui.set_notification_text(format!("⚠️ {e}.").into());
                    }
                }
            });
        });
    });

    // 2FA Hub: delete one authenticator account by id, re-seal, refresh.
    let auth_del_weak = main_window.as_weak();
    let auth_del_vault = Arc::clone(&active_vault);
    let auth_del_master = Arc::clone(&active_master_pw);
    let auth_del_search = Arc::clone(&search_state);
    main_window.on_delete_auth_account(move |id| {
        let Some(ui) = auth_del_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let master_opt = lock_master_pw(&auth_del_master).clone();
        let Some(master_pw) = master_opt else {
            ui.set_notification_text("❌ Vault not unlocked!".into());
            return;
        };
        let weak = auth_del_weak.clone();
        let vault_clone = Arc::clone(&auth_del_vault);
        let search_clone = Arc::clone(&auth_del_search);
        let target = id.as_str().to_string();
        std::thread::spawn(move || {
            // Roll back the in-memory removal if the disk re-seal fails.
            let saved = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                if !remove_totp_account(&mut vault, &target) {
                    Err("authenticator account not found".to_string())
                } else {
                    match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                        Ok(()) => Ok(vault.clone()),
                        Err(e) => {
                            *vault = snapshot;
                            Err(e)
                        }
                    }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match saved {
                    Ok(v) => {
                        ui.set_auth_accounts(rebuild_auth_list(&v));
                        ui.set_auth_rows(rebuild_auth_rows(&v, ui.get_totp_search_query().as_str()));
                        // Standalone 2FA also lives in All items / Favorites.
                        let f = search_clone.lock().unwrap().clone();
                        set_paged_credentials(&ui, vault_to_items(&v, &f));
                        // Hero ticker rebuilds from the vault every second,
                        // so it drops the deleted account on its next tick.
                        ui.set_notification_text(
                            "✅ Authenticator account deleted.".into(),
                        );
                        security::access_log::log_event("auth", "delete");
                        trigger_sync_push(ui.as_weak());
                    }
                    Err(e) => {
                        ui.set_notification_text(format!("⚠️ {e}.").into());
                    }
                }
            });
        });
    });

    // Zero-lockin: GA reverse-export QR pages + full-vault file export.
    // GA pages live in memory only (URIs hold raw secrets — never logged).
    let ga_weak = main_window.as_weak();
    let ga_vault = Arc::clone(&active_vault);
    let ga_pages: Arc<Mutex<Vec<GaPage>>> = Arc::new(Mutex::new(Vec::new()));
    let ga_idx: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    let ga_pages0 = Arc::clone(&ga_pages);
    let ga_idx0 = Arc::clone(&ga_idx);
    main_window.on_ga_export_start(move || {
        let Some(ui) = ga_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let accounts = lock_vault(&ga_vault).totp_accounts.clone();
        if accounts.is_empty() {
            ui.set_notification_text("⚠️ No 2FA accounts to export.".into());
            return;
        }
        ui.set_notification_text("⏳ Building migration QR…".into());
        let weak = ga_weak.clone();
        let pages_arc = Arc::clone(&ga_pages0);
        let idx_arc = Arc::clone(&ga_idx0);
        std::thread::spawn(move || {
            let capped = accounts.len().saturating_sub(100);
            let first: Vec<_> = accounts.into_iter().take(100).collect();
            let built = authenticator::google_migration::build_migration_uris(&first);
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match built {
                    Err(e) => ui.set_notification_text(format!("⚠️ GA export: {e}").into()),
                    Ok((uris, skipped, lossy)) => {
                        let mut pages = Vec::new();
                        let mut failed = 0usize;
                        for uri in uris {
                            match authenticator::google_migration::render_migration_qr_png(&uri) {
                                Ok(png) => pages.push(GaPage { uri, png }),
                                Err(_) => failed += 1,
                            }
                        }
                        if pages.is_empty() {
                            ui.set_notification_text("⚠️ GA export: QR render failed.".into());
                            return;
                        }
                        let mut skipped_all = skipped;
                        if failed > 0 {
                            skipped_all.push(format!("{failed} QR render failures"));
                        }
                        ui.set_ga_warn(ga_warn_text(&skipped_all, &lossy, capped).into());
                        if let Ok(mut g) = pages_arc.lock() {
                            *g = pages;
                        }
                        if let Ok(mut i) = idx_arc.lock() {
                            *i = 0;
                        }
                        if let Ok(g) = pages_arc.lock() {
                            ga_show_page(&ui, &g, 0);
                        }
                        security::access_log::log_event("export", "ga-qr");
                        ui.set_notification_text("📲 Scan the QR with Google Authenticator.".into());
                    }
                }
            });
        });
    });
    let ga_page_weak = main_window.as_weak();
    let ga_page_arc = Arc::clone(&ga_pages);
    let ga_page_idx = Arc::clone(&ga_idx);
    main_window.on_ga_export_page(move |delta| {
        let Some(ui) = ga_page_weak.upgrade() else {
            return;
        };
        let next = {
            let (len, cur) = (
                ga_page_arc.lock().ok().map(|g| g.len()).unwrap_or(0),
                ga_page_idx.lock().ok().map(|g| *g).unwrap_or(0),
            );
            if len == 0 {
                return;
            }
            (cur as i32 + delta).clamp(0, len as i32 - 1) as usize
        };
        if let Ok(mut i) = ga_page_idx.lock() {
            *i = next;
        }
        if let Ok(g) = ga_page_arc.lock() {
            ga_show_page(&ui, &g, next);
        }
    });
    let ga_copy_weak = main_window.as_weak();
    let ga_copy_arc = Arc::clone(&ga_pages);
    let ga_copy_idx = Arc::clone(&ga_idx);
    let ga_copy_ct = Arc::clone(&clipboard_timeout_secs);
    main_window.on_ga_copy_uri(move || {
        let uri = ga_copy_arc
            .lock()
            .ok()
            .and_then(|g| {
                let i = ga_copy_idx.lock().ok().map(|g| *g).unwrap_or(0);
                g.get(i).map(|p| p.uri.clone())
            })
            .unwrap_or_default();
        if uri.is_empty() {
            return;
        }
        let secs = ga_copy_ct.load(std::sync::atomic::Ordering::SeqCst);
        secure_copy_with_feedback(
            ga_copy_weak.clone(),
            uri,
            &format!("📋 Migration URI copied! Secrets on clipboard — auto-clearing in {secs}s."),
            secs,
        );
    });
    // Full-vault file export: master-gated via the reprompt modal (action 4).
    let exp_weak = main_window.as_weak();
    main_window.on_export_vault(move |fmt| {
        let Some(ui) = exp_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        ui.set_rp_action(5);
        ui.set_rp_export_fmt(fmt);
        ui.set_rp_error(String::new().into());
        ui.set_rp_show(true);
        ui.set_notification_text("🔒 Confirm master password — export writes PLAINTEXT to disk.".into());
    });

    // Hub trash section: restore one trashed passkey + re-seal.
    let pk_res_weak = main_window.as_weak();
    let pk_res_vault = Arc::clone(&active_vault);
    let pk_res_master = Arc::clone(&active_master_pw);
    let pk_res_search = Arc::clone(&search_state);
    main_window.on_restore_passkey(move |id| {
        let Some(ui) = pk_res_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let weak = pk_res_weak.clone();
        let vault_clone = Arc::clone(&pk_res_vault);
        let master_clone = Arc::clone(&pk_res_master);
        let search_clone = Arc::clone(&pk_res_search);
        let target = id.as_str().to_string();
        std::thread::spawn(move || {
            let master_opt = lock_master_pw(&master_clone).clone();
            let Some(master_pw) = master_opt else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_notification_text("❌ Vault not unlocked!".into());
                    }
                });
                return;
            };
            let saved: Result<Vault, String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                if !vault.restore_item(7, &target) {
                    Err("passkey is not in Trash (already active?)".to_string())
                } else {
                    match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                        Ok(()) => Ok(vault.clone()),
                        Err(e) => {
                            *vault = snapshot;
                            Err(e)
                        }
                    }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match saved {
                    Ok(v) => {
                        let f = search_clone.lock().unwrap().clone();
                        ui.set_passkeys(rebuild_passkeys(&v, f.fav_only));
                        ui.set_passkeys_trash(rebuild_trashed_passkeys(&v));
                        set_trash_label(&ui, &v);
                        ui.set_notification_text("♻️ Passkey restored to the hub.".into());
                        security::access_log::log_event("passkey", "restore");
                        trigger_sync_push(ui.as_weak());
                    }
                    Err(e) => {
                        ui.set_notification_text(format!("⚠️ {e}.").into());
                    }
                }
            });
        });
    });

    // Hub ⭐ toggle: flip, re-seal, refresh (same pattern as item favorites).
    let pk_fav_weak = main_window.as_weak();
    let pk_fav_vault = Arc::clone(&active_vault);
    let pk_fav_master = Arc::clone(&active_master_pw);
    let pk_fav_search = Arc::clone(&search_state);
    main_window.on_toggle_passkey_fav(move |id| {
        let Some(ui) = pk_fav_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let master_opt = lock_master_pw(&pk_fav_master).clone();
        let Some(master_pw) = master_opt else {
            ui.set_notification_text("❌ Vault not unlocked!".into());
            return;
        };
        let weak = pk_fav_weak.clone();
        let vault_clone = Arc::clone(&pk_fav_vault);
        let search_clone = Arc::clone(&pk_fav_search);
        let target = id.as_str().to_string();
        std::thread::spawn(move || {
            let flipped: Option<bool> = (|| {
                let mut vault = lock_vault(&vault_clone);
                let state = match fav_flag_mut(&mut vault, 7, &target) {
                    Some(f) => {
                        *f = !*f;
                        *f
                    }
                    None => return None,
                };
                if save_vault_secret(&vault, &master_pw, VAULT_FILE).is_err() {
                    if let Some(f) = fav_flag_mut(&mut vault, 7, &target) {
                        *f = !*f; // roll back the flip on disk failure
                    }
                    return None;
                }
                Some(state)
            })();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                let f = search_clone.lock().unwrap().clone();
                let v = lock_vault(&vault_clone);
                ui.set_passkeys(rebuild_passkeys(&v, f.fav_only));
                ui.set_notification_text(match flipped {
                    Some(true) => "⭐ Passkey pinned to Favorites.".into(),
                    Some(false) => "☆ Passkey unpinned.".into(),
                    None => "⚠️ Toggle failed (missing passkey or save error).".into(),
                });
            });
        });
    });

    // Hub ⭐ toggle for standalone 2FA: flip, re-seal, refresh hub + list,
    // then push ciphertext to GitHub (same pattern as item favorites).
    let totp_fav_weak = main_window.as_weak();
    let totp_fav_vault = Arc::clone(&active_vault);
    let totp_fav_master = Arc::clone(&active_master_pw);
    let totp_fav_search = Arc::clone(&search_state);
    // ---- Phase 28: copy guard, reveal toggle, manual clock offset, dedup ----
    //
    // Copy takes an ACCOUNT ID, never a code string. The grid refreshes once a
    // second, so a value rendered on screen can already be a window old by the
    // time the user clicks it; regenerating at click time is the only way the
    // clipboard can be guaranteed to hold a live code.
    let totp_copy_ui = main_window.as_weak();
    let totp_copy_vault = Arc::clone(&active_vault);
    let totp_copy_ct = Arc::clone(&clipboard_timeout_secs);
    main_window.on_copy_totp_requested(move |id| {
        let Some(ui) = totp_copy_ui.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let target = id.as_str().to_string();
        let weak = totp_copy_ui.clone();
        let vault_clone = Arc::clone(&totp_copy_vault);
        let ct_totp = Arc::clone(&totp_copy_ct);
        std::thread::spawn(move || {
            let fresh = {
                let vault = lock_vault(&vault_clone);
                vault
                    .totp_accounts
                    .iter()
                    .find(|a| a.id == target)
                    .and_then(|a| {
                        totp_engine::generate_code_for_account(a)
                            .ok()
                    })
            };
            let Some((code, remaining)) = fresh else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_notification_text("⚠️ Could not generate a code for that card.".into());
                    }
                });
                return;
            };
            // The boundary guard. A code with <=3s left will have expired in the
            // app the user is pasting into before they finish typing their
            // password, and a rejected code reads as "this vault is broken".
            // HOTP is exempt: it has no clock, `remaining` is u64::MAX, and it
            // stays valid until the counter advances.
            if remaining != u64::MAX && remaining <= TOTP_COPY_GUARD_SECS {
                let secs = remaining;
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_notification_text(format!(
                            "⏳ Only {secs}s left — that code expires mid-typing. Try again next window."
                        ).into());
                    }
                });
                return;
            }
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    // Same sanitise + auto-clear + access-log path every other
                    // copy in the app uses. It logs THAT a copy happened, never
                    // the value, and strips pastejacking payloads.
                    let secs =
                        ct_totp.load(std::sync::atomic::Ordering::SeqCst);
                    secure_copy_with_feedback(
                        ui.as_weak(),
                        code.clone(),
                        &format!("✅ 2FA code copied (auto-clearing in {secs}s)"),
                        secs,
                    );
                    ui.set_last_copied(code.clone().into());
                    ui.set_last_copied_id(target.into());
                }
            });
        });
    });

    let totp_next_weak = main_window.as_weak();
    main_window.on_toggle_totp_next(move || {
        let Some(ui) = totp_next_weak.upgrade() else {
            return;
        };
        ui.set_show_totp_next(!ui.get_show_totp_next());
    });

    let off_ui = main_window.as_weak();
    let off_vault = Arc::clone(&active_vault);
    main_window.on_set_totp_offset(move |text| {
        let Some(ui) = off_ui.upgrade() else {
            return;
        };
        let raw = text.as_str().trim();
        let parsed: i64 = if raw.is_empty() { 0 } else { raw.parse().unwrap_or(0) };
        let applied = core::time_offset::set(parsed);
        ui.set_totp_offset_text(applied.to_string().into());
        ui.set_totp_offset_status(match core::time_offset::label() {
            Some(l) => format!("⚠️ All 2FA codes are shifted {l} from this PC's clock.").into(),
            None => "✅ 2FA clock offset cleared — using system time.".into(),
        });
        let v = lock_vault(&off_vault);
        ui.set_auth_rows(rebuild_auth_rows(&v, ui.get_totp_search_query().as_str()));
    });

    let off_reset_weak = main_window.as_weak();
    let off_reset_vault = Arc::clone(&active_vault);
    main_window.on_reset_totp_offset(move || {
        let Some(ui) = off_reset_weak.upgrade() else {
            return;
        };
        core::time_offset::reset();
        ui.set_totp_offset_text("0".into());
        ui.set_totp_offset_status(match core::time_offset::label() {
            Some(l) => format!("⚠️ All 2FA codes are shifted {l} from this PC's clock.").into(),
            None => "✅ 2FA clock offset cleared — using system time.".into(),
        });
        let v = lock_vault(&off_reset_vault);
        ui.set_auth_accounts(rebuild_auth_list(&v));
        ui.set_auth_rows(rebuild_auth_rows(&v, ui.get_totp_search_query().as_str()));
    });

    // Duplicate resolution. The ingest paths PARK a colliding batch and ask;
    // only these three callbacks can write it. Cancel and a failed save both
    // leave the vault byte-identical.
    let dup_ui = main_window.as_weak();
    let dup_vault = Arc::clone(&active_vault);
    let dup_master = Arc::clone(&active_master_pw);
    // Shared by both policy buttons, so it lives behind an Arc rather than
    // being moved into the first callback registration.
    let dup_apply = Arc::new(move |policy: DupPolicy, dup_ui: &slint::Weak<MainWindow>| {
        let Some(ui) = dup_ui.upgrade() else {
            return;
        };
        let Some(batch) = pending_twofa_store().lock().unwrap_or_else(|p| p.into_inner()).take()
        else {
            ui.set_show_dup_confirm(false);
            return;
        };
        ui.set_show_dup_confirm(false);
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let Some(master_pw) = lock_master_pw(&dup_master).clone() else {
            ui.set_notification_text("❌ Vault not unlocked!".into());
            return;
        };
        // Snapshot before merging: `ReplaceExisting` edits cards IN PLACE, so a
        // failed seal could not be undone by removing the newly added entries.
        // Restoring the snapshot is the only rollback that is actually correct.
        let outcome: Result<usize, String> = {
            let mut vault = lock_vault(&dup_vault);
            let snapshot = vault.clone();
            let report: MergeReport = merge_2fa_with_policy(&mut vault, batch, policy);
            match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                Ok(()) => Ok(report.imported + report.replaced),
                Err(e) => {
                    *vault = snapshot;
                    Err(e.to_string())
                }
            }
        };
        match outcome {
            Ok(imported) => {
                let vault = lock_vault(&dup_vault);
                ui.set_auth_accounts(rebuild_auth_list(&vault));
                ui.set_auth_rows(rebuild_auth_rows(&vault, ui.get_totp_search_query().as_str()));
                drop(vault);
                ui.set_notification_text(format!("✅ Imported {imported} 2FA account(s).").into());
                trigger_sync_push(ui.as_weak());
            }
            Err(e) => {
                ui.set_notification_text(format!("⚠️ Import failed: {e}").into());
            }
        }
    });
    let dup_replace_ui = dup_ui.clone();
    let dup_replace_apply = Arc::clone(&dup_apply);
    main_window.on_dup_confirm_replace(move || {
        dup_replace_apply(DupPolicy::ReplaceExisting, &dup_replace_ui)
    });
    let dup_keep_ui = dup_ui.clone();
    let dup_keep_apply = Arc::clone(&dup_apply);
    main_window.on_dup_confirm_keep(move || dup_keep_apply(DupPolicy::KeepBoth, &dup_keep_ui));
    let dup_cancel_ui = dup_ui.clone();
    main_window.on_dup_confirm_cancel(move || {
        // Drop the batch: the user chose nothing, so nothing is written.
        let _ = pending_twofa_store().lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(ui) = dup_cancel_ui.upgrade() {
            ui.set_show_dup_confirm(false);
            ui.set_notification_text("🚫 Import cancelled — nothing was added.".into());
        }
    });

    main_window.on_toggle_totp_favorite(move |id| {
        let Some(ui) = totp_fav_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let master_opt = lock_master_pw(&totp_fav_master).clone();
        let Some(master_pw) = master_opt else {
            ui.set_notification_text("❌ Vault not unlocked!".into());
            return;
        };
        let weak = totp_fav_weak.clone();
        let vault_clone = Arc::clone(&totp_fav_vault);
        let search_clone = Arc::clone(&totp_fav_search);
        let target = id.as_str().to_string();
        std::thread::spawn(move || {
            let flipped: Option<bool> = (|| {
                let mut vault = lock_vault(&vault_clone);
                let state = match fav_flag_mut(&mut vault, 8, &target) {
                    Some(f) => {
                        *f = !*f;
                        *f
                    }
                    None => return None,
                };
                if save_vault_secret(&vault, &master_pw, VAULT_FILE).is_err() {
                    if let Some(f) = fav_flag_mut(&mut vault, 8, &target) {
                        *f = !*f; // roll back the flip on disk failure
                    }
                    return None;
                }
                Some(state)
            })();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                let f = search_clone.lock().unwrap().clone();
                let v = lock_vault(&vault_clone);
                ui.set_auth_accounts(rebuild_auth_list(&v));
                ui.set_auth_rows(rebuild_auth_rows(&v, ui.get_totp_search_query().as_str()));
                set_paged_credentials(&ui, vault_to_items(&v, &f));
                // Keep the open inspector star honest when it shows this account.
                if ui.get_d_id() == target.as_str() {
                    if let Some(fav_now) = fav_flag(&v, 8, &target) {
                        ui.set_d_fav(fav_now);
                    }
                }
                ui.set_notification_text(match flipped {
                    Some(true) => "⭐ 2FA account pinned to Favorites.".into(),
                    Some(false) => "☆ 2FA account unpinned.".into(),
                    None => "⚠️ Toggle failed (missing account or save error).".into(),
                });
                if flipped.is_some() {
                    trigger_sync_push(ui.as_weak());
                }
            });
        });
    });

    let pk_copy_weak = main_window.as_weak();
    let pk_copy_vault = Arc::clone(&active_vault);
    let pk_copyct = Arc::clone(&clipboard_timeout_secs);
    main_window.on_copy_passkey_pub(move |id| {
        let Some(ui) = pk_copy_weak.upgrade() else {
            return;
        };
        let vault = lock_vault(&pk_copy_vault);
        let Some(found) = vault.passkeys.iter().find(|p| p.id == id.as_str()) else {
            ui.set_notification_text("⚠️ Passkey not found.".into());
            return;
        };
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&found.public_key_der);
        drop(vault);
        let secs = pk_copyct.load(std::sync::atomic::Ordering::SeqCst);
        secure_copy_with_feedback(
            ui.as_weak(),
            b64,
            &format!("📋 Passkey public key copied! (auto-clearing in {secs}s)"),
            secs,
        );
    });

    // Recovery sheet PDF: re-split from the live master, save via dialog.
    let sheet_weak = main_window.as_weak();
    let sheet_master = Arc::clone(&active_master_pw);
    main_window.on_export_recovery_sheet(move || {
        let Some(ui) = sheet_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let master_opt = lock_master_pw(&sheet_master).clone();
        let Some(master_pw) = master_opt else {
            ui.set_notification_text("❌ Vault not unlocked!".into());
            return;
        };
        ui.set_notification_text("🖨️ Choose where to save the recovery sheet…".into());
        let weak = sheet_weak.clone();
        std::thread::spawn(move || {
            // Native dialog blocks this worker only — UI stays responsive.
            let dest = rfd::FileDialog::new()
                .set_title("Save emergency recovery sheet")
                .set_file_name("phantom-vault-recovery.pdf")
                .add_filter("PDF", &["pdf"])
                .save_file();
            let Some(dest) = dest else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_notification_text("Export cancelled.".into());
                    }
                });
                return;
            };
            // Fresh split (never stored): each export is an independent set.
            let sheets = match security::shamir::Shamir::split(master_pw.expose_secret()) {
                Ok(s) => s,
                Err(e) => {
                    let msg = format!("❌ Sheet failed: {e}");
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_notification_text(msg.into());
                        }
                    });
                    return;
                }
            };
            let res = security::pdf_sheet::export_recovery_sheet_pdf(&dest, &sheets);
            if res.is_ok() {
                security::access_log::log_event("export", "recovery-sheet");
                // PR-3: success only — cancel/split-fail/pdf-fail never marks.
                mark_recovery_exported();
            }
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    if res.is_ok() {
                        // PR-3: flip the Settings badge immediately.
                        ui.set_recovery_backed_up(true);
                    }
                    ui.set_notification_text(match res {
                        Ok(()) => "🖨️ Recovery sheet saved — print + store fireproof.".into(),
                        Err(e) => format!("❌ Sheet failed: {e}").into(),
                    });
                }
            });
        });
    });

    // Bitwarden-parity: folder engine, custom fields, edit, reprompt.
    // --- Form lifecycle: open fresh / cancel ---
    let form_weak = main_window.as_weak();
    let form_pending = Arc::clone(&pending_cf);
    let form_editing = Arc::clone(&editing_item);
    main_window.on_open_new_form(move |kind| {
        let Some(ui) = form_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        *form_editing.lock().unwrap() = None;
        *form_pending.lock().unwrap() = Vec::new();
        ui.set_custom_fields(ModelRc::new(VecModel::from(Vec::<CustomFieldView>::new())));
        ui.set_new_kind(kind);
        ui.set_f_title("".into());
        ui.set_f_a("".into());
        ui.set_f_b("".into());
        ui.set_f_c("".into());
        ui.set_f_urls(ModelRc::new(VecModel::from(Vec::<slint::SharedString>::new())));
        ui.set_f_url_rules(ModelRc::new(VecModel::from(Vec::<i32>::new())));
        ui.set_f_d("".into());
        ui.set_f_e("".into());
        ui.set_f_company("".into());
        ui.set_f_city("".into());
        ui.set_f_state("".into());
        ui.set_f_zip("".into());
        ui.set_f_country("".into());
        ui.set_f_notes("".into());
        ui.set_f_totp("".into());
        ui.set_f_backup("".into());
        ui.set_f_reprompt(false);
        ui.set_f_fav(false);
        ui.set_f_travel(false);
        ui.set_show_new_menu(false);
        ui.set_show_detail(false);
        ui.set_show_add_form(true);
        ui.set_show_2fa_import(false);
        ui.set_show_sync(false);
    });

    let cancel_weak = main_window.as_weak();
    let cancel_pending = Arc::clone(&pending_cf);
    let cancel_editing = Arc::clone(&editing_item);
    main_window.on_cancel_form(move || {
        *cancel_editing.lock().unwrap() = None;
        *cancel_pending.lock().unwrap() = Vec::new();
        if let Some(ui) = cancel_weak.upgrade() {
            ui.set_custom_fields(ModelRc::new(VecModel::from(Vec::<CustomFieldView>::new())));
            ui.set_f_urls(ModelRc::new(VecModel::from(Vec::<slint::SharedString>::new())));
            ui.set_show_add_form(false);
            ui.set_show_new_menu(false);
        }
    });

    // --- + Folder ---
    let folder_weak = main_window.as_weak();
    let folder_vault = Arc::clone(&active_vault);
    let folder_master = Arc::clone(&active_master_pw);
    main_window.on_add_folder_requested(move |name| {
        let Some(ui) = folder_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_sync_status("⛔ Decoy mode is read-only.".into());
            return;
        }
        let name = name.as_str().trim().to_string();
        let weak = folder_weak.clone();
        let vault_clone = Arc::clone(&folder_vault);
        let master_clone = Arc::clone(&folder_master);
        std::thread::spawn(move || {
            let master_opt = lock_master_pw(&master_clone).clone();
            let Some(master_pw) = master_opt else {
                return;
            };
            let res: Result<Vault, String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                if let Err(e) = vault.add_folder(&name) {
                    Err(e)
                } else {
                    match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                        Ok(()) => Ok(vault.clone()),
                        Err(e) => {
                            *vault = snapshot;
                            Err(e)
                        }
                    }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    match res {
                        Ok(v) => {
                            sync_folders_to_ui(&v, &ui);
                            ui.set_new_folder_name("".into());
                            ui.set_notification_text("📁 Folder created.".into());
                            trigger_sync_push(ui.as_weak());
                        }
                        Err(e) => {
                            ui.set_notification_text(format!("⚠️ {e}").into());
                        }
                    }
                }
            });
        });
    });

    // --- Custom fields: pending (form) add/remove/toggle ---
    let cf_weak = main_window.as_weak();
    let cf_pending = Arc::clone(&pending_cf);
    main_window.on_add_custom_field(move |ftype, name, value| {
        let Some(ui) = cf_weak.upgrade() else {
            return;
        };
        let name = name.as_str().trim().to_string();
        let value = value.as_str().to_string();
        if name.is_empty() || name.len() > 64 {
            ui.set_notification_text("⚠️ Field needs a short label!".into());
            return;
        }
        let mut pending = cf_pending.lock().unwrap();
        if pending.len() >= 24 {
            ui.set_notification_text("⚠️ Max 24 custom fields.".into());
            return;
        }
        if pending.iter().any(|f| f.name == name) {
            ui.set_notification_text("⚠️ Field label already used.".into());
            return;
        }
        // Linked fields mirror a live item field — value is only ever
        // "username" or "password", never a duplicated secret.
        let value = if ftype == 3 {
            match value.as_str() {
                "username" | "password" => value,
                _ => {
                    ui.set_notification_text("⚠️ Pick Username or Password target.".into());
                    return;
                }
            }
        } else {
            value
        };
        pending.push(models::CustomField {
            name,
            value: if ftype == 2 { "false".to_string() } else { value },
            field_type: models::CustomFieldType::from_i32(ftype),
        });
        ui.set_custom_fields(custom_to_ui(&pending));
        ui.set_cf_name("".into());
        ui.set_cf_value("".into());
        ui.set_show_cf_dialog(false);
    });

    let cfdel_weak = main_window.as_weak();
    let cfdel_pending = Arc::clone(&pending_cf);
    main_window.on_delete_custom_field(move |idx| {
        let Some(ui) = cfdel_weak.upgrade() else {
            return;
        };
        let mut pending = cfdel_pending.lock().unwrap();
        let i = idx as usize;
        if i < pending.len() {
            pending.remove(i);
            ui.set_custom_fields(custom_to_ui(&pending));
        }
    });

    // Secondary website URLs: rows live in the Slint model directly
    // (editable rows can't two-way bind, so edits round-trip here).
    // Rules ride a parallel int model, index-aligned; every mutation keeps
    // both models the same length (reads clamp defensively anyway).
    fn f_urls_vec(ui: &MainWindow) -> Vec<slint::SharedString> {
        ui.get_f_urls().iter().collect()
    }
    fn f_rules_vec(ui: &MainWindow) -> Vec<i32> {
        ui.get_f_url_rules().iter().collect()
    }
    let urladd_weak = main_window.as_weak();
    main_window.on_add_url(move || {
        let Some(ui) = urladd_weak.upgrade() else {
            return;
        };
        let mut rows = f_urls_vec(&ui);
        if rows.len() >= 10 {
            ui.set_notification_text("⚠️ Max 10 websites.".into());
            return;
        }
        rows.push("".into());
        let mut rules = f_rules_vec(&ui);
        rules.push(0);
        ui.set_f_urls(ModelRc::new(VecModel::from(rows)));
        ui.set_f_url_rules(ModelRc::new(VecModel::from(rules)));
    });
    let urlcycle_weak = main_window.as_weak();
    main_window.on_cycle_url_rule(move |idx| {
        let Some(ui) = urlcycle_weak.upgrade() else {
            return;
        };
        let mut rules = f_rules_vec(&ui);
        let i = idx as usize;
        if i < rules.len() {
            rules[i] = (rules[i] + 1).rem_euclid(6);
            ui.set_f_url_rules(ModelRc::new(VecModel::from(rules)));
        }
    });
    let urlupd_weak = main_window.as_weak();
    main_window.on_update_url(move |idx, text| {
        let Some(ui) = urlupd_weak.upgrade() else {
            return;
        };
        let mut rows = f_urls_vec(&ui);
        let i = idx as usize;
        if i < rows.len() {
            rows[i] = text;
            ui.set_f_urls(ModelRc::new(VecModel::from(rows)));
        }
    });
    let urldel_weak = main_window.as_weak();
    main_window.on_remove_url(move |idx| {
        let Some(ui) = urldel_weak.upgrade() else {
            return;
        };
        let mut rows = f_urls_vec(&ui);
        let i = idx as usize;
        if i < rows.len() {
            rows.remove(i);
            let mut rules = f_rules_vec(&ui);
            if i < rules.len() {
                rules.remove(i);
            }
            ui.set_f_urls(ModelRc::new(VecModel::from(rows)));
            ui.set_f_url_rules(ModelRc::new(VecModel::from(rules)));
        }
    });

    let cftog_weak = main_window.as_weak();
    let cftog_pending = Arc::clone(&pending_cf);
    main_window.on_toggle_pending_field(move |idx| {
        let Some(ui) = cftog_weak.upgrade() else {
            return;
        };
        let mut pending = cftog_pending.lock().unwrap();
        let i = idx as usize;
        if i < pending.len() && pending[i].field_type == models::CustomFieldType::Checkbox {
            pending[i].value = if pending[i].value == "true" { "false" } else { "true" }.to_string();
            ui.set_custom_fields(custom_to_ui(&pending));
        }
    });

    // --- Custom fields: persisted toggle (detail modal, login kind) ---
    let cfs_weak = main_window.as_weak();
    let cfs_vault = Arc::clone(&active_vault);
    let cfs_master = Arc::clone(&active_master_pw);
    main_window.on_toggle_saved_field(move |kind, id, idx| {
        if kind != 1 {
            return;
        }
        // Same vault-destruction vector as HOTP: the toggle re-seals the file.
        if let Some(ui) = cfs_weak.upgrade() {
            if ui.get_is_decoy() {
                ui.set_notification_text("⛔ Decoy mode is read-only.".into());
                return;
            }
        }
        let weak = cfs_weak.clone();
        let vault_clone = Arc::clone(&cfs_vault);
        let master_clone = Arc::clone(&cfs_master);
        let id = id.as_str().to_string();
        let idx = idx as usize;
        std::thread::spawn(move || {
            let master_opt = lock_master_pw(&master_clone).clone();
            let Some(master_pw) = master_opt else {
                return;
            };
            let res: Result<Vec<models::CustomField>, String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                let Some(cred) = vault.credentials.iter_mut().find(|c| c.id == id) else {
                    return;
                };
                if idx >= cred.custom_fields.len()
                    || cred.custom_fields[idx].field_type != models::CustomFieldType::Checkbox
                {
                    return;
                }
                let cur = cred.custom_fields[idx].value.clone();
                cred.custom_fields[idx].value =
                    if cur == "true" { "false" } else { "true" }.to_string();
                let fields = cred.custom_fields.clone();
                match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                    Ok(()) => Ok(fields),
                    Err(e) => {
                        *vault = snapshot;
                        Err(e)
                    }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    if let Ok(fields) = res {
                        ui.set_d_custom(custom_to_ui(&fields));
                    }
                }
            });
        });
    });

    // --- Detail: fetch full item into modal props (single source of truth) ---
    let detail_weak = main_window.as_weak();
    let detail_vault = Arc::clone(&active_vault);
    // Column-3 deselect: clears the selection so the empty-state placeholder
    // returns (the floating modal is gone — nothing else to dismiss).
    let close_weak = main_window.as_weak();
    main_window.on_close_detail(move || {
        if let Some(ui) = close_weak.upgrade() {
            ui.set_d_id(String::new().into());
            ui.set_show_detail(false);
            ui.set_confirm_delete_detail(false);
            ui.set_confirm_delete_att_id(String::new().into());
        }
    });
    // Column-2 keyboard nav: ↑↓ cycle the rendered rows with wraparound,
    // reusing the full open_detail path (no detail-logic fork to rot).
    let cycle_weak = main_window.as_weak();
    let cycle_vault = Arc::clone(&active_vault);
    let cycle_search = Arc::clone(&search_state);
    main_window.on_cycle_select(move |delta| {
        let Some(ui) = cycle_weak.upgrade() else {
            return;
        };
        let cur = ui.get_d_id().to_string();
        let ids: Vec<String> = {
            let f = cycle_search.lock().unwrap().clone();
            let v = lock_vault(&cycle_vault);
            vault_to_items(&v, &f).iter().map(|r| r.id.to_string()).collect()
        };
        if ids.is_empty() {
            return;
        }
        let next = match ids.iter().position(|x| *x == cur) {
            Some(i) => {
                let n = (i as i32 + delta).rem_euclid(ids.len() as i32) as usize;
                ids[n].clone()
            }
            None => {
                if delta >= 0 {
                    ids[0].clone()
                } else {
                    ids[ids.len() - 1].clone()
                }
            }
        };
        ui.invoke_open_detail(next.into());
    });
    main_window.on_open_detail(move |id| {
        let Some(ui) = detail_weak.upgrade() else {
            return;
        };
        let vault = lock_vault(&detail_vault);
        let id = id.as_str();
        // Only logins track rotation age/history; reset for every other kind.
        ui.set_d_stale(false);
        ui.set_d_age_info(String::new().into());
        ui.set_d_age_frac(0.0);
        ui.set_confirm_delete_detail(false);
        ui.set_confirm_delete_att_id(String::new().into());
        ui.set_d_fav(false);
        ui.set_d_trashed(false);
        ui.set_d_has_icon(false);
        ui.set_d_verified(false);
        ui.set_d_fill_info(String::new().into());
        ui.set_d_health(health_badge_for(id).into());
        ui.set_d_pw_strength(0.0);
        ui.set_d_pw_strength_label(String::new().into());
        ui.set_d_history(ModelRc::new(VecModel::from(Vec::<HistoryView>::new())));
        // Logins carry the richest payload (reprompt, totp, codes, customs).
        if let Some(c) = vault.credentials.iter().find(|c| c.id == id) {
            ui.set_d_id(c.id.clone().into());
            ui.set_d_kind(1);
            ui.set_d_title(c.title.clone().into());
            ui.set_d_user(c.username.clone().into());
            ui.set_d_secret(c.password.clone().into());
            ui.set_d_meta(String::new().into());
            ui.set_d_url(primary_url(&c.urls).into());
            ui.set_d_urls_extra(
                c.urls
                    .iter()
                    .skip(1)
                    .map(|u| u.url())
                    .collect::<Vec<_>>()
                    .join("\n")
                    .into(),
            );
            ui.set_d_notes(c.notes.clone().into());
            ui.set_d_folder(c.folder.clone().into());
            ui.set_d_trashed(c.deleted_at.is_some());
            ui.set_d_reprompt(c.reprompt);
            ui.set_d_totp(c.totp_secret.clone().into());
            ui.set_d_backup(c.backup_codes.join("\n").into());
            ui.set_d_custom(custom_to_ui(&c.custom_fields));
            ui.set_d_stale(crate::models::is_stale(
                c.last_changed,
                crate::models::current_timestamp(),
            ));
            // Per-password strength meter (local estimate + reuse + age).
            {
                let reused = vault
                    .credentials
                    .iter()
                    .filter(|o| {
                        o.id != c.id && o.deleted_at.is_none() && o.password == c.password
                    })
                    .count();
                let stale = crate::models::is_stale(
                    c.last_changed,
                    crate::models::current_timestamp(),
                );
                ui.set_d_pw_strength(crate::core::password_strength::fraction(&c.password));
                ui.set_d_pw_strength_label(
                    crate::core::password_strength::detail(&c.password, reused, stale).into(),
                );
            }
            ui.set_d_fav(c.favorite);
            ui.set_d_history(rebuild_history(c));
            ui.set_d_verified(vault.is_verified(&c.id));
            {
                let (fills, last) = crate::windows_native::native_host::fill_stats_for(&c.id);
                let now = crate::models::current_timestamp();
                let fill_info: String = if fills == 0 {
                    "Never filled via autofill yet.".to_string()
                } else if last == 0 {
                    format!("Filled {fills}× via autofill.")
                } else {
                    format!("Filled {fills}× via autofill • Last: {}.", crate::models::ago(last, now))
                };
                ui.set_d_fill_info(fill_info.into());
            }
            let first_url = c.urls.first().map(|u| u.url()).unwrap_or("");
            if let Some(img) = favicon_for_item(&c.title, first_url) {
                ui.set_d_icon(img);
                ui.set_d_has_icon(true);
            }
            {
                let now = crate::models::current_timestamp();
                let days = now.saturating_sub(c.last_changed) / 86400;
                ui.set_d_age_info(
                    format!("Last edited {} • Password age: {} days", crate::models::ago(c.last_changed, now), days).into(),
                );
                ui.set_d_age_frac((days as f32 / 180.0).min(1.0));
            }
        } else if let Some(l) = vault.licenses.iter().find(|l| l.id == id) {
            ui.set_d_id(l.id.clone().into());
            ui.set_d_kind(2);
            ui.set_d_title(l.app_name.clone().into());
            ui.set_d_user("Software license".into());
            ui.set_d_secret(l.license_key.clone().into());
            ui.set_d_meta(l.expiry_date.clone().unwrap_or_default().into());
            ui.set_d_url(String::new().into());
            ui.set_d_urls_extra(String::new().into());
            ui.set_d_notes(String::new().into());
            ui.set_d_folder(l.folder.clone().into());
            ui.set_d_trashed(l.deleted_at.is_some());
            ui.set_d_fav(l.favorite);
            ui.set_d_reprompt(false);
            ui.set_d_totp(String::new().into());
            ui.set_d_backup(String::new().into());
            ui.set_d_custom(custom_to_ui(&l.custom_fields));
        } else if let Some(n) = vault.notes.iter().find(|n| n.id == id) {
            ui.set_d_id(n.id.clone().into());
            ui.set_d_kind(3);
            ui.set_d_title(n.title.clone().into());
            ui.set_d_user(String::new().into());
            ui.set_d_secret(n.content.clone().into());
            ui.set_d_meta(String::new().into());
            ui.set_d_url(String::new().into());
            ui.set_d_urls_extra(String::new().into());
            ui.set_d_notes(n.content.clone().into());
            ui.set_d_folder(n.folder.clone().into());
            ui.set_d_trashed(n.deleted_at.is_some());
            ui.set_d_fav(n.favorite);
            ui.set_d_reprompt(false);
            ui.set_d_totp(String::new().into());
            ui.set_d_backup(String::new().into());
            ui.set_d_custom(custom_to_ui(&n.custom_fields));
        } else if let Some(k) = vault.cards.iter().find(|k| k.id == id) {
            ui.set_d_id(k.id.clone().into());
            ui.set_d_kind(4);
            ui.set_d_title(k.title.clone().into());
            ui.set_d_user(k.cardholder_name.clone().into());
            ui.set_d_secret(k.card_number.clone().into());
            let brand = card_brand(&k.card_number);
            let brand_chip = if brand.is_empty() {
                String::new()
            } else {
                format!("{brand} • ")
            };
            ui.set_d_meta(
                format!(
                    "{brand_chip}exp {:0>2}/{:0>2}  CVV {}",
                    k.exp_month, k.exp_year, k.cvv
                )
                .into(),
            );
            ui.set_d_url(String::new().into());
            ui.set_d_urls_extra(String::new().into());
            ui.set_d_notes(k.notes.clone().into());
            ui.set_d_folder(k.folder.clone().into());
            ui.set_d_trashed(k.deleted_at.is_some());
            ui.set_d_fav(k.favorite);
            ui.set_d_reprompt(false);
            ui.set_d_totp(String::new().into());
            ui.set_d_backup(String::new().into());
            ui.set_d_custom(custom_to_ui(&k.custom_fields));
        } else if let Some(i) = vault.identities.iter().find(|i| i.id == id) {
            ui.set_d_id(i.id.clone().into());
            ui.set_d_kind(5);
            ui.set_d_title(i.title.clone().into());
            ui.set_d_user(i.full_name.clone().into());
            ui.set_d_secret(i.nid_or_passport.clone().into());
            ui.set_d_meta(i.phone.clone().into());
            ui.set_d_url(i.email.clone().into());
            ui.set_d_urls_extra(String::new().into());
            // Address slot doubles for notes (5 data fields, 1 notes box):
            // notes appended only when present, never a dangling separator.
            // Structured locality (city/state/zip/country/company) composes
            // its own line when any part is present.
            let mut blocks: Vec<String> = Vec::new();
            if !i.address.trim().is_empty() {
                blocks.push(i.address.clone());
            }
            let locality = [
                i.city.trim(),
                i.state.trim(),
                i.zip.trim(),
                i.country.trim(),
            ]
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", ");
            if !locality.is_empty() {
                blocks.push(locality);
            }
            if !i.company.trim().is_empty() {
                blocks.push(format!("Company: {}", i.company.trim()));
            }
            if !i.notes.trim().is_empty() {
                blocks.push(i.notes.clone());
            }
            ui.set_d_notes(blocks.join("\n\n").into());
            ui.set_d_folder(i.folder.clone().into());
            ui.set_d_trashed(i.deleted_at.is_some());
            ui.set_d_fav(i.favorite);
            ui.set_d_reprompt(false);
            ui.set_d_totp(String::new().into());
            ui.set_d_backup(String::new().into());
            ui.set_d_custom(custom_to_ui(&i.custom_fields));
        } else if let Some(s) = vault.ssh_keys.iter().find(|s| s.id == id) {
            ui.set_d_id(s.id.clone().into());
            ui.set_d_kind(6);
            ui.set_d_title(s.title.clone().into());
            ui.set_d_user("SSH key".into());
            ui.set_d_secret(s.private_key.clone().into());
            ui.set_d_meta(s.fingerprint.clone().into());
            ui.set_d_url(String::new().into());
            ui.set_d_urls_extra(String::new().into());
            ui.set_d_notes(s.public_key.clone().into());
            ui.set_d_folder(s.folder.clone().into());
            ui.set_d_trashed(s.deleted_at.is_some());
            ui.set_d_fav(s.favorite);
            ui.set_d_reprompt(false);
            ui.set_d_totp(String::new().into());
            ui.set_d_backup(String::new().into());
            ui.set_d_custom(custom_to_ui(&s.custom_fields));
        } else if let Some(a) = vault.totp_accounts.iter().find(|a| a.id == id) {
            // Standalone 2FA inspector: d_totp carries the SECRET so the
            // Column 3 card + 1s ticker render the live code, countdown ring,
            // and next code exactly like an embedded login TOTP. d_secret
            // stays empty — nothing raw renders as a password row.
            let title = if a.issuer.trim().is_empty() { a.account_name.clone() } else { a.issuer.clone() };
            let meta = match a.otp_type.trim().to_lowercase().as_str() {
                "hotp" => "HOTP — counter advances via Next in the 2FA Hub",
                "steam" => "Steam Guard — 5-character codes",
                _ => "TOTP — 30s codes",
            };
            ui.set_d_id(a.id.clone().into());
            ui.set_d_kind(8);
            ui.set_d_title(title.into());
            ui.set_d_user(a.account_name.clone().into());
            ui.set_d_secret(String::new().into());
            ui.set_d_meta(meta.into());
            ui.set_d_url(String::new().into());
            ui.set_d_urls_extra(String::new().into());
            ui.set_d_notes(String::new().into());
            ui.set_d_folder("General".into());
            ui.set_d_trashed(false);
            ui.set_d_fav(a.favorite);
            ui.set_d_reprompt(false);
            ui.set_d_totp(a.secret.clone().into());
            ui.set_d_backup(String::new().into());
            ui.set_d_custom(custom_to_ui(&[]));
        } else {
            return;
        }
        // Travel flag + attachments ride along for every kind.
        let (travel, files): (bool, Vec<models::EncryptedAttachment>) = match ui.get_d_kind() {
            1 => vault.credentials.iter().find(|c| c.id == id)
                .map(|c| (c.travel_safe, c.attachments.clone())).unwrap_or((false, Vec::new())),
            2 => vault.licenses.iter().find(|l| l.id == id)
                .map(|l| (l.travel_safe, l.attachments.clone())).unwrap_or((false, Vec::new())),
            3 => vault.notes.iter().find(|n| n.id == id)
                .map(|n| (n.travel_safe, Vec::new())).unwrap_or((false, Vec::new())),
            4 => vault.cards.iter().find(|k| k.id == id)
                .map(|k| (k.travel_safe, Vec::new())).unwrap_or((false, Vec::new())),
            5 => vault.identities.iter().find(|i| i.id == id)
                .map(|i| (i.travel_safe, Vec::new())).unwrap_or((false, Vec::new())),
            8 => (false, Vec::new()), // standalone 2FA: no travel flag, no attachments
            _ => vault.ssh_keys.iter().find(|s| s.id == id)
                .map(|s| (s.travel_safe, s.attachments.clone())).unwrap_or((false, Vec::new())),
        };
        ui.set_d_travel(travel);
        ui.set_d_attachments(attachments_to_ui(&files));
        ui.set_d_secret_visible(false);
        ui.set_d_revealed(-1);
        ui.set_show_detail(true);
    });

    // --- Edit: prefill the form from any item ---
    let edit_weak = main_window.as_weak();
    let edit_vault = Arc::clone(&active_vault);
    let edit_pending = Arc::clone(&pending_cf);
    let edit_target = Arc::clone(&editing_item);
    main_window.on_edit_item_requested(move |kind, id| {
        let Some(ui) = edit_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let vault = lock_vault(&edit_vault);
        let id = id.as_str().to_string();
        *edit_target.lock().unwrap() = Some((kind, id.clone()));
        ui.set_new_kind(kind);
        ui.set_show_detail(false);
        ui.set_show_add_form(true);
        match kind {
            1 => {
                if let Some(c) = vault.credentials.iter().find(|c| c.id == id) {
                    ui.set_f_title(c.title.clone().into());
                    ui.set_f_a(c.username.clone().into());
                    ui.set_f_b(c.password.clone().into());
                    // Primary URL in the main box, secondaries as rows.
                    // Rules ride the parallel f_url_rules model (primary is
                    // always Default — its box has no picker).
                    let mut urls = c.urls.iter().filter(|u| !u.url().trim().is_empty());
                    ui.set_f_c(urls.next().map(|u| u.url().to_string()).unwrap_or_default().into());
                    let rest: Vec<(slint::SharedString, i32)> = urls
                        .map(|u| (slint::SharedString::from(u.url()), u.rule() as i32))
                        .collect();
                    ui.set_f_urls(ModelRc::new(VecModel::from(
                        rest.iter().map(|(s, _)| s.clone()).collect::<Vec<_>>(),
                    )));
                    ui.set_f_url_rules(ModelRc::new(VecModel::from(
                        rest.iter().map(|(_, r)| *r).collect::<Vec<_>>(),
                    )));
                    ui.set_f_totp(c.totp_secret.clone().into());
                    ui.set_f_backup(c.backup_codes.join("\n").into());
                    ui.set_f_notes(c.notes.clone().into());
                    ui.set_f_folder(c.folder.clone().into());
                    ui.set_f_reprompt(c.reprompt);
                    ui.set_f_fav(c.favorite);
                    ui.set_f_travel(c.travel_safe);
                    *edit_pending.lock().unwrap() = c.custom_fields.clone();
                    ui.set_custom_fields(custom_to_ui(&c.custom_fields));
                }
            }
            2 => {
                if let Some(l) = vault.licenses.iter().find(|l| l.id == id) {
                    ui.set_f_title(l.app_name.clone().into());
                    ui.set_f_a(l.license_key.clone().into());
                    ui.set_f_b(l.expiry_date.clone().unwrap_or_default().into());
                    ui.set_f_folder(l.folder.clone().into());
                    ui.set_f_fav(l.favorite);
                    ui.set_f_travel(l.travel_safe);
                }
            }
            3 => {
                if let Some(n) = vault.notes.iter().find(|n| n.id == id) {
                    ui.set_f_title(n.title.clone().into());
                    ui.set_f_a(n.content.clone().into());
                    ui.set_f_folder(n.folder.clone().into());
                    ui.set_f_fav(n.favorite);
                    ui.set_f_travel(n.travel_safe);
                }
            }
            4 => {
                if let Some(k) = vault.cards.iter().find(|k| k.id == id) {
                    ui.set_f_title(k.title.clone().into());
                    ui.set_f_a(k.cardholder_name.clone().into());
                    ui.set_f_b(k.card_number.clone().into());
                    ui.set_f_c(format!("{}/{}", k.exp_month, k.exp_year).into());
                    ui.set_f_d(k.cvv.clone().into());
                    ui.set_f_notes(k.notes.clone().into());
                    ui.set_f_folder(k.folder.clone().into());
                    ui.set_f_fav(k.favorite);
                    ui.set_f_travel(k.travel_safe);
                }
            }
            5 => {
                if let Some(i) = vault.identities.iter().find(|i| i.id == id) {
                    ui.set_f_title(i.title.clone().into());
                    ui.set_f_a(i.full_name.clone().into());
                    ui.set_f_b(i.nid_or_passport.clone().into());
                    ui.set_f_c(i.email.clone().into());
                    ui.set_f_d(i.phone.clone().into());
                    ui.set_f_e(i.address.clone().into());
                    ui.set_f_company(i.company.clone().into());
                    ui.set_f_city(i.city.clone().into());
                    ui.set_f_state(i.state.clone().into());
                    ui.set_f_zip(i.zip.clone().into());
                    ui.set_f_country(i.country.clone().into());
                    ui.set_f_folder(i.folder.clone().into());
                    ui.set_f_fav(i.favorite);
                    ui.set_f_travel(i.travel_safe);
                }
            }
            6 => {
                if let Some(s) = vault.ssh_keys.iter().find(|s| s.id == id) {
                    ui.set_f_title(s.title.clone().into());
                    ui.set_f_a(s.public_key.clone().into());
                    ui.set_f_b(s.private_key.clone().into());
                    ui.set_f_c(s.fingerprint.clone().into());
                    ui.set_f_notes(s.notes.clone().into());
                    ui.set_f_folder(s.folder.clone().into());
                    ui.set_f_fav(s.favorite);
                    ui.set_f_travel(s.travel_safe);
                }
            }
            _ => {}
        }
    });

    // --- Reprompt: master-password gate for flagged logins ---
    // rp_action: 1 copy secret, 2 fill (type), 3 delete.
    let rp_weak = main_window.as_weak();
    let rp_master = Arc::clone(&active_master_pw);
    let rp_main = main_window.as_weak();
    let rp_qb = quick_bar.as_weak();
    let rp_vis = Arc::clone(&quickbar_visible);
    let rp_uvis = Arc::clone(&ui_visible);
    let rp_del_vault = Arc::clone(&active_vault);
    let rp_del_search = Arc::clone(&search_state);
    let rp_del_qb = quick_bar.as_weak();
    let rp_travel_off = Arc::clone(&travel_mode);
    let rp_travel_vault = Arc::clone(&active_vault);
    let rp_search = Arc::clone(&search_state);
    let rp_ct = Arc::clone(&clipboard_timeout_secs);
    main_window.on_reprompt_confirm(move |password| {
        let Some(ui) = rp_weak.upgrade() else {
            return;
        };
        let ok = rp_master
            .lock()
            .unwrap()
            .clone()
            .is_some_and(|m| m.expose_secret() == password.as_str());
        if !ok {
            ui.set_rp_error("❌ Wrong master password.".into());
            return;
        }
        ui.set_rp_show(false);
        ui.set_rp_error("".into());
        // Capture BEFORE clearing: action 1 copies this below.
        let gated_secret = ui.get_rp_secret().to_string();
        ui.set_rp_secret("".into());
        match ui.get_rp_action() {
            1 => {
                // Copy the gated secret via the masked path.
                let secs = rp_ct.load(std::sync::atomic::Ordering::SeqCst);
                secure_copy_with_feedback(
                    ui.as_weak(),
                    gated_secret,
                    &format!("📋 Copied! (Masked from Win+V, auto-clearing in {secs}s)"),
                    secs,
                );
            }
            2 => {
                // Look up the login's TOTP so the 2FA chain can arm.
                let totp = rp_del_vault
                    .lock()
                    .ok()
                    .and_then(|v| {
                        v.credentials
                            .iter()
                            .find(|c| ui.get_rp_id() == c.id)
                            .map(|c| c.totp_secret.clone())
                    })
                    .unwrap_or_default();
                trigger_autotype(
                    rp_main.clone(),
                    rp_qb.clone(),
                    Arc::clone(&rp_vis),
                    Arc::clone(&rp_uvis),
                    {
                        let v = lock_vault(&rp_del_vault);
                        login_type_request(
                            &v,
                            ui.get_rp_id().as_ref(),
                            ui.get_rp_user().as_ref(),
                            ui.get_rp_secret().as_ref(),
                            &totp,
                        )
                    },
                );
            }
            3 => {
                // Delete via the standard path (re-dispatch through UI state).
                let weak = rp_main.clone();
                let vault_clone = Arc::clone(&rp_del_vault);
                let master_clone = Arc::clone(&rp_master);
                let search_clone = Arc::clone(&rp_del_search);
                let qb_clone = rp_del_qb.clone();
                let kind = ui.get_rp_kind();
                let id = ui.get_rp_id().to_string();
                    std::thread::spawn(move || {
            let master_opt = lock_master_pw(&master_clone).clone();
            let Some(master_pw) = master_opt else {
                        return;
                    };
                    // Same two-phase rule as the plain delete path.
                    let res: Result<(Vault, bool), String> = {
                        let mut vault = lock_vault(&vault_clone);
                        let snapshot = vault.clone();
                        let already = vault.is_trashed(kind, &id).unwrap_or(false);
                        let ok = if already {
                            vault.delete_item(kind, &id)
                        } else {
                            vault.trash_item(kind, &id, crate::models::current_timestamp())
                        };
                        if !ok {
                            Err("Item not found".to_string())
                        } else {
                            match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                                Ok(()) => Ok((vault.clone(), already)),
                                Err(e) => {
                                    *vault = snapshot;
                                    Err(e)
                                }
                            }
                        }
                    };
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            match res {
                                Ok((v, permanent)) => {
                                    let f = search_clone.lock().unwrap().clone();
                                    set_paged_credentials(&ui, vault_to_items(&v, &f));
                                    set_trash_label(&ui, &v);
                                    if let Some(qb) = qb_clone.upgrade() {
                                        qb.set_filtered_results(vault_quickbar(&v, "", search_clone.lock().unwrap().travel_only));
                                    }
                                    ui.set_notification_text(if permanent {
                                        "🔥 Item permanently shredded.".into()
                                    } else {
                                        "🗑️ Moved to Trash (restorable 30 days).".into()
                                    });
                                    ui.set_show_detail(false);
                                    ui.set_d_id(String::new().into());
                                    trigger_sync_push(ui.as_weak());
                                }
                                Err(e) => {
                                    ui.set_notification_text(format!("❌ Delete failed: {}", e).into());
                                }
                            }
                        }
                    });
                });
            }
            4 => {
                // Travel Mode disarm (master already verified above): show all.
                *rp_travel_off.lock().unwrap() = false;
                if let Some(ui) = rp_main.upgrade() {
                    ui.set_is_travel_mode(false);
                    let vault = lock_vault(&rp_travel_vault);
                    let mut f = rp_search.lock().unwrap().clone();
                    f.travel_only = false;
                    *rp_search.lock().unwrap() = f.clone();
                    set_paged_credentials(&ui, vault_to_items(&vault, &f));
                    ui.set_notification_text("Travel Mode OFF — full vault restored.".into());
                }
            }
            5 => {
                // Zero-lockin file export (master verified above; decoy refused).
                let fmt = ui.get_rp_export_fmt();
                if ui.get_is_decoy() {
                    ui.set_notification_text("⛔ Decoy mode is read-only.".into());
                    return;
                }
                ui.set_export_status("⚠️ Plaintext export — pick a destination…".into());
                let weak = rp_main.clone();
                let vault_clone = Arc::clone(&rp_del_vault);
                std::thread::spawn(move || {
                    // Snapshot under lock, then release before the dialog blocks.
                    // M5: decoy already refused on the event-loop thread
                    // above (`false` here); the gated serializers refuse
                    // again loud if that ever regresses.
                    let (payload, filename, filters, summary) = {
                        let v = lock_vault(&vault_clone);
                        if fmt == 2 {
                            let csv = match importer::exporter::export_csv_gated(&v, false) {
                                Ok(s) => s,
                                Err(e) => {
                                    eprintln!("export refused: {e}");
                                    return;
                                }
                            };
                            let n: usize = v.credentials.iter().filter(|c| c.deleted_at.is_none()).count()
                                + v.cards.iter().filter(|k| k.deleted_at.is_none()).count();
                            (
                                csv.into_bytes(),
                                "phantom-vault-export.csv".to_string(),
                                vec![("CSV", vec!["csv"])],
                                format!("{n} logins/cards"),
                            )
                        } else {
                            let (doc, atts) = match importer::exporter::export_bitwarden_json_gated(&v, false) {
                                Ok(t) => t,
                                Err(e) => {
                                    eprintln!("export refused: {e}");
                                    return;
                                }
                            };
                            let n = doc["items"].as_array().map(|a| a.len()).unwrap_or(0);
                            let f = doc["folders"].as_array().map(|a| a.len()).unwrap_or(0);
                            (
                                serde_json::to_vec_pretty(&doc).unwrap_or_default(),
                                "phantom-vault-export.json".to_string(),
                                vec![("JSON", vec!["json"])],
                                format!("{n} items in {f} folders ({atts} attachments listed, binaries not embedded)"),
                            )
                        }
                    };
                    let mut dlg = rfd::FileDialog::new()
                        .set_title("Export PLAINTEXT vault — anyone with this file reads everything")
                        .set_file_name(&filename);
                    for (label, exts) in &filters {
                        dlg = dlg.add_filter(*label, exts);
                    }
                    let picked = dlg.save_file();
                    let Some(path) = picked else {
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak.upgrade() {
                                ui.set_export_status("Export cancelled — nothing written.".into());
                            }
                        });
                        return;
                    };
                    let res = std::fs::write(&path, &payload).map_err(|e| e.to_string());
                    let path_str = path.to_string_lossy().into_owned();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            match res {
                                Ok(()) => {
                                    ui.set_export_status(
                                        format!("✅ Exported {summary} → {path_str}. Shred it after moving!")
                                            .into(),
                                    );
                                    ui.set_notification_text(
                                        "✅ Vault exported (plaintext!). Shred the file after moving it.".into(),
                                    );
                                    security::access_log::log_event("export", "file");
                                }
                                Err(e) => {
                                    ui.set_export_status(format!("❌ Export failed: {e}").into());
                                }
                            }
                        }
                    });
                });
            }
            _ => {}
        }
    });

    // Phase 17: Shamir recovery sheet (needs unlocked master password).
    let shard_weak = main_window.as_weak();
    let shard_master = Arc::clone(&active_master_pw);
    main_window.on_generate_shards(move || {
        let Some(ui) = shard_weak.upgrade() else {
            return;
        };
        ui.set_drill_status(String::new().into());
        generate_shards_into(&ui, &shard_master);
    });
    // Recovery drill: prove the paper copy works (words #2 + #4 of shard #1).
    // Success flips the same persistent badge as a PDF export.
    let drill_weak = main_window.as_weak();
    main_window.on_verify_shard_drill(move |w2, w4| {
        let Some(ui) = drill_weak.upgrade() else {
            return;
        };
        if security::shamir::Shamir::check_drill(ui.get_shard_1().as_str(), w2.as_str(), w4.as_str()) {
            mark_recovery_exported();
            ui.set_recovery_backed_up(true);
            ui.set_drill_status("✅ Drill passed — paper copy verified.".into());
            security::access_log::log_event("export", "recovery-drill ok");
        } else {
            ui.set_drill_status("❌ No match — copy words #2 and #4 exactly.".into());
        }
    });
    // Post-setup nudge actions: Generate runs the same split core (marks the
    // one-shot pref either way — nagged once, never again).
    let nudge_weak = main_window.as_weak();
    let nudge_master = Arc::clone(&active_master_pw);
    main_window.on_shard_nudge_generate(move || {
        mark_shard_nudged();
        let Some(ui) = nudge_weak.upgrade() else {
            return;
        };
        ui.set_show_shard_nudge(false);
        generate_shards_into(&ui, &nudge_master);
    });
    let later_weak = main_window.as_weak();
    main_window.on_shard_nudge_later(move || {
        mark_shard_nudged();
        if let Some(ui) = later_weak.upgrade() {
            ui.set_show_shard_nudge(false);
        }
    });

    // Phase 17: lock-screen shard recovery → rebuild → standard unlock.
    let rec_weak = main_window.as_weak();
    let rec_vault = Arc::clone(&active_vault);
    let rec_master = Arc::clone(&active_master_pw);
    let rec_search = Arc::clone(&search_state);
    let rec_qb = quick_bar.as_weak();
    let rec_uvis = Arc::clone(&ui_visible);
    main_window.on_recover_with_shards(move |s1, s2, s3| {
        if let Some(ui) = rec_weak.upgrade() {
            ui.set_unlock_error_message("".into());
            ui.set_status_text("⏳ Rebuilding master secret from shards…".into());
        }
        let inputs = [s1.as_str().to_string(), s2.as_str().to_string(), s3.as_str().to_string()];
        let weak = rec_weak.clone();
        let vault_clone = Arc::clone(&rec_vault);
        let master_clone = Arc::clone(&rec_master);
        let search_clone = Arc::clone(&rec_search);
        let qb_clone = rec_qb.clone();
        let uvis_clone = Arc::clone(&rec_uvis);
        std::thread::spawn(move || {
            let refs: Vec<&str> = inputs.iter().map(|s| s.as_str()).collect();
            let pass = match security::shamir::Shamir::combine(&refs) {
                Ok(secret) => String::from_utf8_lossy(secret.expose()).into_owned(),
                Err(e) => {
                    let msg = format!("Need 3 valid shards ({e}).");
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_unlock_error_message(msg.into());
                            ui.set_status_text("Vault is locked. Enter Master Password:".into());
                        }
                    });
                    return;
                }
            };
            if pass.is_empty() {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_unlock_error_message("Shards rebuilt an empty secret.".into());
                    }
                });
                return;
            }
            unlock_with_password(
                SecretString::new(pass), weak, vault_clone, master_clone, search_clone, qb_clone, Arc::clone(&uvis_clone), true, false,
            );
        });
    });

    // Phase 18: Omni-Importer — file picker + sniff + merge, all off-UI-thread.
    // Dry-run preview: pick → parse → dry-merge on a CLONE for exact counts
    // → user confirms → real merge + re-seal. Nothing touches the live vault
    // before Confirm. Staged rows wait in RAM only (never logged, never synced).
    let import_weak = main_window.as_weak();
    let import_vault = Arc::clone(&active_vault);
    let import_master = Arc::clone(&active_master_pw);
    main_window.on_pick_import_file(move || {
        if let Some(ui) = import_weak.upgrade() {
            if ui.get_is_decoy() {
                ui.set_import_status("⛔ Decoy mode is read-only.".into());
                return;
            }
            ui.set_import_status("⏳ Waiting for file picker…".into());
        }
        let weak = import_weak.clone();
        let vault_clone = Arc::clone(&import_vault);
        let master_clone = Arc::clone(&import_master);
        std::thread::spawn(move || {
            // Native dialog blocks this worker only — UI stays at 60 FPS.
            let picked = rfd::FileDialog::new()
                .set_title("Import ANY vault export")
                .add_filter("vault exports", &["json", "csv", "xml", "tsv", "txt"])
                .add_filter("all files", &["*"])
                .pick_file();
            let Some(path) = picked else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_import_status("No file chosen.".into());
                    }
                });
                return;
            };
            let master_opt = lock_master_pw(&master_clone).clone();
            let Some(_) = master_opt else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_import_status("⚠️ Vault not unlocked.".into());
                    }
                });
                return;
            };
            // Parse only; dry-merge into a CLONE for exact counts; stash the
            // rows for the Confirm step. Live vault untouched.
            let res: Result<(importer::ImportSummary, Vec<importer::RawItem>, String), String> = {
                let vault = lock_vault(&vault_clone);
                match importer::parse_import_file(&path) {
                    Ok((raws, mut summary)) => {
                        let mut probe = vault.clone();
                        importer::merge(&mut probe, raws.clone(), &mut summary);
                        probe.ensure_folders();
                        summary.folders = probe.folders.len();
                        Ok((summary, raws, path.to_string_lossy().into_owned()))
                    }
                    Err(e) => Err(e.to_string()),
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match res {
                    Ok((summary, raws, path_str)) => {
                        *pending_import_store().lock().unwrap() = Some(PendingImport {
                            raws,
                            source: summary.source.clone(),
                            path_str,
                        });
                        ui.set_import_preview_text(
                            format!("👁️ Preview — {} — review, then Confirm to merge.", summary.headline()).into(),
                        );
                        ui.set_show_import_preview(true);
                        ui.set_import_status("👁️ Preview ready — nothing merged yet.".into());
                    }
                    Err(e) => {
                        ui.set_import_status(format!("⚠️ Import blocked: {e}").into());
                    }
                }
            });
        });
    });
    let confirm_weak = main_window.as_weak();
    let confirm_vault = Arc::clone(&active_vault);
    let confirm_master = Arc::clone(&active_master_pw);
    let confirm_search = Arc::clone(&search_state);
    let confirm_qb = quick_bar.as_weak();
    main_window.on_confirm_import_file(move || {
        let staged = pending_import_store().lock().unwrap().take();
        let Some(staged) = staged else {
            if let Some(ui) = confirm_weak.upgrade() {
                ui.set_import_status("⚠️ Nothing staged — pick a file first.".into());
            }
            return;
        };
        if let Some(ui) = confirm_weak.upgrade() {
            ui.set_show_import_preview(false);
            ui.set_import_status("⏳ Merging…".into());
        }
        let weak = confirm_weak.clone();
        let vault_clone = Arc::clone(&confirm_vault);
        let master_clone = Arc::clone(&confirm_master);
        let search_clone = Arc::clone(&confirm_search);
        let qb_clone = confirm_qb.clone();
        std::thread::spawn(move || {
            let master_opt = lock_master_pw(&master_clone).clone();
            let Some(master_pw) = master_opt else {
                *pending_import_store().lock().unwrap() = Some(staged);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_show_import_preview(true);
                        ui.set_import_status("⚠️ Vault not unlocked.".into());
                    }
                });
                return;
            };
            // Real merge + re-seal under one lock (rollback on disk failure).
            let res: Result<importer::ImportSummary, String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                let mut summary = importer::ImportSummary {
                    source: staged.source.clone(),
                    ..Default::default()
                };
                importer::merge(&mut vault, staged.raws, &mut summary);
                vault.ensure_folders();
                summary.folders = vault.folders.len();
                match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                    Ok(()) => Ok(summary),
                    Err(e) => {
                        *vault = snapshot;
                        Err(e)
                    }
                }
            };
            let path_str = staged.path_str.clone();
            let imp_fav_vc = Arc::clone(&vault_clone);
            let imp_fav_sc = Arc::clone(&search_clone);
            let imp_fav_w = weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match res {
                    Ok(summary) => {
                        {
                            let vault = lock_vault(&vault_clone);
                            let f = search_clone.lock().unwrap().clone();
                            set_paged_credentials(&ui, vault_to_items(&vault, &f));
                            sync_folders_to_ui(&vault, &ui);
                            if let Some(qb) = qb_clone.upgrade() {
                                qb.set_filtered_results(vault_quickbar(&vault, "", f.travel_only));
                            }
                        }
                        ui.set_import_status(summary.headline().into());
                        ui.set_notification_text(
                            format!("📥 Imported {} items.", summary.total()).into(),
                        );
                        // Cat 8: the source file still holds PLAINTEXT secrets —
                        // offer a DoD shred instead of silently leaving it behind.
                        ui.set_shred_source_path(path_str.into());
                        ui.set_show_shred_source(true);
                        trigger_sync_push(ui.as_weak());
                        // Fresh URLs may need icons — background pass only.
                        trigger_favicon_prefetch(imp_fav_vc, imp_fav_sc, imp_fav_w);
                    }
                    Err(e) => {
                        ui.set_import_status(format!("⚠️ Import blocked: {e}").into());
                    }
                }
            });
        });
    });

    let cancel_weak = main_window.as_weak();
    main_window.on_cancel_import_file(move || {
        *pending_import_store().lock().unwrap() = None;
        if let Some(ui) = cancel_weak.upgrade() {
            ui.set_show_import_preview(false);
            ui.set_import_status("Import cancelled — nothing merged.".into());
        }
    });

    // Cat 8: shred the plaintext import source (DoD 3-pass) on confirm.
    let shred_weak_yes = main_window.as_weak();
    main_window.on_confirm_shred_source(move || {
        let Some(ui) = shred_weak_yes.upgrade() else {
            return;
        };
        let target = ui.get_shred_source_path().to_string();
        ui.set_show_shred_source(false);
        ui.set_shred_source_path("".into());
        if target.trim().is_empty() {
            return;
        }
        ui.set_import_status("🔥 Shredding plaintext source…".into());
        let weak = shred_weak_yes.clone();
        std::thread::spawn(move || {
            let res = security::shredder::shred_file(std::path::Path::new(&target));
            if res.is_ok() {
                security::access_log::log_event("shred", "import source");
            }
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    ui.set_import_status(match res {
                        Ok(()) => "🔥 Source shredded — no plaintext remains.".into(),
                        Err(e) => format!("⚠️ Shred failed: {e}").into(),
                    });
                }
            });
        });
    });
    let shred_weak_no = main_window.as_weak();
    main_window.on_cancel_shred_source(move || {
        if let Some(ui) = shred_weak_no.upgrade() {
            ui.set_show_shred_source(false);
            ui.set_shred_source_path("".into());
            ui.set_import_status("Source file kept (plaintext — guard it).".into());
        }
    });

    // Phase 21: PNG vault locker — hide / restore via native dialogs.
    let stego_weak = main_window.as_weak();
    main_window.on_stego_hide(move || {
        if let Some(ui) = stego_weak.upgrade() {
            if ui.get_is_decoy() {
                ui.set_sync_status("⛔ Decoy mode is read-only.".into());
                return;
            }
            ui.set_sync_status("⏳ Pick a carrier PNG…".into());
        }
        let weak = stego_weak.clone();
        std::thread::spawn(move || {
            let carrier = rfd::FileDialog::new()
                .set_title("Pick carrier PNG (large photo)")
                .add_filter("PNG images", &["png"])
                .pick_file();
            let Some(carrier) = carrier else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_sync_status("No carrier chosen.".into());
                    }
                });
                return;
            };
            let out = rfd::FileDialog::new()
                .set_title("Save concealed PNG as")
                .set_file_name("hidden_vault.png")
                .add_filter("PNG images", &["png"])
                .save_file();
            let Some(out) = out else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_sync_status("Save cancelled.".into());
                    }
                });
                return;
            };
            let payload = match std::fs::read(VAULT_FILE) {
                Ok(b) => b,
                Err(e) => {
                    let msg = format!("⚠️ Cannot read vault: {e}");
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_sync_status(msg.into());
                        }
                    });
                    return;
                }
            };
            let res = security::steganography::embed_in_png(&carrier, &payload, &out);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    match res {
                        Ok(()) => ui.set_sync_status(
                            "🖼️ Vault concealed inside PNG successfully!".into(),
                        ),
                        Err(e) => ui.set_sync_status(format!("⚠️ {e}").into()),
                    }
                }
            });
        });
    });

    let stegor_weak = main_window.as_weak();
    main_window.on_stego_restore(move || {
        if let Some(ui) = stegor_weak.upgrade() {
            if ui.get_is_decoy() {
                ui.set_sync_status("⛔ Decoy mode is read-only.".into());
                return;
            }
            ui.set_sync_status("⏳ Pick a concealed PNG…".into());
        }
        let weak = stegor_weak.clone();
        std::thread::spawn(move || {
            let picked = rfd::FileDialog::new()
                .set_title("Pick PNG holding a vault")
                .add_filter("PNG images", &["png"])
                .pick_file();
            let Some(picked) = picked else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_sync_status("No image chosen.".into());
                    }
                });
                return;
            };
            let bytes = match security::steganography::extract_from_png(&picked) {
                Ok(b) => b,
                Err(e) => {
                    let msg = format!("⚠️ {e}");
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_sync_status(msg.into());
                        }
                    });
                    return;
                }
            };
            // Safety: keep a backup of the live vault before adopting.
            if std::path::Path::new(VAULT_FILE).exists() {
                let _ = std::fs::copy(VAULT_FILE, "my_secure_vault.bak.enc");
            }
            let res = security::shredder::secure_write(std::path::Path::new(VAULT_FILE), &bytes);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    match res {
                        Ok(()) => {
                            ui.set_sync_status(
                                "🔓 Vault restored from image — unlock with its master password.".into(),
                            );
                            ui.set_notification_text(
                                "🔓 Vault restored from image. Previous kept as .bak.enc.".into(),
                            );
                        }
                        Err(e) => ui.set_sync_status(format!("⚠️ Adopt failed: {e}").into()),
                    }
                }
            });
        });
    });

    // --- Travel Mode toggle. ON is instant; OFF demands master reprompt. ---
    let travel_weak = main_window.as_weak();
    let travel_state = Arc::clone(&travel_mode);
    let travel_vault = Arc::clone(&active_vault);
    let travel_search = Arc::clone(&search_state);
    main_window.on_set_travel_mode(move |on| {
        let Some(ui) = travel_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        if !on {
            // Disarming exposes hidden items — gate behind master password.
            ui.set_rp_action(4);
            ui.set_rp_kind(0);
            ui.set_rp_id("".into());
            ui.set_rp_user("".into());
            ui.set_rp_secret("".into());
            ui.set_rp_error("".into());
            ui.set_rp_show(true);
            return;
        }
        *travel_state.lock().unwrap() = true;
        ui.set_is_travel_mode(true);
        let vault = travel_vault.lock().unwrap();
        let mut f = travel_search.lock().unwrap().clone();
        f.travel_only = true;
        *travel_search.lock().unwrap() = f.clone();
        set_paged_credentials(&ui, vault_to_items(&vault, &f));
        ui.set_notification_text("✈️ TRAVEL MODE ACTIVE — only travel-safe items shown.".into());
    });

    // --- Attachments: pick / download / delete (logins + licenses) ---
    let att_weak = main_window.as_weak();
    let att_vault = Arc::clone(&active_vault);
    let att_master = Arc::clone(&active_master_pw);
    let att_search = Arc::clone(&search_state);
    let att_qb = quick_bar.as_weak();
    let att_main = main_window.as_weak();
    main_window.on_pick_attachment(move |kind, id| {
        let Some(ui) = att_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        if !is_attachable(kind) {
            // Passkeys (7) + hub codes (8) carry no attachments.
            ui.set_notification_text(
                "📎 Attachments live on logins, licenses, notes, cards, identities + SSH keys.".into(),
            );
            return;
        }
        let weak = att_weak.clone();
        let weak_main = att_main.clone();
        let vault_clone = Arc::clone(&att_vault);
        let master_clone = Arc::clone(&att_master);
        let search_clone = Arc::clone(&att_search);
        let qb_clone = att_qb.clone();
        let id = id.as_str().to_string();
        std::thread::spawn(move || {
            let picked = rfd::FileDialog::new()
                .set_title("Attach file (max 5MB, sealed into vault)")
                .pick_file();
            let Some(path) = picked else {
                return;
            };
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    let msg = format!("⚠️ Cannot read file: {e}");
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_notification_text(msg.into());
                        }
                    });
                    return;
                }
            };
            if bytes.len() > models::MAX_ATTACHMENT_BYTES {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_notification_text("⚠️ File exceeds 5MB.".into());
                    }
                });
                return;
            }
            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file.bin")
                .to_string();
            let mime = guess_mime(&filename);
            let master_opt = lock_master_pw(&master_clone).clone();
            let Some(master_pw) = master_opt else {
                return;
            };
            let new_id = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| format!("att{}", d.as_millis()))
                .unwrap_or_else(|_| "att0".to_string());
            let saved: Result<Vault, String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                let Some(list) = attachments_mut(&mut vault, kind, &id) else {
                    return;
                };
                if list.len() >= 10 {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_notification_text("⚠️ Max 10 attachments per item.".into());
                        }
                    });
                    return;
                }
                list.push(models::EncryptedAttachment {
                    id: new_id,
                    filename,
                    mime_type: mime,
                    size_bytes: bytes.len(),
                    data: bytes,
                });
                match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                    Ok(()) => Ok(vault.clone()),
                    Err(e) => {
                        *vault = snapshot;
                        Err(e)
                    }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak_main.upgrade() else {
                    return;
                };
                match saved {
                    Ok(v) => {
                        // Refresh detail attachment list for this item.
                        let files = attachments_of(&v, kind, &id);
                        ui.set_d_attachments(attachments_to_ui(&files));
                        let f = search_clone.lock().unwrap().clone();
                        set_paged_credentials(&ui, vault_to_items(&v, &f));
                        if let Some(qb) = qb_clone.upgrade() {
                            qb.set_filtered_results(vault_quickbar(&v, "", search_clone.lock().unwrap().travel_only));
                        }
                        ui.set_notification_text("📎 File sealed into vault.".into());
                        trigger_sync_push(ui.as_weak());
                    }
                    Err(e) => {
                        ui.set_notification_text(format!("❌ Attach failed: {e}").into());
                    }
                }
            });
        });
    });

    // Download = save dialog + plaintext write of that ONE file (user's explicit act).
    let dl_weak = main_window.as_weak();
    let dl_vault = Arc::clone(&active_vault);
    main_window.on_download_attachment(move |kind, id, att_id| {
        let Some(ui) = dl_weak.upgrade() else {
            return;
        };
        let vault = lock_vault(&dl_vault);
        let found: Option<(String, Vec<u8>)> = attachments_of(&vault, kind, id.as_str())
            .iter()
            .find(|a| a.id == att_id.as_str())
            .map(|a| (a.filename.clone(), a.data.clone()));
        drop(vault);
        let Some((filename, data)) = found else {
            ui.set_notification_text("⚠️ Attachment not found.".into());
            return;
        };
        let weak = dl_weak.clone();
        std::thread::spawn(move || {
            let dest = rfd::FileDialog::new()
                .set_title("Export attachment")
                .set_file_name(&filename)
                .save_file();
            let Some(dest) = dest else {
                return;
            };
            let msg = match std::fs::write(&dest, &data) {
                Ok(()) => {
                    security::access_log::log_event("export", "attachment");
                    format!("💾 Exported '{}'.", filename)
                }
                Err(e) => format!("⚠️ Export failed: {e}"),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    ui.set_notification_text(msg.into());
                }
            });
        });
    });

    // In-RAM attachment preview: images decode to pixels, text to string,
    // everything else gets an info panel. Plaintext NEVER touches disk.
    let pv_weak = main_window.as_weak();
    let pv_vault = Arc::clone(&active_vault);
    main_window.on_preview_attachment(move |kind, id, att_id| {
        let Some(ui) = pv_weak.upgrade() else {
            return;
        };
        let vault = lock_vault(&pv_vault);
        let found: Option<(String, Vec<u8>)> = attachments_of(&vault, kind, id.as_str())
            .iter()
            .find(|a| a.id == att_id.as_str())
            .map(|a| (a.filename.clone(), a.data.clone()));
        drop(vault);
        let Some((filename, data)) = found else {
            ui.set_notification_text("⚠️ Attachment not found.".into());
            return;
        };
        let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
        let info = format!("{} • {}", filename, human_bytes(data.len()));
        ui.set_att_preview_id(att_id);
        ui.set_att_preview_name(filename.into());
        ui.set_att_preview_info(info.into());
        if matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "webp" | "gif" | "bmp") {
            match png_bytes_to_image(&data) {
                Some(img) => {
                    ui.set_att_preview_image(img);
                    ui.set_att_preview_text(String::new().into());
                    ui.set_att_preview_kind("image".into());
                }
                None => {
                    ui.set_att_preview_kind("other".into());
                    ui.set_att_preview_text(String::new().into());
                }
            }
        } else if matches!(ext.as_str(), "txt" | "md" | "json" | "csv" | "log" | "xml" | "html") {
            let mut text = String::from_utf8_lossy(&data).into_owned();
            if text.len() > 8000 {
                text.truncate(8000);
                text.push_str("\n… (truncated, export for full file)");
            }
            ui.set_att_preview_text(text.into());
            ui.set_att_preview_kind("text".into());
        } else {
            ui.set_att_preview_text(String::new().into());
            ui.set_att_preview_kind("other".into());
        }
        ui.set_att_preview(true);
    });

    // Delete attachment → re-seal → refresh detail list.
    let del_weak = main_window.as_weak();
    let del_vault = Arc::clone(&active_vault);
    let del_master = Arc::clone(&active_master_pw);
    let del_search = Arc::clone(&search_state);
    let del_qb = quick_bar.as_weak();
    let del_main = main_window.as_weak();
    main_window.on_delete_attachment(move |kind, id, att_id| {
        let Some(ui) = del_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let weak = del_main.clone();
        let vault_clone = Arc::clone(&del_vault);
        let master_clone = Arc::clone(&del_master);
        let search_clone = Arc::clone(&del_search);
        let qb_clone = del_qb.clone();
        let (id, att_id) = (id.as_str().to_string(), att_id.as_str().to_string());
        std::thread::spawn(move || {
            let master_opt = lock_master_pw(&master_clone).clone();
            let Some(master_pw) = master_opt else {
                return;
            };
            let saved: Result<Vault, String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                let removed = attachments_mut(&mut vault, kind, &id).map(|list| {
                    let before = list.len();
                    list.retain(|a| a.id != att_id);
                    before != list.len()
                });
                if removed != Some(true) {
                    Err("Attachment not found".to_string())
                } else {
                    match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                        Ok(()) => Ok(vault.clone()),
                        Err(e) => {
                            *vault = snapshot;
                            Err(e)
                        }
                    }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match saved {
                    Ok(v) => {
                        let files = attachments_of(&v, kind, &id);
                        ui.set_d_attachments(attachments_to_ui(&files));
                        let f = search_clone.lock().unwrap().clone();
                        set_paged_credentials(&ui, vault_to_items(&v, &f));
                        if let Some(qb) = qb_clone.upgrade() {
                            qb.set_filtered_results(vault_quickbar(&v, "", search_clone.lock().unwrap().travel_only));
                        }
                        ui.set_notification_text("🗑️ Attachment deleted.".into());
                        trigger_sync_push(ui.as_weak());
                    }
                    Err(e) => {
                        ui.set_notification_text(format!("❌ Delete failed: {e}").into());
                    }
                }
            });
        });
    });

    // Travel-safe flag flip (any of the 6 kinds) → re-seal → refresh.
    let trav_weak = main_window.as_weak();
    let trav_vault = Arc::clone(&active_vault);
    let trav_master = Arc::clone(&active_master_pw);
    main_window.on_toggle_travel(move |kind, id| {
        let Some(ui) = trav_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let weak = trav_weak.clone();
        let vault_clone = Arc::clone(&trav_vault);
        let master_clone = Arc::clone(&trav_master);
        let id = id.as_str().to_string();
        std::thread::spawn(move || {
            let master_opt = lock_master_pw(&master_clone).clone();
            let Some(master_pw) = master_opt else {
                return;
            };
            let saved: Result<(Vault, bool), String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                let flipped: Option<bool> = match kind {
                    1 => vault.credentials.iter_mut().find(|c| c.id == id).map(|c| { c.travel_safe = !c.travel_safe; c.travel_safe }),
                    2 => vault.licenses.iter_mut().find(|l| l.id == id).map(|l| { l.travel_safe = !l.travel_safe; l.travel_safe }),
                    3 => vault.notes.iter_mut().find(|n| n.id == id).map(|n| { n.travel_safe = !n.travel_safe; n.travel_safe }),
                    4 => vault.cards.iter_mut().find(|k| k.id == id).map(|k| { k.travel_safe = !k.travel_safe; k.travel_safe }),
                    5 => vault.identities.iter_mut().find(|i| i.id == id).map(|i| { i.travel_safe = !i.travel_safe; i.travel_safe }),
                    6 => vault.ssh_keys.iter_mut().find(|s| s.id == id).map(|s| { s.travel_safe = !s.travel_safe; s.travel_safe }),
                    _ => None,
                };
                let Some(now) = flipped else {
                    return;
                };
                match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                    Ok(()) => Ok((vault.clone(), now)),
                    Err(e) => {
                        *vault = snapshot;
                        Err(e)
                    }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    match saved {
                        Ok((v, now)) => {
                            ui.set_d_travel(now);
                            ui.set_notification_text(
                                if now { "✈️ Marked safe for travel.".into() } else { "Item hidden in Travel Mode.".into() },
                            );
                            let _ = v;
                        }
                        Err(e) => {
                            ui.set_notification_text(format!("⚠️ {e}").into());
                        }
                    }
                }
            });
        });
    });
    // Phase 24: HOTP counter advance — renders the NEXT code per RFC 4226.
    let hotp_weak = main_window.as_weak();
    let hotp_vault = Arc::clone(&active_vault);
    let hotp_master = Arc::clone(&active_master_pw);
    main_window.on_hotp_next(move |id| {
        // Decoy MUST NOT advance here: the re-seal below would overwrite the
        // real vault file with decoy content under the duress password.
        if let Some(ui) = hotp_weak.upgrade() {
            if ui.get_is_decoy() {
                ui.set_notification_text("⛔ Decoy mode is read-only.".into());
                return;
            }
        }
        let weak = hotp_weak.clone();
        let vault_clone = Arc::clone(&hotp_vault);
        let master_clone = Arc::clone(&hotp_master);
        let id = id.as_str().to_string();
        std::thread::spawn(move || {
            let master_opt = lock_master_pw(&master_clone).clone();
            let Some(master_pw) = master_opt else {
                return;
            };
            let saved: Result<Vault, String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                let Some(acc) = vault.totp_accounts.iter_mut().find(|a| a.id == id) else {
                    return;
                };
                if acc.otp_type.trim().to_lowercase() != "hotp" {
                    return;
                }
                acc.counter = acc.counter.saturating_add(1);
                match save_vault_secret(&vault, &master_pw, VAULT_FILE) {
                    Ok(()) => Ok(vault.clone()),
                    Err(e) => {
                        *vault = snapshot;
                        Err(e)
                    }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    match saved {
                        Ok(v) => {
                                ui.set_auth_accounts(rebuild_auth_list(&v));
                            ui.set_auth_rows(rebuild_auth_rows(&v, ui.get_totp_search_query().as_str()));
                            ui.set_notification_text("🔢 HOTP advanced to next code.".into());
                            trigger_sync_push(ui.as_weak());
                        }
                        Err(e) => {
                            ui.set_notification_text(format!("⚠️ HOTP advance failed: {e}").into());
                        }
                    }
                }
            });
        });
    });

    main_window.on_lock_now(move || {
        // Cat 8: a copied secret must not outlive the session — flush the
        // clipboard BEFORE the process (and its guarded auto-clear thread) dies.
        windows_native::clipboard::flush_now();
        security::access_log::log_event("lock", "manual exit");
        std::process::exit(0);
    });
    // Close-to-tray preference toggle (persisted, default ON).
    let traypref_weak = main_window.as_weak();
    main_window.on_set_tray_minimize(move |on| {
        windows_native::tray::save_tray_pref(on);
        if let Some(ui) = traypref_weak.upgrade() {
            ui.set_tray_minimize(on);
            ui.set_notification_text(if on {
                "📥 Close button minimizes to tray.".into()
            } else {
                "⚠️ Close button now exits the app.".into()
            });
        }
    });
    // Scheduled backups: toggle / interval / folder / run-now.
    let bk_weak = main_window.as_weak();
    main_window.on_set_backup_enabled(move |on| {
        let mut cfg = storage::backup_scheduler::load_config();
        cfg.enabled = on;
        let msg = match storage::backup_scheduler::save_config(&cfg) {
            Ok(()) => if on { "💾 Scheduled backups ON." } else { "💾 Scheduled backups OFF." },
            Err(_) => "⚠️ Could not save schedule.",
        };
        if let Some(ui) = bk_weak.upgrade() {
            ui.set_backup_enabled(on);
            ui.set_notification_text(msg.into());
            security::access_log::log_event("backup", if on { "schedule on" } else { "schedule off" });
        }
    });
    let bki_weak = main_window.as_weak();
    main_window.on_set_backup_interval(move |days| {
        let days = (days as u32).clamp(1, 30);
        let mut cfg = storage::backup_scheduler::load_config();
        cfg.interval_days = if days <= 1 { 1 } else if days <= 7 { 7 } else { 30 };
        let label = cfg.interval_days;
        let ok = storage::backup_scheduler::save_config(&cfg).is_ok();
        if let Some(ui) = bki_weak.upgrade() {
            ui.set_backup_interval(label as i32);
            ui.set_notification_text(if ok {
                format!("💾 Backup interval: every {label}d.").into()
            } else {
                "⚠️ Could not save schedule.".into()
            });
        }
    });
    let bkb_weak = main_window.as_weak();
    main_window.on_browse_backup_dir(move || {
        let picked = rfd::FileDialog::new()
            .set_title("Scheduled backup folder")
            .pick_folder();
        let Some(dir) = picked else { return };
        let mut cfg = storage::backup_scheduler::load_config();
        cfg.backup_dir = dir.to_string_lossy().into_owned();
        let ok = storage::backup_scheduler::save_config(&cfg).is_ok();
        if let Some(ui) = bkb_weak.upgrade() {
            ui.set_backup_dir(cfg.backup_dir.clone().into());
            ui.set_notification_text(if ok {
                "💾 Backup folder updated.".into()
            } else {
                "⚠️ Could not save schedule.".into()
            });
        }
    });
    let bkn_weak = main_window.as_weak();
    main_window.on_backup_now(move || {
        if let Some(ui) = bkn_weak.upgrade() {
            ui.set_backup_status("⏳ Backing up…".into());
        }
        let weak = bkn_weak.clone();
        std::thread::spawn(move || {
            let now = crate::models::current_timestamp();
            let mut cfg = storage::backup_scheduler::load_config();
            let res = storage::backup_scheduler::run_backup(&mut cfg, now);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    match res {
                        Ok(o) => {
                            ui.set_backup_status(
                                format!("✅ {} (pruned {})", o.path, o.pruned).into(),
                            );
                            ui.set_notification_text("💾 Manual backup complete.".into());
                        }
                        Err(e) => {
                            ui.set_backup_status(format!("⚠️ Backup failed: {e}").into());
                        }
                    }
                }
            });
        });
    });
    let bb_weak = main_window.as_weak();
    main_window.on_set_blackout(move |on| {
        if let Some(ui) = bb_weak.upgrade() {
            #[cfg(windows)]
            {
                if on {
                    windows_native::display_guard::guard_window(ui.window());
                } else {
                    windows_native::display_guard::clear_window(ui.window());
                }
                // Force repaint so DWM flushes its visual cache instantly —
                // no manual window move needed to unmask.
                ui.window().request_redraw();
                windows_native::display_guard::save_blackout_pref(on);
            }
            println!("🛡️ Blackout Guard set to: {}", on);
            ui.set_blackout_enabled(on);
        }
    });
    // Favicons toggle: persisted pref, list repaint, prefetch when ON.
    let fav_weak = main_window.as_weak();
    let fav_vault = Arc::clone(&active_vault);
    let fav_search = Arc::clone(&search_state);
    main_window.on_set_favicons(move |on| {
        let Some(ui) = fav_weak.upgrade() else {
            return;
        };
        crate::core::favicon::set_show_favicons(on);
        ui.set_favicons_enabled(on);
        ui.set_notification_text(if on {
            "🖼️ Website favicons ON (cached, offline-friendly).".into()
        } else {
            "🖼️ Website favicons OFF (letter icons).".into()
        });
        if on {
            trigger_favicon_prefetch(
                Arc::clone(&fav_vault),
                Arc::clone(&fav_search),
                fav_weak.clone(),
            );
        } else {
            let f = fav_search.lock().unwrap().clone();
            let v = lock_vault(&fav_vault);
            set_paged_credentials(&ui, vault_to_items(&v, &f));
            ui.set_d_has_icon(false);
        }
    });
    // Per-domain logo override: pick a local image for the open login's
    // domain (worker thread — the native dialog blocks). Validated before a
    // byte hits disk; RAM + list + detail repaint on success.
    let ov_weak = main_window.as_weak();
    let ov_vault = Arc::clone(&active_vault);
    let ov_search = Arc::clone(&search_state);
    main_window.on_override_favicon(move |id| {
        let Some(ui) = ov_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        let id = id.as_str().to_string();
        let weak = ov_weak.clone();
        let vault_clone = Arc::clone(&ov_vault);
        let search_clone = Arc::clone(&ov_search);
        std::thread::spawn(move || {
            let target: Option<(String, String)> = {
                let v = lock_vault(&vault_clone);
                v.credentials.iter().find(|c| c.id == id).map(|c| {
                    (
                        c.title.clone(),
                        c.urls.first().map(|u| u.url().to_string()).unwrap_or_default(),
                    )
                })
            };
            let Some((title, url)) = target else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_notification_text("⚠️ Logo override needs an open login.".into());
                    }
                });
                return;
            };
            let Some(domain) = crate::core::favicon::icon_domain(&title, &url) else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_notification_text("⚠️ No domain on this item (title/URL).".into());
                    }
                });
                return;
            };
            let picked = rfd::FileDialog::new()
                .set_title(format!("Logo for {domain} (PNG/ICO/JPG)"))
                .add_filter("images", &["png", "ico", "jpg", "jpeg", "webp", "bmp", "gif"])
                .pick_file();
            let Some(path) = picked else {
                return;
            };
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    let msg = format!("⚠️ Cannot read file: {e}");
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_notification_text(msg.into());
                        }
                    });
                    return;
                }
            };
            match crate::core::favicon::save_custom_icon(&domain, &bytes) {
                Err(e) => {
                    let msg = format!("⚠️ Not a usable logo: {e}");
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_notification_text(msg.into());
                        }
                    });
                }
                Ok(_) => {
                    {
                        let mut cache = favicon_bytes().lock().unwrap_or_else(|p| p.into_inner());
                        cache.insert(domain.clone(), bytes);
                    }
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            let f = search_clone.lock().unwrap().clone();
                            let v = lock_vault(&vault_clone);
                            set_paged_credentials(&ui, vault_to_items(&v, &f));
                            if ui.get_d_kind() == 1 && ui.get_d_id().as_str() == id.as_str() {
                                if let Some(img) = favicon_for_item(&title, &url) {
                                    ui.set_d_icon(img);
                                    ui.set_d_has_icon(true);
                                }
                            }
                            ui.set_notification_text(
                                format!("🖼️ Custom logo saved for {domain}.").into(),
                            );
                        }
                    });
                }
            }
        });
    });
    // Clear all custom logos (fetched cache + disk untouched).
    let cc_weak = main_window.as_weak();
    let cc_vault = Arc::clone(&active_vault);
    let cc_search = Arc::clone(&search_state);
    main_window.on_clear_custom_favicons(move || {
        let Some(ui) = cc_weak.upgrade() else {
            return;
        };
        let n = crate::core::favicon::clear_custom_icons();
        clear_favicon_bytes();
        crate::core::favicon::clear_memory_cache();
        let f = cc_search.lock().unwrap().clone();
        let v = lock_vault(&cc_vault);
        set_paged_credentials(&ui, vault_to_items(&v, &f));
        ui.set_d_has_icon(false);
        ui.set_notification_text(
            if n == 0 {
                "🖼️ No custom logos to clear.".into()
            } else {
                format!("🧹 Cleared {n} custom logo{}.", if n == 1 { "" } else { "s" }).into()
            },
        );
        // Re-resolve fetched icons in the background (attempted-set was reset).
        trigger_favicon_prefetch(Arc::clone(&cc_vault), Arc::clone(&cc_search), cc_weak.clone());
    });
    // Cat 8 AND-mode toggle: password + Hello both required to unlock.
    let and_weak = main_window.as_weak();
    main_window.on_set_and_mode(move |on| {
        if let Some(ui) = and_weak.upgrade() {
            ui.set_and_mode(on);
            ui.set_notification_text(if on {
                "🔐 Two-factor unlock ON (password + Hello).".into()
            } else {
                "🔓 Two-factor unlock OFF.".into()
            });
        }
    });
    // Moat #4: hands-free 2FA chain opt-out (`chain_2fa.pref`, missing = ON).
    let chain_weak = main_window.as_weak();
    main_window.on_set_chain_2fa(move |on| {
        let _ = std::fs::write("chain_2fa.pref", if on { "1" } else { "0" });
        if let Some(ui) = chain_weak.upgrade() {
            ui.set_chain_2fa(on);
            ui.set_notification_text(if on {
                "⚡ Hands-free 2FA ON.".into()
            } else {
                "⌨️ Hands-free 2FA OFF — codes stay manual.".into()
            });
        }
    });
    // App PIN setup/removal (Settings, unlocked only — seals the LIVE master;
    // decoy mode is read-only like every other mutation path).
    let pinset_weak = main_window.as_weak();
    let pinset_master = Arc::clone(&active_master_pw);
    main_window.on_setup_app_pin(move |pin, confirm| {
        let Some(ui) = pinset_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_pin_status("⛔ Decoy mode is read-only.".into());
            return;
        }
        let (pin, confirm) = (pin.as_str().trim().to_string(), confirm.as_str().trim().to_string());
        if pin != confirm {
            ui.set_pin_status("⚠️ PINs do not match.".into());
            return;
        }
        let master_opt = lock_master_pw(&pinset_master).clone();
        let Some(master_pw) = master_opt else {
            ui.set_pin_status("❌ Vault not unlocked!".into());
            return;
        };
        use secrecy::ExposeSecret;
        match security::app_pin::enroll(Path::new("."), &pin, master_pw.expose_secret()) {
            Ok(()) => {
                ui.set_pin_available(true);
                ui.set_pin_status("✅ App PIN set — lock screen shows PIN unlock on this PC.".into());
            }
            Err(e) => {
                ui.set_pin_status(format!("⚠️ {e}").into());
            }
        }
    });
    let pindis_weak = main_window.as_weak();
    main_window.on_disable_app_pin(move || {
        let Some(ui) = pindis_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_pin_status("⛔ Decoy mode is read-only.".into());
            return;
        }
        security::app_pin::disable(Path::new("."));
        ui.set_pin_available(false);
        ui.set_pin_status("App PIN removed from this PC.".into());
    });
    // Extension PIN management (Settings is the ONLY writer — the extension
    // itself only reads the served hash). Unlocked + non-decoy required.
    // Raw PINs arrive here (Slint has no SHA-256); they are hashed then
    // dropped before sealing — never logged, never stored.
    let epinset_weak = main_window.as_weak();
    let epinset_master = Arc::clone(&active_master_pw);
    main_window.on_setup_ext_pin(move |pin, confirm| {
        let Some(ui) = epinset_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_ext_pin_status("⛔ Decoy mode is read-only.".into());
            return;
        }
        let (pin, confirm) = (pin.as_str().trim().to_string(), confirm.as_str().trim().to_string());
        if pin != confirm {
            ui.set_ext_pin_status("⚠️ PINs do not match.".into());
            return;
        }
        if pin.len() < 4 || pin.len() > 8 || !pin.bytes().all(|c| c.is_ascii_digit()) {
            ui.set_ext_pin_status("⚠️ PIN must be 4–8 digits.".into());
            return;
        }
        let master_opt = lock_master_pw(&epinset_master).clone();
        if master_opt.is_none() {
            ui.set_ext_pin_status("❌ Vault not unlocked!".into());
            return;
        }
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(pin.as_bytes());
        let hash_hex: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        drop(pin);
        drop(confirm);
        match security::ext_pin::set(Path::new("."), &hash_hex) {
            Ok(()) => {
                ui.set_ext_pin_set(true);
                ui.set_ext_pin_status("✅ Extension PIN set — browser will ask for it.".into());
            }
            Err(e) => {
                ui.set_ext_pin_status(format!("⚠️ {e}").into());
            }
        }
    });
    let epindis_weak = main_window.as_weak();
    main_window.on_disable_ext_pin(move || {
        let Some(ui) = epindis_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_ext_pin_status("⛔ Decoy mode is read-only.".into());
            return;
        }
        security::ext_pin::clear(Path::new("."));
        ui.set_ext_pin_set(false);
        ui.set_ext_pin_status("Extension PIN removed — browser is unmanaged.".into());
    });
    // Wire-up #3: dynamic clipboard timeout (all copy paths read the atomic).
    let ct_weak = main_window.as_weak();
    let ct_store = Arc::clone(&clipboard_timeout_secs);
    main_window.on_set_clipboard_timeout(move |secs| {
        let v = (secs as u64).clamp(5, 300);
        ct_store.store(v, std::sync::atomic::Ordering::SeqCst);
        if let Some(ui) = ct_weak.upgrade() {
            ui.set_clipboard_timeout(secs);
            ui.set_notification_text(format!("Clipboard auto-clear: {secs}s").into());
        }
    });
    // Wire-up #3: auto-lock timeout + activity touch.
    let al_weak = main_window.as_weak();
    let al_store = Arc::clone(&autolock_timeout_mins);
    let al_touch = Arc::clone(&last_activity);
    main_window.on_set_autolock_timeout(move |mins| {
        let v = (mins as u64).clamp(0, 120);
        al_store.store(v, std::sync::atomic::Ordering::SeqCst);
        if let Ok(mut t) = al_touch.lock() {
            *t = std::time::Instant::now();
        }
        if let Some(ui) = al_weak.upgrade() {
            ui.set_autolock_timeout(mins);
            if mins == 0 { ui.set_notification_text("Auto-lock: Never".into()); } else { ui.set_notification_text(format!("Auto-lock: {mins} min").into()); }
        }
    });
    // Cat 8 kill-switch: one toggle silences sync + HIBP audit paths.
    let ks_weak = main_window.as_weak();
    main_window.on_set_offline_mode(move |off| {
        set_net_allowed(!off);
        if let Some(ui) = ks_weak.upgrade() {
            ui.set_offline_mode(off);
            ui.set_sync_status(if off {
                "📴 Offline mode — network silenced.".into()
            } else {
                "🌐 Online — sync available.".into()
            });
            ui.set_notification_text(if off {
                "📴 Offline kill-switch ON.".into()
            } else {
                "🌐 Back online.".into()
            });
        }
    });
    // Phase 25: BLE proximity auto-lock settings. Persisted to proximity.json
    // on every change; the monitor resets so a renamed device never inherits
    // the old device's sightings (no false lock, no missed walk-away).
    let prox_weak_en = main_window.as_weak();
    let prox_cfg_en = Arc::clone(&prox_config);
    let prox_mon_en = Arc::clone(&prox_monitor);
    main_window.on_set_prox_enabled(move |on| {
        let Some(ui) = prox_weak_en.upgrade() else {
            return;
        };
        {
            let mut cfg = prox_config_lock(&prox_cfg_en);
            cfg.enabled = on;
            cfg.save();
        }
        if let Ok(mut m) = prox_mon_en.lock() {
            m.reset();
        }
        ui.set_prox_enabled(on);
        ui.set_notification_text(if on {
            "📱 Proximity lock ON — walk away to test it.".into()
        } else {
            "📱 Proximity lock OFF.".into()
        });
    });
    let prox_weak_dev = main_window.as_weak();
    let prox_cfg_dev = Arc::clone(&prox_config);
    let prox_mon_dev = Arc::clone(&prox_monitor);
    main_window.on_save_prox_device(move |name| {
        let Some(ui) = prox_weak_dev.upgrade() else {
            return;
        };
        let name = name.as_str().trim().to_string();
        if name.is_empty() {
            ui.set_notification_text("⚠️ Enter your phone's Bluetooth name first.".into());
            return;
        }
        if name.len() > 64 {
            ui.set_notification_text("⚠️ Device name too long (64 max).".into());
            return;
        }
        {
            let mut cfg = prox_config_lock(&prox_cfg_dev);
            cfg.device_name = name.clone();
            cfg.save();
        }
        if let Ok(mut m) = prox_mon_dev.lock() {
            m.reset();
        }
        ui.set_prox_device(name.into());
        ui.set_notification_text("📱 Tracking device saved.".into());
    });
    let prox_weak_sen = main_window.as_weak();
    let prox_cfg_sen = Arc::clone(&prox_config);
    main_window.on_set_prox_sensitivity(move |level| {
        let Some(ui) = prox_weak_sen.upgrade() else {
            return;
        };
        let threshold = windows_native::proximity_lock::threshold_for_sensitivity(level);
        {
            let mut cfg = prox_config_lock(&prox_cfg_sen);
            cfg.rssi_threshold = threshold;
            cfg.save();
        }
        ui.set_prox_sensitivity(level);
        ui.set_notification_text(
            format!("📱 Sensitivity: {threshold} dBm cutoff.").into(),
        );
    });
    // Batch-4: SSH agent status badge — real named-pipe probe, off-thread.
    let ssh_weak = main_window.as_weak();
    // Favicon manual refresh (no lock/unlock dance needed).
    let favr_weak = main_window.as_weak();
    let favr_vault = Arc::clone(&active_vault);
    let favr_search = Arc::clone(&search_state);
    main_window.on_refresh_favicons(move || {
        if let Some(ui) = favr_weak.upgrade() {
            ui.set_notification_text("🎨 Refreshing website icons…".into());
        }
        trigger_favicon_prefetch(
            Arc::clone(&favr_vault),
            Arc::clone(&favr_search),
            favr_weak.clone(),
        );
    });
    main_window.on_refresh_ssh_status(move || {        let Some(ui) = ssh_weak.upgrade() else {
            return;
        };
        ui.set_ssh_status("Probing…".into());
        let weak = ssh_weak.clone();
        std::thread::spawn(move || {
            let pipe = developer::ssh_agent::pipe_name();
            let live = developer::ssh_agent::is_serving(&pipe);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    ui.set_ssh_status(if live {
                        "● Running".into()
                    } else {
                        "○ Stopped".into()
                    });
                    ui.set_ssh_agent_running(live);
                }
            });
        });
    });
    // One-click agent Start: snapshot vault SSH keys into a background serving
    // thread. Unlocked + non-decoy only (decoy keys must never be served).
    // Lock always stops the session (see lock_vault_now) — keys die with it.
    let start_weak = main_window.as_weak();
    let start_vault = Arc::clone(&active_vault);
    let start_master = Arc::clone(&active_master_pw);
    main_window.on_start_ssh_agent(move || {
        let Some(ui) = start_weak.upgrade() else {
            return;
        };
        if ui.get_is_decoy() {
            ui.set_notification_text("⛔ Decoy mode is read-only.".into());
            return;
        }
        if lock_master_pw(&start_master).is_none() {
            ui.set_notification_text("❌ Vault not unlocked!".into());
            return;
        }
        let keys = developer::ssh_agent::collect_keys(&lock_vault(&start_vault));
        match developer::ssh_agent::start_agent(keys) {
            Ok(()) => {
                ui.set_ssh_agent_running(true);
                ui.set_ssh_status("● Running".into());
                ui.set_notification_text("🔑 SSH agent serving vault keys.".into());
                security::access_log::log_event("ssh-agent", "start");
            }
            Err(e) => {
                ui.set_notification_text(format!("⚠️ Agent not started: {e}").into());
            }
        }
    });
    let stop_weak = main_window.as_weak();
    main_window.on_stop_ssh_agent(move || {
        developer::ssh_agent::stop_agent();
        if let Some(ui) = stop_weak.upgrade() {
            ui.set_ssh_agent_running(false);
            ui.set_ssh_status("○ Stopped".into());
            ui.set_notification_text("🔑 SSH agent stopped.".into());
            security::access_log::log_event("ssh-agent", "stop");
        }
    });

    // Cat 8 access-log viewer: newest 20 events + chain verdict.
    let alog_weak = main_window.as_weak();
    main_window.on_view_access_log(move || {
        if let Some(ui) = alog_weak.upgrade() {
            let (n, valid) = security::access_log::verify();
            let fail_note = security::access_log::verify_at_detailed(std::path::Path::new("access.log")).2
                .map(|i| format!(" (first-bad line {i})"))
                .unwrap_or_default();
            let rows = security::access_log::recent_filtered(20, ui.get_access_log_hide_bridge());
            let body = if rows.is_empty() {
                "No events recorded yet.".to_string()
            } else {
                rows.join("\n")
            };
            ui.set_access_log_text(
                format!(
                    "{} entries · chain {}{}.\n\n{}",
                    n,
                    if valid { "VALID ✅" } else { "BROKEN 🚨" },
                    fail_note,
                    body
                )
                .into(),
            );
            ui.set_show_access_log(true);
        }
    });
    // Access-log bridge filter toggle (re-render with the flipped flag).
    let bridge_weak = main_window.as_weak();
    main_window.on_toggle_log_bridge(move || {
        if let Some(ui) = bridge_weak.upgrade() {
            ui.set_access_log_hide_bridge(!ui.get_access_log_hide_bridge());
            let rows = security::access_log::recent_filtered(20, ui.get_access_log_hide_bridge());
            let (n, valid) = security::access_log::verify();
            let fail_note = security::access_log::verify_at_detailed(std::path::Path::new("access.log")).2
                .map(|i| format!(" (first-bad line {i})"))
                .unwrap_or_default();
            let body = if rows.is_empty() {
                "No events recorded yet.".to_string()
            } else {
                rows.join("\n")
            };
            ui.set_access_log_text(
                format!(
                    "{} entries · chain {}{}.\n\n{}",
                    n,
                    if valid { "VALID ✅" } else { "BROKEN 🚨" },
                    fail_note,
                    body
                )
                .into(),
            );
        }
    });
    // Phase 26: anti-photography toggles (persist + mirror to Slint).
    let peep_weak = main_window.as_weak();
    main_window.on_set_peep_mode(move |on| {
        let mut cfg = security::anti_camera::load_config();
        cfg.peep_hole_enabled = on;
        security::anti_camera::save_config(&cfg);
        if let Some(ui) = peep_weak.upgrade() {
            ui.set_peep_hole_mode(on);
        }
    });
    let moire_weak = main_window.as_weak();
    main_window.on_set_moire(move |on| {
        let mut cfg = security::anti_camera::load_config();
        cfg.moire_enabled = on;
        security::anti_camera::save_config(&cfg);
        if let Some(ui) = moire_weak.upgrade() {
            ui.set_moire_guard_active(on);
        }
    });
    // Mirror persisted guards onto the UI at startup (both default OFF).
    {
        let cfg = security::anti_camera::load_config();
        main_window.set_peep_hole_mode(cfg.peep_hole_enabled);
        main_window.set_moire_guard_active(cfg.moire_enabled);
    }
    // Wire-up #4: pill click → auto-type the matched credential, hide pill.
    let pill_weak = main_window.as_weak();
    let pill_qb = quick_bar.as_weak();
    let pill_vis = Arc::clone(&quickbar_visible);
    let pill_uvis = Arc::clone(&ui_visible);
    let pill_vault = Arc::clone(&active_vault);
    let pill_app_click = Arc::clone(&pill_app);
    let pill_touch = Arc::clone(&last_activity);
    main_window.on_autofill_pill_clicked(move || {
        if let Some(ui) = pill_weak.upgrade() {
            ui.set_show_autofill_pill(false);
        }
        if let Ok(mut t) = pill_touch.lock() {
            *t = std::time::Instant::now();
        }
        let app = pill_app_click.lock().map(|a| a.clone()).unwrap_or_default();
        let (qid, user, pass, totp) = {
            let v = lock_vault(&pill_vault);
            let needle = app.to_lowercase();
            // Trashed logins never surface in autofill (active vault only).
            let live = |c: &Credential| c.deleted_at.is_none();
            let pick = if needle.is_empty() {
                v.credentials.iter().find(|c| live(c))
            } else {
                v.credentials
                    .iter()
                    .find(|c| {
                        live(c)
                            && (c.title.to_lowercase().contains(&needle)
                                || c.urls.iter().any(|u| u.url().to_lowercase().contains(&needle)))
                    })
                    .or_else(|| v.credentials.iter().find(|c| live(c)))
            };
            match pick {
                Some(c) => (
                    c.id.clone(),
                    c.username.clone(),
                    c.password.clone(),
                    c.totp_secret.clone(),
                ),
                None => return,
            }
        };
        if pass.is_empty() {
            return;
        }
        // Reprompt gate: same modal detour as QuickBar (rp_action 2 = type).
        if let Some(main_ui) = pill_weak.upgrade() {
            let gated = {
                let v = lock_vault(&pill_vault);
                reprompt_gate(&v, 1, &qid)
            };
            if let Some((g_user, g_secret)) = gated {
                main_ui.set_rp_action(2);
                main_ui.set_rp_kind(1);
                main_ui.set_rp_id(qid.into());
                main_ui.set_rp_user(g_user.into());
                main_ui.set_rp_secret(g_secret.into());
                main_ui.set_rp_error(String::new().into());
                main_ui.set_rp_show(true);
                main_ui.set_notification_text("🔒 Master re-prompt required.".into());
                return;
            }
        }
        trigger_autotype(
            pill_weak.clone(),
            pill_qb.clone(),
            Arc::clone(&pill_vis),
            Arc::clone(&pill_uvis),
            {
                let v = lock_vault(&pill_vault);
                login_type_request(&v, &qid, &user, &pass, &totp)
            },
        );
    });
    // Wire-up #5: real secret-leak scan via native folder picker + worker.
    let sc_weak = main_window.as_weak();
    // Dev card: copy a shell-completion script (public subcommands only —
    // never vault titles) to the clipboard for the shell profile.
    let comp_weak = main_window.as_weak();
    main_window.on_copy_shell_complete(move |shell| {
        let script = match shell.as_str() {
            "bash" => developer::shell_complete::bash_script(),
            "nushell" => developer::shell_complete::nushell_script(),
            _ => developer::shell_complete::powershell_script(),
        };
        let msg = match windows_native::clipboard::copy_sensitive(&script, 60, || {}) {
            Ok(()) => format!("📋 {shell} completion copied (60s) — paste into your shell profile."),
            Err(e) => format!("⚠️ Copy failed: {e}"),
        };
        if let Some(ui) = comp_weak.upgrade() {
            ui.set_health_status(msg.clone().into());
            ui.set_notification_text(msg.into());
        }
    });
    main_window.on_scan_secrets(move || {
        let picked = rfd::FileDialog::new().pick_folder();
        let Some(folder) = picked else {
            if let Some(ui) = sc_weak.upgrade() {
                ui.set_notification_text("Scan cancelled.".into());
            }
            return;
        };
        if let Some(ui) = sc_weak.upgrade() {
            ui.set_health_status("🔍 Scanning working tree for leaked secrets…".into());
            ui.set_notification_text("🔍 Scanning for leaked secrets…".into());
        }
        let weak = sc_weak.clone();
        thread::spawn(move || {
            let findings = developer::secret_scanner::scan_dir(&folder);
            for f in &findings {
                // Finding carries file:line + rule only — never secret values.
                eprintln!("[leak] {}:{} rule={}", f.file, f.line, f.rule);
            }
            let n = findings.len();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    if n == 0 {
                        ui.set_health_status("✅ Scan complete: no leaked secrets found.".into());
                        ui.set_notification_text(
                            "✅ Scan complete: No leaked secrets found in directory!".into(),
                        );
                    } else {
                        ui.set_health_status(
                            format!("🚨 Scan complete: {n} potential secrets. See terminal log.").into(),
                        );
                        ui.set_notification_text(
                            format!("🚨 Leak Alert: Found {n} potential secrets! Check terminal log.").into(),
                        );
                    }
                }
            });
        });
    });
    // Wire-up #1: HaveIBeenPwned vault audit (k-anonymity, background thread).
    let audit_weak = main_window.as_weak();
    let audit_vault_arc = Arc::clone(&active_vault);
    let audit_search = Arc::clone(&search_state);
    main_window.on_audit_vault(move || {
        // Offline mode: local reuse/weakness only — zero packets leave the
        // device. The global kill-switch forces this path unconditionally.
        let offline = audit_weak
            .upgrade()
            .map(|ui| ui.get_offline_audit() || !net_allowed())
            .unwrap_or(false);
        if let Some(ui) = audit_weak.upgrade() {
            if ui.get_is_decoy() {
                ui.set_health_status("⛔ Decoy mode is read-only.".into());
                return;
            }
            ui.set_health_status(if offline {
                "⏳ Auditing passwords locally (offline — no network)…".into()
            } else {
                "⏳ Auditing passwords (k-anonymity, no plaintext leaves device)…".into()
            });
            ui.set_notification_text("🛡️ Auditing vault health…".into());
        }
        let weak = audit_weak.clone();
        let vault_clone = Arc::clone(&audit_vault_arc);
        let search_clone = Arc::clone(&audit_search);
        thread::spawn(move || {
            let creds = {
                let v = lock_vault(&vault_clone);
                audit_scope_credentials(&v)
            };
            if creds.is_empty() {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_health_report("Vault is empty — nothing to audit.".into());
                        ui.set_health_rows(ModelRc::new(VecModel::from(Vec::<HealthRow>::new())));
                        ui.set_show_health(true);
                        ui.set_health_status("Vault is empty.".into());
                        ui.set_health_score(100);
                        ui.set_health_headline("Good Security Health".into());
                        ui.set_health_breached(0);
                        ui.set_health_reused(0);
                        ui.set_health_weak(0);
                        ui.set_health_stale(0);
                        ui.set_health_coverage(0);
                    }
                });
                return;
            }
            let report = if offline {
                security::breach_check::scan_vault_health_offline(&creds)
            } else {
                let Some(rt) = tokio_rt() else {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_health_status("⚠️ Could not start network runtime.".into());
                        }
                    });
                    return;
                };
                rt.block_on(security::breach_check::scan_vault_health(&creds))
            };
            let headline = report.headline();
            let badges = report.badges();
            let kinds = report.kinds();
            let score = report.score() as i32;
            let head_line = report.health_line();
            let (breached, reused, weak_n, stale, coverage) = (
                report.breached as i32,
                report.reused as i32,
                report.weak as i32,
                report.stale as i32,
                report.coverage_pct() as i32,
            );
            // Detailed per-item lines (titles + flags only, never passwords).
            // Kept as the accessible plain-text fallback (health_report prop).
            let mut detail = String::new();
            for r in &report.results {
                if r.breached.is_some() || r.reused || r.weak || r.stale {
                    let mut flags = Vec::new();
                    if let Some(n) = r.breached {
                        flags.push(format!("breached×{n}"));
                    }
                    if r.reused {
                        flags.push("reused".to_string());
                    }
                    if r.weak {
                        flags.push("weak".to_string());
                    }
                    if r.stale {
                        flags.push("stale 6m+".to_string());
                    }
                    detail.push_str(&format!("• {} [{}]\n", r.title, flags.join(", ")));
                }
            }
            if detail.is_empty() {
                detail = "All passwords look healthy — no breaches, reuse, or weakness found.".to_string();
            }
            // Grouped tappable rows: severity-ordered (breached → reused →
            // weak → stale) with section headers. Header rows carry id "".
            let rows = health_rows_for(&report.results);
            let full = format!("{headline}\n\n{detail}");
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    // Publish badges + metric kinds to the process-wide registries.
                    if let Ok(mut reg) = health_registry().lock() {
                        reg.clear();
                        reg.extend(badges);
                    }
                    if let Ok(mut reg) = health_kind_registry().lock() {
                        reg.clear();
                        reg.extend(kinds);
                    }
                    ui.set_health_report(full.into());
                    ui.set_health_rows(ModelRc::new(VecModel::from(rows)));
                    ui.set_show_health(true);
                    ui.set_health_status(headline.into());
                    // Scoreboard dashboard props.
                    ui.set_health_score(score);
                    ui.set_health_headline(head_line.into());
                    ui.set_health_breached(breached);
                    ui.set_health_reused(reused);
                    ui.set_health_weak(weak_n);
                    ui.set_health_stale(stale);
                    ui.set_health_coverage(coverage);
                    security::access_log::log_event("audit", "health scan");
                    let f = search_clone.lock().map(|s| s.clone()).unwrap_or_default();
                    let v = lock_vault(&vault_clone);
                    set_paged_credentials(&ui, vault_to_items(&v, &f));
                }
            });
        });
    });

    run_startup_pull(main_window.as_weak());

    // Scoreboard metric click → filter the middle list to matching accounts.
    // Toggles: clicking the active metric clears the filter. Jumps to the
    // vault view so the filtered list is immediately visible.
    let filter_weak = main_window.as_weak();
    let filter_vault = Arc::clone(&active_vault);
    let filter_search = Arc::clone(&search_state);
    let filter_qb = quick_bar.as_weak();
    main_window.on_filter_health(move |metric| {
        let Some(ui) = filter_weak.upgrade() else {
            return;
        };
        let want = metric.as_str();
        let mut f = filter_search.lock().map(|s| s.clone()).unwrap_or_default();
        // Toggle off when clicking the active metric.
        f.health = if f.health == want { String::new() } else { want.to_string() };
        f.limit = LIST_CAP;
        *filter_search.lock().unwrap() = f.clone();
        ui.set_health_filter(f.health.clone().into());
        ui.set_active_nav(0);
        let v = lock_vault(&filter_vault);
        set_paged_credentials(&ui, vault_to_items(&v, &f));
        if let Some(qb) = filter_qb.upgrade() {
            qb.set_filtered_results(vault_quickbar(&v, "", f.travel_only));
        }
        if f.health.is_empty() {
            ui.set_notification_text("Health filter cleared.".into());
        } else {
            ui.set_notification_text(
                format!("🛡️ Showing {} flagged accounts — click again to clear.", f.health).into(),
            );
        }
    });

    // Janitor review queue: unverified + never-filled logins (fake/stale
    // cleanup candidates). Toggles like the health filter; pairs with
    // select-mode bulk trash for one-sweep cleanup. Read-only under decoy
    // (trash itself refuses there) — no gate needed on the view.
    let jan_weak = main_window.as_weak();
    let jan_vault = Arc::clone(&active_vault);
    let jan_search = Arc::clone(&search_state);
    let jan_qb = quick_bar.as_weak();
    main_window.on_open_janitor(move || {
        let Some(ui) = jan_weak.upgrade() else {
            return;
        };
        let mut f = jan_search.lock().map(|s| s.clone()).unwrap_or_default();
        f.janitor = !f.janitor;
        f.limit = LIST_CAP;
        *jan_search.lock().unwrap() = f.clone();
        ui.set_janitor_active(f.janitor);
        ui.set_active_nav(0);
        let v = lock_vault(&jan_vault);
        set_paged_credentials(&ui, vault_to_items(&v, &f));
        if let Some(qb) = jan_qb.upgrade() {
            qb.set_filtered_results(vault_quickbar(&v, "", f.travel_only));
        }
        if f.janitor {
            let n = janitor_ids(&v, &read_fill_keys()).len();
            ui.set_notification_text(
                format!("🧹 {n} review candidates (unverified, never filled) — Select mode + 🗑️ Trash to sweep. Click Janitor again to close.").into(),
            );
        } else {
            ui.set_notification_text("Janitor queue closed.".into());
        }
    });

    // Phase 25: BLE proximity auto-lock service. Passive scan + 4s heartbeat
    // on a worker thread; the fire path reuses the standard lock pipeline
    // (RAM wipe + clipboard flush + access log + lock screen).
    {
        let main_weak_prox = main_window.as_weak();
        let cap_weak_prox = capture_window.as_weak();
        let vault_prox = Arc::clone(&active_vault);
        let master_prox = Arc::clone(&active_master_pw);
        let pending_prox = Arc::clone(&pending_cf);
        let editing_prox = Arc::clone(&editing_item);
        let master_is_open: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new({
            let master_prox = Arc::clone(&active_master_pw);
            move || master_prox.lock().map(|m| m.is_some()).unwrap_or(false)
        });
        let status_weak = main_window.as_weak();
        windows_native::proximity_lock::start_proximity_service(
            Arc::clone(&prox_config),
            Arc::clone(&prox_monitor),
            master_is_open,
            move |status| {
                let weak = status_weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_prox_status(status.into());
                    }
                });
            },
            // Direct call like the auto-lock ticker: `lock_vault_now` wipes
            // RAM + flushes the clipboard inline and dispatches UI work to
            // the event loop itself.
            move || {
                lock_vault_now(
                    main_weak_prox.clone(),
                    cap_weak_prox.clone(),
                    &vault_prox,
                    &master_prox,
                    &pending_prox,
                    &editing_prox,
                    "📱 Proximity Lock: Device walked away.",
                    "proximity-lock",
                );
            },
        );
    }

    // Phase 15 (Option 1): anti-debug watchdog — wipe + hard exit on trip.
    let watch_vault = Arc::clone(&active_vault);
    let watch_master = Arc::clone(&active_master_pw);
    security::anti_debug::start_watchdog(move || {
        panic_wipe(&watch_vault, &watch_master);
    });

    main_window.run()
}

/// Bitwarden-parity: construct + push any of the 6 item kinds.
/// Pure field-mapping (no I/O) — heavily exercised via integration path.
#[allow(clippy::too_many_arguments)]
fn push_new_item(
    vault: &mut Vault,
    kind: i32,
    id: String,
    title: &str,
    a: &str,
    b: &str,
    cc: &str,
    dd: &str,
    ee: &str,
    notes: &str,
    folder: &str,
    urls: Vec<models::LoginUrl>,
    backup: Vec<String>,
    custom: Vec<models::CustomField>,
    totp: &str,
    reprompt: bool,
    fav: bool,
    travel: bool,
    company: &str,
    city: &str,
    state: &str,
    zip: &str,
    country: &str,
) {
    match kind {
        1 => vault.credentials.push(Credential {
            id,
            title: title.to_string(),
            username: a.to_string(),
            password: b.to_string(),
            totp_secret: totp.to_string(),
            urls,
            backup_codes: backup,
            custom_fields: custom,
            notes: notes.to_string(),
            folder: folder.to_string(),
            reprompt,
            attachments: Vec::new(),
            travel_safe: travel,
            last_changed: crate::models::current_timestamp(),
            password_history: Vec::new(),
            favorite: fav,
            deleted_at: None,
        }),
        2 => vault.licenses.push(models::SoftwareLicense {
            id,
            app_name: title.to_string(),
            license_key: a.to_string(),
            expiry_date: (!b.trim().is_empty()).then(|| b.to_string()),
            folder: folder.to_string(),
            custom_fields: custom.clone(),
            attachments: Vec::new(),
            travel_safe: travel,
            favorite: fav,
            deleted_at: None,
        }),
        3 => vault.notes.push(models::SecureNote {
            id,
            title: title.to_string(),
            content: a.to_string(),
            folder: folder.to_string(),
            custom_fields: custom.clone(),
            attachments: Vec::new(),
            travel_safe: travel,
            favorite: fav,
            deleted_at: None,
        }),
        4 => {
            // Handler gate refuses garbage first; blank fallback here is
            // unreachable in production (defense in depth, never silent).
            let (em, ey) = parse_card_expiry(cc).unwrap_or_default();
            vault.cards.push(models::PaymentCard {
                id,
                title: title.to_string(),
                cardholder_name: a.to_string(),
                card_number: b.to_string(),
                exp_month: em,
                exp_year: ey,
                cvv: dd.to_string(),
                folder: folder.to_string(),
                notes: notes.to_string(),
                custom_fields: custom.clone(),
                attachments: Vec::new(),
                travel_safe: travel,
                favorite: fav,
                deleted_at: None,
            })
        }
        5 => vault.identities.push(models::IdentityItem {
            id,
            title: title.to_string(),
            full_name: a.to_string(),
            nid_or_passport: b.to_string(),
            email: cc.to_string(),
            phone: dd.to_string(),
            address: ee.to_string(),
            company: company.to_string(),
            city: city.to_string(),
            state: state.to_string(),
            zip: zip.to_string(),
            country: country.to_string(),
            folder: folder.to_string(),
            notes: notes.to_string(),
            custom_fields: custom.clone(),
            attachments: Vec::new(),
            travel_safe: travel,
            favorite: fav,
            deleted_at: None,
        }),
        6 => vault.ssh_keys.push(models::SshKeyItem {
            id,
            title: title.to_string(),
            public_key: a.to_string(),
            private_key: b.to_string(),
            // Blank fingerprint auto-derives (OpenSSH `SHA256:`) from the
            // pasted key; unparseable input stays blank (never blocks save).
            fingerprint: if cc.trim().is_empty() {
                crate::developer::ssh_agent::fingerprint_of_private(b)
                    .unwrap_or_default()
            } else {
                cc.to_string()
            },
            folder: folder.to_string(),
            notes: notes.to_string(),
            custom_fields: custom.clone(),
            attachments: Vec::new(),
            travel_safe: travel,
            favorite: fav,
            deleted_at: None,
        }),
        _ => {}
    }
}

/// Attachment vectors by kind (logins/licenses/notes/cards/identities/SSH).
/// Passkeys + standalone 2FA carry none (None). Single choke point so a new
/// attachable kind updates one match, not five call sites.
/// Kinds carrying attachments (1 login, 2 license, 3 note, 4 card,
/// 5 identity, 6 SSH). Passkeys (7) + hub codes (8) excluded.
fn is_attachable(kind: i32) -> bool {
    matches!(kind, 1..=6)
}

fn attachments_mut<'a>(
    vault: &'a mut Vault,
    kind: i32,
    id: &str,
) -> Option<&'a mut Vec<models::EncryptedAttachment>> {
    match kind {
        1 => vault.credentials.iter_mut().find(|c| c.id == id).map(|c| &mut c.attachments),
        2 => vault.licenses.iter_mut().find(|l| l.id == id).map(|l| &mut l.attachments),
        3 => vault.notes.iter_mut().find(|n| n.id == id).map(|n| &mut n.attachments),
        4 => vault.cards.iter_mut().find(|k| k.id == id).map(|k| &mut k.attachments),
        5 => vault.identities.iter_mut().find(|i| i.id == id).map(|i| &mut i.attachments),
        6 => vault.ssh_keys.iter_mut().find(|s| s.id == id).map(|s| &mut s.attachments),
        _ => None,
    }
}

fn attachments_of(vault: &Vault, kind: i32, id: &str) -> Vec<models::EncryptedAttachment> {
    let found: Option<&Vec<models::EncryptedAttachment>> = match kind {
        1 => vault.credentials.iter().find(|c| c.id == id).map(|c| &c.attachments),
        2 => vault.licenses.iter().find(|l| l.id == id).map(|l| &l.attachments),
        3 => vault.notes.iter().find(|n| n.id == id).map(|n| &n.attachments),
        4 => vault.cards.iter().find(|k| k.id == id).map(|k| &k.attachments),
        5 => vault.identities.iter().find(|i| i.id == id).map(|i| &i.attachments),
        6 => vault.ssh_keys.iter().find(|s| s.id == id).map(|s| &s.attachments),
        _ => None,
    };
    found.cloned().unwrap_or_default()
}

/// Edit-mode: overwrite an existing item's fields in place. Returns false if missing.
#[allow(clippy::too_many_arguments)]
fn replace_item(
    vault: &mut Vault,
    kind: i32,
    id: &str,
    title: &str,
    a: &str,
    b: &str,
    cc: &str,
    dd: &str,
    ee: &str,
    notes: &str,
    folder: &str,
    urls: &[models::LoginUrl],
    backup: &[String],
    custom: &[models::CustomField],
    totp: &str,
    reprompt: bool,
    fav: bool,
    travel: bool,
    company: &str,
    city: &str,
    state: &str,
    zip: &str,
    country: &str,
) -> bool {
    match kind {
        1 => {
            let Some(c) = vault.credentials.iter_mut().find(|c| c.id == id) else {
                return false;
            };
            c.title = title.to_string();
            c.username = a.to_string();
            // Retire the outgoing password (only on real change), then rotate.
            if c.password != b {
                let retired = c.password.clone();
                crate::models::push_history(
                    &mut c.password_history,
                    &retired,
                    crate::models::current_timestamp(),
                );
            }
            c.password = b.to_string();
            // Rotation clock restarts on every credential edit.
            c.last_changed = crate::models::current_timestamp();
            c.totp_secret = totp.to_string();
            c.urls = urls.to_vec();
            c.backup_codes = backup.to_vec();
            c.custom_fields = custom.to_vec();
            c.notes = notes.to_string();
            c.folder = folder.to_string();
            c.reprompt = reprompt;
            c.favorite = fav;
            c.travel_safe = travel;
            true
        }
        2 => {
            let Some(l) = vault.licenses.iter_mut().find(|l| l.id == id) else {
                return false;
            };
            l.app_name = title.to_string();
            l.license_key = a.to_string();
            l.expiry_date = (!b.trim().is_empty()).then(|| b.to_string());
            l.custom_fields = custom.to_vec();
            l.folder = folder.to_string();
            l.favorite = fav;
            l.travel_safe = travel;
            true
        }
        3 => {
            let Some(n) = vault.notes.iter_mut().find(|n| n.id == id) else {
                return false;
            };
            n.title = title.to_string();
            n.content = a.to_string();
            n.custom_fields = custom.to_vec();
            n.folder = folder.to_string();
            n.favorite = fav;
            n.travel_safe = travel;
            true
        }
        4 => {
            let Some(k) = vault.cards.iter_mut().find(|k| k.id == id) else {
                return false;
            };
            k.title = title.to_string();
            k.cardholder_name = a.to_string();
            k.card_number = b.to_string();
            // Handler gate refuses garbage first; blank fallback here is
            // unreachable in production (defense in depth, never silent).
            let (em, ey) = parse_card_expiry(cc).unwrap_or_default();
            k.exp_month = em;
            k.exp_year = ey;
            k.cvv = dd.to_string();
            k.folder = folder.to_string();
            k.notes = notes.to_string();
            k.custom_fields = custom.to_vec();
            k.favorite = fav;
            k.travel_safe = travel;
            true
        }
        5 => {
            let Some(i) = vault.identities.iter_mut().find(|i| i.id == id) else {
                return false;
            };
            i.title = title.to_string();
            i.full_name = a.to_string();
            i.nid_or_passport = b.to_string();
            i.email = cc.to_string();
            i.phone = dd.to_string();
            i.address = ee.to_string();
            i.company = company.to_string();
            i.city = city.to_string();
            i.state = state.to_string();
            i.zip = zip.to_string();
            i.country = country.to_string();
            i.notes = notes.to_string();
            i.custom_fields = custom.to_vec();
            i.folder = folder.to_string();
            i.favorite = fav;
            i.travel_safe = travel;
            true
        }
        6 => {
            let Some(s) = vault.ssh_keys.iter_mut().find(|s| s.id == id) else {
                return false;
            };
            s.title = title.to_string();
            s.public_key = a.to_string();
            s.private_key = b.to_string();
            // Same auto-derive rule as create: explicit wins, blank derives,
            // garbage stays blank.
            s.fingerprint = if cc.trim().is_empty() {
                crate::developer::ssh_agent::fingerprint_of_private(b)
                    .unwrap_or_default()
            } else {
                cc.to_string()
            };
            s.folder = folder.to_string();
            s.notes = notes.to_string();
            s.custom_fields = custom.to_vec();
            s.favorite = fav;
            s.travel_safe = travel;
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod grid_tests {
    use super::*;

    #[test]
    fn qb_rank_prefers_prefix_then_fav() {
        assert!(qb_rank_score("git", "GitHub", "u", false) > qb_rank_score("git", "My Github", "u", false));
        assert!(qb_rank_score("git", "My Github", "u", false) > qb_rank_score("git", "Other", "u", false));
        assert!(qb_rank_score("git", "Other", "u", true) > qb_rank_score("git", "Other", "u", false));
        assert_eq!(qb_rank_score("", "A", "u", true), 15);
        assert_eq!(qb_rank_score("", "A", "u", false), 0);
    }

    // Merge repair (parallel flake): `vault_to_items` writes the process-global
    // `total_matches_registry`, so tests that build list models must never run
    // concurrently — same precedent as tray.rs ACTION_TEST_LOCK.
    static LIST_MODEL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn totp_acct(id: &str, issuer: &str, name: &str) -> TotpAccount {
        TotpAccount {
            id: id.into(),
            issuer: issuer.into(),
            account_name: name.into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            otp_type: "totp".into(),
            algorithm: "SHA1".into(),
            digits: 6,
            period: 30,
            counter: 0,
            favorite: false,
        }
    }

    // -----------------------------------------------------------------------
    // Phase 28: duplicate detection.
    // -----------------------------------------------------------------------

    /// The badge has to keep meaning "there are genuinely two of these", so a
    /// lone card must never wear it.
    #[test]
    fn dup_marks_are_false_for_a_lone_account() {
        let a = totp_acct("1", "GitHub", "me");
        assert_eq!(dup_marks(&[&a]), vec![false]);
    }

    #[test]
    fn dup_marks_flag_only_true_same_pair_accounts() {
        let a = totp_acct("1", "GitHub", "me");
        let b = totp_acct("2", "GitHub", "me");
        let c = totp_acct("3", "GitHub", "other");
        assert_eq!(dup_marks(&[&a, &b, &c]), vec![true, true, false]);
    }

    /// Users retype names by hand; "github" and "ME" are the same account.
    #[test]
    fn dup_marks_ignore_issuer_case_and_name_case() {
        let a = totp_acct("1", "GitHub", "me");
        let b = totp_acct("2", "github", "ME");
        assert_eq!(dup_marks(&[&a, &b]), vec![true, true]);
    }

    /// The whole point of `strip_dup_suffix` in the key: the copy we made for
    /// a collision must resolve to its ORIGINAL, or resolving a conflict would
    /// make the duplicate badge disappear and invite a third import.
    #[test]
    fn dup_key_groups_the_suffixed_card_with_its_original() {
        let a = totp_acct("1", "Bank", "main");
        let mut b = totp_acct("2", "Bank", "main");
        b.account_name = format!("main{DUP_SUFFIX}");
        assert_eq!(dup_key(&a.issuer, &a.account_name), dup_key(&b.issuer, &b.account_name));
        assert_eq!(dup_marks(&[&a, &b]), vec![true, true]);
    }

    #[test]
    fn dup_key_ignores_surrounding_whitespace() {
        let k = dup_key(" GitHub ", "  me  ");
        assert_eq!(k, ("github".to_string(), "me".to_string()));
    }

    /// The tooltip must explain the collision WITHOUT echoing key material.
    #[test]
    fn dup_of_label_names_the_account_and_never_the_secret() {
        let a = totp_acct("1", "GitHub", "me");
        let mut b = totp_acct("2", "GitHub", "me");
        b.secret = "SECRETSECRETSECRET".into();
        b.account_name = format!("me{DUP_SUFFIX}");
        let accs = [&a, &b];
        let label = dup_of_label(&accs, &b);
        assert!(label.contains("GitHub"));
        assert!(label.contains("me"));
        assert!(!label.contains("SECRET"), "secret leaked into label: {label}");
    }

    #[test]
    fn dup_of_label_is_empty_for_a_lone_account() {
        let a = totp_acct("1", "GitHub", "me");
        assert_eq!(dup_of_label(&[&a], &a), "");
    }

    /// The ingest layer and the merge MUST agree, or the user gets asked about
    /// a "conflict" the merge then silently skips.
    #[test]
    fn dup_conflicts_ignore_cosmetic_secret_differences() {
        let mut v = Vault::new();
        v.totp_accounts.push(totp_acct("1", "GitHub", "me"));
        let mut same = totp_acct("2", "GitHub", "me");
        same.secret = "jbswy3dp ehpk3pxp".into();
        assert!(dup_conflicts_against(&v, &[same]).is_empty());
    }

    #[test]
    fn dup_conflicts_flag_a_genuine_same_name_different_secret() {
        let mut v = Vault::new();
        v.totp_accounts.push(totp_acct("1", "Facebook", "abe"));
        let mut other = totp_acct("2", "Facebook", "abe");
        other.secret = "KRUGKIDROVUWG2ZAMJZG653OPBHY".into();
        let c = dup_conflicts_against(&v, &[other]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].issuer, "Facebook");
    }

    /// Regression guard for the original misdiagnosis: two logins on one
    /// service are not duplicates, and must never be collapsed.
    #[test]
    fn dup_conflicts_leave_two_logins_on_one_issuer_alone() {
        let mut v = Vault::new();
        v.totp_accounts.push(totp_acct("1", "GitHub", "zjhasan13"));
        let mut other = totp_acct("2", "GitHub", "zjhasan33");
        other.secret = "KRUGKIDROVUWG2ZAMJZG653OPBHY".into();
        assert!(dup_conflicts_against(&v, &[other]).is_empty());
    }

    // -----------------------------------------------------------------------
    // Phase 28: hub ordering + card rendering.
    // -----------------------------------------------------------------------

    /// When one service is enrolled twice, the surviving card must be the
    /// newest import — it is the one that actually works.
    #[test]
    fn auth_rows_put_the_latest_scan_first_within_a_duplicate_pair() {
        let mut v = Vault::new();
        let mut old = totp_acct("1", "Bank", "main");
        old.secret = "AAAAAAAAAAAAAAAA".into();
        let mut new = totp_acct("2", "Bank", "main");
        new.account_name = format!("main{DUP_SUFFIX}");
        new.secret = "BBBBBBBBBBBBBBBB".into();
        v.totp_accounts.push(old);
        v.totp_accounts.push(new);
        let rows = build_auth_rows(&v);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].name.as_str().ends_with(DUP_SUFFIX), "got {rows:?}");
        assert_eq!(rows[0].code.as_str(), rows[0].display.as_str().replace(' ', ""));
        assert!(rows[0].is_dup && rows[1].is_dup);
    }

    /// The duplicate cards must stay adjacent and alphabetical, not be split by
    /// the `[Imported]` marker being sorted as part of the name.
    #[test]
    fn auth_rows_sort_bare_names_not_the_marker() {
        let mut v = Vault::new();
        for (i, n) in ["abe", "me", "zz"].iter().enumerate() {
            v.totp_accounts.push(totp_acct(&format!("a{i}"), "Facebook", n));
        }
        let mut b = totp_acct("b1", "Facebook", "abe");
        b.account_name = format!("abe{DUP_SUFFIX}");
        v.totp_accounts.push(b);
        let rows = build_auth_rows(&v);
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names.len(), 4);
        let abe_pair: Vec<&&str> = names.iter().filter(|n| n.starts_with("abe")).collect();
        assert_eq!(abe_pair.len(), 2, "the abe pair must be adjacent");
    }

    /// Favourites stay on top — the badge change must not disturb that.
    #[test]
    fn auth_rows_keep_favorites_first_even_with_duplicates() {
        let mut v = Vault::new();
        let mut pinned = totp_acct("1", "Zebra", "acc");
        pinned.favorite = true;
        v.totp_accounts.push(pinned);
        let a = totp_acct("2", "Apple", "me");
        let mut b = totp_acct("3", "Apple", "me");
        b.account_name = format!("me{DUP_SUFFIX}");
        v.totp_accounts.push(a);
        v.totp_accounts.push(b);
        let rows = build_auth_rows(&v);
        assert_eq!(rows[0].id.as_str(), "1");
        assert!(rows[0].fav);
    }

    #[test]
    fn auth_rows_leave_a_clean_account_unflagged() {
        let mut v = Vault::new();
        v.totp_accounts.push(totp_acct("1", "GitHub", "me"));
        let rows = build_auth_rows(&v);
        assert!(!rows[0].is_dup);
        assert_eq!(rows[0].dup_of.as_str(), "");
    }

    /// The revealed line must be self-describing so the two numbers on a card
    /// can never be read as one.
    #[test]
    fn next_label_is_self_describing_for_totp() {
        let mut v = Vault::new();
        v.totp_accounts.push(totp_acct("1", "GitHub", "me"));
        let rows = build_auth_rows(&v);
        assert!(
            rows[0].next_label.starts_with("NEXT in "),
            "got {:?}",
            rows[0].next_label.as_str()
        );
        assert!(rows[0].next_label.contains('·'));
    }

    /// A broken secret must not render anything that could be read as a code —
    /// and `group_code` must not mangle the warning into "badsecretreenroll".
    #[test]
    fn broken_secret_never_renders_a_plausible_code() {
        let mut v = Vault::new();
        let mut bad = totp_acct("a", "GitHub", "me");
        bad.secret = "!!!not-base32!!!".into();
        v.totp_accounts.push(bad);
        let rows = build_auth_rows(&v);
        assert_eq!(rows[0].display.as_str(), "------");
        assert!(rows[0].next.as_str().contains("bad secret"));
        assert_eq!(rows[0].next.as_str(), rows[0].next_label.as_str());
    }

    /// The ≤3s guard reads `secs`, so HOTP must report -1 and stay exempt.
    #[test]
    fn hotp_card_reports_no_countdown_so_the_guard_never_blocks_it() {
        let mut v = Vault::new();
        let mut hotp = totp_acct("h", "Bank", "acct");
        hotp.otp_type = "hotp".into();
        hotp.counter = 7;
        v.totp_accounts.push(hotp);
        let rows = build_auth_rows(&v);
        assert_eq!(rows[0].secs, -1);
        assert_eq!(rows[0].countdown.as_str(), "HOTP");
        // `-1 <= 3` is true, so the Slint predicate must special-case it.
        assert!(rows[0].secs < 0 || rows[0].secs > 3);
        // Shape, not a hardcoded HMAC value: the counter must be explicit
        // (it is what HOTP users actually need) and the code grouped 3+3.
        assert!(rows[0].next_label.starts_with("NEXT (counter 8) · "));
        let code = rows[0].next_label.rsplit('·').next().unwrap().trim();
        assert_eq!(code.len(), 7, "expected 3+3 grouping, got {code:?}");
        assert_eq!(code, format!("{} {}", &code[..3], &code[4..]));
    }

    /// The hub's own countdown is what the guard threshold is expressed in, so
    /// it has to land on a sane 0..=30 range rather than a wrapped u64.
    #[test]
    fn totp_countdown_is_plausible() {
        let mut v = Vault::new();
        v.totp_accounts.push(totp_acct("1", "GitHub", "me"));
        let rows = build_auth_rows(&v);
        assert!(rows[0].secs >= 1 && rows[0].secs <= 30, "got {}", rows[0].secs);
        assert!(rows[0].countdown.as_str().ends_with('s'));
    }

    #[test]
    fn code_grouping_matches_reference_grid() {
        assert_eq!(group_code("513710"), "513 710");
        assert_eq!(group_code("149147"), "149 147");
        assert_eq!(group_code("------"), "------");
        // Non-6-digit codes (Steam 5-char, 8-digit) pass through ungrouped.
        assert_eq!(group_code("ABCDE"), "ABCDE");
        assert_eq!(group_code("12345678"), "12345678");
    }

    #[test]
    fn brand_letters_and_tints() {
        let (l, t) = brand_of("Google", "x@gmail.com");
        assert_eq!(l, 'G');
        assert_eq!((t.red(), t.green(), t.blue()), (66, 133, 244));
        let (l, _) = brand_of("", "discord-user");
        assert_eq!(l, 'D');
        let (l, _) = brand_of("", "");
        assert_eq!(l, '?');
        let (_, t) = brand_of("Some Unknown Service", "u");
        assert_eq!((t.red(), t.green(), t.blue()), (139, 124, 246));
    }

    #[test]
    fn reprompt_gate_only_arms_logins() {
        let mut v = Vault::new();
        v.credentials.push(Credential {
            id: "r1".into(),
            title: "t".into(),
            username: "u".into(),
            password: "p".into(),
            totp_secret: String::new(),
            urls: Vec::new(),
            backup_codes: Vec::new(),
            custom_fields: Vec::new(),
            notes: String::new(),
            folder: "General".into(),
            reprompt: true,
            attachments: Vec::new(),
            travel_safe: false,
            last_changed: 0,
            password_history: Vec::new(),
            favorite: false,
            deleted_at: None,
        });
        v.credentials.push(Credential {
            id: "r2".into(),
            title: "t".into(),
            username: "u2".into(),
            password: "p2".into(),
            totp_secret: String::new(),
            urls: Vec::new(),
            backup_codes: Vec::new(),
            custom_fields: Vec::new(),
            notes: String::new(),
            folder: "General".into(),
            reprompt: false,
            attachments: Vec::new(),
            travel_safe: false,
            last_changed: 0,
            password_history: Vec::new(),
            favorite: false,
            deleted_at: None,
        });
        assert_eq!(
            reprompt_gate(&v, 1, "r1"),
            Some(("u".to_string(), "p".to_string()))
        );
        assert_eq!(reprompt_gate(&v, 1, "r2"), None);
        assert_eq!(reprompt_gate(&v, 1, "nope"), None);
        // Non-login kinds never gate, even with a colliding id.
        assert_eq!(reprompt_gate(&v, 4, "r1"), None);
        assert_eq!(reprompt_gate(&v, 0, "r1"), None);
    }

    #[test]
    fn janitor_lists_unverified_never_filled() {
        fn login(id: &str) -> Credential {
            Credential {
                id: id.into(),
                title: "t".into(),
                username: "u".into(),
                password: "p".into(),
                totp_secret: String::new(),
                urls: Vec::new(),
                backup_codes: Vec::new(),
                custom_fields: Vec::new(),
                notes: String::new(),
                folder: "General".into(),
                reprompt: false,
                attachments: Vec::new(),
                travel_safe: false,
                last_changed: 0,
                password_history: Vec::new(),
                favorite: false,
                deleted_at: None,
            }
        }
        let mut v = Vault::new();
        v.credentials.push(login("fake-never-used"));
        v.credentials.push(login("daily-driver"));
        v.credentials.push(login("trashed-fake"));
        v.credentials[2].deleted_at = Some(1);
        assert!(v.set_verified("daily-driver", true));
        let filled: std::collections::HashSet<String> =
            ["daily-driver".to_string()].into_iter().collect();
        // Only the unverified, never-filled, live login survives.
        assert_eq!(janitor_ids(&v, &filled), vec!["fake-never-used".to_string()]);
        // Empty vault / all-clean ⇒ empty queue, never an error.
        assert!(janitor_ids(&Vault::new(), &filled).is_empty());
    }

    #[test]
    fn find_live_login_id_matches_ci_and_skips_trash() {
        fn login(id: &str, title: &str, user: &str, trashed: bool) -> Credential {
            Credential {
                id: id.into(),
                title: title.into(),
                username: user.into(),
                password: "p".into(),
                totp_secret: String::new(),
                urls: Vec::new(),
                backup_codes: Vec::new(),
                custom_fields: Vec::new(),
                notes: String::new(),
                folder: "General".into(),
                reprompt: false,
                attachments: Vec::new(),
                travel_safe: false,
                last_changed: 0,
                password_history: Vec::new(),
                favorite: false,
                deleted_at: trashed.then_some(1),
            }
        }
        let mut v = Vault::new();
        v.credentials.push(login("a", "GitHub", "octo", false));
        v.credentials.push(login("b", "GitHub", "octo", true));
        // Case-insensitive + trimmed match on the LIVE row.
        assert_eq!(find_live_login_id(&v, "  github ", "OCTO"), Some("a".to_string()));
        assert_eq!(find_live_login_id(&v, "GitHub", "other"), None);
        assert_eq!(find_live_login_id(&v, "", "octo"), None);
        assert_eq!(find_live_login_id(&v, "GitHub", ""), None);
        // Trash-only vault ⇒ no match (trashed never blocks).
        let mut t = Vault::new();
        t.credentials.push(login("b", "GitHub", "octo", true));
        assert_eq!(find_live_login_id(&t, "GitHub", "octo"), None);
    }

    #[test]
    fn rotate_reused_makes_unique_with_history() {        fn login(id: &str, pw: &str) -> Credential {
            Credential {
                id: id.into(),
                title: "t".into(),
                username: "u".into(),
                password: pw.into(),
                totp_secret: String::new(),
                urls: Vec::new(),
                backup_codes: Vec::new(),
                custom_fields: Vec::new(),
                notes: String::new(),
                folder: "General".into(),
                reprompt: false,
                attachments: Vec::new(),
                travel_safe: false,
                last_changed: 0,
                password_history: Vec::new(),
                favorite: false,
                deleted_at: None,
            }
        }
        let mut v = Vault::new();
        v.credentials.push(login("a", "shared123"));
        v.credentials.push(login("b", "shared123"));
        v.credentials.push(login("c", "unique-strong-1"));
        assert_eq!(rotate_reused_passwords(&mut v), 2);
        let pa = v.credentials.iter().find(|c| c.id == "a").unwrap().password.clone();
        let pb = v.credentials.iter().find(|c| c.id == "b").unwrap().password.clone();
        // Unique, no longer the shared password, history kept.
        assert_ne!(pa, pb);
        assert_ne!(pa, "shared123");
        assert_ne!(pb, "shared123");
        for id in ["a", "b"] {
            let c = v.credentials.iter().find(|c| c.id == id).unwrap();
            assert_eq!(c.password_history.len(), 1);
            assert_eq!(c.password_history[0].password, "shared123");
            assert!(c.last_changed > 0);
        }
        // Untouched: unique password, no history.
        let c = v.credentials.iter().find(|c| c.id == "c").unwrap();
        assert_eq!(c.password, "unique-strong-1");
        assert!(c.password_history.is_empty());
        // Second run: nothing shared ⇒ 0, no churn.
        assert_eq!(rotate_reused_passwords(&mut v), 0);
    }

    #[test]
    fn paging_grows_window_and_reports_total() {
        let _guard = LIST_MODEL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        fn login(id: &str) -> Credential {
            Credential {
                id: id.into(),
                title: "t".into(),
                username: "u".into(),
                password: "p".into(),
                totp_secret: String::new(),
                urls: Vec::new(),
                backup_codes: Vec::new(),
                custom_fields: Vec::new(),
                notes: String::new(),
                folder: "General".into(),
                reprompt: false,
                attachments: Vec::new(),
                travel_safe: false,
                last_changed: 0,
                password_history: Vec::new(),
                favorite: false,
                deleted_at: None,
            }
        }
        let mut v = Vault::new();
        for i in 0..120 {
            v.credentials.push(login(&format!("c{i}")));
        }
        // Default window: first page only, total recorded.
        let f = FilterState::default();
        assert_eq!(f.limit, LIST_CAP);
        let page1 = vault_to_items(&v, &f);
        assert_eq!(page1.iter().count(), LIST_CAP);
        assert_eq!(total_matches(), 120);
        // Load More: window grows, same total.
        let mut f2 = f.clone();
        f2.limit += LIST_PAGE;
        let page2 = vault_to_items(&v, &f2);
        assert_eq!(page2.iter().count(), LIST_CAP + LIST_PAGE);
        assert_eq!(total_matches(), 120);
        // Narrow query resets are the caller's job; the builder honors any
        // window, including beyond-total (no panic, no padding).
        let mut f3 = f.clone();
        f3.limit = 10_000;
        assert_eq!(vault_to_items(&v, &f3).iter().count(), 120);
    }

    #[test]
    fn identity_notes_survive_push_and_replace() {
        // Regression: kind-5 notes were silently dropped on create AND edit.
        let _guard = LIST_MODEL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut v = Vault::new();
        crate::push_new_item(
            &mut v, 5, "id1".into(), "Passport", "Jane Doe", "N123",
            "jane@x.com", "555-0100", "12 Main St", "my secret note",
            "General", Vec::new(), Vec::new(), Vec::new(), "", false, false, false,
            "Acme", "Dhaka", "DHK", "1000", "BD",
        );
        assert_eq!(v.identities.len(), 1);
        assert_eq!(v.identities[0].notes, "my secret note");
        assert_eq!(v.identities[0].email, "jane@x.com");
        assert_eq!(v.identities[0].company, "Acme");
        assert_eq!(v.identities[0].city, "Dhaka");
        assert_eq!(v.identities[0].zip, "1000");
        // Edit path preserves notes too.
        let ok = crate::replace_item(
            &mut v, 5, "id1", "Passport", "Jane Doe", "N123",
            "jane@x.com", "555-0100", "12 Main St", "updated note",
            "General", &[], &[], &[], "", false, false, false,
            "Acme2", "", "", "", "",
        );
        assert!(ok);
        assert_eq!(v.identities[0].notes, "updated note");
        assert_eq!(v.identities[0].company, "Acme2");
        assert_eq!(v.identities[0].city, "");
    }

    #[test]
    fn login_url_rules_survive_push_and_replace() {
        use crate::models::{url_rule, LoginUrl};
        let _guard = LIST_MODEL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut v = Vault::new();
        crate::push_new_item(
            &mut v, 1, "u1".into(), "Bank", "me", "pw", "", "", "", "n", "General",
            vec![
                LoginUrl::new("https://bank.com/login".into(), url_rule::EXACT),
                LoginUrl::Plain("https://bank.com".into()),
            ],
            Vec::new(), Vec::new(), "", false, false, false,
            "", "", "", "", "",
        );
        assert_eq!(v.credentials.len(), 1);
        let urls = &v.credentials[0].urls;
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0].rule(), url_rule::EXACT);
        assert_eq!(urls[1].rule(), url_rule::DEFAULT);
        // Edit path keeps rules (replace takes the full LoginUrl vec).
        let ok = crate::replace_item(
            &mut v, 1, "u1", "Bank", "me", "pw", "", "", "", "n", "General",
            &[LoginUrl::new("https://bank.com/login".into(), url_rule::HOST)],
            &[], &[], "", false, false, false,
            "", "", "", "", "",
        );
        assert!(ok);
        assert_eq!(v.credentials[0].urls[0].rule(), url_rule::HOST);
    }

    #[test]
    fn ssh_fingerprint_auto_derives_only_when_blank() {
        let _guard = LIST_MODEL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Real PEM via ssh-key itself (deterministic seed — NOT a secret).
        use ssh_key::private::Ed25519Keypair;
        let pair = Ed25519Keypair::from_seed(&[7u8; 32]);
        let pem = ssh_key::PrivateKey::from(pair)
            .to_openssh(ssh_key::LineEnding::LF)
            .map(|s| s.to_string())
            .unwrap();
        // Blank → derived `SHA256:…`, matching the helper directly.
        let mut v = Vault::new();
        crate::push_new_item(
            &mut v, 6, "s1".into(), "Deploy", "ssh-ed25519 PUB", &pem, "", "", "",
            "n", "General", Vec::new(), Vec::new(), Vec::new(), "", false, false,
            false, "", "", "", "", "",
        );
        assert_eq!(v.ssh_keys.len(), 1);
        let fp = &v.ssh_keys[0].fingerprint;
        assert!(fp.starts_with("SHA256:"), "derived, got {fp}");
        assert_eq!(
            Some(fp.clone()),
            crate::developer::ssh_agent::fingerprint_of_private(&pem)
        );
        // Garbage key parses to nothing → stays blank, save NOT blocked.
        let mut v3 = Vault::new();
        crate::push_new_item(
            &mut v3, 6, "s3".into(), "Deploy", "pub", "not-a-key", "", "", "", "n",
            "General", Vec::new(), Vec::new(), Vec::new(), "", false, false, false,
            "", "", "", "", "",
        );
        assert_eq!(v3.ssh_keys[0].fingerprint, "");
        // Explicit fingerprint always wins over derivation.
        let mut v2 = Vault::new();
        crate::push_new_item(
            &mut v2, 6, "s2".into(), "Deploy", "pub", &pem, "SHA256:mine", "", "",
            "n", "General", Vec::new(), Vec::new(), Vec::new(), "", false, false,
            false, "", "", "", "", "",
        );
        assert_eq!(v2.ssh_keys[0].fingerprint, "SHA256:mine");
    }

    #[test]
    fn grid_chunks_in_pairs() {        assert!(chunk_rows_of::<u8>(vec![], 2).is_empty());
        assert_eq!(chunk_rows_of(vec![1, 2], 2), vec![vec![1, 2]]);
        // 5 items → 2 + 2 + 1; the lone card gets spacers, never full-width.
        assert_eq!(
            chunk_rows_of(vec![1, 2, 3, 4, 5], 2),
            vec![vec![1, 2], vec![3, 4], vec![5]]
        );
    }

    #[test]
    fn grid_chunks_in_threes_for_hub() {
        assert_eq!(
            chunk_rows_of(vec![1, 2, 3, 4, 5, 6, 7], 3),
            vec![vec![1, 2, 3], vec![4, 5, 6], vec![7]]
        );
        // Degenerate stride never panics or drops items.
        assert_eq!(chunk_rows_of(vec![1, 2], 0), vec![vec![1], vec![2]]);
    }

    #[test]
    fn hub_sorts_favorites_first_then_alpha() {
        fn acc(issuer: &str, name: &str, fav: bool) -> TotpAccount {
            TotpAccount {
                id: format!("{issuer}:{name}"),
                account_name: name.into(),
                issuer: issuer.into(),
                secret: "JBSWY3DPEHPK3PXP".into(),
                digits: 6,
                period: 30,
                algorithm: "SHA1".into(),
                otp_type: "totp".into(),
                counter: 0,
                favorite: fav,
            }
        }
        let mut v = Vault::new();
        v.totp_accounts.push(acc("Twitter", "z", false));
        v.totp_accounts.push(acc("GitHub", "z", false));
        v.totp_accounts.push(acc("Google", "a", true));
        v.totp_accounts.push(acc("Facebook", "m", false));
        let rows = build_auth_rows(&v);
        let order: Vec<String> = rows.iter().map(|r| r.issuer.to_string()).collect();
        assert_eq!(order, vec!["Google", "Facebook", "GitHub", "Twitter"]);
    }

    #[test]
    fn totp_search_is_isolated_and_case_insensitive() {
        assert!(totp_matches("me@gmail.com", "Google", ""));
        assert!(totp_matches("me@gmail.com", "Google", "goog"));
        assert!(totp_matches("me@gmail.com", "Google", "GMAIL"));
        assert!(!totp_matches("me@gmail.com", "Google", "discord"));
        assert!(!totp_matches("a", "b", "zzz"));
    }

    #[test]
    fn card_expiry_split_roundtrip() {
        // UI add/edit "MM/YY" must split into (month, year) — the year used
        // to be dropped by push_new_item/replace_item (nested in main(), so
        // this pins the splitter both paths now share with the importer).
        assert_eq!(split_card_expiry("12/28"), ("12".to_string(), "28".to_string()));
        assert_eq!(split_card_expiry("12-28"), ("12".to_string(), "28".to_string()));
        assert_eq!(split_card_expiry("12.28"), ("12".to_string(), "28".to_string()));
        assert_eq!(split_card_expiry(" 12 "), ("12".to_string(), "".to_string()));
        assert_eq!(split_card_expiry(""), ("".to_string(), "".to_string()));
        // Year survives a simulated edit round-trip: prefill joins with "/",
        // the save path must split it back.
        let (m, y) = split_card_expiry(&format!("{}/{}", "05", "31"));
        assert_eq!((m, y), ("05".to_string(), "31".to_string()));
    }

    #[test]
    fn card_brand_and_luhn_vectors() {
        // Real BINs (test numbers, not live cards).
        assert_eq!(card_brand("4111 1111 1111 1111"), "Visa");
        assert_eq!(card_brand("5555-5555-5555-4444"), "Mastercard");
        assert_eq!(card_brand("2221 0000 0000 0009"), "Mastercard");
        assert_eq!(card_brand("378282246310005"), "Amex");
        assert_eq!(card_brand("6011111111111117"), "Discover");
        assert_eq!(card_brand("30569309025904"), "Diners");
        assert_eq!(card_brand("3530111333300000"), "JCB");
        assert_eq!(card_brand("6200000000000005"), "UnionPay");
        assert_eq!(card_brand("9999999999999999"), "");
        assert_eq!(card_brand(""), "");
        // Luhn: the same numbers validate (spaces/dashes ignored).
        assert!(luhn_valid("4111 1111 1111 1111"));
        assert!(luhn_valid("5555-5555-5555-4444"));
        assert!(luhn_valid("378282246310005"));
        assert!(!luhn_valid("4111 1111 1111 1112"));
        assert!(!luhn_valid("123"));
        assert!(!luhn_valid(""));
        assert!(!luhn_valid("abcd"));
    }

    #[test]
    fn card_expiry_parse_refuses_garbage() {
        let ok = |s: &str| parse_card_expiry(s).map(|(m, y)| format!("{m}/{y}"));
        // Valid shapes (separators normalized like the splitter).
        assert_eq!(ok("12/28").as_deref(), Some("12/28"));
        assert_eq!(ok("01-99").as_deref(), Some("01/99"));
        assert_eq!(ok(" 05.31 ").as_deref(), Some("05/31"));
        // Empty stays optional (blank pair, never a refusal).
        assert_eq!(ok("").as_deref(), Some("/"));
        assert_eq!(ok("   ").as_deref(), Some("/"));
        // Garbage → None so the save gate refuses LOUD (never month 13).
        for bad in ["13/99", "00/25", "1/25", "123/45", "ab/cd", "12/", "/25", "12/2", "1225"] {
            assert_eq!(ok(bad), None, "must refuse {bad:?}");
        }
    }

    #[test]
    fn audit_scope_skips_trash() {
        fn login(id: &str, trashed: bool) -> Credential {
            Credential {
                id: id.into(),
                title: "t".into(),
                username: "u".into(),
                password: "p".into(),
                totp_secret: String::new(),
                urls: Vec::new(),
                backup_codes: Vec::new(),
                custom_fields: Vec::new(),
                notes: String::new(),
                folder: "General".into(),
                reprompt: false,
                attachments: Vec::new(),
                travel_safe: false,
                last_changed: 0,
                password_history: Vec::new(),
                favorite: false,
                deleted_at: trashed.then_some(1000),
            }
        }
        let mut v = Vault::new();
        v.credentials.push(login("live", false));
        v.credentials.push(login("old", true));
        let scoped = audit_scope_credentials(&v);
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].id, "live");
        // All-trashed vault audits as empty (same "Vault is empty" path).
        let mut only_trash = Vault::new();
        only_trash.credentials.push(login("old", true));
        assert!(audit_scope_credentials(&only_trash).is_empty());
    }

    #[test]
    fn totp_delete_removes_by_id() {
        fn acc(id: &str) -> TotpAccount {
            TotpAccount {
                id: id.into(),
                account_name: "a".into(),
                issuer: "i".into(),
                secret: "JBSWY3DPEHPK3PXP".into(),
                digits: 6,
                period: 30,
                algorithm: "SHA1".into(),
                otp_type: "totp".into(),
                counter: 0,
                favorite: false,
            }
        }
        let mut v = Vault::new();
        v.totp_accounts.push(acc("t1"));
        v.totp_accounts.push(acc("t2"));
        assert!(remove_totp_account(&mut v, "t1"));
        assert_eq!(v.totp_accounts.len(), 1);
        assert_eq!(v.totp_accounts[0].id, "t2");
        assert!(!remove_totp_account(&mut v, "nope"));
        assert!(!remove_totp_account(&mut Vault::new(), "t1"));
    }

    #[test]
    fn standalone_2fa_in_all_items_and_favorites() {
        let _guard = LIST_MODEL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        fn acc(id: &str, fav: bool) -> TotpAccount {
            TotpAccount {
                id: id.into(),
                account_name: "user@x".into(),
                issuer: "Google".into(),
                secret: "JBSWY3DPEHPK3PXP".into(),
                digits: 6,
                period: 30,
                algorithm: "SHA1".into(),
                otp_type: "totp".into(),
                counter: 0,
                favorite: fav,
            }
        }
        let mut v = Vault::new();
        v.totp_accounts.push(acc("t1", false));
        v.totp_accounts.push(acc("t2", true));
        // All items (kind 0): both hub accounts appear as kind-8 rows with
        // NO secrets riding the list model.
        let all = vault_to_items(&v, &FilterState::default());
        let rows: Vec<_> = all.iter().filter(|r| r.kind == 8).collect();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.password.as_str().is_empty() && r.totp.as_str().is_empty()));
        assert!(rows.iter().all(|r| r.title.as_str() == "Google"));
        // Favorites: only the pinned one survives.
        let favs = vault_to_items(&v, &FilterState { fav_only: true, ..Default::default() });
        let fav_rows: Vec<_> = favs.iter().filter(|r| r.kind == 8).collect();
        assert_eq!(fav_rows.len(), 1);
        assert_eq!(fav_rows[0].id.as_str(), "t2");
        // Login-only filter hides them; QuickBar never carries them.
        let logins = vault_to_items(&v, &FilterState { kind: 1, ..Default::default() });
        assert!(logins.iter().all(|r| r.kind != 8));
        assert!(vault_quickbar(&v, "", false).iter().all(|r| r.kind != 8));
        // Favorite flags round-trip through the kind-8 arms.
        assert_eq!(fav_flag(&v, 8, "t2"), Some(true));
        *fav_flag_mut(&mut v, 8, "t1").unwrap() = true;
        assert_eq!(fav_flag(&v, 8, "t1"), Some(true));
        assert_eq!(fav_flag(&v, 8, "nope"), None);
    }

    #[test]
    fn factory_targets_cover_vault_backups_and_seals_only() {
        let dir = std::env::temp_dir().join(format!("pv-factory-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for name in [
            "my_secure_vault.enc",
            "my_secure_vault.enc.bak",
            "my_secure_vault.bak.1.enc",
            "my_secure_vault.bak.2.enc",
            "decoy_vault.enc",
            "vault_hello.dpapi",
            "device.dpapi",
            "pin.dpapi",
            "pin_attempts.dpapi",
            "ext_pin.dpapi",
            "blackout.pref",
            "favicons.pref",
            "totp_offset.pref",
        ] {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        let got: Vec<String> = collect_factory_targets_in(&dir)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        // Vault + generations + decoy + seals (+ PIN seals) shred; prefs survive.
        for want in [
            "my_secure_vault.enc",
            "my_secure_vault.enc.bak",
            "my_secure_vault.bak.1.enc",
            "my_secure_vault.bak.2.enc",
            "decoy_vault.enc",
            "vault_hello.dpapi",
            "device.dpapi",
            "pin.dpapi",
            "pin_attempts.dpapi",
            "ext_pin.dpapi",
        ] {
            assert!(got.contains(&want.to_string()), "missing {want}: {got:?}");
        }
        assert!(!got.iter().any(|n| n.ends_with(".pref")), "{got:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn health_rows_group_and_order() {
        use crate::security::breach_check::BreachResult;
        let mk = |id: &str, breached: Option<u64>, reused, weak, stale| BreachResult {
            credential_id: id.into(),
            title: id.into(),
            breached,
            reused,
            weak,
            stale,
        };
        let results = vec![
            mk("stale1", None, false, false, true),
            mk("weak1", None, false, true, false),
            mk("ok", None, false, false, false),
            mk("breach1", Some(5), true, true, true),
            mk("reuse1", None, true, false, false),
        ];
        let rows = health_rows_for(&results);
        // 4 headers + 4 items (ok excluded), breached group first.
        assert_eq!(rows.len(), 8);
        assert_eq!(rows[0].sev, -1);
        assert_eq!(rows[1].id.as_str(), "breach1");
        assert_eq!(rows[1].sev, 0);
        assert!(rows[1].flags.as_str().contains("breached×5"));
        assert_eq!(rows[3].id.as_str(), "reuse1");
        assert_eq!(rows[3].sev, 1);
        // Priority: breached wins even when all flags set.
        assert!(!rows.iter().any(|r| r.id.as_str() == "ok"));
        // Empty input → no rows (dialog shows the healthy line).
        assert!(health_rows_for(&[]).is_empty());
    }

    #[test]
    fn totp_icon_domain_resolution() {
        let v = Vault::new();
        // Famous issuers resolve without any vault data.
        assert_eq!(famous_issuer_domain("Google"), Some("google.com"));
        assert_eq!(famous_issuer_domain("  DISCORD "), Some("discord.com"));
        assert_eq!(famous_issuer_domain("my-unknown-app"), None);
        assert_eq!(
            totp_icon_domain(&v, "GitHub", "octo").as_deref(),
            Some("github.com")
        );
        // Domain-like issuer works directly.
        assert_eq!(
            totp_icon_domain(&v, "2captcha.com", "u").as_deref(),
            Some("2captcha.com")
        );
        // Unknown issuer with no vault match → None (letter fallback).
        assert!(totp_icon_domain(&v, "my-unknown-app", "u").is_none());
        // Vault-login match lends its URL.
        let mut v2 = Vault::new();
        v2.credentials.push(models::Credential {
            id: "c1".into(),
            title: "ACME Corp".into(),
            username: "u".into(),
            password: "p".into(),
            totp_secret: String::new(),
            urls: vec!["https://login.acme.example.com".into()],
            backup_codes: Vec::new(),
            custom_fields: Vec::new(),
            notes: String::new(),
            folder: crate::models::DEFAULT_FOLDER.to_string(),
            reprompt: false,
            attachments: Vec::new(),
            travel_safe: false,
            last_changed: 0,
            password_history: Vec::new(),
            favorite: false,
            deleted_at: None,
        });
        assert_eq!(
            totp_icon_domain(&v2, "ACME Corp", "u").as_deref(),
            Some("login.acme.example.com")
        );
    }

    #[test]
    fn native_host_launch_detection() {
        assert!(is_native_host_launch("native-host"));
        assert!(is_native_host_launch(
            "chrome-extension://goegfnjadkancnkldlamofedndcppafo/"
        ));
        // Extra Chromium args (parent-window handle) must not matter: only
        // argv[1] is inspected, so any origin-shaped first arg serves.
        assert!(!is_native_host_launch("run"));
        assert!(!is_native_host_launch(""));
        assert!(!is_native_host_launch("chrome-extension"));
        assert!(!is_native_host_launch("https://github.com/"));
    }

    #[test]
    fn pr3_missing_pref_means_not_backed_up() {
        let p = std::env::temp_dir().join(format!(
            "pv-rec-{}-missing.pref",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        assert!(!recovery_exported_at(&p));
    }

    #[test]
    fn pr3_exported_pref_means_backed_up() {
        let p = std::env::temp_dir().join(format!(
            "pv-rec-{}-done.pref",
            std::process::id()
        ));
        std::fs::write(&p, "1").unwrap();
        assert!(recovery_exported_at(&p));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn pr3_garbage_pref_means_not_backed_up() {
        let p = std::env::temp_dir().join(format!(
            "pv-rec-{}-junk.pref",
            std::process::id()
        ));
        std::fs::write(&p, "yes-ish").unwrap();
        assert!(!recovery_exported_at(&p));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a2lite_favicon_ram_cap_is_100() {
        assert_eq!(FAVICON_RAM_CAP, 100);
        // Simulate the capped insert: 150 domains → exactly 100 retained.
        let mut cache: std::collections::HashMap<String, Vec<u8>> =
            std::collections::HashMap::new();
        for i in 0..150 {
            let d = format!("d{i}.example");
            if !cache.contains_key(&d) {
                if cache.len() >= FAVICON_RAM_CAP {
                    if let Some(k) = cache.keys().next().cloned() {
                        cache.remove(&k);
                    }
                }
                cache.insert(d, vec![1, 2, 3]);
            }
        }
        assert_eq!(cache.len(), 100);
    }

    #[test]
    fn a2lite_lock_clear_empties_favicon_ram() {
        {
            let mut c = favicon_bytes().lock().unwrap_or_else(|p| p.into_inner());
            c.insert("x.example".to_string(), vec![9u8; 8]);
        }
        clear_favicon_bytes();
        assert!(favicon_bytes()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty());
    }

    #[test]
    fn pr1_missing_hello_token_is_not_new_device() {
        let p = std::env::temp_dir().join(format!(
            "pv-hello-nd-{}-missing.dpapi",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        assert!(!is_hello_token_unreadable_at(&p));
    }

    #[test]
    fn pr1_corrupt_hello_token_is_new_device() {
        let p = std::env::temp_dir().join(format!(
            "pv-hello-nd-{}-junk.dpapi",
            std::process::id()
        ));
        std::fs::write(&p, b"definitely-not-a-dpapi-blob").unwrap();
        assert!(is_hello_token_unreadable_at(&p));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn pr1_sealed_hello_token_reads_back() {
        let p = std::env::temp_dir().join(format!(
            "pv-hello-nd-{}-sealed.dpapi",
            std::process::id()
        ));
        let blob = crate::core::memory::DpapiGuard::protect(b"nd-probe").unwrap();
        std::fs::write(&p, &blob).unwrap();
        assert!(!is_hello_token_unreadable_at(&p));
        let back = crate::core::memory::DpapiGuard::unprotect(
            &std::fs::read(&p).unwrap(),
        )
        .unwrap();
        assert_eq!(back.expose(), b"nd-probe");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn passkey_fav_flag_kind_seven() {
        let mut v = Vault::new();
        v.passkeys.push(models::PasskeyItem {
            id: "pk".into(),
            rp_id: String::new(),
            user_name: String::new(),
            user_handle: Vec::new(),
            credential_id: Vec::new(),
            private_key_pkcs8: Vec::new(),
            public_key_der: Vec::new(),
            sign_count: 0,
            created_at: 0,
            favorite: false,
            deleted_at: None,
        });
        assert_eq!(fav_flag(&v, 7, "pk"), Some(false));
        *fav_flag_mut(&mut v, 7, "pk").unwrap() = true;
        assert_eq!(fav_flag(&v, 7, "pk"), Some(true));
        assert_eq!(fav_flag(&v, 7, "nope"), None);
        assert_eq!(fav_flag(&v, 9, "pk"), None);
    }
}
