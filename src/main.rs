#[allow(dead_code)]
mod crypto;
#[allow(dead_code)]
mod models;
#[allow(dead_code)]
mod storage;
mod totp_engine;
mod authenticator;
mod core;
mod developer;
mod error;
mod importer;
mod security;
mod sync;
mod windows_native;

use arboard::Clipboard;
use core::generator::{PasswordGenerator, PasswordPolicy};
use secrecy::{ExposeSecret, SecretString};
use models::{Credential, TotpAccount, Vault};
use slint::{ComponentHandle, Model, ModelRc, VecModel};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use storage::save_vault;

slint::include_modules!();

const VAULT_FILE: &str = "my_secure_vault.enc";
const HELLO_TOKEN_FILE: &str = "vault_hello.dpapi";

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
fn trigger_autotype(
    main_weak: slint::Weak<MainWindow>,
    qb_weak: slint::Weak<QuickBarWindow>,
    qb_visible: Arc<std::sync::atomic::AtomicBool>,
    username: String,
    password: String,
    totp_secret: String,
) {
    use core::memory::LockedMemory;
    use windows_native::autotype::type_sequence;
    if let Some(ui) = main_weak.upgrade() {
        ui.set_notification_text("⌨️ vault minimized — focus the target field…".into());
        ui.window().set_minimized(true);
    }
    if let Some(qb) = qb_weak.upgrade() {
        qb.hide().ok();
    }
    qb_visible.store(false, std::sync::atomic::Ordering::SeqCst);
    thread::spawn(move || {
        // Even an unexpected panic mid-typing must restore the window —
        // never leave the user staring at a vanished vault.
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Batch-1: the password rides a VirtualLock-pinned page while typing.
            let secret = LockedMemory::new(password)
                .map_err(|e| crate::error::VaultError::AutoType(e.to_string()))?;
            let out = type_sequence(&username, secret.expose());
            drop(secret);
            out
        }))
        .map_err(|_| {
            crate::error::VaultError::AutoType("typing aborted unexpectedly".into())
        })
        .and_then(|r| r);
        let chained = res.is_ok() && !totp_secret.trim().is_empty();
        // Arm the 2FA watcher BEFORE restoring UI (overlaps the app's
        // password-submit round-trip instead of serializing after it).
        let chain_handle = chained.then(|| {
            let weak = main_weak.clone();
            let mut secret = totp_secret.trim().to_string();
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
                match &res {
                    Ok(()) => {
                        if chain_handle.is_none() {
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
    use core::memory::LockedMemory;
    use windows_native::desktop_autofill::otp_screen_visible;
    let secret = LockedMemory::new(totp_secret.trim().to_string()).ok()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if otp_screen_visible() {
            std::thread::sleep(Duration::from_millis(300));
            let (code, _) = totp_engine::generate_live_code(secret.expose()).ok()?;
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
            }
        });
        return;
    }
    let fb_msg = format!("📋 Copied (fallback path — auto-clearing in {secs}s)");
    match windows_native::clipboard::copy_sensitive(&text, secs, move || {
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak_clear.upgrade() {
                ui.set_notification_text("🧹 Clipboard auto-cleared for security!".into());
            }
        });
    }) {
        Ok(()) => {
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak_ok.upgrade() {
                    ui.set_notification_text(msg.into());
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
    panic_wipe(vault_arc, master_arc);
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
        // Purge every secret-holding list model…
        ui.set_credentials(ModelRc::new(VecModel::from(Vec::<CredentialView>::new())));
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
        ui.set_show_detail(false);
        ui.set_f_title(String::new().into());
        ui.set_f_a(String::new().into());
        ui.set_f_b(String::new().into());
        ui.set_f_c(String::new().into());
        ui.set_f_d(String::new().into());
        ui.set_f_e(String::new().into());
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
#[allow(clippy::too_many_arguments)]
fn unlock_with_password(
    pass: String,
    main_weak: slint::Weak<MainWindow>,
    vault_arc: Arc<Mutex<Vault>>,
    master_pw_arc: Arc<Mutex<Option<SecretString>>>,
    search_state: Arc<Mutex<FilterState>>,
    qb_weak: slint::Weak<QuickBarWindow>,
    cache_hello_token: bool,
    and_mode: bool,
) {
    if pass.is_empty() {
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
            match storage::load_vault_versioned(&pass, VAULT_FILE) {
                Ok((vault, was_legacy)) => {
                    if was_legacy {
                        // Best-effort forward migration: re-seal as v2 hybrid.
                        // Unlock proceeds regardless; a retry happens next unlock.
                        let _ = save_vault(&vault, &pass, VAULT_FILE);
                    }
                    Ok(vault)
                }
                Err(e) => Err(e),
            }
        } else {
            // First run: initialize with demo credential
            let mut init_vault = Vault::new();
            init_vault.credentials.push(Credential {
                id: "1".into(),
                title: "GitHub Personal Token".into(),
                username: "developer@gmail.com".into(),
                password: "ghp_SecretTokenLiveDemo999!".into(),
                totp_secret: String::new(),
                backup_codes: Vec::new(),
                custom_fields: Vec::new(),
                urls: vec!["https://github.com".to_string()],
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
            init_vault.totp_accounts.push(TotpAccount {
                id: "2".into(),
                account_name: "Google Workspace".into(),
                issuer: "Google".into(),
                secret: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".into(),
                digits: 6,
                period: 30,
                algorithm: "SHA1".to_string(),
                otp_type: "totp".to_string(),
                counter: 0,
            });

            match save_vault(&init_vault, &pass, VAULT_FILE) {
                Ok(()) => Ok(init_vault),
                Err(e) => Err(format!("Failed to create vault: {}", e)),
            }
        };

        // Phase 11: on success, DPAPI-seal the passphrase for Hello unlocks.
        // Failures are silent — Hello simply stays unavailable.
        if cache_hello_token && loaded_result.is_ok() {
            if let Ok(blob) = core::memory::DpapiGuard::protect(pass.as_bytes()) {
                let _ = std::fs::write(HELLO_TOKEN_FILE, blob);
            }
        }

        // Phase 15 (Option 1): duress fallback. Only attempted when the real
        // vault rejects the password AND a decoy container exists. The extra
        // Argon2id cost lands solely on failed attempts — never on the happy path.
        let decoy_vault: Option<Vault> =
            if loaded_result.is_err() && security::decoy::decoy_exists() {
                security::decoy::try_open_decoy(&pass)
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
                let _ = save_vault(v, &pass, VAULT_FILE);
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
        if and_mode && matches!(&loaded_result, Ok(_)) && decoy_vault.is_none() && hello_enrolled
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
                        unlock_with_password(pass2, w2, v2, m2, s2, q2, false, false);
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
            and_mode && matches!(&loaded_result, Ok(_)) && decoy_vault.is_none() && !hello_enrolled;

        let pass_for_store = pass.clone();
        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = main_weak.upgrade() else {
                return;
            };
            match loaded_result {
                Ok(vault) => {
                    *lock_master_pw(&master_pw_arc) = Some(SecretString::new(pass_for_store));
                    *search_state.lock().unwrap() = FilterState::default();
                    ui.set_search_query("".into());
                    // View props must mirror the reset filter — otherwise a
                    // pre-lock Trash/Favorites view desyncs from the list.
                    ui.set_showing_trash(false);
                    ui.set_show_fav_only(false);
                    ui.set_show_empty_confirm(false);
                    ui.set_type_filter(0);
                    ui.set_folder_filter("All".into());
                    let mut vault = vault;
                    vault.ensure_folders();
                    sync_folders_to_ui(&vault, &ui);
                    let items = vault_to_items(&vault, &FilterState::default());
                    ui.set_credentials(items.clone());
                    set_trash_label(&ui, &vault);
                    if let Some(qb) = qb_weak.upgrade() {
                        qb.set_filtered_results(vault_quickbar(&vault, "", search_state.lock().unwrap().travel_only));
                    }
                    *lock_vault(&vault_arc) = vault;
                    ui.set_is_unlocked(true);
                    ui.set_is_decoy(false);
                    ui.set_status_text("✅ Vault unlocked".into());
                    // Hardware binding (rules Cat 6): warn-only machine check.
                    // Registry + DPAPI read is milliseconds — safe inline.
                    if windows_native::device_bind::check_device() {
                        ui.set_notification_text(
                            "⚠️ Bound to a different machine (ignore for portable USB).".into(),
                        );
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

                    // Phase 24: authenticator list now + live refresh ticker.
                    // The same 1s loop drives the hero countdown and refreshes
                    // all dynamic codes every 5s (cheap, few accounts).
                    {
                        let v = lock_vault(&vault_arc);
                            ui.set_auth_accounts(rebuild_auth_list(&v));
                            ui.set_auth_rows(rebuild_auth_rows(&v));
                        // Fresh unlock resets the filter (see above), so the
                        // hub starts unfiltered; trashed keys get their own
                        // hub section instead of the sidebar Trash view.
                        ui.set_passkeys(rebuild_passkeys(&v, false));
                        ui.set_passkeys_trash(rebuild_trashed_passkeys(&v));
                    }
                    let window_for_totp = ui.as_weak();
                    let vault_for_auth = Arc::clone(&vault_arc);
                    thread::spawn(move || {
                        let mut tick = 0u64;
                        loop {
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
                                    if let Some((label, code, when)) = hero {
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
                            tick += 1;
                            if tick.is_multiple_of(5) {
                                // ModelRc is !Send: move the vault handle in,
                                // build the model on the event-loop thread.
                                let vault_for_row = Arc::clone(&vault_for_auth);
                                let window_clone = window_for_totp.clone();
                                let _ = slint::invoke_from_event_loop(move || {
                                    if let Some(ui) = window_clone.upgrade() {
                                        let v = lock_vault(&vault_for_row);
                                        ui.set_auth_accounts(rebuild_auth_list(&v));
                                        ui.set_auth_rows(rebuild_auth_rows(&v));
                                    }
                                });
                            }
                            thread::sleep(Duration::from_secs(1));
                        }
                    });
                }
                Err(e) => {
                    // Duress path: verified decoy opens a believable fake vault.
                    // No migration, no Hello cache, no sync — pure read-mostly cover.
                    if let Some(decoy) = decoy_vault {
                        *lock_master_pw(&master_pw_arc) = Some(SecretString::new(pass_for_store));
                        *search_state.lock().unwrap() = FilterState::default();
                        ui.set_search_query("".into());
                        ui.set_showing_trash(false);
                        ui.set_show_fav_only(false);
                        ui.set_show_empty_confirm(false);
                        ui.set_type_filter(0);
                        ui.set_folder_filter("All".into());
                        let items = vault_to_items(&decoy, &FilterState::default());
                        ui.set_credentials(items.clone());
                        set_trash_label(&ui, &decoy);
                        if let Some(qb) = qb_weak.upgrade() {
                            qb.set_filtered_results(vault_quickbar(&decoy, "", search_state.lock().unwrap().travel_only));
                        }
                        *lock_vault(&vault_arc) = decoy;
                        ui.set_is_unlocked(true);
                        ui.set_is_decoy(true);
                        ui.set_status_text("✅ Vault unlocked".into());
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
fn build_auth_rows(vault: &Vault) -> Vec<AuthView> {
    vault
        .totp_accounts
        .iter()
        .map(|a| {
            let (code, _) = totp_engine::generate_code_for_account(a)
                .unwrap_or(("------".to_string(), 0));
            let next = totp_engine::next_code_for_account(a).unwrap_or_else(|_| "------".to_string());
            let kind = match a.otp_type.trim().to_lowercase().as_str() {
                "hotp" => "HOTP",
                "steam" => "STEAM",
                _ => "TOTP",
            };
            let (icon, tint) = brand_of(&a.issuer, &a.account_name);
            AuthView {
                id: a.id.clone().into(),
                name: a.account_name.clone().into(),
                issuer: a.issuer.clone().into(),
                code: code.clone().into(),
                display: group_code(&code).into(),
                next: group_code(&next).into(),
                icon: icon.to_string().into(),
                tint,
                kind: kind.into(),
                is_hotp: kind == "HOTP",
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

/// Chunk a flat row vec into grid rows of 3 (last row may be short).
/// Pure — unit tested.
fn chunk_rows<T: Clone>(items: Vec<T>) -> Vec<Vec<T>> {
    items
        .chunks(3)
        .map(|c| c.to_vec())
        .collect()
}

/// Grid model for the authenticator page: `[[AuthView]]` rows of 3.
fn rebuild_auth_rows(vault: &Vault) -> ModelRc<ModelRc<AuthView>> {
    let rows: Vec<ModelRc<AuthView>> = chunk_rows(build_auth_rows(vault))
        .into_iter()
        .map(|r| ModelRc::new(VecModel::from(r)))
        .collect();
    ModelRc::new(VecModel::from(rows))
}

/// Retired-password rows: secret + relative age, newest first.
/// The secret rides the row (copy button needs it); the list lives only in
/// RAM on the detail view and dies with it — never logged, never synced raw.
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

/// Mutable favorite flag for any of the 6 kinds (toggle path).
fn fav_flag_mut<'a>(vault: &'a mut Vault, kind: i32, id: &str) -> Option<&'a mut bool> {
    match kind {
        1 => vault.credentials.iter_mut().find(|c| c.id == id).map(|c| &mut c.favorite),
        2 => vault.licenses.iter_mut().find(|l| l.id == id).map(|l| &mut l.favorite),
        3 => vault.notes.iter_mut().find(|n| n.id == id).map(|n| &mut n.favorite),
        4 => vault.cards.iter_mut().find(|k| k.id == id).map(|k| &mut k.favorite),
        5 => vault.identities.iter_mut().find(|i| i.id == id).map(|i| &mut i.favorite),
        6 => vault.ssh_keys.iter_mut().find(|s| s.id == id).map(|s| &mut s.favorite),
        7 => vault.passkeys.iter_mut().find(|p| p.id == id).map(|p| &mut p.favorite),
        _ => None,
    }
}

/// Read-only favorite flag for any of the 7 kinds (refresh path).
fn fav_flag(vault: &Vault, kind: i32, id: &str) -> Option<bool> {
    match kind {
        1 => vault.credentials.iter().find(|c| c.id == id).map(|c| c.favorite),
        2 => vault.licenses.iter().find(|l| l.id == id).map(|l| l.favorite),
        3 => vault.notes.iter().find(|n| n.id == id).map(|n| n.favorite),
        4 => vault.cards.iter().find(|k| k.id == id).map(|k| k.favorite),
        5 => vault.identities.iter().find(|i| i.id == id).map(|i| i.favorite),
        6 => vault.ssh_keys.iter().find(|s| s.id == id).map(|s| s.favorite),
        7 => vault.passkeys.iter().find(|p| p.id == id).map(|p| p.favorite),
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
}

impl Default for FilterState {
    fn default() -> Self {
        Self { query: String::new(), kind: 0, folder: "All".to_string(), travel_only: false, fav_only: false, show_trash: false }
    }
}

fn eff_folder(folder: &str) -> &str {
    if folder.is_empty() {
        "General"
    } else {
        folder
    }
}

fn primary_url(urls: &[String]) -> String {
    urls.first().cloned().unwrap_or_default()
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
        health: health_badge_for(id).into(),
        fav,
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

/// Unified list builder: search query + type + folder over all 6 vectors.
fn vault_to_items(vault: &Vault, f: &FilterState) -> ModelRc<CredentialView> {
    let q = f.query.trim().to_lowercase();
    let mut items = Vec::new();
    for c in &vault.credentials {
        push_item(&mut items, f, &q, &c.id, 1, &c.title, &c.username, &c.password, "", &primary_url(&c.urls), &c.notes, &c.folder, &c.totp_secret, c.travel_safe, c.favorite, c.deleted_at.is_some());
    }
    for l in &vault.licenses {
        push_item(&mut items, f, &q, &l.id, 2, &l.app_name, "Software license",
            &l.license_key, &l.expiry_date.clone().unwrap_or_default(), "", "", &l.folder, "", l.travel_safe, l.favorite, l.deleted_at.is_some());
    }
    for n in &vault.notes {
        let preview: String = n.content.lines().next().unwrap_or("").chars().take(48).collect();
        push_item(&mut items, f, &q, &n.id, 3, &n.title, &preview, &n.content, "", "", &n.content, &n.folder, "", n.travel_safe, n.favorite, n.deleted_at.is_some());
    }
    for k in &vault.cards {
        let exp = format!("{:0>2}/{:0>2}", k.exp_month, k.exp_year);
        let meta = format!("exp {exp}  CVV {}", k.cvv);
        push_item(&mut items, f, &q, &k.id, 4, &k.title, &k.cardholder_name, &k.card_number, &meta, "", "", &k.folder, "", k.travel_safe, k.favorite, k.deleted_at.is_some());
    }
    for i in &vault.identities {
        push_item(&mut items, f, &q, &i.id, 5, &i.title, &i.full_name, &i.nid_or_passport, &i.phone, &i.email, &i.address, &i.folder, "", i.travel_safe, i.favorite, i.deleted_at.is_some());
    }
    for s in &vault.ssh_keys {
        push_item(&mut items, f, &q, &s.id, 6, &s.title, "SSH key", &s.private_key, &s.fingerprint, "", &s.public_key, &s.folder, "", s.travel_safe, s.favorite, s.deleted_at.is_some());
    }
    ModelRc::new(VecModel::from(items))
}

/// QuickBar feed: logins only, optional query.
/// D6: Omni-Search QuickBar feed — ALL kinds (logins, cards, notes, licenses,
/// identities, ssh). Rows display title + subtitle only (numbers/keys stay
/// masked until Copy/Type), so screen-sharers see no secrets.
fn vault_quickbar(vault: &Vault, query: &str, travel_only: bool) -> ModelRc<CredentialView> {
    vault_to_items(
        vault,
        &FilterState { query: query.to_string(), kind: 0, folder: "All".to_string(), travel_only, fav_only: false, show_trash: false },
    )
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
    if let Ok(dir) = std::env::var("PHANTOM_VAULT_DIR") {
        let dir = dir.trim().to_string();
        if !dir.is_empty() {
            let res: std::io::Result<()> =
                std::fs::create_dir_all(&dir).and_then(|()| std::env::set_current_dir(&dir));
            match res {
                Ok(()) => eprintln!("📦 Portable mode: data dir = {dir}"),
                Err(e) => eprintln!("⚠️ Portable dir unusable ({dir}): {e} — using default."),
            }
        }
    }
    // Cat 8 process hardening, applied before any secret exists in RAM:
    // refuse injected DLLs, opt out of WER crash-dump uploads, probe admin.
    let dll_guarded = windows_native::process_guard::block_injected_dlls();
    let wer_excluded = windows_native::process_guard::exclude_from_crash_dumps();
    let elevated = windows_native::process_guard::is_elevated();
    // NOTE: stderr only — stdout belongs to the Native Messaging frame
    // protocol when Chromium launches us (any println here corrupts the
    // length-prefixed pipe and the popup hangs on "Loading…").
    if dll_guarded {
        eprintln!("🛡️ DLL-injection block active (Microsoft-only binaries).");
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
    let quick_bar = QuickBarWindow::new()?;
    let capture_window = QuickCaptureWindow::new()?;
    let quickbar_visible = Arc::new(std::sync::atomic::AtomicBool::new(false));
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
            if idle < Duration::from_secs(mins * 60) {
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
        thread::spawn(move || {
            use windows_native::ime_guard::hwnd_of;
            let mut last_shown = String::new();
            let mut had_focus = true; // assume focused until proven otherwise
            let mut ours: Vec<isize> = vec![0, 0, 0];
            loop {
                thread::sleep(Duration::from_millis(1500));
                let unlocked = master_pill.lock().map(|m| m.is_some()).unwrap_or(false);
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

    // Phase Batch-1: DWM Anti-Capture Guard (WDA_MONITOR, delayed 250ms).
    // Covers MainWindow + QuickBar + QuickCapture so secrets never leak via
    // ShareX/GDI-BitBlt OR OBS/Zoom/Discord WGC pipelines.
    #[cfg(windows)]
    {
        let main_weak_guard = main_window.as_weak();
        let qb_weak_guard = quick_bar.as_weak();
        let cap_weak_guard = capture_window.as_weak();
        // Delayed off-loop: DWM needs the top-level HWNDs fully adopted first.
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(250));
            let _ = slint::invoke_from_event_loop(move || {
                let mut guarded = 0;
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

    // Phase 13: Auto-Type from QuickBar (username + password keystroke fill)
    let type_qb_main = main_window.as_weak();
    let type_qb_self = quick_bar.as_weak();
    let type_qb_vis = Arc::clone(&quickbar_visible);
    let type_qb_vault = Arc::clone(&active_vault);
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
            username.as_str().to_string(),
            password.as_str().to_string(),
            totp.as_str().to_string(),
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
                match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
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
                            ui.set_credentials(vault_to_items(&v, &f));
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

    // 1. Unlock handler — delegates to the shared unlock pipeline
    let window_weak = main_window.as_weak();
    let vault_arc = Arc::clone(&active_vault);
    let master_pw_arc = Arc::clone(&active_master_pw);
    let search_state_unlock = Arc::clone(&search_state);
    let qb_weak_unlock = quick_bar.as_weak();
    let travel_off = Arc::clone(&travel_mode);
    let activity_unlock = Arc::clone(&last_activity);
    main_window.on_unlock_requested(move |entered_password| {
        if let Ok(mut t) = activity_unlock.lock() {
            *t = std::time::Instant::now();
        }
        let pass = entered_password.as_str().trim().to_string();
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

    // Phase 11: Windows Hello — biometric unlock request
    let bio_weak = main_window.as_weak();
    let bio_vault = Arc::clone(&active_vault);
    let bio_master = Arc::clone(&active_master_pw);
    let bio_search = Arc::clone(&search_state);
    let bio_qb = quick_bar.as_weak();
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
                        pass, weak, vault_clone, master_clone, search_clone, qb_clone, false,
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
    urls: Vec<String>,
    backup: Vec<String>,
    custom: Vec<models::CustomField>,
    totp: &str,
    reprompt: bool,
    fav: bool,
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
            travel_safe: false,
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
            attachments: Vec::new(),
            travel_safe: false,
            favorite: fav,
            deleted_at: None,
        }),
        3 => vault.notes.push(models::SecureNote {
            id,
            title: title.to_string(),
            content: a.to_string(),
            folder: folder.to_string(),
            travel_safe: false,
            favorite: fav,
            deleted_at: None,
        }),
        4 => {
            let (em, ey) = split_card_expiry(cc);
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
                travel_safe: false,
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
            folder: folder.to_string(),
            notes: String::new(),
            travel_safe: false,
            favorite: fav,
            deleted_at: None,
        }),
        6 => vault.ssh_keys.push(models::SshKeyItem {
            id,
            title: title.to_string(),
            public_key: a.to_string(),
            private_key: b.to_string(),
            fingerprint: cc.to_string(),
            folder: folder.to_string(),
            notes: notes.to_string(),
            travel_safe: false,
            favorite: fav,
            deleted_at: None,
        }),
        _ => {}
    }
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
    urls: &[String],
    backup: &[String],
    custom: &[models::CustomField],
    totp: &str,
    reprompt: bool,
    fav: bool,
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
            true
        }
        2 => {
            let Some(l) = vault.licenses.iter_mut().find(|l| l.id == id) else {
                return false;
            };
            l.app_name = title.to_string();
            l.license_key = a.to_string();
            l.expiry_date = (!b.trim().is_empty()).then(|| b.to_string());
            l.folder = folder.to_string();
            l.favorite = fav;
            true
        }
        3 => {
            let Some(n) = vault.notes.iter_mut().find(|n| n.id == id) else {
                return false;
            };
            n.title = title.to_string();
            n.content = a.to_string();
            n.folder = folder.to_string();
            n.favorite = fav;
            true
        }
        4 => {
            let Some(k) = vault.cards.iter_mut().find(|k| k.id == id) else {
                return false;
            };
            k.title = title.to_string();
            k.cardholder_name = a.to_string();
            k.card_number = b.to_string();
            let (em, ey) = split_card_expiry(cc);
            k.exp_month = em;
            k.exp_year = ey;
            k.cvv = dd.to_string();
            k.folder = folder.to_string();
            k.notes = notes.to_string();
            k.favorite = fav;
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
            i.folder = folder.to_string();
            i.favorite = fav;
            true
        }
        6 => {
            let Some(s) = vault.ssh_keys.iter_mut().find(|s| s.id == id) else {
                return false;
            };
            s.title = title.to_string();
            s.public_key = a.to_string();
            s.private_key = b.to_string();
            s.fingerprint = cc.to_string();
            s.folder = folder.to_string();
            s.notes = notes.to_string();
            s.favorite = fav;
            true
        }
        _ => false,
    }
}

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
        move |kind, title, a, b, c, d, e, notes, folder, totp, backup, reprompt, fav| {
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
            let cc = c.as_str().to_string();
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
            let title_for_thread = title.clone();
            let backup_for_thread = backup_for_cb.clone();
            let totp_for_thread = totp_for_cb.clone();
            let reprompt_for_thread = reprompt;
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
                let save_result: Result<Vault, String> = {
                    let mut vault = lock_vault(&vault_clone);
                    // Snapshot for rollback (cheap, in-RAM vaults are small).
                    let snapshot = vault.clone();
                    let urls: Vec<String> = cc
                        .lines()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect();
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
                            fav_for_thread,
                        )
                    } else {
                        false
                    };
                    if !replaced {
                        push_new_item(
                            &mut vault, kind, new_id, &title_for_thread,
                            &a, &b, &cc, &dd, &ee, &notes, &folder,
                            urls, backup, custom, &totp_for_thread, reprompt_for_thread,
                            fav_for_thread,
                        );
                    }

                    match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
                        Ok(()) => Ok(vault.clone()),
                        Err(e) => {
                            *vault = snapshot;
                            Err(e)
                        }
                    }
                };

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
                            if let Some(qb) = qb_weak.upgrade() {
                                qb.set_filtered_results(vault_quickbar(&vault_snapshot, "", search_clone.lock().unwrap().travel_only));
                            }
                            ui.set_notification_text(
                                "✅ Item encrypted to disk!".into(),
                            );
                            // Clear form, exit edit mode, drop pending custom fields
                            ui.set_f_title("".into());
                            ui.set_f_a("".into());
                            ui.set_f_b("".into());
                            ui.set_f_c("".into());
                            ui.set_f_d("".into());
                            ui.set_f_e("".into());
                            ui.set_f_notes("".into());
                            ui.set_f_totp("".into());
                            ui.set_f_backup("".into());
                            ui.set_f_reprompt(false);
                            ui.set_f_fav(false);
                            ui.set_show_add_form(false);
                            *editing_done.lock().unwrap() = None;
                            *pending_done.lock().unwrap() = Vec::new();
                            ui.set_custom_fields(ModelRc::new(VecModel::from(Vec::<CustomFieldView>::new())));
                            sync_folders_to_ui(&vault_snapshot, &ui);
                            trigger_sync_push(ui.as_weak());
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
                let already = vault.is_trashed(kind, &id).unwrap_or(false);
                let ok = if already {
                    vault.delete_item(kind, &id)
                } else {
                    vault.trash_item(kind, &id, crate::models::current_timestamp())
                };
                if !ok {
                    Err("Item not found (already deleted?)".to_string())
                } else {
                    match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
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
                match save_result {
                    Ok((vault_snapshot, permanent)) => {
                        let f = search_clone.lock().unwrap().clone();
                        ui.set_credentials(vault_to_items(&vault_snapshot, &f));
                        set_trash_label(&ui, &vault_snapshot);
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
                    match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
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
                        ui.set_credentials(vault_to_items(&vault_snapshot, &f));
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
                    match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
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
                        ui.set_credentials(vault_to_items(&vault_snapshot, &f));
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
        // Search stays inside the current view (vault or Trash).
        *search_state_search.lock().unwrap() = f.clone();
        let vault = lock_vault(&vault_arc_search);
        if let Some(ui) = window_weak_search.upgrade() {
            ui.set_credentials(vault_to_items(&vault, &f));
        }
    });

    let window_weak_type = main_window.as_weak();
    let vault_arc_type = Arc::clone(&active_vault);
    let search_state_type = Arc::clone(&search_state);
    main_window.on_type_filter_changed(move |kind| {
        let mut f = search_state_type.lock().unwrap().clone();
        f.kind = kind;
        // Leaving any view always exits Trash (prop mirrors the state).
        f.show_trash = false;
        *search_state_type.lock().unwrap() = f.clone();
        let vault = lock_vault(&vault_arc_type);
        if let Some(ui) = window_weak_type.upgrade() {
            ui.set_showing_trash(false);
            ui.set_credentials(vault_to_items(&vault, &f));
        }
    });

    let window_weak_folder = main_window.as_weak();
    let vault_arc_folder = Arc::clone(&active_vault);
    let search_state_folder = Arc::clone(&search_state);
    main_window.on_folder_filter_changed(move |folder| {
        let mut f = search_state_folder.lock().unwrap().clone();
        f.folder = folder.as_str().to_string();
        f.show_trash = false;
        *search_state_folder.lock().unwrap() = f.clone();
        let vault = lock_vault(&vault_arc_folder);
        if let Some(ui) = window_weak_folder.upgrade() {
            ui.set_showing_trash(false);
            ui.set_credentials(vault_to_items(&vault, &f));
        }
    });

    // Sidebar ⭐ filter: same refresh pattern, kind stays untouched.
    let window_weak_favf = main_window.as_weak();
    let vault_arc_favf = Arc::clone(&active_vault);
    let search_state_favf = Arc::clone(&search_state);
    main_window.on_fav_filter_changed(move |only| {
        let mut f = search_state_favf.lock().unwrap().clone();
        f.fav_only = only;
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
            ui.set_credentials(vault_to_items(&vault, &f));
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
        *search_state_trash.lock().unwrap() = f.clone();
        let vault = lock_vault(&vault_arc_trash);
        if let Some(ui) = window_weak_trash.upgrade() {
            ui.set_type_filter(0);
            ui.set_folder_filter("All".into());
            ui.set_show_fav_only(false);
            ui.set_showing_trash(true);
            ui.set_show_empty_confirm(false);
            ui.set_credentials(vault_to_items(&vault, &f));
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
                if save_vault(&vault, master_pw.expose_secret(), VAULT_FILE).is_err() {
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
                ui.set_credentials(vault_to_items(&v, &f));
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

    // 8a: Manual URL paste (otpauth-migration:// or otpauth://)
    let window_weak_url = main_window.as_weak();
    let vault_arc_url = Arc::clone(&active_vault);
    let master_pw_url = Arc::clone(&active_master_pw);
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
        // Parse synchronously (fast prost decode) then delegate to background save
        match authenticator::parse_google_migration_url(&input) {
            Ok(accounts) => {
                // Reuse helper logic — spawn save in background
                let vault_clone = Arc::clone(&vault_arc_url);
                let master_clone = Arc::clone(&master_pw_url);
                let count = accounts.len();
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
                    let save_result: Result<(), String> = {
                        let mut vault = lock_vault(&vault_clone);
                        vault.totp_accounts.extend(accounts);
                        match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
                            Ok(()) => Ok(()),
                            Err(e) => {
                                for _ in 0..count {
                                    vault.totp_accounts.pop();
                                }
                                Err(e)
                            }
                        }
                    };
                    let vault_for_list = Arc::clone(&vault_clone);
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            match save_result {
                                Ok(()) => {
                                    ui.set_notification_text(
                                        format!("✅ Imported {} 2FA accounts successfully!", count)
                                            .into(),
                                    );
                                    ui.set_import_input("".into());
                                    ui.set_show_2fa_import(false);
                                    {
                                        let v = lock_vault(&vault_for_list);
                                        ui.set_auth_accounts(rebuild_auth_list(&v));
                                        ui.set_auth_rows(rebuild_auth_rows(&v));
                                    }
                                    trigger_sync_push(ui.as_weak());
                                }
                                Err(e) => {
                                    ui.set_notification_text(
                                        format!("❌ Import save failed: {}", e).into(),
                                    );
                                }
                            }
                        }
                    });
                });
            }
            Err(e) => {
                if let Some(ui) = window_weak_url.upgrade() {
                    ui.set_notification_text(format!("❌ Import failed: {}", e).into());
                }
            }
        }
    });

    // 8b: Clipboard QR scan (Win+Shift+S)
    let window_weak_qr = main_window.as_weak();
    let vault_arc_qr = Arc::clone(&active_vault);
    let master_pw_qr = Arc::clone(&active_master_pw);
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
            let accounts = match authenticator::parse_google_migration_url(&qr_content) {
                Ok(a) => a,
                Err(e) => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_notification_text(format!("❌ QR parse failed: {}", e).into());
                        }
                    });
                    return;
                }
            };
            let count = accounts.len();
            let master_opt = lock_master_pw(&master_clone).clone();
            let Some(master_pw) = master_opt else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_notification_text("❌ Vault not unlocked!".into());
                    }
                });
                return;
            };
            let save_result: Result<(), String> = {
                let mut vault = lock_vault(&vault_clone);
                vault.totp_accounts.extend(accounts);
                match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        for _ in 0..count {
                            vault.totp_accounts.pop();
                        }
                        Err(e)
                    }
                }
            };
            let vault_for_list_qr = Arc::clone(&vault_clone);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    match save_result {
                        Ok(()) => {
                            ui.set_notification_text(
                                format!("✅ Imported {} 2FA accounts successfully!", count).into(),
                            );
                            ui.set_show_2fa_import(false);
                            {
                                let v = lock_vault(&vault_for_list_qr);
                                ui.set_auth_accounts(rebuild_auth_list(&v));
                                ui.set_auth_rows(rebuild_auth_rows(&v));
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

    // Batch-4: live webcam QR → same import pipeline as clipboard QR.
    // The capture callback runs on the camera worker thread and owns the
    // parse → re-seal → UI-refresh flow end to end (no dead arms).
    let window_weak_cam = main_window.as_weak();
    let vault_arc_cam = Arc::clone(&active_vault);
    let master_pw_cam = Arc::clone(&active_master_pw);
    main_window.on_scan_webcam_requested(move || {
        if let Some(ui) = window_weak_cam.upgrade() {
            if ui.get_is_decoy() {
                ui.set_notification_text("⛔ Decoy mode is read-only.".into());
                return;
            }
            ui.set_show_webcam_scan(true);
            ui.set_notification_text("📷 Point the QR at camera 0…".into());
        }
        let weak = window_weak_cam.clone();
        let vault_clone = Arc::clone(&vault_arc_cam);
        let master_clone = Arc::clone(&master_pw_cam);
        std::thread::spawn(move || {
            let weak_cb = weak.clone();
            let res = authenticator::camera_scanner::capture_and_scan_frame(move |qr_content| {
                let weak_in = weak_cb.clone();
                // Parse the decoded QR string (migration or plain otpauth).
                let accounts = match authenticator::parse_google_migration_url(&qr_content) {
                    Ok(a) => a,
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
                let count = accounts.len();
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
                let save_result: Result<(), String> = {
                    let mut vault = lock_vault(&vault_clone);
                    vault.totp_accounts.extend(accounts);
                    match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
                        Ok(()) => Ok(()),
                        Err(e) => {
                            for _ in 0..count {
                                vault.totp_accounts.pop();
                            }
                            Err(e)
                        }
                    }
                };
                let vault_for_list = Arc::clone(&vault_clone);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak_in.upgrade() {
                        ui.set_show_webcam_scan(false);
                        match save_result {
                            Ok(()) => {
                                ui.set_notification_text(
                                    format!("✅ Webcam imported {} 2FA accounts!", count).into(),
                                );
                                {
                                    let v = lock_vault(&vault_for_list);
                                    ui.set_auth_accounts(rebuild_auth_list(&v));
                                ui.set_auth_rows(rebuild_auth_rows(&v));
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
            // Camera-level failure (no device / timeout / cancel): the modal
            // closes here; per-account outcomes were already reported above.
            if let Err(e) = res {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_show_webcam_scan(false);
                        ui.set_notification_text(format!("❌ Webcam scan: {}", e).into());
                    }
                });
            }
        });
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
        trigger_autotype(
            type_main.clone(),
            type_main_qb.clone(),
            Arc::clone(&type_main_vis),
            username.as_str().to_string(),
            password.as_str().to_string(),
            totp.as_str().to_string(),
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
    });

    // Website launch: http(s) only (never file://, javascript:, or bare
    // commands) + quoted arg, so a hostile stored URL cannot escape into
    // command execution. Best-effort: failure is a toast, never a panic.
    let window_weak_url = main_window.as_weak();
    main_window.on_open_url(move |url| {
        let Some(ui) = window_weak_url.upgrade() else {
            return;
        };
        let target = url.as_str().trim().to_string();
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
    });

    // Phase 10: Password & Diceware Generator callbacks
    let gen_weak_regen = main_window.as_weak();
    main_window.on_regenerate(move || {
        let Some(ui) = gen_weak_regen.upgrade() else { return; };
        let result: Option<(String, f64)> = if ui.get_gen_diceware_mode() {
            let wc = ui.get_gen_word_count().clamp(4, 12) as usize;
            let bits = PasswordGenerator::entropy_bits_diceware(wc);
            PasswordGenerator::generate_diceware(wc, '-')
                .map(|s| (s.expose_secret().to_owned(), bits))
                .ok()
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

    // Batch-4: registry-install the browser native host (HKCU, both browsers).
    let host_weak = main_window.as_weak();
    main_window.on_install_browser_host(move || {
        let Some(ui) = host_weak.upgrade() else {
            return;
        };
        ui.set_sync_status("⏳ Installing browser extension host…".into());
        let weak = host_weak.clone();
        std::thread::spawn(move || {
            // Registry writes are milliseconds; kept off-thread for uniformity.
            let res = windows_native::native_host::register_native_host();
            if res.is_ok() {
                security::access_log::log_event("bridge", "host installed");
            }
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    ui.set_sync_status(match res {
                        Ok(path) => format!("🌐 Host installed → {path} (add your extension ID to allowed_origins).").into(),
                        Err(e) => format!("⚠️ Host install failed: {e}").into(),
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
            let title = {
                let mut vault = lock_vault(&vault_clone);
                security::canary::plant_canary(&mut vault)
            };
            // Persist (hybrid re-seal) — roll back the plant on disk failure.
            let saved = {
                let vault = lock_vault(&vault_clone);
                save_vault(&vault, master_pw.expose_secret(), VAULT_FILE)
            };
            if saved.is_err() {
                let mut vault = lock_vault(&vault_clone);
                vault.credentials.pop();
            }
            let saved_ok = saved.is_ok();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    if saved_ok {
                        let vault = lock_vault(&vault_clone);
                        let f = search_clone.lock().unwrap().clone();
                        let items = vault_to_items(&vault, &f);
                        ui.set_credentials(items.clone());
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
                match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
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
                    match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
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
        let target = id.as_str().to_string();
        std::thread::spawn(move || {
            // Roll back the in-memory removal if the disk re-seal fails.
            let saved = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                if !remove_totp_account(&mut vault, &target) {
                    Err("authenticator account not found".to_string())
                } else {
                    match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
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
                        ui.set_auth_rows(rebuild_auth_rows(&v));
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
                    match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
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
                if save_vault(&vault, master_pw.expose_secret(), VAULT_FILE).is_err() {
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
            }
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
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
        ui.set_f_d("".into());
        ui.set_f_e("".into());
        ui.set_f_notes("".into());
        ui.set_f_totp("".into());
        ui.set_f_backup("".into());
        ui.set_f_reprompt(false);
        ui.set_f_fav(false);
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
                if let Err(e) = vault.add_folder(&name) {
                    Err(e)
                } else {
                    match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
                        Ok(()) => Ok(vault.clone()),
                        Err(e) => Err(e),
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
                match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
                    Ok(()) => Ok(fields),
                    Err(_) => return,
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
    main_window.on_open_detail(move |id| {
        let Some(ui) = detail_weak.upgrade() else {
            return;
        };
        let vault = lock_vault(&detail_vault);
        let id = id.as_str();
        // Only logins track rotation age/history; reset for every other kind.
        ui.set_d_stale(false);
        ui.set_d_fav(false);
        ui.set_d_trashed(false);
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
            ui.set_d_urls_extra(c.urls.iter().skip(1).cloned().collect::<Vec<_>>().join("\n").into());
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
            ui.set_d_fav(c.favorite);
            ui.set_d_history(rebuild_history(c));
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
            ui.set_d_custom(custom_to_ui(&[]));
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
            ui.set_d_custom(custom_to_ui(&[]));
        } else if let Some(k) = vault.cards.iter().find(|k| k.id == id) {
            ui.set_d_id(k.id.clone().into());
            ui.set_d_kind(4);
            ui.set_d_title(k.title.clone().into());
            ui.set_d_user(k.cardholder_name.clone().into());
            ui.set_d_secret(k.card_number.clone().into());
            ui.set_d_meta(format!("exp {:0>2}/{:0>2}  CVV {}", k.exp_month, k.exp_year, k.cvv).into());
            ui.set_d_url(String::new().into());
            ui.set_d_urls_extra(String::new().into());
            ui.set_d_notes(k.notes.clone().into());
            ui.set_d_folder(k.folder.clone().into());
            ui.set_d_trashed(k.deleted_at.is_some());
            ui.set_d_fav(k.favorite);
            ui.set_d_reprompt(false);
            ui.set_d_totp(String::new().into());
            ui.set_d_backup(String::new().into());
            ui.set_d_custom(custom_to_ui(&[]));
        } else if let Some(i) = vault.identities.iter().find(|i| i.id == id) {
            ui.set_d_id(i.id.clone().into());
            ui.set_d_kind(5);
            ui.set_d_title(i.title.clone().into());
            ui.set_d_user(i.full_name.clone().into());
            ui.set_d_secret(i.nid_or_passport.clone().into());
            ui.set_d_meta(i.phone.clone().into());
            ui.set_d_url(i.email.clone().into());
            ui.set_d_urls_extra(String::new().into());
            ui.set_d_notes(i.address.clone().into());
            ui.set_d_folder(i.folder.clone().into());
            ui.set_d_trashed(i.deleted_at.is_some());
            ui.set_d_fav(i.favorite);
            ui.set_d_reprompt(false);
            ui.set_d_totp(String::new().into());
            ui.set_d_backup(String::new().into());
            ui.set_d_custom(custom_to_ui(&[]));
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
            _ => vault.ssh_keys.iter().find(|s| s.id == id)
                .map(|s| (s.travel_safe, Vec::new())).unwrap_or((false, Vec::new())),
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
                    ui.set_f_c(c.urls.join("\n").into());
                    ui.set_f_totp(c.totp_secret.clone().into());
                    ui.set_f_backup(c.backup_codes.join("\n").into());
                    ui.set_f_notes(c.notes.clone().into());
                    ui.set_f_folder(c.folder.clone().into());
                    ui.set_f_reprompt(c.reprompt);
                    ui.set_f_fav(c.favorite);
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
                }
            }
            3 => {
                if let Some(n) = vault.notes.iter().find(|n| n.id == id) {
                    ui.set_f_title(n.title.clone().into());
                    ui.set_f_a(n.content.clone().into());
                    ui.set_f_folder(n.folder.clone().into());
                    ui.set_f_fav(n.favorite);
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
                    ui.set_f_folder(i.folder.clone().into());
                    ui.set_f_fav(i.favorite);
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
        ui.set_rp_secret("".into());
        match ui.get_rp_action() {
            1 => {
                // Copy the gated secret via the masked path.
                let secs = rp_ct.load(std::sync::atomic::Ordering::SeqCst);
                secure_copy_with_feedback(
                    ui.as_weak(),
                    ui.get_rp_secret().to_string(),
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
                    ui.get_rp_user().to_string(),
                    ui.get_rp_secret().to_string(),
                    totp,
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
                            match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
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
                                    ui.set_credentials(vault_to_items(&v, &f));
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
                    ui.set_credentials(vault_to_items(&vault, &f));
                    ui.set_notification_text("Travel Mode OFF — full vault restored.".into());
                }
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
        if ui.get_is_decoy() {
            ui.set_sync_status("⛔ Decoy mode has no recovery sheet.".into());
            return;
        }
        let master_opt = lock_master_pw(&shard_master).clone();
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
    });

    // Phase 17: lock-screen shard recovery → rebuild → standard unlock.
    let rec_weak = main_window.as_weak();
    let rec_vault = Arc::clone(&active_vault);
    let rec_master = Arc::clone(&active_master_pw);
    let rec_search = Arc::clone(&search_state);
    let rec_qb = quick_bar.as_weak();
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
                pass, weak, vault_clone, master_clone, search_clone, qb_clone, true, false,
            );
        });
    });

    // Phase 18: Omni-Importer — file picker + sniff + merge, all off-UI-thread.
    let import_weak = main_window.as_weak();
    let import_vault = Arc::clone(&active_vault);
    let import_master = Arc::clone(&active_master_pw);
    let import_search = Arc::clone(&search_state);
    let import_qb = quick_bar.as_weak();
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
        let search_clone = Arc::clone(&import_search);
        let qb_clone = import_qb.clone();
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
            let Some(master_pw) = master_opt else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_import_status("⚠️ Vault not unlocked.".into());
                    }
                });
                return;
            };
            // Merge + re-seal under one lock (rollback on disk failure).
            let res: Result<importer::ImportSummary, String> = {
                let mut vault = lock_vault(&vault_clone);
                let snapshot = vault.clone();
                match importer::import_any_file(&path, &mut vault) {
                    Ok(summary) => match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
                        Ok(()) => Ok(summary),
                        Err(e) => {
                            *vault = snapshot;
                            Err(e)
                        }
                    },
                    Err(e) => Err(e.to_string()),
                }
            };
            let path_str = path.to_string_lossy().into_owned();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match res {
                    Ok(summary) => {
                        {
                            let vault = lock_vault(&vault_clone);
                            let f = search_clone.lock().unwrap().clone();
                            ui.set_credentials(vault_to_items(&vault, &f));
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
                    }
                    Err(e) => {
                        ui.set_import_status(format!("⚠️ Import blocked: {e}").into());
                    }
                }
            });
        });
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
        ui.set_credentials(vault_to_items(&vault, &f));
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
        if kind != 1 && kind != 2 {
            ui.set_notification_text("⚠️ Attachments live on logins + licenses.".into());
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
                let target: Option<&mut Vec<models::EncryptedAttachment>> = match kind {
                    1 => vault.credentials.iter_mut().find(|c| c.id == id).map(|c| &mut c.attachments),
                    2 => vault.licenses.iter_mut().find(|l| l.id == id).map(|l| &mut l.attachments),
                    _ => None,
                };
                let Some(list) = target else {
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
                match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
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
                        let files: Vec<models::EncryptedAttachment> = match kind {
                            1 => v.credentials.iter().find(|c| c.id == id).map(|c| c.attachments.clone()).unwrap_or_default(),
                            2 => v.licenses.iter().find(|l| l.id == id).map(|l| l.attachments.clone()).unwrap_or_default(),
                            _ => Vec::new(),
                        };
                        ui.set_d_attachments(attachments_to_ui(&files));
                        let f = search_clone.lock().unwrap().clone();
                        ui.set_credentials(vault_to_items(&v, &f));
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
        let found: Option<(String, Vec<u8>)> = match kind {
            1 => vault.credentials.iter().find(|c| c.id == id.as_str()).and_then(|c| {
                c.attachments.iter().find(|a| a.id == att_id.as_str())
                    .map(|a| (a.filename.clone(), a.data.clone()))
            }),
            2 => vault.licenses.iter().find(|l| l.id == id.as_str()).and_then(|l| {
                l.attachments.iter().find(|a| a.id == att_id.as_str())
                    .map(|a| (a.filename.clone(), a.data.clone()))
            }),
            _ => None,
        };
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
                let removed = match kind {
                    1 => vault.credentials.iter_mut().find(|c| c.id == id).map(|c| {
                        let before = c.attachments.len();
                        c.attachments.retain(|a| a.id != att_id);
                        before != c.attachments.len()
                    }),
                    2 => vault.licenses.iter_mut().find(|l| l.id == id).map(|l| {
                        let before = l.attachments.len();
                        l.attachments.retain(|a| a.id != att_id);
                        before != l.attachments.len()
                    }),
                    _ => None,
                };
                if removed != Some(true) {
                    Err("Attachment not found".to_string())
                } else {
                    match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
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
                        let files: Vec<models::EncryptedAttachment> = match kind {
                            1 => v.credentials.iter().find(|c| c.id == id).map(|c| c.attachments.clone()).unwrap_or_default(),
                            2 => v.licenses.iter().find(|l| l.id == id).map(|l| l.attachments.clone()).unwrap_or_default(),
                            _ => Vec::new(),
                        };
                        ui.set_d_attachments(attachments_to_ui(&files));
                        let f = search_clone.lock().unwrap().clone();
                        ui.set_credentials(vault_to_items(&v, &f));
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
                match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
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
                match save_vault(&vault, master_pw.expose_secret(), VAULT_FILE) {
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
                            ui.set_auth_rows(rebuild_auth_rows(&v));
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
            }
            println!("🛡️ Blackout Guard set to: {}", on);
            ui.set_blackout_enabled(on);
        }
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
    main_window.on_refresh_ssh_status(move || {
        let Some(ui) = ssh_weak.upgrade() else {
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
                        "○ Stopped (run: phantom_vault ssh-agent)".into()
                    });
                }
            });
        });
    });

    // Cat 8 access-log viewer: newest 20 events + chain verdict.
    let alog_weak = main_window.as_weak();
    main_window.on_view_access_log(move || {
        if let Some(ui) = alog_weak.upgrade() {
            let (n, valid) = security::access_log::verify();
            let rows = security::access_log::recent(20);
            let body = if rows.is_empty() {
                "No events recorded yet.".to_string()
            } else {
                rows.join("\n")
            };
            ui.set_access_log_text(
                format!(
                    "{} entries · chain {}.\n\n{}",
                    n,
                    if valid { "VALID ✅" } else { "BROKEN 🚨" },
                    body
                )
                .into(),
            );
            ui.set_show_access_log(true);
        }
    });
    // Wire-up #4: pill click → auto-type the matched credential, hide pill.
    let pill_weak = main_window.as_weak();
    let pill_qb = quick_bar.as_weak();
    let pill_vis = Arc::clone(&quickbar_visible);
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
                                || c.urls.iter().any(|u| u.to_lowercase().contains(&needle)))
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
            user,
            pass,
            totp,
        );
    });
    // Wire-up #5: real secret-leak scan via native folder picker + worker.
    let sc_weak = main_window.as_weak();
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
                        ui.set_show_health(true);
                        ui.set_health_status("Vault is empty.".into());
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
            // Detailed per-item lines (titles + flags only, never passwords).
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
            let full = format!("{headline}\n\n{detail}");
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    // Publish badges to the process-wide registry + refresh list.
                    if let Ok(mut reg) = health_registry().lock() {
                        reg.clear();
                        reg.extend(badges);
                    }
                    ui.set_health_report(full.into());
                    ui.set_show_health(true);
                    ui.set_health_status(headline.into());
                    security::access_log::log_event("audit", "health scan");
                    let f = search_clone.lock().map(|s| s.clone()).unwrap_or_default();
                    let v = lock_vault(&vault_clone);
                    ui.set_credentials(vault_to_items(&v, &f));
                }
            });
        });
    });

    run_startup_pull(main_window.as_weak());

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

#[cfg(test)]
mod grid_tests {
    use super::*;

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
    fn grid_chunks_in_threes() {
        assert!(chunk_rows::<u8>(vec![]).is_empty());
        assert_eq!(chunk_rows(vec![1, 2, 3]), vec![vec![1, 2, 3]]);
        // 7 items → 3 + 3 + 1, like the photo's last row.
        assert_eq!(
            chunk_rows(vec![1, 2, 3, 4, 5, 6, 7]),
            vec![vec![1, 2, 3], vec![4, 5, 6], vec![7]]
        );
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
