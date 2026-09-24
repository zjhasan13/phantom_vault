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
use secrecy::ExposeSecret;
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
/// Win+V + cloud excluded, guarded 15s auto-clear. If the native path fails,
/// falls back to arboard (still auto-cleared) rather than failing silently.
fn secure_copy_with_feedback(main_weak: slint::Weak<MainWindow>, text: String, copied_msg: &str) {
    let weak_ok = main_weak.clone();
    let weak_clear = main_weak.clone();
    let weak_fb_msg = main_weak.clone();
    let weak_fb_clear = main_weak.clone();
    let msg = copied_msg.to_string();
    match windows_native::clipboard::copy_sensitive(&text, 15, move || {
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
                        ui.set_notification_text(
                            "📋 Copied (fallback path — auto-clearing in 15s)".into(),
                        );
                    }
                });
                thread::spawn(move || {
                    thread::sleep(Duration::from_secs(15));
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
    arc: &Arc<Mutex<Option<String>>>,
) -> std::sync::MutexGuard<'_, Option<String>> {
    arc.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Phase 15 (Option 1): best-effort RAM wipe of all vault secrets.
/// Called by the Panic Nuke hotkey and the anti-debug watchdog, right
/// before hard exit. OS reclaims the rest on process death.
fn panic_wipe(vault_arc: &Arc<Mutex<Vault>>, master_arc: &Arc<Mutex<Option<String>>>) {
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
    }
    if let Ok(mut master) = master_arc.lock() {
        if let Some(mut pw) = master.take() {
            pw.zeroize();
        }
    }
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
#[allow(clippy::too_many_arguments)]
fn unlock_with_password(
    pass: String,
    main_weak: slint::Weak<MainWindow>,
    vault_arc: Arc<Mutex<Vault>>,
    master_pw_arc: Arc<Mutex<Option<String>>>,
    search_state: Arc<Mutex<FilterState>>,
    qb_weak: slint::Weak<QuickBarWindow>,
    cache_hello_token: bool,
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
        // Heavy work: Argon2id KDF + XChaCha20Poly1305 + file I/O
        // (+ ML-KEM-768 hybrid on save, transparent v1→v2 migration on unlock)
        let loaded_result: Result<Vault, String> = if Path::new(VAULT_FILE).exists() {
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

        let pass_for_store = pass.clone();
        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = main_weak.upgrade() else {
                return;
            };
            match loaded_result {
                Ok(vault) => {
                    *lock_master_pw(&master_pw_arc) = Some(pass_for_store);
                    *search_state.lock().unwrap() = FilterState::default();
                    ui.set_search_query("".into());
                    let mut vault = vault;
                    vault.ensure_folders();
                    sync_folders_to_ui(&vault, &ui);
                    let items = vault_to_items(&vault, &FilterState::default());
                    ui.set_credentials(items.clone());
                    if let Some(qb) = qb_weak.upgrade() {
                        qb.set_filtered_results(vault_quickbar(&vault, "", search_state.lock().unwrap().travel_only));
                    }
                    *lock_vault(&vault_arc) = vault;
                    ui.set_is_unlocked(true);
                    ui.set_is_decoy(false);
                    ui.set_status_text("✅ Vault unlocked".into());
                    trigger_sync_push(ui.as_weak());

                    // Phase 24: authenticator list now + live refresh ticker.
                    // The same 1s loop drives the hero countdown and refreshes
                    // all dynamic codes every 5s (cheap, few accounts).
                    {
                        let v = lock_vault(&vault_arc);
                        ui.set_auth_accounts(rebuild_auth_list(&v));
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
                        *lock_master_pw(&master_pw_arc) = Some(pass_for_store);
                        *search_state.lock().unwrap() = FilterState::default();
                        ui.set_search_query("".into());
                        let items = vault_to_items(&decoy, &FilterState::default());
                        ui.set_credentials(items.clone());
                        if let Some(qb) = qb_weak.upgrade() {
                            qb.set_filtered_results(vault_quickbar(&decoy, "", search_state.lock().unwrap().travel_only));
                        }
                        *lock_vault(&vault_arc) = decoy;
                        ui.set_is_unlocked(true);
                        ui.set_is_decoy(true);
                        ui.set_status_text("✅ Vault unlocked".into());
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

/// Phase 24: render every authenticator account through the dynamic engine.
/// Failures render as "------" (never blank, never panics).
fn rebuild_auth_list(vault: &Vault) -> ModelRc<AuthView> {
    let rows: Vec<AuthView> = vault
        .totp_accounts
        .iter()
        .map(|a| {
            let (code, _) = totp_engine::generate_code_for_account(a)
                .unwrap_or(("------".to_string(), 0));
            let kind = match a.otp_type.trim().to_lowercase().as_str() {
                "hotp" => "HOTP",
                "steam" => "STEAM",
                _ => "TOTP",
            };
            AuthView {
                id: a.id.clone().into(),
                name: a.account_name.clone().into(),
                issuer: a.issuer.clone().into(),
                code: code.into(),
                kind: kind.into(),
                is_hotp: kind == "HOTP",
            }
        })
        .collect();
    ModelRc::new(VecModel::from(rows))
}

/// Item-kind codes shared with Slint: 0 All, 1 login, 2 license, 3 note,
/// 4 card, 5 identity, 6 ssh.
#[derive(Clone)]
struct FilterState {
    query: String,
    kind: i32,
    folder: String,
    travel_only: bool,
}

impl Default for FilterState {
    fn default() -> Self {
        Self { query: String::new(), kind: 0, folder: "All".to_string(), travel_only: false }
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
) {
    if f.kind != 0 && f.kind != kind {
        return;
    }
    // Travel Mode: only travel-safe items survive in list, QuickBar, search.
    if f.travel_only && !travel_safe {
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
        push_item(&mut items, f, &q, &c.id, 1, &c.title, &c.username, &c.password, "", &primary_url(&c.urls), &c.notes, &c.folder, &c.totp_secret, c.travel_safe);
    }
    for l in &vault.licenses {
        push_item(&mut items, f, &q, &l.id, 2, &l.app_name, "Software license",
            &l.license_key, &l.expiry_date.clone().unwrap_or_default(), "", "", &l.folder, "", l.travel_safe);
    }
    for n in &vault.notes {
        let preview: String = n.content.lines().next().unwrap_or("").chars().take(48).collect();
        push_item(&mut items, f, &q, &n.id, 3, &n.title, &preview, &n.content, "", "", &n.content, &n.folder, "", n.travel_safe);
    }
    for k in &vault.cards {
        let exp = format!("{:0>2}/{:0>2}", k.exp_month, k.exp_year);
        let meta = format!("exp {exp}  CVV {}", k.cvv);
        push_item(&mut items, f, &q, &k.id, 4, &k.title, &k.cardholder_name, &k.card_number, &meta, "", "", &k.folder, "", k.travel_safe);
    }
    for i in &vault.identities {
        push_item(&mut items, f, &q, &i.id, 5, &i.title, &i.full_name, &i.nid_or_passport, &i.phone, &i.email, &i.address, &i.folder, "", i.travel_safe);
    }
    for s in &vault.ssh_keys {
        push_item(&mut items, f, &q, &s.id, 6, &s.title, "SSH key", &s.private_key, &s.fingerprint, "", &s.public_key, &s.folder, "", s.travel_safe);
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
        &FilterState { query: query.to_string(), kind: 0, folder: "All".to_string(), travel_only },
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
    // Phase 16 (Option 2): headless CLI modes — exit before any GUI init.
    //   vault run -e TITLE=VAR ... -- <cmd>   (memory-only env injection)
    //   vault scan [path]                     (secret-leak check, exit 1 on hits)
    //   vault ssh-agent                       (named-pipe agent, foreground)
    //   vault shred <file>...                (DoD 3-pass shred + delete)
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() > 1 {
        let code = match argv[1].as_str() {
            "run" => developer::vault_run::run_cli(&argv[2..]),
            "scan" => developer::vault_run::scan_cli(&argv[2..]),
            "ssh-agent" => developer::ssh_agent::serve_cli(),
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
            _ => {
                eprintln!("usage: phantom_vault [run|scan|ssh-agent] ...");
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
    let active_master_pw: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
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
    quick_bar.on_item_selected(move |password| {
        if let Some(qb) = qb_weak_select.upgrade() {
            qb.hide().ok();
        }
        qb_visible_select.store(false, std::sync::atomic::Ordering::SeqCst);
        // Phase 20: masked copy (Win+V excluded) with guarded auto-clear.
        if let Some(main_ui) = main_weak_for_copy.upgrade() {
            secure_copy_with_feedback(
                main_ui.as_weak(),
                password.as_str().to_string(),
                "📋 Password copied! (Masked from Win+V, auto-clearing in 15s)",
            );
        }
    });

    // Phase 13: Auto-Type from QuickBar (username + password keystroke fill)
    let type_qb_main = main_window.as_weak();
    let type_qb_self = quick_bar.as_weak();
    let type_qb_vis = Arc::clone(&quickbar_visible);
    let type_qb_vault = Arc::clone(&active_vault);
    quick_bar.on_type_selected(move |username, password, totp| {
        if let Some(title) =
            check_canary_trip(&type_qb_vault, password.as_str(), "autotype-quickbar")
        {
            if let Some(ui) = type_qb_main.upgrade() {
                ui.set_notification_text(
                    format!("🚨 CANARY TRIPPED: '{title}' — logged!").into(),
                );
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
                    // Panic Nuke first: wipe RAM and die. No UI round-trip.
                    if Some(event.id) == panic_id {
                        panic_wipe(&vault_arc_nuke, &master_pw_nuke);
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
                });
                match save_vault(&vault, &master_pw, VAULT_FILE) {
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
    main_window.on_unlock_requested(move |entered_password| {
        let pass = entered_password.as_str().trim().to_string();
        // Fresh unlock always starts with Travel Mode OFF.
        *travel_off.lock().unwrap() = false;
        if let Some(ui) = window_weak.upgrade() {
            ui.set_is_travel_mode(false);
        }
        unlock_with_password(
            pass,
            window_weak.clone(),
            Arc::clone(&vault_arc),
            Arc::clone(&master_pw_arc),
            Arc::clone(&search_state_unlock),
            qb_weak_unlock.clone(),
            true,
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
        if available {
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = hello_weak.upgrade() {
                    ui.set_hello_available(true);
                }
            });
        }
    });

    // Phase 11: Windows Hello — biometric unlock request
    let bio_weak = main_window.as_weak();
    let bio_vault = Arc::clone(&active_vault);
    let bio_master = Arc::clone(&active_master_pw);
    let bio_search = Arc::clone(&search_state);
    let bio_qb = quick_bar.as_weak();
    main_window.on_request_biometric_unlock(move || {
        if let Some(ui) = bio_weak.upgrade() {
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
        }),
        2 => vault.licenses.push(models::SoftwareLicense {
            id,
            app_name: title.to_string(),
            license_key: a.to_string(),
            expiry_date: (!b.trim().is_empty()).then(|| b.to_string()),
            folder: folder.to_string(),
            attachments: Vec::new(),
            travel_safe: false,
        }),
        3 => vault.notes.push(models::SecureNote {
            id,
            title: title.to_string(),
            content: a.to_string(),
            folder: folder.to_string(),
            travel_safe: false,
        }),
        4 => vault.cards.push(models::PaymentCard {
            id,
            title: title.to_string(),
            cardholder_name: a.to_string(),
            card_number: b.to_string(),
            exp_month: cc.to_string(),
            exp_year: String::new(),
            cvv: dd.to_string(),
            folder: folder.to_string(),
            notes: notes.to_string(),
            travel_safe: false,
        }),
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
) -> bool {
    match kind {
        1 => {
            let Some(c) = vault.credentials.iter_mut().find(|c| c.id == id) else {
                return false;
            };
            c.title = title.to_string();
            c.username = a.to_string();
            c.password = b.to_string();
            c.totp_secret = totp.to_string();
            c.urls = urls.to_vec();
            c.backup_codes = backup.to_vec();
            c.custom_fields = custom.to_vec();
            c.notes = notes.to_string();
            c.folder = folder.to_string();
            c.reprompt = reprompt;
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
            true
        }
        3 => {
            let Some(n) = vault.notes.iter_mut().find(|n| n.id == id) else {
                return false;
            };
            n.title = title.to_string();
            n.content = a.to_string();
            n.folder = folder.to_string();
            true
        }
        4 => {
            let Some(k) = vault.cards.iter_mut().find(|k| k.id == id) else {
                return false;
            };
            k.title = title.to_string();
            k.cardholder_name = a.to_string();
            k.card_number = b.to_string();
            k.exp_month = cc.to_string();
            k.cvv = dd.to_string();
            k.folder = folder.to_string();
            k.notes = notes.to_string();
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
        move |kind, title, a, b, c, d, e, notes, folder, totp, backup, reprompt| {
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
                        )
                    } else {
                        false
                    };
                    if !replaced {
                        push_new_item(
                            &mut vault, kind, new_id, &title_for_thread,
                            &a, &b, &cc, &dd, &ee, &notes, &folder,
                            urls, backup, custom, &totp_for_thread, reprompt_for_thread,
                        );
                    }

                    match save_vault(&vault, &master_pw, VAULT_FILE) {
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
            let save_result: Result<Vault, String> = {
                let mut vault = lock_vault(&vault_clone);
                if !vault.delete_item(kind, &id) {
                    Err("Item not found (already deleted?)".to_string())
                } else {
                    match save_vault(&vault, &master_pw, VAULT_FILE) {
                        Ok(()) => Ok(vault.clone()),
                        Err(e) => Err(e),
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
                        if let Some(qb) = qb_weak.upgrade() {
                            qb.set_filtered_results(vault_quickbar(&vault_snapshot, "", search_clone.lock().unwrap().travel_only));
                        }
                        ui.set_notification_text("🗑️ Item deleted.".into());
                        ui.set_show_detail(false);
                        trigger_sync_push(ui.as_weak());
                    }
                    Err(e) => {
                        ui.set_notification_text(format!("❌ Delete failed: {}", e).into());
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
        *search_state_type.lock().unwrap() = f.clone();
        let vault = lock_vault(&vault_arc_type);
        if let Some(ui) = window_weak_type.upgrade() {
            ui.set_credentials(vault_to_items(&vault, &f));
        }
    });

    let window_weak_folder = main_window.as_weak();
    let vault_arc_folder = Arc::clone(&active_vault);
    let search_state_folder = Arc::clone(&search_state);
    main_window.on_folder_filter_changed(move |folder| {
        let mut f = search_state_folder.lock().unwrap().clone();
        f.folder = folder.as_str().to_string();
        *search_state_folder.lock().unwrap() = f.clone();
        let vault = lock_vault(&vault_arc_folder);
        if let Some(ui) = window_weak_folder.upgrade() {
            ui.set_credentials(vault_to_items(&vault, &f));
        }
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
                        match save_vault(&vault, &master_pw, VAULT_FILE) {
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
                match save_vault(&vault, &master_pw, VAULT_FILE) {
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
    main_window.on_copy_password_requested(move |password_to_copy| {
        let Some(ui) = window_weak_copy.upgrade() else {
            return;
        };

        // Phase 15 (Option 1): honeytoken tripwire — loud alert + log, copy proceeds.
        // The alert doubles as the copy confirmation so it isn't clobbered.
        let copied_msg = match check_canary_trip(
            &vault_arc_copy,
            password_to_copy.as_str(),
            "copy",
        ) {
            Some(title) => {
                format!("🚨 CANARY TRIPPED: '{title}' — copied + ransack logged!")
            }
            None => "📋 Password copied! (Masked from Win+V, auto-clearing in 15s)".to_string(),
        };
        secure_copy_with_feedback(
            ui.as_weak(),
            password_to_copy.as_str().to_string(),
            &copied_msg,
        );
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
            secure_copy_with_feedback(
                ui.as_weak(),
                pwd.to_string(),
                "📋 Generated password copied! (Masked from Win+V, auto-clearing in 15s)",
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
        ui.set_sync_status(format!("✅ Connected to {owner}/{repo} (ciphertext only).").into());
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
                save_vault(&vault, &master_pw, VAULT_FILE)
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
                    match save_vault(&vault, &master_pw, VAULT_FILE) {
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
                match save_vault(&vault, &master_pw, VAULT_FILE) {
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
            ui.set_d_reprompt(c.reprompt);
            ui.set_d_totp(c.totp_secret.clone().into());
            ui.set_d_backup(c.backup_codes.join("\n").into());
            ui.set_d_custom(custom_to_ui(&c.custom_fields));
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
                }
            }
            3 => {
                if let Some(n) = vault.notes.iter().find(|n| n.id == id) {
                    ui.set_f_title(n.title.clone().into());
                    ui.set_f_a(n.content.clone().into());
                    ui.set_f_folder(n.folder.clone().into());
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
    main_window.on_reprompt_confirm(move |password| {
        let Some(ui) = rp_weak.upgrade() else {
            return;
        };
        let ok = rp_master
            .lock()
            .unwrap()
            .clone()
            .is_some_and(|m| m == password.as_str());
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
                secure_copy_with_feedback(
                    ui.as_weak(),
                    ui.get_rp_secret().to_string(),
                    "📋 Copied! (Masked from Win+V, auto-clearing in 15s)",
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
                    let res: Result<Vault, String> = {
                        let mut vault = lock_vault(&vault_clone);
                        if !vault.delete_item(kind, &id) {
                            Err("Item not found".to_string())
                        } else {
                            match save_vault(&vault, &master_pw, VAULT_FILE) {
                                Ok(()) => Ok(vault.clone()),
                                Err(e) => Err(e),
                            }
                        }
                    };
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            match res {
                                Ok(v) => {
                                    let f = search_clone.lock().unwrap().clone();
                                    ui.set_credentials(vault_to_items(&v, &f));
                                    if let Some(qb) = qb_clone.upgrade() {
                                        qb.set_filtered_results(vault_quickbar(&v, "", search_clone.lock().unwrap().travel_only));
                                    }
                                    ui.set_notification_text("🗑️ Item deleted.".into());
                                    ui.set_show_detail(false);
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
        if master_pw.len() > security::shamir::WORD_SECRET_MAX {
            ui.set_sync_status("⚠️ Master password over 64 bytes — shorten it to print shards.".into());
            return;
        }
        match security::shamir::Shamir::split(&master_pw) {
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
                pass, weak, vault_clone, master_clone, search_clone, qb_clone, true,
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
                    Ok(summary) => match save_vault(&vault, &master_pw, VAULT_FILE) {
                        Ok(()) => Ok(summary),
                        Err(e) => {
                            *vault = snapshot;
                            Err(e)
                        }
                    },
                    Err(e) => Err(e.to_string()),
                }
            };
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
                        trigger_sync_push(ui.as_weak());
                    }
                    Err(e) => {
                        ui.set_import_status(format!("⚠️ Import blocked: {e}").into());
                    }
                }
            });
        });
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
                match save_vault(&vault, &master_pw, VAULT_FILE) {
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
                Ok(()) => format!("💾 Exported '{}'.", filename),
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
                    match save_vault(&vault, &master_pw, VAULT_FILE) {
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
                match save_vault(&vault, &master_pw, VAULT_FILE) {
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
                match save_vault(&vault, &master_pw, VAULT_FILE) {
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
        std::process::exit(0);
    });
    let bb_weak = main_window.as_weak();
    main_window.on_set_blackout(move |on| {
        if let Some(ui) = bb_weak.upgrade() {
            #[cfg(windows)]
            {
                let _ = on;
                let _ = windows_native::display_guard::guard_window(ui.window());
            }
            ui.set_blackout_enabled(on);
        }
    });
    let ct_weak = main_window.as_weak();
    let ct_state = Arc::new(Mutex::new(15u64));
    main_window.on_set_clipboard_timeout(move |secs| {
        *ct_state.lock().unwrap() = secs as u64;
        if let Some(ui) = ct_weak.upgrade() {
            ui.set_clipboard_timeout(secs);
            ui.set_notification_text(format!("Clipboard auto-clear: {secs}s").into());
        }
    });
    let al_weak = main_window.as_weak();
    main_window.on_set_autolock_timeout(move |mins| {
        if let Some(ui) = al_weak.upgrade() {
            ui.set_autolock_timeout(mins);
            if mins == 0 { ui.set_notification_text("Auto-lock: Never".into()); } else { ui.set_notification_text(format!("Auto-lock: {mins} min").into()); }
        }
    });
    let pill_weak = main_window.as_weak();
    main_window.on_autofill_pill_clicked(move || {
        if let Some(ui) = pill_weak.upgrade() {
            ui.set_show_autofill_pill(false);
            let _ = ui;
        }
    });
    let sc_weak = main_window.as_weak();
    main_window.on_scan_secrets(move || {
        if let Some(ui) = sc_weak.upgrade() {
            ui.set_notification_text("🔍 Scan started...".into());
        }
    });

    run_startup_pull(main_window.as_weak());

    // Phase 15 (Option 1): anti-debug watchdog — wipe + hard exit on trip.
    let watch_vault = Arc::clone(&active_vault);
    let watch_master = Arc::clone(&active_master_pw);
    security::anti_debug::start_watchdog(move || {
        panic_wipe(&watch_vault, &watch_master);
    });

    main_window.run()
}
