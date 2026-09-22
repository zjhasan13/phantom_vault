#[allow(dead_code)]
mod crypto;
#[allow(dead_code)]
mod models;
#[allow(dead_code)]
mod storage;
mod totp_engine;
mod authenticator;

use arboard::Clipboard;
use models::{Credential, TotpAccount, Vault};
use slint::{ComponentHandle, ModelRc, VecModel};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use storage::{load_vault, save_vault};
use totp_engine::generate_live_code;

slint::include_modules!();

const VAULT_FILE: &str = "my_secure_vault.enc";

fn vault_to_ui_model(vault: &Vault) -> ModelRc<CredentialView> {
    let ui_creds: Vec<CredentialView> = vault
        .credentials
        .iter()
        .map(|c| CredentialView {
            title: c.title.clone().into(),
            username: c.username.clone().into(),
            password: c.password.clone().into(),
        })
        .collect();
    ModelRc::new(VecModel::from(ui_creds))
}

fn vault_to_filtered_model(vault: &Vault, query: &str) -> ModelRc<CredentialView> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return vault_to_ui_model(vault);
    }
    let filtered: Vec<CredentialView> = vault
        .credentials
        .iter()
        .filter(|c| {
            c.title.to_lowercase().contains(&q) || c.username.to_lowercase().contains(&q)
        })
        .map(|c| CredentialView {
            title: c.title.clone().into(),
            username: c.username.clone().into(),
            password: c.password.clone().into(),
        })
        .collect();
    ModelRc::new(VecModel::from(filtered))
}

#[cfg(windows)]
fn bring_to_foreground(window: &slint::Window) {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows_sys::Win32::UI::WindowsAndMessaging::SetForegroundWindow;
    let handle_wrapper = window.window_handle();
    if let Ok(handle) = handle_wrapper.window_handle() {
        if let RawWindowHandle::Win32(win32) = handle.as_raw() {
            let hwnd = win32.hwnd.get() as *mut core::ffi::c_void;
            unsafe {
                SetForegroundWindow(hwnd as _);
            }
        }
    }
}

fn main() -> Result<(), slint::PlatformError> {
    let main_window = MainWindow::new()?;
    let quick_bar = QuickBarWindow::new()?;
    let quickbar_visible = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let active_vault = Arc::new(Mutex::new(Vault::new()));
    // Store master password in RAM for re-encryption on add (wrapped in Arc/Mutex)
    let active_master_pw: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    // Phase 7: shared search query for filtering after add/unlock
    let search_state: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));

    // Phase 7: Windows Anti-Screen Capture / OBS Blackout
    // Obtain native HWND via main_window.window().window_handle() and apply
    // SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE = 0x00000011)
    #[cfg(windows)]
    {
        use raw_window_handle::{HasWindowHandle, RawWindowHandle};
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE,
        };
        // Spec requires: main_window.window().window_handle()
        // Window::window_handle() returns slint::WindowHandle which implements HasWindowHandle
        let slint_window_handle = main_window.window().window_handle();
        if let Ok(handle) = slint_window_handle.window_handle() {
            if let RawWindowHandle::Win32(win32) = handle.as_raw() {
                let hwnd = win32.hwnd.get() as *mut core::ffi::c_void;
                unsafe {
                    SetWindowDisplayAffinity(hwnd as _, WDA_EXCLUDEFROMCAPTURE);
                }
            }
        }
        // Also apply to QuickBarWindow
        let qb_handle = quick_bar.window().window_handle();
        if let Ok(handle) = qb_handle.window_handle() {
            if let RawWindowHandle::Win32(win32) = handle.as_raw() {
                let hwnd = win32.hwnd.get() as *mut core::ffi::c_void;
                unsafe {
                    SetWindowDisplayAffinity(hwnd as _, WDA_EXCLUDEFROMCAPTURE);
                }
            }
        }
    }

    // Phase 9: QuickBarWindow callbacks — query filtering, copy + auto-clear, dismiss
    let qb_weak_query = quick_bar.as_weak();
    let vault_arc_qb_query = Arc::clone(&active_vault);
    quick_bar.on_query_changed(move |query| {
        let q = query.as_str().to_string();
        let vault = vault_arc_qb_query.lock().unwrap();
        let filtered = vault_to_filtered_model(&vault, &q);
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
        if let Ok(mut clipboard) = Clipboard::new() {
            let _ = clipboard.set_text(password.as_str());
            if let Some(main_ui) = main_weak_for_copy.upgrade() {
                main_ui.set_notification_text("📋 Password copied! (Auto-clearing in 15s)".into());
                let weak = main_ui.as_weak();
                thread::spawn(move || {
                    thread::sleep(Duration::from_secs(15));
                    if let Ok(mut cb) = Clipboard::new() {
                        let _ = cb.clear();
                    }
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_notification_text("🧹 Clipboard auto-cleared for security!".into());
                        }
                    });
                });
            } else {
                // Fallback auto-clear without notification
                thread::spawn(move || {
                    thread::sleep(Duration::from_secs(15));
                    if let Ok(mut cb) = Clipboard::new() {
                        let _ = cb.clear();
                    }
                });
            }
        }
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
        // Keep manager alive for lifetime of app
        let manager = GlobalHotKeyManager::new().expect("Failed to create hotkey manager");
        let hotkey = HotKey::new(Some(Modifiers::ALT), Code::Space);
        let hotkey_id = hotkey.id();
        manager.register(hotkey).expect("Failed to register Alt+Space");
        // Prevent manager drop — leak or keep in Arc
        std::mem::forget(manager);

        let main_weak_hk = main_window.as_weak();
        let qb_weak_hk = quick_bar.as_weak();
        let vault_arc_hk = Arc::clone(&active_vault);
        let master_pw_hk = Arc::clone(&active_master_pw);
        let qb_visible_hk = Arc::clone(&quickbar_visible);
        thread::spawn(move || {
            let receiver = GlobalHotKeyEvent::receiver();
            loop {
                if let Ok(event) = receiver.recv() {
                    if event.id != hotkey_id {
                        continue;
                    }
                    let main_weak = main_weak_hk.clone();
                    let qb_weak = qb_weak_hk.clone();
                    let vault_clone = Arc::clone(&vault_arc_hk);
                    let master_clone = Arc::clone(&master_pw_hk);
                    let qb_visible = Arc::clone(&qb_visible_hk);
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
                        let is_unlocked = master_clone.lock().unwrap().is_some();
                        if !is_unlocked {
                            if let Some(main_ui) = main_weak.upgrade() {
                                main_ui.show().ok();
                                bring_to_foreground(&main_ui.window());
                            }
                            return;
                        }
                        // Vault unlocked: populate QuickBarWindow and show
                        if let Some(qb) = qb_weak.upgrade() {
                            let vault = vault_clone.lock().unwrap();
                            let filtered = vault_to_filtered_model(&vault, "");
                            qb.set_quick_query("".into());
                            qb.set_filtered_results(filtered);
                            qb.show().ok();
                            bring_to_foreground(&qb.window());
                            qb_visible.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                    });
                }
            }
        });
    }
    #[cfg(not(windows))]
    {
        // Non-Windows: keep quick_bar logic but hotkey disabled
        let _ = &quick_bar;
    }

    // 1. Unlock handler — heavy Argon2id + disk I/O offloaded to background thread
    let window_weak = main_window.as_weak();
    let vault_arc = Arc::clone(&active_vault);
    let master_pw_arc = Arc::clone(&active_master_pw);
    let search_state_unlock = Arc::clone(&search_state);
    let qb_weak_unlock = quick_bar.as_weak();
    main_window.on_unlock_requested(move |entered_password| {
        let pass = entered_password.as_str().trim().to_string();

        if pass.is_empty() {
            if let Some(ui) = window_weak.upgrade() {
                ui.set_status_text("⚠️ Password cannot be empty!".into());
            }
            return;
        }

        // Immediate UI feedback — no blocking, keeps window responsive at 60 FPS
        if let Some(ui) = window_weak.upgrade() {
            ui.set_status_text("⏳ Decrypting vault (Argon2id)…".into());
        }

        let weak = window_weak.clone();
        let vault_clone = Arc::clone(&vault_arc);
        let master_clone = Arc::clone(&master_pw_arc);
        let search_clone = Arc::clone(&search_state_unlock);
        let qb_weak = qb_weak_unlock.clone();

        std::thread::spawn(move || {
            // Heavy work: Argon2id KDF + XChaCha20Poly1305 + file I/O
            let loaded_result: Result<Vault, String> = if Path::new(VAULT_FILE).exists() {
                load_vault(&pass, VAULT_FILE)
            } else {
                // First run: initialize with demo credential
                let mut init_vault = Vault::new();
                init_vault.credentials.push(Credential {
                    id: "1".into(),
                    title: "GitHub Personal Token".into(),
                    username: "developer@gmail.com".into(),
                    password: "ghp_SecretTokenLiveDemo999!".into(),
                    url: "https://github.com".into(),
                    notes: "Primary Token".into(),
                });
                init_vault.totp_accounts.push(TotpAccount {
                    id: "2".into(),
                    account_name: "Google Workspace".into(),
                    issuer: "Google".into(),
                    secret: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".into(),
                    digits: 6,
                    period: 30,
                });

                match save_vault(&init_vault, &pass, VAULT_FILE) {
                    Ok(()) => Ok(init_vault),
                    Err(e) => Err(format!("Failed to create vault: {}", e)),
                }
            };

            let pass_for_store = pass.clone();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match loaded_result {
                    Ok(vault) => {
                        // Persist master password for subsequent save_vault calls
                        *master_clone.lock().unwrap() = Some(pass_for_store);
                        // Reset search on unlock and show all
                        *search_clone.lock().unwrap() = String::new();
                        ui.set_search_query("".into());
                        let filtered = vault_to_filtered_model(&vault, "");
                        ui.set_credentials(filtered.clone());
                        // Also populate QuickBar's filtered_results
                        if let Some(qb) = qb_weak.upgrade() {
                            qb.set_filtered_results(filtered);
                        }
                        *vault_clone.lock().unwrap() = vault;
                        ui.set_is_unlocked(true);
                        ui.set_status_text("✅ Vault unlocked".into());

                        // Live 2FA background thread (lightweight, 1s ticker)
                        let window_for_totp = ui.as_weak();
                        thread::spawn(move || {
                            let google_secret = "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ";
                            loop {
                                if let Ok((code, remaining)) = generate_live_code(google_secret) {
                                    let code_copy = code.clone();
                                    let remaining_str = format!("{}s", remaining);

                                    let window_clone = window_for_totp.clone();
                                    let _ = slint::invoke_from_event_loop(move || {
                                        if let Some(ui) = window_clone.upgrade() {
                                            ui.set_live_totp_code(code_copy.into());
                                            ui.set_totp_countdown(remaining_str.into());
                                        }
                                    });
                                }
                                thread::sleep(Duration::from_secs(1));
                            }
                        });
                    }
                    Err(e) => {
                        // Preserve original UX: wrong password message, but surface other I/O errors
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
    });

    // 2. Add New Password handler — Argon2id re-encryption offloaded to background thread
    let window_weak_add = main_window.as_weak();
    let vault_arc_add = Arc::clone(&active_vault);
    let master_pw_add = Arc::clone(&active_master_pw);
    let search_state_add = Arc::clone(&search_state);
    let qb_weak_add = quick_bar.as_weak();
    main_window.on_add_credential_requested(move |title, username, password| {
        let title = title.trim().to_string();
        let username = username.trim().to_string();
        let password_val = password.to_string(); // keep as-is, allow spaces/symbols

        if title.is_empty() || username.is_empty() || password_val.trim().is_empty() {
            if let Some(ui) = window_weak_add.upgrade() {
                ui.set_notification_text("⚠️ All fields required!".into());
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
        let username_for_thread = username.clone();
        let password_for_thread = password_val.clone();

        std::thread::spawn(move || {
            let master_opt = master_clone.lock().unwrap().clone();
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
                .map(|d| d.as_millis().to_string())
                .unwrap_or_else(|_| format!("{}", vault_clone.lock().unwrap().credentials.len() + 1));

            // Critical section + heavy crypto: push + save_vault (Argon2id) inside worker thread
            let save_result: Result<Vault, String> = {
                let mut vault = vault_clone.lock().unwrap();
                vault.credentials.push(Credential {
                    id: new_id,
                    title: title_for_thread.clone(),
                    username: username_for_thread.clone(),
                    password: password_for_thread.clone(),
                    url: String::new(),
                    notes: String::new(),
                });

                match save_vault(&*vault, &master_pw, VAULT_FILE) {
                    Ok(()) => Ok(vault.clone()),
                    Err(e) => {
                        // Roll back in-memory push on disk failure
                        vault.credentials.pop();
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
                        // Re-apply current search filter so list stays consistent
                        let current_query = search_clone.lock().unwrap().clone();
                        let filtered = vault_to_filtered_model(&vault_snapshot, &current_query);
                        ui.set_credentials(filtered.clone());
                        if let Some(qb) = qb_weak.upgrade() {
                            qb.set_filtered_results(filtered);
                        }
                        ui.set_notification_text(format!("✅ '{}' encrypted to disk!", title).into());
                        // Clear form and hide it
                        ui.set_new_title("".into());
                        ui.set_new_username("".into());
                        ui.set_new_password("".into());
                        ui.set_show_add_form(false);
                    }
                    Err(e) => {
                        ui.set_notification_text(format!("❌ Save failed: {}", e).into());
                    }
                }
            });
        });
    });

    // Phase 7: Real-time Search / Filter — case-insensitive on title or username
    let window_weak_search = main_window.as_weak();
    let vault_arc_search = Arc::clone(&active_vault);
    let search_state_search = Arc::clone(&search_state);
    main_window.on_search_changed(move |query| {
        let q = query.as_str().to_string();
        *search_state_search.lock().unwrap() = q.clone();
        let vault = vault_arc_search.lock().unwrap();
        let filtered = vault_to_filtered_model(&vault, &q);
        if let Some(ui) = window_weak_search.upgrade() {
            ui.set_credentials(filtered);
        }
    });

    // 8a: Manual URL paste (otpauth-migration:// or otpauth://)
    let window_weak_url = main_window.as_weak();
    let vault_arc_url = Arc::clone(&active_vault);
    let master_pw_url = Arc::clone(&active_master_pw);
    main_window.on_import_url_requested(move |url_text| {
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
                    let master_opt = master_clone.lock().unwrap().clone();
                    let Some(master_pw) = master_opt else {
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak.upgrade() {
                                ui.set_notification_text("❌ Vault not unlocked!".into());
                            }
                        });
                        return;
                    };
                    let save_result: Result<(), String> = {
                        let mut vault = vault_clone.lock().unwrap();
                        vault.totp_accounts.extend(accounts);
                        match save_vault(&*vault, &master_pw, VAULT_FILE) {
                            Ok(()) => Ok(()),
                            Err(e) => {
                                for _ in 0..count {
                                    vault.totp_accounts.pop();
                                }
                                Err(e)
                            }
                        }
                    };
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
            let master_opt = master_clone.lock().unwrap().clone();
            let Some(master_pw) = master_opt else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.set_notification_text("❌ Vault not unlocked!".into());
                    }
                });
                return;
            };
            let save_result: Result<(), String> = {
                let mut vault = vault_clone.lock().unwrap();
                vault.totp_accounts.extend(accounts);
                match save_vault(&*vault, &master_pw, VAULT_FILE) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        for _ in 0..count {
                            vault.totp_accounts.pop();
                        }
                        Err(e)
                    }
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    match save_result {
                        Ok(()) => {
                            ui.set_notification_text(
                                format!("✅ Imported {} 2FA accounts successfully!", count).into(),
                            );
                            ui.set_show_2fa_import(false);
                        }
                        Err(e) => {
                            ui.set_notification_text(format!("❌ Import save failed: {}", e).into());
                        }
                    }
                }
            });
        });
    });

    // 3. Password copy with 15-second auto-clear (per-card, already non-blocking)
    let window_weak_copy = main_window.as_weak();
    main_window.on_copy_password_requested(move |password_to_copy| {
        let Some(ui) = window_weak_copy.upgrade() else {
            return;
        };

        if let Ok(mut clipboard) = Clipboard::new() {
            let _ = clipboard.set_text(password_to_copy.as_str());
            ui.set_notification_text("📋 Password copied! (Auto-clearing in 15s)".into());

            let ui_weak = ui.as_weak();
            thread::spawn(move || {
                thread::sleep(Duration::from_secs(15));
                if let Ok(mut cb) = Clipboard::new() {
                    let _ = cb.clear();
                }
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_notification_text("🧹 Clipboard auto-cleared for security!".into());
                    }
                });
            });
        }
    });

    main_window.run()
}
