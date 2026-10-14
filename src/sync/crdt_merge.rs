//! Phase 4 — CRDT-style sync merge (field/item level).
//!
//! The default whole-blob adopt paths (`sync_with_peer`, startup pull,
//! `push_remote` conflict refusal) are UNTOUCHED — this is an explicit
//! preview → confirm flow only, never automatic.
//!
//! Rules (no new model fields — everything derives from existing data):
//! - Logins: per-item last-writer-wins on `last_changed`. Delete-vs-edit
//!   and same-timestamp divergence keep local + report a conflict.
//! - Every other collection: id-union; same-id divergence keeps local +
//!   reports a conflict (no secret auto-merge, ever).
//! - Folders + verified ids: union (verified swept to live ids).
//! - Device-local unlock second factor (`totp_unlock_*`) NEVER merges —
//!   always kept local, silently (it is per-device by design).

use crate::models::Vault;
use secrecy::SecretString;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Report types (metadata only — ids + kinds, never secrets).
// ---------------------------------------------------------------------------

/// One unmerged divergence. Local won by rule, user resolves by hand.
#[derive(Debug, Clone, PartialEq)]
pub struct ItemConflict {
    pub kind: &'static str,
    pub id: String,
    pub reason: &'static str,
}

#[derive(Debug)]
pub struct MergeReport {
    pub merged: Vault,
    pub conflicts: Vec<ItemConflict>,
    pub took_remote: usize,
    pub took_local_union: usize,
}

fn id_of(v: &Value) -> &str {
    v.get("id").and_then(|x| x.as_str()).unwrap_or("")
}

fn is_tombstone(v: &Value) -> bool {
    !v.get("deleted_at").map(|x| x.is_null()).unwrap_or(true)
}

fn last_changed_of(v: &Value) -> u64 {
    v.get("last_changed").and_then(|x| x.as_u64()).unwrap_or(0)
}

/// Generic id-union with keep-local-on-divergence. Returns
/// (merged values, took_remote, conflicts).
fn merge_id_list(
    local: Vec<Value>,
    remote: Vec<Value>,
    kind: &'static str,
    lww: bool,
) -> (Vec<Value>, usize, Vec<ItemConflict>) {
    use std::collections::{HashMap, HashSet};
    let mut by_id: HashMap<String, Value> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut idless: Vec<Value> = Vec::new();
    for item in local {
        let id = id_of(&item).to_string();
        if id.is_empty() {
            // No id → cannot match safely; keep as-is (never drop data).
            idless.push(item);
            continue;
        }
        order.push(id.clone());
        by_id.insert(id, item);
    }
    let mut took_remote = 0usize;
    let mut conflicts = Vec::new();
    let mut seen_remote: HashSet<String> = HashSet::new();
    for item in remote {
        let id = id_of(&item).to_string();
        if id.is_empty() {
            idless.push(item);
            continue;
        }
        seen_remote.insert(id.clone());
        match by_id.get(&id) {
            None => {
                order.push(id.clone());
                by_id.insert(id, item);
                took_remote += 1;
            }
            Some(cur) => {
                if cur == &item {
                    continue;
                }
                let tomb = is_tombstone(cur) || is_tombstone(&item);
                if lww && !tomb {
                    let (lc, rc) = (last_changed_of(cur), last_changed_of(&item));
                    if rc > lc {
                        by_id.insert(id.clone(), item);
                        took_remote += 1;
                        continue;
                    }
                    if rc == lc {
                        conflicts.push(ItemConflict {
                            kind,
                            id: id.clone(),
                            reason: "same-timestamp divergence",
                        });
                        continue;
                    }
                    // Local strictly newer — local already wins, no report.
                    continue;
                }
                conflicts.push(ItemConflict {
                    kind,
                    id: id.clone(),
                    reason: if tomb { "delete-vs-edit" } else { "diverged" },
                });
            }
        }
    }
    let _ = seen_remote;
    let mut out = Vec::with_capacity(order.len() + idless.len());
    for id in order {
        if let Some(v) = by_id.remove(&id) {
            out.push(v);
        }
    }
    out.extend(idless);
    (out, took_remote, conflicts)
}

fn from_values<T>(vals: Vec<Value>, what: &'static str) -> Result<Vec<T>, String>
where
    T: serde::de::DeserializeOwned,
{
    vals.into_iter()
        .map(|v| serde_json::from_value(v).map_err(|e| format!("{what} reshape failed: {e}")))
        .collect()
}

fn to_values<T>(items: &[T], what: &'static str) -> Result<Vec<Value>, String>
where
    T: serde::Serialize,
{
    items
        .iter()
        .map(|x| serde_json::to_value(x).map_err(|e| format!("{what} reshape failed: {e}")))
        .collect()
}

/// Merge `remote` into `local`. Local is the base: ties, deletes-vs-edits,
/// and non-login divergence all keep local + report. Never touches disk or
/// network — pure.
pub fn merge_vaults(local: &Vault, remote: &Vault) -> Result<MergeReport, String> {
    let mut took_remote = 0usize;
    let mut conflicts: Vec<ItemConflict> = Vec::new();

    let (credentials, took, conf) = merge_id_list(
        to_values(&local.credentials, "logins")?,
        to_values(&remote.credentials, "logins")?,
        "login",
        true,
    );
    took_remote += took;
    conflicts.extend(conf);
    let credentials = from_values(credentials, "logins")?;

    let mut others: Vec<(&str, Vec<Value>)> = Vec::new();
    for (kind, lv, rv) in [
        ("totp", to_values(&local.totp_accounts, "totp")?, to_values(&remote.totp_accounts, "totp")?),
        ("license", to_values(&local.licenses, "licenses")?, to_values(&remote.licenses, "licenses")?),
        ("note", to_values(&local.notes, "notes")?, to_values(&remote.notes, "notes")?),
        ("card", to_values(&local.cards, "cards")?, to_values(&remote.cards, "cards")?),
        ("identity", to_values(&local.identities, "identities")?, to_values(&remote.identities, "identities")?),
        ("ssh", to_values(&local.ssh_keys, "ssh")?, to_values(&remote.ssh_keys, "ssh")?),
        ("passkey", to_values(&local.passkeys, "passkeys")?, to_values(&remote.passkeys, "passkeys")?),
    ] {
        let (merged, took, conf) = merge_id_list(lv, rv, kind, false);
        took_remote += took;
        conflicts.extend(conf);
        others.push((kind, merged));
    }
    let get = |kind: &str| -> Vec<Value> {
        others.iter().find(|(k, _)| *k == kind).map(|(_, v)| v.clone()).unwrap_or_default()
    };
    let took_local_union = credentials.len()
        + get("totp").len()
        + get("license").len()
        + get("note").len()
        + get("card").len()
        + get("identity").len()
        + get("ssh").len()
        + get("passkey").len();

    // Folders: union, local order first.
    let mut folders = local.folders.clone();
    for f in &remote.folders {
        if !folders.iter().any(|x| x == f) {
            folders.push(f.clone());
        }
    }
    // Verified ids: union, then sweep to ids live in the MERGED vault.
    let mut verified_ids = local.verified_ids.clone();
    for id in &remote.verified_ids {
        if !verified_ids.iter().any(|x| x == id) {
            verified_ids.push(id.clone());
        }
    }

    let merged = Vault {
        version: local.version,
        folders,
        credentials,
        totp_accounts: from_values(get("totp"), "totp")?,
        licenses: from_values(get("license"), "licenses")?,
        notes: from_values(get("note"), "notes")?,
        cards: from_values(get("card"), "cards")?,
        identities: from_values(get("identity"), "identities")?,
        ssh_keys: from_values(get("ssh"), "ssh")?,
        passkeys: from_values(get("passkey"), "passkeys")?,
        // Device-local second factor: NEVER merged, silently kept local.
        totp_unlock_enabled: local.totp_unlock_enabled,
        totp_unlock_secret: local.totp_unlock_secret.clone(),
        verified_ids,
    };
    let mut merged = merged;
    {
        let live: std::collections::HashSet<&str> = merged
            .credentials
            .iter()
            .map(|c| c.id.as_str())
            .chain(merged.totp_accounts.iter().map(|t| t.id.as_str()))
            .collect();
        merged.verified_ids.retain(|id| live.contains(id.as_str()));
    }

    Ok(MergeReport {
        merged,
        conflicts,
        took_remote,
        took_local_union,
    })
}

// ---------------------------------------------------------------------------
// Remote-blob decrypt (bytes, no disk): mirrors the storage 3-way dispatch
// so merge-preview accepts whatever the normal sync paths accept.
// ---------------------------------------------------------------------------

/// Decrypt a remote vault blob (as fetched by `pull_remote`) with the
/// unlocked master. JSON-era only — pre-JSON bincode payloads refuse LOUD
/// (the normal pull path owns that migration, not merge preview).
pub fn decrypt_blob_to_vault(master: &SecretString, bytes: &[u8]) -> Result<Vault, String> {
    use crate::crypto::{
        decrypt_vault_hybrid_legacy_secret, decrypt_vault_portable_secret, decrypt_vault_secret,
        detect_version, VaultVersion,
    };
    let decrypted = match detect_version(bytes) {
        VaultVersion::V2Portable => decrypt_vault_portable_secret(master, bytes).or_else(|_| {
            let dk = crate::storage::load_legacy_pq_dk()?;
            let out = decrypt_vault_hybrid_legacy_secret(master, bytes, dk.expose());
            drop(dk);
            out
        })?,
        VaultVersion::V2Legacy => {
            let primary = (|| {
                let dk = crate::storage::load_legacy_pq_dk()?;
                let out = decrypt_vault_hybrid_legacy_secret(master, bytes, dk.expose());
                drop(dk);
                out
            })();
            match primary {
                Ok(d) => d,
                Err(_) => decrypt_vault_portable_secret(master, bytes)?,
            }
        }
        VaultVersion::V1Classical => decrypt_vault_secret(master, bytes)?,
    };
    serde_json::from_slice::<Vault>(&decrypted)
        .map_err(|_| "remote blob is not a JSON-era vault — pull normally first".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Credential, Vault};

    fn login(id: &str, pw: &str, changed: u64, deleted: bool) -> Credential {
        Credential {
            id: id.into(),
            title: id.into(),
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
            last_changed: changed,
            password_history: Vec::new(),
            favorite: false,
            deleted_at: deleted.then_some(9_999),
        }
    }

    #[test]
    fn disjoint_vaults_union() {
        let mut a = Vault::new();
        let mut b = Vault::new();
        a.credentials.push(login("a1", "p1", 100, false));
        b.credentials.push(login("b1", "p2", 100, false));
        b.folders.push("Work".into());
        let r = merge_vaults(&a, &b).unwrap();
        assert_eq!(r.merged.credentials.len(), 2);
        assert_eq!(r.took_remote, 1);
        assert!(r.conflicts.is_empty());
        assert!(r.merged.folders.iter().any(|f| f == "Work"));
    }

    #[test]
    fn login_lww_newer_wins_either_side() {
        let mut a = Vault::new();
        let mut b = Vault::new();
        a.credentials.push(login("x", "local-pw", 200, false));
        b.credentials.push(login("x", "remote-pw", 100, false));
        let r = merge_vaults(&a, &b).unwrap();
        assert_eq!(r.merged.credentials[0].password, "local-pw");
        assert!(r.conflicts.is_empty());
        // Flip: remote strictly newer wins.
        let mut c = Vault::new();
        let mut d = Vault::new();
        c.credentials.push(login("x", "local-pw", 100, false));
        d.credentials.push(login("x", "remote-pw", 300, false));
        let r2 = merge_vaults(&c, &d).unwrap();
        assert_eq!(r2.merged.credentials[0].password, "remote-pw");
        assert_eq!(r2.took_remote, 1);
        assert!(r2.conflicts.is_empty());
    }

    #[test]
    fn tie_and_delete_vs_edit_keep_local_and_report() {
        let mut a = Vault::new();
        let mut b = Vault::new();
        a.credentials.push(login("tie", "local-pw", 100, false));
        b.credentials.push(login("tie", "remote-pw", 100, false));
        let mut c = Vault::new();
        let mut d = Vault::new();
        c.credentials.push(login("del", "pw", 100, true));
        d.credentials.push(login("del", "pw2", 200, false));
        let mut e = Vault::new();
        e.credentials.extend([a.credentials[0].clone(), c.credentials[0].clone()]);
        let mut f = Vault::new();
        f.credentials.extend([b.credentials[0].clone(), d.credentials[0].clone()]);
        let r = merge_vaults(&e, &f).unwrap();
        assert_eq!(r.conflicts.len(), 2);
        assert!(r.conflicts.iter().any(|x| x.reason == "same-timestamp divergence"));
        assert!(r.conflicts.iter().any(|x| x.reason == "delete-vs-edit"));
        // Local kept in both cases.
        let tie = r.merged.credentials.iter().find(|x| x.id == "tie").unwrap();
        assert_eq!(tie.password, "local-pw");
        let del = r.merged.credentials.iter().find(|x| x.id == "del").unwrap();
        assert!(del.deleted_at.is_some());
    }

    #[test]
    fn remote_only_tombstone_respected_and_unlock_never_merges() {
        let a = Vault::new();
        let mut b = Vault::new();
        b.credentials.push(login("gone", "pw", 100, true));
        b.totp_unlock_enabled = true;
        b.totp_unlock_secret = "REMOTE-SECRET".into();
        let r = merge_vaults(&a, &b).unwrap();
        let gone = r.merged.credentials.iter().find(|x| x.id == "gone").unwrap();
        assert!(gone.deleted_at.is_some());
        assert!(!r.merged.totp_unlock_enabled);
        assert!(r.merged.totp_unlock_secret.is_empty());
    }

    #[test]
    fn other_kinds_union_and_divergence_conflicts() {
        use crate::models::SecureNote;
        let mut a = Vault::new();
        let mut b = Vault::new();
        a.notes.push(SecureNote {
            id: "n1".into(),
            title: "n".into(),
            content: "local".into(),
            folder: "General".into(),
            custom_fields: Vec::new(),
            attachments: Vec::new(),
            travel_safe: false,
            favorite: false,
            deleted_at: None,
        });
        let mut nb = a.notes[0].clone();
        nb.content = "remote".into();
        b.notes.push(nb);
        b.notes.push(SecureNote {
            id: "n2".into(),
            title: "n2".into(),
            content: "only-remote".into(),
            folder: "General".into(),
            custom_fields: Vec::new(),
            attachments: Vec::new(),
            travel_safe: false,
            favorite: false,
            deleted_at: None,
        });
        let r = merge_vaults(&a, &b).unwrap();
        assert_eq!(r.merged.notes.len(), 2);
        let n1 = r.merged.notes.iter().find(|x| x.id == "n1").unwrap();
        assert_eq!(n1.content, "local");
        assert!(r.conflicts.iter().any(|x| x.kind == "note" && x.reason == "diverged"));
        assert!(r.merged.notes.iter().any(|x| x.id == "n2"));
    }

    #[test]
    fn blob_roundtrip_decrypts() {
        use crate::crypto::encrypt_vault_portable_secret;
        let mut v = Vault::new();
        v.credentials.push(login("z", "pw", 100, false));
        let plain = serde_json::to_vec(&v).unwrap();
        let master = SecretString::new("merge-test-master-pw".to_string());
        let blob = encrypt_vault_portable_secret(&master, &plain).unwrap();
        let back = decrypt_blob_to_vault(&master, &blob).unwrap();
        assert_eq!(back.credentials.len(), 1);
        assert_eq!(back.credentials[0].password, "pw");
        // Wrong master fails closed.
        let wrong = SecretString::new("wrong".to_string());
        assert!(decrypt_blob_to_vault(&wrong, &blob).is_err());
    }
}
