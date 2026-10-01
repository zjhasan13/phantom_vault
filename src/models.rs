use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Folder fallback for items created before folders existed.
pub const DEFAULT_FOLDER: &str = "General";

/// Built-in folders seeded into every vault missing them.
pub const BUILTIN_FOLDERS: &[&str] = &["General", "Personal", "Work", "Finance"];

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq, Default)]
pub enum CustomFieldType {
    #[default]
    Text,
    Hidden,
    Checkbox,
    /// Mirrors a live item field. `CustomField.value` holds the target:
    /// `"username"` or `"password"`. Never duplicates secrets at rest.
    Linked,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Default)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    pub field_type: CustomFieldType,
}

impl CustomFieldType {
    pub fn from_i32(v: i32) -> Self {
        match v {
            1 => CustomFieldType::Hidden,
            2 => CustomFieldType::Checkbox,
            3 => CustomFieldType::Linked,
            _ => CustomFieldType::Text,
        }
    }

    pub fn to_i32(&self) -> i32 {
        match self {
            CustomFieldType::Text => 0,
            CustomFieldType::Hidden => 1,
            CustomFieldType::Checkbox => 2,
            CustomFieldType::Linked => 3,
        }
    }
}

/// Base64 codec for raw byte fields, used via `#[serde(with = "serde_b64")]`.
/// serde_json has no native bytes type — without this, JSON would balloon
/// every byte into a JSON number (~4-6x). STANDARD alphabet is JSON-safe.
/// Bincode ignores the attribute harmlessly (still length-prefixed bytes).
pub mod serde_b64 {
    use base64::Engine as _;

    const ENGINE: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::STANDARD;

    pub fn serialize<S: serde::Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&ENGINE.encode(v))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        ENGINE
            .decode(s.trim())
            .map_err(|e| serde::de::Error::custom(format!("base64 bytes: {e}")))
    }
}

/// Encrypted file attachment (stored sealed inside the vault container).
/// 5MB per-file cap enforced at ingestion; never written to disk plaintext.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Default)]
pub struct EncryptedAttachment {
    pub id: String,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: usize,
    #[serde(with = "serde_b64")]
    pub data: Vec<u8>,
}

pub const MAX_ATTACHMENT_BYTES: usize = 5 * 1024 * 1024;

/// One retired password + when it was replaced. Cap enforced by `push_history`.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Default, PartialEq)]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub changed_at: u64,
}

/// Rotation depth: how many retired passwords a login remembers.
pub const PASSWORD_HISTORY_KEEP: usize = 5;

/// Prepend `old_pw` (with `now`) and trim to the newest KEEP entries.
/// Empty passwords are never recorded. Pure — unit tested.
pub fn push_history(
    hist: &mut Vec<PasswordHistoryEntry>,
    old_pw: &str,
    now: u64,
) {
    if old_pw.is_empty() {
        return;
    }
    hist.insert(
        0,
        PasswordHistoryEntry {
            password: old_pw.to_string(),
            changed_at: now,
        },
    );
    hist.truncate(PASSWORD_HISTORY_KEEP);
}

/// Human "Changed … ago" for history rows. Pure — unit tested.
pub fn ago(ts: u64, now: u64) -> String {
    let d = now.saturating_sub(ts);
    const MIN: u64 = 60;
    const HOUR: u64 = 3600;
    const DAY: u64 = 86400;
    const WEEK: u64 = 7 * DAY;
    if d < MIN {
        "just now".to_string()
    } else if d < HOUR {
        format!("{} min ago", d / MIN)
    } else if d < DAY {
        format!("{}h ago", d / HOUR)
    } else if d < WEEK {
        format!("{}d ago", d / DAY)
    } else if d < 30 * DAY {
        format!("{}w ago", d / WEEK)
    } else if d < 365 * DAY {
        format!("{}mo ago", d / (30 * DAY))
    } else {
        format!("{}y ago", d / (365 * DAY))
    }
}

/// Rich login item (Bitwarden parity).
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Credential {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub totp_secret: String,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub backup_codes: Vec<String>,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    pub notes: String,
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub reprompt: bool,
    #[serde(default)]
    pub attachments: Vec<EncryptedAttachment>,
    #[serde(default)]
    pub travel_safe: bool,
    /// Unix seconds of the last password set. Refreshed on add/edit;
    /// unknown-age legacy items stamp the migration moment (rotation clock
    /// starts at upgrade rather than mass-flagging everything stale).
    #[serde(default = "current_timestamp")]
    pub last_changed: u64,
    /// Retired passwords, newest first (capped by `push_history`).
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
    /// Pinned by the user (sidebar ⭐ filter).
    #[serde(default)]
    pub favorite: bool,
    /// Soft-delete timestamp (None = active vault). Trash = Some(..).
    #[serde(default)]
    pub deleted_at: Option<u64>,
}

/// Seconds in 180 days — past this a password is "stale" (rotation nudge).
pub const STALE_AFTER_SECS: u64 = 180 * 24 * 3600;

/// Current Unix timestamp (seconds). Zero only when the clock is broken.
pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// True when `now - last_changed` exceeds the 180-day rotation window.
/// A zero stamp (clock failure) never counts as stale. Pure — unit tested.
pub fn is_stale(last_changed: u64, now: u64) -> bool {
    last_changed != 0 && now.saturating_sub(last_changed) > STALE_AFTER_SECS
}

/// 2FA authenticator account — algorithm/type/counter ride along so imports
/// stay bit-identical to Google Authenticator (no silent SHA1 fallback).
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq)]
pub struct TotpAccount {
    pub id: String,
    pub account_name: String,
    pub issuer: String,
    pub secret: String, // Base32 Secret Key
    #[serde(default = "default_digits")]
    pub digits: u32, // 6 or 8 (5 for Steam, rendered from its own path)
    #[serde(default = "default_period")]
    pub period: u64, // Usually 30s
    #[serde(default = "default_algorithm")]
    pub algorithm: String, // "SHA1", "SHA256", "SHA512", "MD5"(→SHA1)
    #[serde(default = "default_otp_type")]
    pub otp_type: String, // "totp", "hotp", "steam"
    #[serde(default)]
    pub counter: u64, // HOTP moving factor
    #[serde(default)]
    pub favorite: bool, // sidebar ⭐ (serde default keeps old vaults loading)
}

fn default_algorithm() -> String {
    "SHA1".into()
}

fn default_digits() -> u32 {
    6
}

fn default_period() -> u64 {
    30
}

fn default_otp_type() -> String {
    "totp".into()
}

/// সফটওয়্যার ও গেম লাইসেন্স কি
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SoftwareLicense {
    pub id: String,
    pub app_name: String,
    pub license_key: String,
    pub expiry_date: Option<String>,
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub attachments: Vec<EncryptedAttachment>,
    #[serde(default)]
    pub travel_safe: bool,
    /// Pinned by the user (sidebar ⭐ filter).
    #[serde(default)]
    pub favorite: bool,
    /// Soft-delete timestamp (None = active vault). Trash = Some(..).
    #[serde(default)]
    pub deleted_at: Option<u64>,
}

/// সিকিউর নোটস
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecureNote {
    pub id: String,
    pub title: String,
    pub content: String,
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub travel_safe: bool,
    /// Pinned by the user (sidebar ⭐ filter).
    #[serde(default)]
    pub favorite: bool,
    /// Soft-delete timestamp (None = active vault). Trash = Some(..).
    #[serde(default)]
    pub deleted_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Default)]
pub struct PaymentCard {
    pub id: String,
    pub title: String,
    pub cardholder_name: String,
    pub card_number: String,
    pub exp_month: String,
    pub exp_year: String,
    pub cvv: String,
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub travel_safe: bool,
    /// Pinned by the user (sidebar ⭐ filter).
    #[serde(default)]
    pub favorite: bool,
    /// Soft-delete timestamp (None = active vault). Trash = Some(..).
    #[serde(default)]
    pub deleted_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Default)]
pub struct IdentityItem {
    pub id: String,
    pub title: String,
    pub full_name: String,
    pub nid_or_passport: String,
    pub email: String,
    pub phone: String,
    pub address: String,
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub travel_safe: bool,
    /// Pinned by the user (sidebar ⭐ filter).
    #[serde(default)]
    pub favorite: bool,
    /// Soft-delete timestamp (None = active vault). Trash = Some(..).
    #[serde(default)]
    pub deleted_at: Option<u64>,
}

/// Resident WebAuthn/FIDO2 credential (Ed25519). The private seed never
/// leaves the encrypted container; assertions are signed in-process and the
/// counter bumps + re-seals on every use (clone detection by the RP).
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Default, PartialEq)]
pub struct PasskeyItem {
    pub id: String,
    pub rp_id: String, // Relying party (e.g. "github.com", "google.com")
    pub user_name: String,
    #[serde(with = "serde_b64")]
    pub user_handle: Vec<u8>,
    #[serde(with = "serde_b64")]
    pub credential_id: Vec<u8>,
    #[serde(with = "serde_b64")]
    pub private_key_pkcs8: Vec<u8>,
    #[serde(with = "serde_b64")]
    pub public_key_der: Vec<u8>,
    pub sign_count: u32,
    pub created_at: u64,
    /// Pinned by the user (hub ⭐ toggle + Favorites filter).
    /// `serde(default)` keeps pre-favorite JSON vaults loading.
    #[serde(default)]
    pub favorite: bool,
    /// Soft-delete timestamp (None = active vault). Trash = Some(..).
    /// `serde(default)` keeps pre-trash JSON vaults loading.
    #[serde(default)]
    pub deleted_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Default)]
pub struct SshKeyItem {
    pub id: String,
    pub title: String,
    pub public_key: String,
    pub private_key: String,
    pub fingerprint: String,
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub travel_safe: bool,
    /// Pinned by the user (sidebar ⭐ filter).
    #[serde(default)]
    pub favorite: bool,
    /// Soft-delete timestamp (None = active vault). Trash = Some(..).
    #[serde(default)]
    pub deleted_at: Option<u64>,
}

/// সম্পূর্ণ মূল ভল্ট কন্টেইনার.
/// C3 Hardening: Zeroize-derived so EVERY heap clone (snapshots, rollback
/// copies, invoke payloads) is scrubbed on drop — no lingering plaintext.
#[derive(Debug, Clone, Serialize, Deserialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct Vault {
    pub version: u32,
    #[serde(default)]
    pub folders: Vec<String>,
    pub credentials: Vec<Credential>,
    pub totp_accounts: Vec<TotpAccount>,
    pub licenses: Vec<SoftwareLicense>,
    pub notes: Vec<SecureNote>,
    #[serde(default)]
    pub cards: Vec<PaymentCard>,
    #[serde(default)]
    pub identities: Vec<IdentityItem>,
    #[serde(default)]
    pub ssh_keys: Vec<SshKeyItem>,
    /// Resident passkeys. `serde(default)` + Gen-chain `From` keep pre-passkey
    /// vaults loading (same pattern as cards/identities/ssh_keys).
    #[serde(default)]
    pub passkeys: Vec<PasskeyItem>,
    /// Optional vault-unlock second factor. STRICTLY default OFF — plain
    /// password/Hello unlock stays untouched unless the user arms this.
    #[serde(default)]
    pub totp_unlock_enabled: bool,
    /// Base32 TOTP secret guarding unlock when enabled. Verified locally
    /// against the device clock (same dispatcher as authenticator codes).
    #[serde(default)]
    pub totp_unlock_secret: String,
    /// Login ids the user confirmed as working ("✅ Verified" — the real
    /// password among decoys/rotations). Syncs with the vault by design.
    /// Stale ids (deleted/unknown) are ignored by readers and swept on write.
    #[serde(default)]
    pub verified_ids: Vec<String>,
}

/// Successful fills that auto-mark a login as working. Equality-crossing
/// only (see auto_verify_crossed): the 4th, 5th… fill must NOT re-seal,
/// and a manual un-verify at count 5 followed by fill 6 must stay off.
pub const AUTO_VERIFY_FILLS: u64 = 3;

/// True exactly on the crossing fill: the count just hit the threshold AND
/// the item is not already verified. Pure — both bridge and desktop fill
/// paths share this so neither can double-fire or fight a manual un-verify.
pub fn auto_verify_crossed(fill_count: u64, already_verified: bool) -> bool {
    fill_count == AUTO_VERIFY_FILLS && !already_verified
}

impl Vault {
    pub fn new() -> Self {
        Self {
            version: 1,
            folders: BUILTIN_FOLDERS.iter().map(|s| s.to_string()).collect(),
            credentials: Vec::new(),
            totp_accounts: Vec::new(),
            licenses: Vec::new(),
            notes: Vec::new(),
            cards: Vec::new(),
            identities: Vec::new(),
            ssh_keys: Vec::new(),
            passkeys: Vec::new(),
            totp_unlock_enabled: false,
            totp_unlock_secret: String::new(),
            verified_ids: Vec::new(),
        }
    }

    /// True when `id` is both marked AND a live login (stale marks from
    /// deleted items never render). Pure.
    pub fn is_verified(&self, id: &str) -> bool {
        self.verified_ids.iter().any(|v| v == id)
            && self.credentials.iter().any(|c| c.id == id)
    }

    /// Mark/unmark a login as working. Unknown ids are refused (typos can't
    /// pollute the list); stale ids are swept opportunistically. Pure.
    /// Returns false when `id` is not a login in this vault.
    pub fn set_verified(&mut self, id: &str, on: bool) -> bool {
        if !self.credentials.iter().any(|c| c.id == id) {
            return false;
        }
        if on {
            if !self.verified_ids.iter().any(|v| v == id) {
                self.verified_ids.push(id.to_string());
            }
        } else {
            self.verified_ids.retain(|v| v != id);
        }
        let live: Vec<String> = self.credentials.iter().map(|c| c.id.clone()).collect();
        self.verified_ids.retain(|v| live.iter().any(|id| id == v));
        true
    }

    /// Seed built-ins into vaults that predate the folder engine.
    /// Pure — unit tested.
    pub fn ensure_folders(&mut self) {
        for builtin in BUILTIN_FOLDERS {
            if !self.folders.iter().any(|f| f == builtin) {
                self.folders.push(builtin.to_string());
            }
        }
        // Folders referenced by items but missing from the registry heal too.
        let mut referenced: Vec<String> = Vec::new();
        for c in &self.credentials {
            referenced.push(eff_folder_name(&c.folder).to_string());
        }
        for l in &self.licenses {
            referenced.push(eff_folder_name(&l.folder).to_string());
        }
        for n in &self.notes {
            referenced.push(eff_folder_name(&n.folder).to_string());
        }
        for k in &self.cards {
            referenced.push(eff_folder_name(&k.folder).to_string());
        }
        for i in &self.identities {
            referenced.push(eff_folder_name(&i.folder).to_string());
        }
        for s in &self.ssh_keys {
            referenced.push(eff_folder_name(&s.folder).to_string());
        }
        for r in referenced {
            if !self.folders.iter().any(|f| f == &r) {
                self.folders.push(r);
            }
        }
        self.folders.sort();
    }

    /// Create a custom folder. Rejects empties, slashes, and duplicates.
    /// Pure — unit tested.
    pub fn add_folder(&mut self, name: &str) -> Result<(), String> {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err("Folder name is empty".to_string());
        }
        if name.len() > 48 {
            return Err("Folder name too long (48 max)".to_string());
        }
        if name.contains('/') || name.contains('\\') {
            return Err("Folder name cannot contain slashes".to_string());
        }
        if self
            .folders
            .iter()
            .any(|f| f.to_lowercase() == name.to_lowercase())
        {
            return Err("Folder already exists".to_string());
        }
        self.folders.push(name);
        self.folders.sort();
        Ok(())
    }

    /// Remove any item by (kind, id). Kinds: 1 login, 2 license, 3 note,
    /// 4 card, 5 identity, 6 ssh, 7 passkey. Returns true if something was
    /// removed. Permanent removal (Trash second phase + empty-trash internals).
    /// Pure — unit tested.
    pub fn delete_item(&mut self, kind: i32, id: &str) -> bool {
        fn drop_by_id<T>(v: &mut Vec<T>, id: &str, get: impl Fn(&T) -> &str) -> bool {
            let before = v.len();
            v.retain(|x| get(x) != id);
            v.len() != before
        }
        match kind {
            1 => drop_by_id(&mut self.credentials, id, |c| &c.id),
            2 => drop_by_id(&mut self.licenses, id, |l| &l.id),
            3 => drop_by_id(&mut self.notes, id, |n| &n.id),
            4 => drop_by_id(&mut self.cards, id, |c| &c.id),
            5 => drop_by_id(&mut self.identities, id, |i| &i.id),
            6 => drop_by_id(&mut self.ssh_keys, id, |s| &s.id),
            7 => drop_by_id(&mut self.passkeys, id, |p| &p.id),
            _ => false,
        }
    }

    /// Trash state lookup: None = missing item, Some(false) = active,
    /// Some(true) = in trash. Pure.
    pub fn is_trashed(&self, kind: i32, id: &str) -> Option<bool> {
        let flag = match kind {
            1 => self.credentials.iter().find(|c| c.id == id)?.deleted_at,
            2 => self.licenses.iter().find(|l| l.id == id)?.deleted_at,
            3 => self.notes.iter().find(|n| n.id == id)?.deleted_at,
            4 => self.cards.iter().find(|k| k.id == id)?.deleted_at,
            5 => self.identities.iter().find(|i| i.id == id)?.deleted_at,
            6 => self.ssh_keys.iter().find(|s| s.id == id)?.deleted_at,
            7 => self.passkeys.iter().find(|p| p.id == id)?.deleted_at,
            _ => return None,
        };
        Some(flag.is_some())
    }

    /// Soft-delete: stamp `deleted_at`, keep the bytes. Pure — unit tested.
    pub fn trash_item(&mut self, kind: i32, id: &str, now: u64) -> bool {
        let slot: Option<&mut Option<u64>> = match kind {
            1 => self.credentials.iter_mut().find(|c| c.id == id).map(|c| &mut c.deleted_at),
            2 => self.licenses.iter_mut().find(|l| l.id == id).map(|l| &mut l.deleted_at),
            3 => self.notes.iter_mut().find(|n| n.id == id).map(|n| &mut n.deleted_at),
            4 => self.cards.iter_mut().find(|k| k.id == id).map(|k| &mut k.deleted_at),
            5 => self.identities.iter_mut().find(|i| i.id == id).map(|i| &mut i.deleted_at),
            6 => self.ssh_keys.iter_mut().find(|s| s.id == id).map(|s| &mut s.deleted_at),
            7 => self.passkeys.iter_mut().find(|p| p.id == id).map(|p| &mut p.deleted_at),
            _ => None,
        };
        match slot {
            Some(s) => {
                *s = Some(now);
                true
            }
            None => false,
        }
    }

    /// Restore a trashed item to the active vault. Pure — unit tested.
    pub fn restore_item(&mut self, kind: i32, id: &str) -> bool {
        let slot: Option<&mut Option<u64>> = match kind {
            1 => self.credentials.iter_mut().find(|c| c.id == id).map(|c| &mut c.deleted_at),
            2 => self.licenses.iter_mut().find(|l| l.id == id).map(|l| &mut l.deleted_at),
            3 => self.notes.iter_mut().find(|n| n.id == id).map(|n| &mut n.deleted_at),
            4 => self.cards.iter_mut().find(|k| k.id == id).map(|k| &mut k.deleted_at),
            5 => self.identities.iter_mut().find(|i| i.id == id).map(|i| &mut i.deleted_at),
            6 => self.ssh_keys.iter_mut().find(|s| s.id == id).map(|s| &mut s.deleted_at),
            7 => self.passkeys.iter_mut().find(|p| p.id == id).map(|p| &mut p.deleted_at),
            _ => None,
        };
        match slot {
            Some(s) if s.is_some() => {
                *s = None;
                true
            }
            _ => false,
        }
    }

    /// Total items with `deleted_at.is_some()` across all 7 vectors
    /// (logins, licenses, notes, cards, identities, ssh keys, passkeys).
    pub fn trash_count(&self) -> usize {
        self.credentials.iter().filter(|c| c.deleted_at.is_some()).count()
            + self.licenses.iter().filter(|l| l.deleted_at.is_some()).count()
            + self.notes.iter().filter(|n| n.deleted_at.is_some()).count()
            + self.cards.iter().filter(|k| k.deleted_at.is_some()).count()
            + self.identities.iter().filter(|i| i.deleted_at.is_some()).count()
            + self.ssh_keys.iter().filter(|s| s.deleted_at.is_some()).count()
            + self.passkeys.iter().filter(|p| p.deleted_at.is_some()).count()
    }

    /// Drop every trashed item (empty-trash / 30-day purge share this).
    /// Returns the number destroyed. Pure — unit tested.
    pub fn empty_trash(&mut self) -> usize {
        let before = self.trash_count();
        self.credentials.retain(|c| c.deleted_at.is_none());
        self.licenses.retain(|l| l.deleted_at.is_none());
        self.notes.retain(|n| n.deleted_at.is_none());
        self.cards.retain(|k| k.deleted_at.is_none());
        self.identities.retain(|i| i.deleted_at.is_none());
        self.ssh_keys.retain(|s| s.deleted_at.is_none());
        self.passkeys.retain(|p| p.deleted_at.is_none());
        before
    }

    /// Destroy trashed items older than `retention_secs`. Pure — unit tested.
    pub fn purge_expired_trash(&mut self, now: u64, retention_secs: u64) -> usize {
        let fresh = |t: Option<u64>| -> bool {
            match t {
                None => true, // active items always survive
                Some(ts) => now.saturating_sub(ts) < retention_secs,
            }
        };
        let before = self.trash_count();
        self.credentials.retain(|c| fresh(c.deleted_at));
        self.licenses.retain(|l| fresh(l.deleted_at));
        self.notes.retain(|n| fresh(n.deleted_at));
        self.cards.retain(|k| fresh(k.deleted_at));
        self.identities.retain(|i| fresh(i.deleted_at));
        self.ssh_keys.retain(|s| fresh(s.deleted_at));
        self.passkeys.retain(|p| fresh(p.deleted_at));
        before - self.trash_count()
    }
}

/// Trash retention: trashed items are shredded after 30 days.
pub const TRASH_RETENTION_SECS: u64 = 30 * 24 * 3600;

pub fn eff_folder_name(folder: &str) -> &str {
    if folder.trim().is_empty() {
        DEFAULT_FOLDER
    } else {
        folder
    }
}

// ---------------------------------------------------------------------------
// Legacy shapes for bincode fallback. The on-disk history:
// - Gen 0: no folders, no new vectors, lean Credential (6 fields).
// - Gen 1: folder fields + cards/identities/ssh_keys (current code before rich upgrade).
// Decode newest-first, upgrade with defaults.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyCredentialGen0 {
    id: String,
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyLicenseGen0 {
    id: String,
    app_name: String,
    license_key: String,
    expiry_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyNoteGen0 {
    id: String,
    title: String,
    content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultLegacy {
    version: u32,
    credentials: Vec<LegacyCredentialGen0>,
    totp_accounts: Vec<TotpAccount>,
    licenses: Vec<LegacyLicenseGen0>,
    notes: Vec<LegacyNoteGen0>,
}

impl From<VaultLegacy> for Vault {
    fn from(old: VaultLegacy) -> Self {
        let mut v = Vault {
            version: old.version,
            folders: Vec::new(),
            credentials: old
                .credentials
                .into_iter()
                .map(|c| Credential {
                    id: c.id,
                    title: c.title,
                    username: c.username,
                    password: c.password,
                    totp_secret: String::new(),
                    urls: Vec::new(),
                    backup_codes: Vec::new(),
                    custom_fields: Vec::new(),
                    notes: c.notes,
                    folder: DEFAULT_FOLDER.to_string(),
                    reprompt: false,
                
                    attachments: Vec::new(),
                    travel_safe: false,
                    // Unknown age: rotation clock starts at migration.
                    last_changed: current_timestamp(),
                    password_history: Vec::new(),
                    favorite: false,
                    deleted_at: None,
                })
                .collect(),
            totp_accounts: old.totp_accounts,
            licenses: old
                .licenses
                .into_iter()
                .map(|l| SoftwareLicense {
                    id: l.id,
                    app_name: l.app_name,
                    license_key: l.license_key,
                    expiry_date: l.expiry_date,
                    folder: DEFAULT_FOLDER.to_string(),
                    attachments: Vec::new(),
                    travel_safe: false,
                    favorite: false,
                    deleted_at: None,
                })
                .collect(),
            notes: old
                .notes
                .into_iter()
                .map(|n| SecureNote {
                    id: n.id,
                    title: n.title,
                    content: n.content,
                    folder: DEFAULT_FOLDER.to_string(),
                    travel_safe: false,
                    favorite: false,
                    deleted_at: None,
                })
                .collect(),
            cards: Vec::new(),
            identities: Vec::new(),
            ssh_keys: Vec::new(),
            // Pre-passkey generation: nothing to migrate, start empty.
            passkeys: Vec::new(),
            totp_unlock_enabled: false,
            totp_unlock_secret: String::new(),
            verified_ids: Vec::new(),
        };
        v.ensure_folders();
        v
    }
}

/// Gen-1 shape: everything current EXCEPT the rich Credential fields,
/// notes-on-card/identity/ssh, and the folders registry. (Field-for-field
/// identical to the structs above minus those additions.)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Gen1Credential {
    id: String,
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    folder: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Gen1Card {
    id: String,
    title: String,
    cardholder_name: String,
    card_number: String,
    exp_month: String,
    exp_year: String,
    cvv: String,
    folder: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Gen1Identity {
    id: String,
    title: String,
    full_name: String,
    nid_or_passport: String,
    email: String,
    phone: String,
    address: String,
    folder: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Gen1Ssh {
    id: String,
    title: String,
    public_key: String,
    private_key: String,
    fingerprint: String,
    folder: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultGen1 {
    version: u32,
    credentials: Vec<Gen1Credential>,
    totp_accounts: Vec<TotpAccount>,
    licenses: Vec<SoftwareLicense>,
    notes: Vec<SecureNote>,
    cards: Vec<Gen1Card>,
    identities: Vec<Gen1Identity>,
    ssh_keys: Vec<Gen1Ssh>,
}

impl From<VaultGen1> for Vault {
    fn from(old: VaultGen1) -> Self {
        let mut v = Vault {
            version: old.version,
            folders: Vec::new(),
            credentials: old
                .credentials
                .into_iter()
                .map(|c| Credential {
                    id: c.id,
                    title: c.title,
                    username: c.username,
                    password: c.password,
                    totp_secret: String::new(),
                    urls: Vec::new(),
                    backup_codes: Vec::new(),
                    custom_fields: Vec::new(),
                    notes: c.notes,
                    folder: c.folder,
                    reprompt: false,
                
                    attachments: Vec::new(),
                    travel_safe: false,
                    // Unknown age: rotation clock starts at migration.
                    last_changed: current_timestamp(),
                    password_history: Vec::new(),
                    favorite: false,
                    deleted_at: None,
                })
                .collect(),
            totp_accounts: old.totp_accounts,
            licenses: old.licenses,
            notes: old.notes,
            cards: old
                .cards
                .into_iter()
                .map(|k| PaymentCard {
                    id: k.id,
                    title: k.title,
                    cardholder_name: k.cardholder_name,
                    card_number: k.card_number,
                    exp_month: k.exp_month,
                    exp_year: k.exp_year,
                    cvv: k.cvv,
                    folder: k.folder,
                    notes: String::new(),
                    travel_safe: false,
                    favorite: false,
                    deleted_at: None,
                })
                .collect(),
            identities: old
                .identities
                .into_iter()
                .map(|i| IdentityItem {
                    id: i.id,
                    title: i.title,
                    full_name: i.full_name,
                    nid_or_passport: i.nid_or_passport,
                    email: i.email,
                    phone: i.phone,
                    address: i.address,
                    folder: i.folder,
                    notes: String::new(),
                    travel_safe: false,
                    favorite: false,
                    deleted_at: None,
                })
                .collect(),
            ssh_keys: old
                .ssh_keys
                .into_iter()
                .map(|s| SshKeyItem {
                    id: s.id,
                    title: s.title,
                    public_key: s.public_key,
                    private_key: s.private_key,
                    fingerprint: s.fingerprint,
                    folder: s.folder,
                    notes: String::new(),
                    travel_safe: false,
                    favorite: false,
                    deleted_at: None,
                })
                .collect(),
            // Pre-passkey generation: nothing to migrate, start empty.
            passkeys: Vec::new(),
            totp_unlock_enabled: false,
            totp_unlock_secret: String::new(),
            verified_ids: Vec::new(),
        };
        v.ensure_folders();
        v
    }
}

/// Gen-2 shape: everything current EXCEPT attachments, travel_safe flags,
/// and the folders registry additions that followed. (Field-for-field
/// identical to the structs above minus those additions.)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Gen2Credential {
    id: String,
    title: String,
    username: String,
    password: String,
    totp_secret: String,
    urls: Vec<String>,
    backup_codes: Vec<String>,
    custom_fields: Vec<CustomField>,
    notes: String,
    folder: String,
    reprompt: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Gen2License {
    id: String,
    app_name: String,
    license_key: String,
    expiry_date: Option<String>,
    folder: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Gen2Note {
    id: String,
    title: String,
    content: String,
    folder: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Gen2Card {
    id: String,
    title: String,
    cardholder_name: String,
    card_number: String,
    exp_month: String,
    exp_year: String,
    cvv: String,
    folder: String,
    notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Gen2Identity {
    id: String,
    title: String,
    full_name: String,
    nid_or_passport: String,
    email: String,
    phone: String,
    address: String,
    folder: String,
    notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Gen2Ssh {
    id: String,
    title: String,
    public_key: String,
    private_key: String,
    fingerprint: String,
    folder: String,
    notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultGen2 {
    version: u32,
    folders: Vec<String>,
    credentials: Vec<Gen2Credential>,
    totp_accounts: Vec<TotpAccount>,
    licenses: Vec<Gen2License>,
    notes: Vec<Gen2Note>,
    cards: Vec<Gen2Card>,
    identities: Vec<Gen2Identity>,
    ssh_keys: Vec<Gen2Ssh>,
}

impl From<VaultGen2> for Vault {
    fn from(old: VaultGen2) -> Self {
        let mut v = Vault {
            version: old.version,
            folders: old.folders,
            credentials: old
                .credentials
                .into_iter()
                .map(|c| Credential {
                    id: c.id,
                    title: c.title,
                    username: c.username,
                    password: c.password,
                    totp_secret: c.totp_secret,
                    urls: c.urls,
                    backup_codes: c.backup_codes,
                    custom_fields: c.custom_fields,
                    notes: c.notes,
                    folder: c.folder,
                    reprompt: c.reprompt,
                    attachments: Vec::new(),
                    travel_safe: false,
                    // Unknown age: rotation clock starts at migration.
                    last_changed: current_timestamp(),
                    password_history: Vec::new(),
                    favorite: false,
                    deleted_at: None,
                })
                .collect(),
            totp_accounts: old.totp_accounts,
            licenses: old
                .licenses
                .into_iter()
                .map(|l| SoftwareLicense {
                    id: l.id,
                    app_name: l.app_name,
                    license_key: l.license_key,
                    expiry_date: l.expiry_date,
                    folder: l.folder,
                    attachments: Vec::new(),
                    travel_safe: false,
                    favorite: false,
                    deleted_at: None,
                })
                .collect(),
            notes: old
                .notes
                .into_iter()
                .map(|n| SecureNote {
                    id: n.id,
                    title: n.title,
                    content: n.content,
                    folder: n.folder,
                    travel_safe: false,
                    favorite: false,
                    deleted_at: None,
                })
                .collect(),
            cards: old
                .cards
                .into_iter()
                .map(|k| PaymentCard {
                    id: k.id,
                    title: k.title,
                    cardholder_name: k.cardholder_name,
                    card_number: k.card_number,
                    exp_month: k.exp_month,
                    exp_year: k.exp_year,
                    cvv: k.cvv,
                    folder: k.folder,
                    notes: k.notes,
                    travel_safe: false,
                    favorite: false,
                    deleted_at: None,
                })
                .collect(),
            identities: old
                .identities
                .into_iter()
                .map(|i| IdentityItem {
                    id: i.id,
                    title: i.title,
                    full_name: i.full_name,
                    nid_or_passport: i.nid_or_passport,
                    email: i.email,
                    phone: i.phone,
                    address: i.address,
                    folder: i.folder,
                    notes: i.notes,
                    travel_safe: false,
                    favorite: false,
                    deleted_at: None,
                })
                .collect(),
            ssh_keys: old
                .ssh_keys
                .into_iter()
                .map(|s| SshKeyItem {
                    id: s.id,
                    title: s.title,
                    public_key: s.public_key,
                    private_key: s.private_key,
                    fingerprint: s.fingerprint,
                    folder: s.folder,
                    notes: s.notes,
                    travel_safe: false,
                    favorite: false,
                    deleted_at: None,
                })
                .collect(),
            // Pre-passkey generation: nothing to migrate, start empty.
            passkeys: Vec::new(),
            totp_unlock_enabled: false,
            totp_unlock_secret: String::new(),
            verified_ids: Vec::new(),
        };
        v.ensure_folders();
        v
    }
}

/// Gen-3 shape: identical to current EXCEPT the lean pre-dynamic TotpAccount
/// (no algorithm/otp_type/counter). Added when the 2FA engine went dynamic;
/// old vaults upgrade with SHA1/totp/0 defaults (exactly their old behavior).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OldTotp {
    id: String,
    account_name: String,
    issuer: String,
    secret: String,
    digits: u32,
    period: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultGen3 {
    version: u32,
    folders: Vec<String>,
    credentials: Vec<Credential>,
    totp_accounts: Vec<OldTotp>,
    licenses: Vec<SoftwareLicense>,
    notes: Vec<SecureNote>,
    cards: Vec<PaymentCard>,
    identities: Vec<IdentityItem>,
    ssh_keys: Vec<SshKeyItem>,
}

impl From<VaultGen3> for Vault {
    fn from(old: VaultGen3) -> Self {
        let mut v = Vault {
            version: old.version,
            folders: old.folders,
            credentials: old.credentials,
            totp_accounts: old
                .totp_accounts
                .into_iter()
                .map(|t| TotpAccount {
                    id: t.id,
                    account_name: t.account_name,
                    issuer: t.issuer,
                    secret: t.secret,
                    digits: t.digits,
                    period: t.period,
                    algorithm: default_algorithm(),
                    otp_type: default_otp_type(),
                    counter: 0,
                    favorite: false,
                })
                .collect(),
            licenses: old.licenses,
            notes: old.notes,
            cards: old.cards,
            identities: old.identities,
            ssh_keys: old.ssh_keys,
            // Pre-passkey generation: nothing to migrate, start empty.
            passkeys: Vec::new(),
            totp_unlock_enabled: false,
            totp_unlock_secret: String::new(),
            verified_ids: Vec::new(),
        };
        v.ensure_folders();
        v
    }
}

/// Gen-4 shape: identical to current EXCEPT the vault-unlock 2FA pair
/// (`totp_unlock_enabled`, `totp_unlock_secret`). Pre-gate vaults upgrade
/// with the gate strictly OFF (old unlock behavior preserved bit-for-bit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultGen4 {
    version: u32,
    folders: Vec<String>,
    credentials: Vec<Credential>,
    totp_accounts: Vec<TotpAccount>,
    licenses: Vec<SoftwareLicense>,
    notes: Vec<SecureNote>,
    cards: Vec<PaymentCard>,
    identities: Vec<IdentityItem>,
    ssh_keys: Vec<SshKeyItem>,
    passkeys: Vec<PasskeyItem>,
}

impl From<VaultGen4> for Vault {
    fn from(old: VaultGen4) -> Self {
        let mut v = Vault {
            version: old.version,
            folders: old.folders,
            credentials: old.credentials,
            totp_accounts: old.totp_accounts,
            licenses: old.licenses,
            notes: old.notes,
            cards: old.cards,
            identities: old.identities,
            ssh_keys: old.ssh_keys,
            passkeys: old.passkeys,
            totp_unlock_enabled: false,
            totp_unlock_secret: String::new(),
            verified_ids: Vec::new(),
        };
        v.ensure_folders();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_item_hits_every_vector() {
        let mut v = Vault::new();
        v.credentials.push(Credential {
            id: "c1".into(),
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
                    last_changed: current_timestamp(),
                    password_history: Vec::new(),
                    favorite: false,
                    deleted_at: None,
                });
        v.cards.push(PaymentCard {
            id: "k1".into(),
            title: "Bank".into(),
            cardholder_name: "A U".into(),
            card_number: "4111111111111111".into(),
            exp_month: "12".into(),
            exp_year: "28".into(),
            cvv: "123".into(),
            folder: "Finance".into(),
            notes: String::new(),
            travel_safe: false,
            favorite: false,
            deleted_at: None,
        });
        assert!(v.delete_item(1, "c1"));
        assert!(v.credentials.is_empty());
        assert!(v.delete_item(4, "k1"));
        assert!(v.cards.is_empty());
        assert!(!v.delete_item(9, "nope"));
        assert!(!v.delete_item(1, "gone"));
    }

    #[test]
    fn legacy_upgrades_with_default_folder() {
        let old = VaultLegacy {
            version: 1,
            credentials: vec![LegacyCredentialGen0 {
                id: "a".into(),
                title: "t".into(),
                username: "u".into(),
                password: "p".into(),
                url: String::new(),
                notes: String::new(),
            }],
            totp_accounts: Vec::new(),
            licenses: Vec::new(),
            notes: Vec::new(),
        };
        let v: Vault = old.into();
        assert_eq!(v.credentials[0].folder, "General");
        assert!(v.credentials[0].custom_fields.is_empty());
        assert!(v.folders.contains(&"Work".to_string()));
    }

    #[test]
    fn gen4_upgrades_with_gate_strictly_off() {
        // Simulate a pre-Phase-27 vault: full current shape minus the gate.
        let old = VaultGen4 {
            version: 1,
            folders: vec!["General".into()],
            credentials: Vec::new(),
            totp_accounts: Vec::new(),
            licenses: Vec::new(),
            notes: Vec::new(),
            cards: Vec::new(),
            identities: Vec::new(),
            ssh_keys: Vec::new(),
            passkeys: Vec::new(),
        };
        // Bincode round-trip through the OLD shape, then upgrade.
        let bytes = bincode::serialize(&old).unwrap();
        let decoded: VaultGen4 = bincode::deserialize(&bytes).unwrap();
        let v: Vault = decoded.into();
        assert!(!v.totp_unlock_enabled);
        assert!(v.totp_unlock_secret.is_empty());
    }

    #[test]
    fn verified_marks_only_live_logins_and_sweeps_stale() {
        let mut v = Vault::new();
        // Unknown id refused (typos can't pollute).
        assert!(!v.set_verified("ghost", true));
        assert!(!v.is_verified("ghost"));
        v.credentials.push(Credential {
            id: "t1".into(),
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
        });
        assert!(!v.is_verified("t1"));
        assert!(v.set_verified("t1", true));
        assert!(v.is_verified("t1"));
        // Idempotent re-mark; unmark clears.
        assert!(v.set_verified("t1", true));
        assert_eq!(v.verified_ids.len(), 1);
        assert!(v.set_verified("t1", false));
        assert!(!v.is_verified("t1"));
        // Stale id swept on next write.
        v.verified_ids.push("deleted-id".into());
        assert!(v.set_verified("t1", true));
        assert!(!v.verified_ids.iter().any(|x| x == "deleted-id"));
        assert!(v.is_verified("t1"));
    }

    #[test]
    fn auto_verify_crossing_semantics() {
        // Fires ONLY on equality-crossing while unverified.
        assert!(!auto_verify_crossed(0, false));
        assert!(!auto_verify_crossed(AUTO_VERIFY_FILLS - 1, false));
        assert!(auto_verify_crossed(AUTO_VERIFY_FILLS, false));
        assert!(!auto_verify_crossed(AUTO_VERIFY_FILLS + 1, false));
        // Already verified (manual or prior auto): never re-fires.
        assert!(!auto_verify_crossed(AUTO_VERIFY_FILLS, true));
        assert!(!auto_verify_crossed(0, true));
    }

    #[test]
    fn trash_lifecycle_trash_restore_empty() {
        let mut v = Vault::new();
        v.credentials.push(Credential {
            id: "t1".into(),
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
        });
        assert_eq!(v.is_trashed(1, "t1"), Some(false));
        assert_eq!(v.is_trashed(1, "nope"), None);
        assert_eq!(v.is_trashed(9, "t1"), None);
        assert!(v.trash_item(1, "t1", 1000));
        assert!(!v.trash_item(1, "nope", 1000));
        assert_eq!(v.is_trashed(1, "t1"), Some(true));
        assert_eq!(v.trash_count(), 1);
        // Restoring an active item is a no-op false.
        assert!(v.restore_item(1, "t1"));
        assert_eq!(v.is_trashed(1, "t1"), Some(false));
        assert!(!v.restore_item(1, "t1"));
        assert_eq!(v.trash_count(), 0);
        // Re-trash + empty destroys.
        assert!(v.trash_item(1, "t1", 2000));
        assert_eq!(v.empty_trash(), 1);
        assert!(v.credentials.is_empty());
        assert_eq!(v.trash_count(), 0);
    }

    #[test]
    fn purge_expired_keeps_fresh_trash() {
        let mut v = Vault::new();
        // Old trashed at T0, fresh 2 days later: a 29d/31d window splits them.
        const T0: u64 = 1_000_000;
        const DAY: u64 = 24 * 3600;
        for (id, ts) in [("old", T0), ("fresh", T0 + 2 * DAY)] {
            v.notes.push(SecureNote {
                id: id.into(),
                title: "t".into(),
                content: "c".into(),
                folder: "General".into(),
                travel_safe: false,
                favorite: false,
                deleted_at: Some(ts),
            });
        }
        // Old is 29d old, fresh 27d: nothing expires yet.
        assert_eq!(v.purge_expired_trash(T0 + 29 * DAY, TRASH_RETENTION_SECS), 0);
        assert_eq!(v.trash_count(), 2);
        // Old hits 31d (fresh only 29d): only the old one is shredded.
        assert_eq!(v.purge_expired_trash(T0 + 31 * DAY, TRASH_RETENTION_SECS), 1);
        assert_eq!(v.notes.len(), 1);
        assert_eq!(v.notes[0].id, "fresh");
    }

    #[test]
    fn folder_engine_validates() {
        let mut v = Vault::new();
        assert!(v.add_folder("Side").is_ok());
        assert!(v.add_folder("side").is_err());
        assert!(v.add_folder("").is_err());
        assert!(v.add_folder("a/b").is_err());
        assert!(v.folders.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn ensure_folders_heals_references() {
        let mut v = Vault::new();
        v.folders.clear();
        v.credentials.push(Credential {
            id: "c".into(),
            title: "t".into(),
            username: "u".into(),
            password: "p".into(),
            totp_secret: String::new(),
            urls: Vec::new(),
            backup_codes: Vec::new(),
            custom_fields: Vec::new(),
            notes: String::new(),
            folder: "SecretLab".into(),
            reprompt: false,
        
                    attachments: Vec::new(),
                    travel_safe: false,
                    last_changed: current_timestamp(),
                    password_history: Vec::new(),
                    favorite: false,
                    deleted_at: None,
                });
        v.ensure_folders();
        assert!(v.folders.contains(&"SecretLab".to_string()));
        assert!(v.folders.contains(&"General".to_string()));
    }

    #[test]
    fn history_caps_at_five_and_skips_empty() {
        let mut h = Vec::new();
        push_history(&mut h, "", 100);
        assert!(h.is_empty());
        for i in 1..=7u64 {
            push_history(&mut h, &format!("pw{i}"), 1000 + i);
        }
        assert_eq!(h.len(), PASSWORD_HISTORY_KEEP);
        assert_eq!(h[0].password, "pw7");
        assert_eq!(h[0].changed_at, 1007);
        assert_eq!(h[4].password, "pw3");
    }

    #[test]
    fn ago_buckets() {
        let now = 2_000_000_000u64;
        assert_eq!(ago(now, now), "just now");
        assert_eq!(ago(now - 90, now), "1 min ago");
        assert_eq!(ago(now - 7200, now), "2h ago");
        assert_eq!(ago(now - 3 * 86400, now), "3d ago");
        assert_eq!(ago(now - 14 * 86400, now), "2w ago");
        assert_eq!(ago(now - 60 * 86400, now), "2mo ago");
        assert_eq!(ago(now - 400 * 86400, now), "1y ago");
    }

    #[test]
    fn staleness_window() {
        let now = current_timestamp();
        assert!(now > 0);
        assert!(!is_stale(now, now));
        assert!(!is_stale(now.saturating_sub(STALE_AFTER_SECS), now));
        assert!(is_stale(now.saturating_sub(STALE_AFTER_SECS + 1), now));
        assert!(is_stale(1, now));
        assert!(!is_stale(0, now), "zero stamp (broken clock) never counts");
    }

    #[test]
    fn gen1_migration_stamps_rotation_clock() {
        // Pre-age-tracking vaults must load AND enter the rotation scheme.
        let old = VaultGen1 {
            version: 1,
            credentials: vec![Gen1Credential {
                id: "g".into(),
                title: "t".into(),
                username: "u".into(),
                password: "p".into(),
                url: String::new(),
                notes: String::new(),
                folder: "General".into(),
            }],
            totp_accounts: Vec::new(),
            licenses: Vec::new(),
            notes: Vec::new(),
            cards: Vec::new(),
            identities: Vec::new(),
            ssh_keys: Vec::new(),
        };
        let v: Vault = old.into();
        assert!(v.credentials[0].last_changed > 0);
        assert!(!is_stale(v.credentials[0].last_changed, current_timestamp()));
    }

    #[test]
    fn passkey_trash_and_fav_lifecycle() {
        let mut v = Vault::new();
        v.passkeys.push(PasskeyItem {
            id: "pk1".into(),
            rp_id: "github.com".into(),
            user_name: "octo".into(),
            user_handle: Vec::new(),
            credential_id: Vec::new(),
            private_key_pkcs8: Vec::new(),
            public_key_der: Vec::new(),
            sign_count: 0,
            created_at: 0,
            favorite: false,
            deleted_at: None,
        });
        // Favorite flag flips without touching trash state.
        assert_eq!(v.is_trashed(7, "pk1"), Some(false));
        v.passkeys[0].favorite = true;
        assert!(v.passkeys[0].favorite);
        // Soft-delete → restore → permanent shred, like the other 6 kinds.
        assert!(v.trash_item(7, "pk1", 1000));
        assert_eq!(v.is_trashed(7, "pk1"), Some(true));
        assert_eq!(v.trash_count(), 1);
        assert!(v.restore_item(7, "pk1"));
        assert_eq!(v.is_trashed(7, "pk1"), Some(false));
        assert!(v.trash_item(7, "pk1", 2000));
        assert!(v.delete_item(7, "pk1"));
        assert!(v.passkeys.is_empty());
        assert!(!v.delete_item(7, "gone"));
        assert_eq!(v.is_trashed(7, "gone"), None);
    }

    #[test]
    fn passkey_old_json_defaults_to_active_unpinned() {
        // Pre-trash vaults carry no favorite/deleted_at keys — serde(default)
        // must fill them so old containers keep loading AND stay usable.
        let old = serde_json::json!({
            "id": "pk-old",
            "rp_id": "example.com",
            "user_name": "u",
            "user_handle": "",
            "credential_id": "",
            "private_key_pkcs8": "",
            "public_key_der": "",
            "sign_count": 3,
            "created_at": 1700000000u64
        });
        let pk: PasskeyItem = serde_json::from_value(old).unwrap();
        assert!(!pk.favorite);
        assert_eq!(pk.deleted_at, None);
        assert_eq!(pk.sign_count, 3);
        // And a full round-trip preserves the new flags.
        let mut full = pk;
        full.favorite = true;
        full.deleted_at = Some(1000);
        let back: PasskeyItem =
            serde_json::from_value(serde_json::to_value(&full).unwrap()).unwrap();
        assert!(back.favorite);
        assert_eq!(back.deleted_at, Some(1000));
    }

    #[test]
    fn custom_field_type_roundtrip() {
        assert_eq!(CustomFieldType::from_i32(1), CustomFieldType::Hidden);
        assert_eq!(CustomFieldType::from_i32(2), CustomFieldType::Checkbox);
        assert_eq!(CustomFieldType::from_i32(3), CustomFieldType::Linked);
        assert_eq!(CustomFieldType::from_i32(9), CustomFieldType::Text);
        assert_eq!(CustomFieldType::Hidden.to_i32(), 1);
        assert_eq!(CustomFieldType::Linked.to_i32(), 3);
    }
}
