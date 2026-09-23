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
}

/// 2FA অথেনটিকেটর অ্যাকাউন্ট (Google/Proton TOTP)
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TotpAccount {
    pub id: String,
    pub account_name: String,
    pub issuer: String,
    pub secret: String, // Base32 Secret Key
    pub digits: u32,    // 6 or 8 digits
    pub period: u64,    // Default 30s
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
}

/// সিকিউর নোটস
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecureNote {
    pub id: String,
    pub title: String,
    pub content: String,
    #[serde(default)]
    pub folder: String,
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
}

/// সম্পূর্ণ মূল ভল্ট কন্টেইনার
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
        }
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
    /// 4 card, 5 identity, 6 ssh. Returns true if something was removed.
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
            _ => false,
        }
    }
}

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
                })
                .collect(),
            cards: Vec::new(),
            identities: Vec::new(),
            ssh_keys: Vec::new(),
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
                })
                .collect(),
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
        });
        v.ensure_folders();
        assert!(v.folders.contains(&"SecretLab".to_string()));
        assert!(v.folders.contains(&"General".to_string()));
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
