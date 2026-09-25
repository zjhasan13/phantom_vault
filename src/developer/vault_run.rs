//! Phase 16 (Option 2b) — `vault run` CLI secret injector.
//!
//! Usage: `phantom_vault run -e GitHub=GH_TOKEN -e GitHub.user=GH_USER -- npm start`
//! Secrets travel vault → child-process env only. No `.env` files, no shell
//! history (values never echoed), no disk writes. Values are zeroized in our
//! own memory right after spawn; the child owns its copy from there on.

use crate::models::Vault;
use crate::storage::load_vault_versioned;
use zeroize::Zeroize;

pub const VAULT_FILE: &str = "my_secure_vault.enc";

/// One `-e TITLE=VAR` / `-e TITLE.user=VAR` mapping.
#[derive(Debug, PartialEq)]
pub struct EnvMap {
    pub title: String,
    pub field_user: bool,
    pub var: String,
}

/// Parse CLI args after `run`. Returns (mappings, command+args).
/// Pure — unit tested. Expects the `--` separator before the command.
pub fn parse_run_args(args: &[String]) -> Result<(Vec<EnvMap>, Vec<String>), String> {
    let mut maps = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-e" | "--env" => {
                i += 1;
                let spec = args
                    .get(i)
                    .ok_or_else(|| "missing value after -e/--env".to_string())?;
                maps.push(parse_env_spec(spec)?);
            }
            "--" => {
                let cmd: Vec<String> = args[i + 1..].to_vec();
                if cmd.is_empty() {
                    return Err("missing command after --".to_string());
                }
                if maps.is_empty() {
                    return Err("no -e/--env mappings given".to_string());
                }
                return Ok((maps, cmd));
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
        i += 1;
    }
    Err("missing -- <command>".to_string())
}

fn parse_env_spec(spec: &str) -> Result<EnvMap, String> {
    let (left, var) = spec
        .split_once('=')
        .ok_or_else(|| format!("bad -e spec (want TITLE=VAR): {spec}"))?;
    if left.is_empty() || var.is_empty() {
        return Err(format!("bad -e spec (want TITLE=VAR): {spec}"));
    }
    let (title, field_user) = match left.strip_suffix(".user") {
        Some(t) if !t.is_empty() => (t.to_string(), true),
        _ => (left.to_string(), false),
    };
    if !var
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
        || var.starts_with(|c: char| c.is_ascii_digit())
    {
        return Err(format!("bad env var name: {var}"));
    }
    Ok(EnvMap { title, field_user, var: var.to_string() })
}

/// Resolve mappings against an unlocked vault → (VAR, value) pairs.
pub fn resolve_env(maps: &[EnvMap], vault: &Vault) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for m in maps {
        let cred = vault
            .credentials
            .iter()
            .find(|c| c.title == m.title)
            .ok_or_else(|| format!("no credential titled '{}'", m.title))?;
        let value = if m.field_user {
            cred.username.clone()
        } else {
            cred.password.clone()
        };
        out.push((m.var.clone(), value));
    }
    Ok(out)
}

/// Headless entrypoint. Returns process exit code. Never panics on bad input.
pub fn run_cli(args: &[String]) -> i32 {
    let (maps, cmd) = match parse_run_args(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vault run: {e}");
            eprintln!("usage: vault run -e TITLE=VAR [-e TITLE.user=VAR2 ...] -- <cmd> [args...]");
            return 2;
        }
    };
    eprint!("Master password: ");
    let mut password = match rpassword::read_password() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vault run: cannot read password: {e}");
            return 2;
        }
    };
    if password.trim().is_empty() {
        password.zeroize();
        eprintln!("vault run: empty password");
        return 2;
    }
    let (vault, _) = match load_vault_versioned(password.trim(), VAULT_FILE) {
        Ok(v) => v,
        Err(e) => {
            password.zeroize();
            eprintln!("vault run: unlock failed: {e}");
            return 1;
        }
    };
    password.zeroize();
    let pairs = match resolve_env(&maps, &vault) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vault run: {e}");
            return 2;
        }
    };
    let mut child_cmd = std::process::Command::new(&cmd[0]);
    child_cmd.args(&cmd[1..]);
    for (k, v) in &pairs {
        child_cmd.env(k, v);
    }
    // Zeroize our copies the moment the child owns them.
    let mut pairs = pairs;
    for (_, v) in pairs.iter_mut() {
        v.zeroize();
    }
    drop(pairs);
    match child_cmd.status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => {
            eprintln!("vault run: spawn failed: {e}");
            1
        }
    }
}

/// `vault scan [path]` — pre-commit style leak check. Exit 1 on findings.
pub fn scan_cli(args: &[String]) -> i32 {
    use super::secret_scanner::scan_dir;
    let root = args.first().map(|s| s.as_str()).unwrap_or(".");
    let findings = scan_dir(std::path::Path::new(root));
    if findings.is_empty() {
        println!("scan: clean — no secrets detected under {root}");
        0
    } else {
        println!("scan: {} finding(s) — secrets never printed:", findings.len());
        for f in &findings {
            println!("  {}:{} [{}]", f.file, f.line, f.rule);
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parses_maps_and_command() {
        let (maps, cmd) =
            parse_run_args(&s(&["-e", "GitHub=GH_TOKEN", "-e", "GitHub.user=GH_USER", "--", "npm", "start"]))
                .unwrap();
        assert_eq!(maps.len(), 2);
        assert_eq!(maps[0].var, "GH_TOKEN");
        assert!(!maps[0].field_user);
        assert!(maps[1].field_user);
        assert_eq!(cmd, s(&["npm", "start"]));
    }

    #[test]
    fn rejects_missing_separator() {
        assert!(parse_run_args(&s(&["-e", "A=B", "npm"])).is_err());
    }

    #[test]
    fn rejects_empty_maps() {
        assert!(parse_run_args(&s(&["--", "npm"])).is_err());
    }

    #[test]
    fn rejects_bad_var_name() {
        assert!(parse_env_spec("T=9BAD").is_err());
        assert!(parse_env_spec("NOEQUALS").is_err());
    }

    #[test]
    fn resolves_against_vault() {
        use crate::models::Credential;
        let mut vault = Vault::new();
        vault.credentials.push(Credential {
            id: "1".into(),
            title: "GitHub".into(),
            username: "octo".into(),
            password: "ghp_x".into(),
            totp_secret: String::new(),
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
        let maps = vec![
            EnvMap { title: "GitHub".into(), field_user: false, var: "GH_TOKEN".into() },
            EnvMap { title: "GitHub".into(), field_user: true, var: "GH_USER".into() },
        ];
        let pairs = resolve_env(&maps, &vault).unwrap();
        assert_eq!(pairs[0], ("GH_TOKEN".to_string(), "ghp_x".to_string()));
        assert_eq!(pairs[1], ("GH_USER".to_string(), "octo".to_string()));
    }

    #[test]
    fn missing_title_errors() {
        let vault = Vault::new();
        let maps = vec![EnvMap { title: "Nope".into(), field_user: false, var: "X".into() }];
        assert!(resolve_env(&maps, &vault).is_err());
    }
}
