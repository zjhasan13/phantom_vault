//! A20 slice 2: `phantom_vault share ...` CLI (create / serve / open / list /
//! revoke). Headless, vault-password prompted, no UI dependency.

use crate::share::{self, ShareItem};
use crate::share_store;
use secrecy::{ExposeSecret, SecretString};
use std::io::{Read, Write};
use std::time::Duration;
use zeroize::Zeroize;

const VAULT_FILE: &str = crate::developer::vault_run::VAULT_FILE;

pub fn share_cli(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("create") => create(&args[1..]),
        Some("serve") => serve(&args[1..]),
        Some("open") => open(&args[1..]),
        Some("list") => list(),
        Some("revoke") => revoke(&args[1..]),
        _ => {
            eprintln!("usage:");
            eprintln!("  phantom_vault share create <title> [--ttl 24h] [--views 1] [--serve] [--relay gist] [--passphrase]");
            eprintln!("  phantom_vault share open <pvshare://...> [--file bundle.pvsh] [--json] [--import]");
            eprintln!("  phantom_vault share serve [--port N]");
            eprintln!("  phantom_vault share list");
            eprintln!("  phantom_vault share revoke <id>");
            2
        }
    }
}

fn prompt_password(what: &str) -> Option<SecretString> {
    eprint!("{what}: ");
    let mut pw = rpassword::read_password().ok()?;
    if pw.trim().is_empty() {
        pw.zeroize();
        return None;
    }
    let out = SecretString::new(pw.trim().to_string());
    pw.zeroize();
    Some(out)
}

fn load_vault(what: &str) -> Option<crate::models::Vault> {
    let pw = prompt_password(what)?;
    match crate::storage::load_vault_versioned_secret(&pw, VAULT_FILE) {
        Ok((v, _)) => Some(v),
        Err(e) => {
            eprintln!("share: unlock failed: {e}");
            None
        }
    }
}

pub(crate) fn parse_ttl(text: &str) -> Option<u64> {    let t = text.trim().to_ascii_lowercase();
    let (num, unit) = match t.chars().last()? {
        's' => (&t[..t.len() - 1], 1u64),
        'm' => (&t[..t.len() - 1], 60),
        'h' => (&t[..t.len() - 1], 3600),
        'd' => (&t[..t.len() - 1], 86_400),
        _ => (t.as_str(), 1),
    };
    let n: u64 = num.parse().ok()?;
    n.checked_mul(unit).filter(|s| *s > 0)
}

fn create(args: &[String]) -> i32 {
    let mut title = None;
    let mut ttl = "24h".to_string();
    let mut views: u32 = 1;
    let mut serve_after = false;
    let mut json = false;
    let mut with_pass = false;
    let mut relay_gist = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--ttl" => {
                ttl = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--views" => {
                views = args.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(1);
                i += 2;
            }
            "--serve" => {
                serve_after = true;
                i += 1;
            }
            "--relay" => {
                match args.get(i + 1).map(String::as_str) {
                    Some("gist") => relay_gist = true,
                    Some(other) => {
                        eprintln!("share create: unknown relay {other:?} (expected gist)");
                        return 2;
                    }
                    None => {
                        eprintln!("share create: --relay needs a value (gist)");
                        return 2;
                    }
                }
                i += 2;
            }
            "--passphrase" => {
                with_pass = true;
                i += 1;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            opt if opt.starts_with("--") => {
                eprintln!("share create: unknown option {opt}");
                return 2;
            }
            t => {
                title = Some(t.to_string());
                i += 1;
            }
        }
    }
    let Some(title) = title else {
        eprintln!("share create: missing title");
        return 2;
    };
    let Some(ttl_secs) = parse_ttl(&ttl) else {
        eprintln!("share create: bad --ttl (use e.g. 30m, 24h, 7d)");
        return 2;
    };
    if relay_gist && serve_after {
        eprintln!("share create: --relay gist and --serve are different transports; pick one");
        return 2;
    }
    if relay_gist && views > 0 {
        println!(
            "share create: one-view is LAN-only; the gist relay cannot enforce it — using unlimited views."
        );
        views = 0;
    }
    let Some(vault) = load_vault("Master password") else {
        return 1;
    };
    let matches: Vec<_> = vault
        .credentials
        .iter()
        .filter(|c| c.deleted_at.is_none() && c.title.eq_ignore_ascii_case(&title))
        .collect();
    if matches.is_empty() {
        eprintln!("share create: no login titled {title:?}");
        return 1;
    }
    if matches.len() > 1 {
        eprintln!("share create: title is ambiguous; rename one first");
        return 1;
    }
    let c = matches[0];
    let item = ShareItem::from_credential(c);
    let pass = if with_pass {
        let Some(p1) = prompt_password("Share passphrase") else {
            eprintln!("share create: empty passphrase");
            return 2;
        };
        let Some(p2) = prompt_password("Confirm share passphrase") else {
            eprintln!("share create: empty confirmation");
            return 2;
        };
        if p1.expose_secret() != p2.expose_secret() {
            eprintln!("share create: passphrases do not match");
            return 2;
        }
        Some(p1)
    } else {
        None
    };
    let created = match share::create_with_passphrase(vec![item], ttl_secs, views, pass.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("share create: {e}");
            return 1;
        }
    };
    let published = if relay_gist {
        match crate::share_relay::publish_sync(&created.bundle) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("share create: {e}");
                return 1;
            }
        }
    } else {
        None
    };
    let gist_id = published.as_ref().map(|p| p.gist_id.clone());
    if let Err(e) = share_store::save(&created) {
        if let Some(gist) = gist_id.as_deref() {
            let _ = crate::share_relay::delete_sync(gist);
        }
        eprintln!("share create: {e}");
        return 1;
    }
    if let Some(gist) = gist_id.as_deref() {
        if let Err(e) = share_store::set_relay_gist(&created.id, gist) {
            let _ = crate::share_relay::delete_sync(gist);
            let _ = share_store::revoke(&created.id);
            eprintln!("share create: {e}");
            return 1;
        }
    }
    let link = match published.as_ref() {
        Some(p) => created.link_via_gist(&p.owner, &p.gist_id),
        None => created.link(),
    };
    let expires = created.expires_at;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "id": created.id,
                "link": link,
                "bundle": share_store::get(&created.id).map(|r| r.bundle_path.to_string_lossy().into_owned()).unwrap_or_default(),
                "expires_at": expires,
                "max_views": created.max_views,
                "passphrase": created.passphrase,
                "relay": gist_id.is_some(),
                "gist": gist_id,
                "gist_owner": published.as_ref().map(|p| p.owner.clone()),
            })
        );
    } else {
        println!("share id: {}", created.id);
        println!(
            "{} link: {link}",
            if gist_id.is_some() {
                "gist"
            } else {
                "file"
            }
        );
        if gist_id.is_none() {
            println!(
                "bundle: {}",
                share_store::get(&created.id)
                    .map(|r| r.bundle_path.to_string_lossy().into_owned())
                    .unwrap_or_default()
            );
        }
        println!(
            "expires in {}h; max views: {}; passphrase: {}",
            (expires.saturating_sub(share::now_secs())) / 3600,
            if created.max_views == 0 { "unlimited".to_string() } else { created.max_views.to_string() },
            if created.passphrase { "required" } else { "none" }
        );
        if created.passphrase {
            println!(
                "🔒 the link has no key — send it and the passphrase over different channels."
            );
        } else {
            println!("⚠️ the link fragment IS the key — send it over a channel you trust.");
        }
        if gist_id.is_some() {
            println!(
                "☁️ GitHub sees only ciphertext; it does not expire the gist — revoke when done. Not one-time."
            );
        }
    }
    if serve_after {
        let ip = crate::share_serve::local_ipv4().unwrap_or_else(|| "127.0.0.1".to_string());
        let server = match crate::share_serve::serve("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                eprintln!("share create: {e}");
                return 1;
            }
        };
        let host = format!("{ip}:{}", server.port);
        println!("LAN link: {}", created.link_via(&host));
        println!("serving until Ctrl+C (one-view/TTL enforced)…");
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
        #[allow(unreachable_code)]
        {
            server.stop();
        }
    }
    0
}

fn serve(args: &[String]) -> i32 {
    let mut port = 0u16;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                port = args.get(i + 1).and_then(|p| p.parse().ok()).unwrap_or(0);
                i += 2;
            }
            opt => {
                eprintln!("share serve: unknown option {opt}");
                return 2;
            }
        }
    }
    share_store::purge_expired();
    let active = share_store::list();
    if active.is_empty() {
        eprintln!("share serve: no active shares");
        return 1;
    }
    let ip = crate::share_serve::local_ipv4().unwrap_or_else(|| "127.0.0.1".to_string());
    let server = match crate::share_serve::serve(&format!("0.0.0.0:{port}")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("share serve: {e}");
            return 1;
        }
    };
    let host = format!("{ip}:{}", server.port);
    println!(
        "serving {} active share(s) on {host}; use the host link printed at create time (prefix pvshare://{host}/).",
        active.len()
    );
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
    #[allow(unreachable_code)]
    {
        server.stop();
        0
    }
}

pub(crate) fn fetch_bundle(url: &str) -> Result<Vec<u8>, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "share host must be http://host:port".to_string())?;
    let (host, path) = rest
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((rest, "/".to_string()));
    let addr = host
        .to_socket_addrs_first()
        .ok_or_else(|| format!("bad share host {host}"))?;
    let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(8))
        .map_err(|e| format!("share host unreachable: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|e| format!("share fetch write: {e}"))?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e)
                if !raw.is_empty()
                    && matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                    ) =>
            {
                break;
            }
            Err(e) => return Err(format!("share fetch read: {e}")),
        }
    }
    let text = raw.as_slice();
    let pos = text
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed share response".to_string())?;
    let head = String::from_utf8_lossy(&text[..pos]);
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if status != 200 {
        return Err(format!("share fetch refused (HTTP {status})"));
    }
    Ok(text[pos + 4..].to_vec())
}

trait ToSocketAddrFirst {
    fn to_socket_addrs_first(&self) -> Option<std::net::SocketAddr>;
}
impl ToSocketAddrFirst for str {
    fn to_socket_addrs_first(&self) -> Option<std::net::SocketAddr> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs().ok()?.next()
    }
}

fn open(args: &[String]) -> i32 {
    let mut link = None;
    let mut file = None;
    let mut json = false;
    let mut import = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--file" => {
                file = args.get(i + 1).cloned();
                i += 2;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            "--import" => {
                import = true;
                i += 1;
            }
            opt if opt.starts_with("--") => {
                eprintln!("share open: unknown option {opt}");
                return 2;
            }
            l => {
                link = Some(l.to_string());
                i += 1;
            }
        }
    }
    let Some(link) = link else {
        eprintln!("share open: missing pvshare:// link");
        return 2;
    };
    let Some(parsed) = share::parse_link(&link) else {
        eprintln!("share open: bad link (expected pvshare://…)");
        return 2;
    };
    let bundle = match file {
        Some(path) => match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("share open: read {path}: {e}");
                return 1;
            }
        },
        None => {
            if parsed.is_gist() {
                match crate::share_relay::fetch_sync(parsed.gist_owner.as_deref(), &parsed.id) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("share open: {e}");
                        return 1;
                    }
                }
            } else if let Some(host) = parsed.host.as_deref() {
                match fetch_bundle(&format!("http://{host}/{}", parsed.id)) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("share open: {e}");
                        return 1;
                    }
                }
            } else {
                eprintln!("share open: this is a file link — pass --file <bundle.pvsh>");
                return 2;
            }
        }
    };
    let pass = if parsed.needs_passphrase {
        match prompt_password("Share passphrase") {
            Some(p) => Some(p),
            None => {
                eprintln!("share open: this share requires a passphrase");
                return 2;
            }
        }
    } else {
        None
    };
    let payload = match share::open(
        &bundle,
        parsed.key.as_deref(),
        pass.as_ref().map(|p| p.expose_secret().as_str()),
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("share open: {e}");
            return 1;
        }
    };
    if json {
        println!("{}", serde_json::to_string(&payload).unwrap_or_default());
    } else {
        println!(
            "share {} — opened (max views {})",
            parsed.id,
            if payload.max_views == 0 { "unlimited".to_string() } else { payload.max_views.to_string() }
        );
        for item in &payload.items {
            println!("title: {}", item.title);
            println!("username: {}", item.username);
            println!("password: {}", item.password);
            if !item.url.is_empty() {
                println!("url: {}", item.url);
            }
            if !item.notes.is_empty() {
                println!("notes: {}", item.notes);
            }
            if !item.totp.is_empty() {
                println!("totp secret: {}", item.totp);
            }
            for (k, v) in &item.custom_fields {
                println!("{k}: {v}");
            }
        }
    }
    if import {
        let Some(mut vault) = load_vault("Master password (import into this vault)") else {
            return 1;
        };
        let added = share::add_items_to_vault(&mut vault, &payload.items);
        let pw = prompt_password("Master password (confirm save)");
        let Some(pw) = pw else {
            return 1;
        };
        match crate::storage::save_vault_secret(&vault, &pw, VAULT_FILE) {
            Ok(()) => println!("imported {added} login(s)"),
            Err(e) => {
                eprintln!("share open: save failed: {e}");
                return 1;
            }
        }
    }
    0
}

fn list() -> i32 {
    share_store::purge_expired();
    let items = share_store::list();
    if items.is_empty() {
        println!("no active shares");
        return 0;
    }
    for r in items {
        let expired = if r.expires_at <= share::now_secs() {
            "  EXPIRED — revoke to delete any remote gist"
        } else {
            ""
        };
        println!(
            "{}  expires in {}s  views {}/{}{}{}",
            r.id,
            r.expires_at.saturating_sub(share::now_secs()),
            r.views,
            if r.max_views == 0 { "∞".to_string() } else { r.max_views.to_string() },
            if r.relay_gist.is_some() {
                "  relay:gist"
            } else {
                ""
            },
            expired
        );
    }
    0
}

fn revoke(args: &[String]) -> i32 {
    let Some(id) = args.first() else {
        eprintln!("share revoke: missing id");
        return 2;
    };
    if let Some(gist) = share_store::get(id).and_then(|r| r.relay_gist) {
        match crate::share_relay::delete_sync(&gist) {
            Ok(()) => println!("deleted relay gist {gist}"),
            Err(e) => eprintln!(
                "warning: relay gist {gist} was not deleted: {e} — delete it on GitHub manually"
            ),
        }
    }
    match share_store::revoke(id) {
        Ok(()) => {
            println!("revoked {id}");
            0
        }
        Err(e) => {
            eprintln!("share revoke: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_ttl;

    #[test]
    fn ttl_units_and_bare_seconds() {
        assert_eq!(parse_ttl("24h"), Some(86_400));
        assert_eq!(parse_ttl("30m"), Some(1_800));
        assert_eq!(parse_ttl("45s"), Some(45));
        assert_eq!(parse_ttl("2d"), Some(172_800));
        assert_eq!(parse_ttl("3600"), Some(3_600));
    }

    #[test]
    fn ttl_is_trimmed_and_case_insensitive() {
        assert_eq!(parse_ttl("  24H "), Some(86_400));
        assert_eq!(parse_ttl("1D"), Some(86_400));
    }

    #[test]
    fn ttl_rejects_zero_junk_and_overflow() {
        assert_eq!(parse_ttl("0"), None, "a zero-second share is not a share");
        assert_eq!(parse_ttl("0h"), None);
        assert_eq!(parse_ttl(""), None);
        assert_eq!(parse_ttl("abc"), None);
        assert_eq!(parse_ttl("10x"), None);
        assert_eq!(parse_ttl("18446744073709551615h"), None, "checked_mul");
        assert_eq!(parse_ttl("99999999999999999999h"), None, "parse overflow");
    }
}