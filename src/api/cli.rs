//! A23: `phantom_vault pv status | pv get ...` client.
//!
//! Talks only to the app's loopback API. The app must be running, unlocked and
//! have the local API enabled; the token/port files live next to the vault
//! (or `PV_API_DIR`).

use crate::api::local::{client_dir, client_get};
use std::time::Duration;

const GET_TIMEOUT: Duration = Duration::from_secs(45);
const STATUS_TIMEOUT: Duration = Duration::from_secs(5);

pub fn pv_cli(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("status") => status(),
        Some("get") => get(&args[1..]),
        _ => {
            eprintln!("usage:");
            eprintln!("  phantom_vault pv status");
            eprintln!("  phantom_vault pv get <title> [--field password|username] [--json]");
            eprintln!("  phantom_vault pv get --id <id> [--field ...] [--json]");
            2
        }
    }
}

fn status() -> i32 {
    let Some(dir) = client_dir() else {
        eprintln!("local API is off — enable it in Settings → Local API");
        return 1;
    };
    match client_get(&dir, "/v1/status", STATUS_TIMEOUT) {
        Ok((200, body)) => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                let locked = v.get("locked").and_then(|b| b.as_bool()).unwrap_or(true);
                let version = v.get("version").and_then(|s| s.as_str()).unwrap_or("?");
                println!(
                    "{} (v{version})",
                    if locked { "locked" } else { "unlocked" }
                );
                0
            } else {
                eprintln!("unexpected API reply: {body}");
                1
            }
        }
        Ok((code, body)) => {
            eprintln!("local API error {code}: {body}");
            1
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

struct GetArgs {
    selector: String,
    field: String,
    json: bool,
}

fn parse_get(args: &[String]) -> Result<GetArgs, String> {
    let mut selector = None;
    let mut field = "password".to_string();
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--field" => {
                let f = args.get(i + 1).ok_or("--field needs a value")?;
                if f != "password" && f != "username" {
                    return Err("--field must be password or username".to_string());
                }
                field = f.clone();
                i += 2;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            "--id" => {
                let id = args.get(i + 1).ok_or("--id needs a value")?;
                selector = Some(format!(
                    "id={}",
                    percent_encoding::utf8_percent_encode(id, percent_encoding::NON_ALPHANUMERIC)
                ));
                i += 2;
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown option {other}"));
            }
            title => {
                if selector.is_some() {
                    return Err("give either a title or --id, not both".to_string());
                }
                selector = Some(format!(
                    "title={}",
                    percent_encoding::utf8_percent_encode(title, percent_encoding::NON_ALPHANUMERIC)
                ));
                i += 1;
            }
        }
    }
    let selector = selector.ok_or("missing login title (or --id)")?;
    Ok(GetArgs {
        selector,
        field,
        json,
    })
}

fn get(args: &[String]) -> i32 {
    let parsed = match parse_get(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("pv get: {e}");
            return 2;
        }
    };
    let Some(dir) = client_dir() else {
        eprintln!("local API is off — enable it in Settings → Local API");
        return 1;
    };
    let path = format!("/v1/get?{}&field={}", parsed.selector, parsed.field);
    let request_id = match client_get(&dir, &path, GET_TIMEOUT) {
        Ok((202, body)) => {
            let v: serde_json::Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(_) => {
                    eprintln!("unexpected API reply: {body}");
                    return 1;
                }
            };
            let Some(id) = v.get("request_id").and_then(|x| x.as_str()) else {
                eprintln!("unexpected API reply: {body}");
                return 1;
            };
            id.to_string()
        }        Ok((403, _)) => {
            eprintln!("⛔ request refused in the app");
            return 1;
        }
        Ok((423, _)) => {
            eprintln!("⛔ vault is locked — unlock the app and retry");
            return 1;
        }
        Ok((404, _)) => {
            eprintln!("no matching login");
            return 1;
        }
        Ok((409, _)) => {
            eprintln!("ambiguous title — use --id");
            return 1;
        }
        Ok((429, _)) => {
            eprintln!("rate limit reached (30/minute)");
            return 1;
        }
        Ok((code, body)) => {
            eprintln!("local API error {code}: {body}");
            return 1;
        }
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    // Poll until the user answers in the app (server-side TTL is 60s).
    let started = std::time::Instant::now();
    loop {
        if started.elapsed() >= Duration::from_secs(50) {
            eprintln!("timed out waiting for approval");
            return 1;
        }
        let result_path = format!("/v1/result?id={request_id}");
        match client_get(&dir, &result_path, Duration::from_secs(5)) {
            Ok((202, _)) => {
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
            Ok((200, body)) => {
                if parsed.json {
                    println!("{body}");
                    return 0;
                }
                match serde_json::from_str::<serde_json::Value>(&body) {
                    Ok(v) => {
                        if let Some(value) = v.get("value").and_then(|x| x.as_str()) {
                            println!("{value}");
                            return 0;
                        } else {
                            eprintln!("unexpected API reply: {body}");
                            return 1;
                        }
                    }
                    Err(_) => {
                        eprintln!("unexpected API reply: {body}");
                        return 1;
                    }
                }
            }
            Ok((403, _)) => {
                eprintln!("⛔ denied in the app");
                return 1;
            }
            Ok((408, _)) => {
                eprintln!("approval timed out");
                return 1;
            }
            Ok((404, _)) => {
                eprintln!("request expired — retry");
                return 1;
            }
            Ok((code, body)) => {
                eprintln!("local API error {code}: {body}");
                return 1;
            }
            Err(e) => {
                eprintln!("{e}");
                return 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_args_parse_title_id_field_and_json() {
        let p = parse_get(&["Gmail".into()]).unwrap();
        assert!(p.selector.starts_with("title=Gmail"));
        assert_eq!(p.field, "password");
        assert!(!p.json);
        let p = parse_get(&["--id".into(), "abc".into(), "--field".into(), "username".into(), "--json".into()]).unwrap();
        assert_eq!(p.selector, "id=abc");
        assert_eq!(p.field, "username");
        assert!(p.json);
        assert!(parse_get(&[]).is_err());
        assert!(parse_get(&["--field".into(), "totp".into(), "x".into()]).is_err());
        assert!(parse_get(&["a".into(), "b".into()]).is_err());
        assert!(parse_get(&["--nope".into()]).is_err());
    }
}
