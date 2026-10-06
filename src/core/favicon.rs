//! Privacy-preserving website favicon engine.
//!
//! Source: `https://icons.duckduckgo.com/ip3/{domain}.ico` (no tracking,
//! no cookies — a bare GET for a public icon). Permanent local disk cache
//! under `%LOCALAPPDATA%\PhantomVault\favicons\{domain}.png`: disk is
//! ALWAYS checked first, so repeat views never touch the network.
//!
//! Hard privacy gates (checked by the caller before any fetch):
//! - user toggle `favicons.pref` (default ON),
//! - global offline kill-switch (`net_allowed`),
//! - per-call network closure (tests inject `|| false` — hermetic).
//!
//! Failures (offline, 404, non-image, oversize) fall back to the built-in
//! letter-circle icon and are remembered per session (no refetch storms).

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;

const PREF_FILE: &str = "favicons.pref";
const DDG_ICON: &str = "https://icons.duckduckgo.com/ip3/";
const GOOGLE_S2: &str = "https://www.google.com/s2/favicons?domain=";
const MAX_ICON_BYTES: u64 = 256 * 1024;
const MAX_DOMAINS_PER_PASS: usize = 200;
/// Extension-harvested icons: strict 64 KB cap (disk-bloat/DoS guard).
pub const HARVEST_MAX_BYTES: usize = 64 * 1024;
/// Harvested icons must be favicon-scale; absurd dimensions rejected.
const HARVEST_MAX_DIM: u32 = 512;

/// Strict harvest-domain sanitizer (bridge `cache_favicon` choke-point).
/// Allows `[a-z0-9.-]` only, max 120 chars; rejects `..`, separators,
/// control chars, and leading/trailing dots/hyphens. The sanitized name is
/// joined as `{domain}.png` — separators can never reach the path, so
/// traversal is structurally impossible (plus a starts_with containment
/// assert at the write site).
pub fn sanitize_harvest_domain(raw: &str) -> Result<String, String> {
    let d = raw.trim().to_lowercase();
    if d.is_empty() || d.len() > 120 {
        return Err("bad domain (empty/too long)".to_string());
    }
    if d.contains("..") || d.contains('/') || d.contains('\\') {
        return Err("bad domain (path characters)".to_string());
    }
    if !d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return Err("bad domain (charset)".to_string());
    }
    if d.starts_with(['.', '-']) || d.ends_with(['.', '-']) {
        return Err("bad domain (edge punctuation)".to_string());
    }
    if !d.contains('.') {
        return Err("bad domain (no dot)".to_string());
    }
    Ok(d)
}

/// Store an extension-harvested icon: sanitize → 64KB cap → decode-validate
/// → dimension cap → normalize to clean PNG → cache dir. Returns the
/// normalized domain. Errors are fail-closed strings (no panics).
pub fn save_harvested_icon(domain: &str, bytes: &[u8]) -> Result<String, String> {
    let d = sanitize_harvest_domain(domain)?;
    if bytes.is_empty() {
        return Err("empty icon".to_string());
    }
    if bytes.len() > HARVEST_MAX_BYTES {
        return Err("icon too large (64KB cap)".to_string());
    }
    let img = image::load_from_memory(bytes).map_err(|_| "not a decodable image".to_string())?;
    if img.width() > HARVEST_MAX_DIM || img.height() > HARVEST_MAX_DIM {
        return Err("icon dimensions too large".to_string());
    }
    let mut png = Vec::new();
    img.write_to(
        &mut std::io::Cursor::new(&mut png),
        image::ImageFormat::Png,
    )
    .map_err(|e| format!("png encode: {e}"))?;
    let dir = cache_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("cache dir: {e}"))?;
    let path = dir.join(format!("{d}.png"));
    debug_assert!(path.starts_with(&dir));
    std::fs::write(&path, &png).map_err(|e| format!("write: {e}"))?;
    Ok(d)
}

/// Persisted user choice (`favicons.pref` = "1"/"0"). Missing file = ON.
pub fn show_favicons() -> bool {
    std::fs::read_to_string(PREF_FILE)
        .map(|s| s.trim() != "0")
        .unwrap_or(true)
}

/// Best-effort persist of the toggle (never blocks the UI thread caller).
pub fn set_show_favicons(on: bool) {
    let _ = std::fs::write(PREF_FILE, if on { "1" } else { "0" });
}

/// Disk cache root: `%LOCALAPPDATA%\PhantomVault\favicons`, falling back to
/// a local `favicons` dir when the env var is absent (portable mode).
pub fn cache_dir() -> PathBuf {
    match std::env::var("LOCALAPPDATA") {
        Ok(base) if !base.trim().is_empty() => {
            PathBuf::from(base).join("PhantomVault").join("favicons")
        }
        _ => PathBuf::from("favicons"),
    }
}

fn file_name_for(domain: &str) -> String {
    format!(
        "{}.png",
        domain
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
            .collect::<String>()
    )
}

fn icon_path(domain: &str) -> PathBuf {
    cache_dir().join(file_name_for(domain))
}

/// User overrides live here (`favicons/custom/`), checked BEFORE the
/// fetched cache. Same validation as fetched icons.
pub fn custom_dir() -> PathBuf {
    cache_dir().join("custom")
}

fn custom_path(domain: &str) -> PathBuf {
    custom_dir().join(file_name_for(domain))
}

fn valid_icon_bytes(b: &[u8]) -> bool {
    !b.is_empty() && (b.len() as u64) <= MAX_ICON_BYTES && image::load_from_memory(b).is_ok()
}

pub fn custom_icon_bytes(domain: &str) -> Option<Vec<u8>> {
    std::fs::read(custom_path(domain)).ok().filter(|b| valid_icon_bytes(b))
}

/// Store a user-picked logo file for a domain (PNG/ICO/JPG — validated
/// before a byte hits disk). Returns the normalized domain.
pub fn save_custom_icon(domain: &str, bytes: &[u8]) -> Result<String, String> {
    if !valid_icon_bytes(bytes) {
        return Err("file is not a decodable image (too big?)".to_string());
    }
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() || !domain.contains('.') {
        return Err("bad domain".to_string());
    }
    std::fs::create_dir_all(custom_dir()).map_err(|e| format!("cache dir: {e}"))?;
    std::fs::write(custom_path(&domain), bytes).map_err(|e| format!("write: {e}"))?;
    Ok(domain)
}

pub fn custom_count() -> usize {
    std::fs::read_dir(custom_dir())
        .map(|rd| rd.flatten().filter(|e| e.path().is_file()).count())
        .unwrap_or(0)
}

/// Delete all user overrides (fetched cache untouched). Returns files removed.
pub fn clear_custom_icons() -> usize {
    let n = custom_count();
    let _ = std::fs::remove_dir_all(custom_dir());
    n
}

/// Extract a fetchable registrable-ish host from a stored URL. Returns None
/// for empty strings, bare IPs, localhost, `.local`/`.invalid` names, and
/// unparseable input (no request is ever made for those).
pub fn domain_of_url(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    let with_scheme = if t.contains("://") { t.to_string() } else { format!("https://{t}") };
    let url = url::Url::parse(&with_scheme).ok()?;
    let mut host = url.host_str()?.trim_end_matches('.').to_lowercase();
    if host.is_empty() || host == "localhost" || host.ends_with(".local") || host.ends_with(".invalid") {
        return None;
    }
    // Skip IPv4/IPv6 literals (routers, printers — DDG has no icons for them).
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    if !host.contains('.') {
        return None;
    }
    if let Some(stripped) = host.strip_prefix("www.") {
        if stripped.contains('.') {
            host = stripped.to_string();
        }
    }
    Some(host)
}

/// Best display domain for an item: stored URL wins; otherwise the title
/// itself when it IS a domain (`2captcha.com`, `account.proton.me` —
/// Bitwarden imports often carry the host as the title with an empty URL).
/// Android/iOS package titles (`com.instagram.android`) unfold to their
/// domain; bare famous names (`Instagram`) map via [`famous_domain`].
/// Human titles (`GitHub Personal Token`, `--`) and IPs yield None.
pub fn icon_domain(title: &str, url: &str) -> Option<String> {
    domain_of_url(url)
        .or_else(|| package_domain(title))
        .or_else(|| domain_of_url(title))
        .or_else(|| famous_domain(title).map(str::to_string))
}

/// Reverse-DNS app-package titles → domain (`com.instagram.android` →
/// `instagram.com`). Requires 3+ labels, a known first label, and an
/// `android`/`ios` tail — plain words never match.
pub fn package_domain(title: &str) -> Option<String> {
    let labels: Vec<&str> = title
        .trim()
        .split('.')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    if labels.len() < 3 {
        return None;
    }
    let first = labels[0].to_lowercase();
    let last = labels[labels.len() - 1].to_lowercase();
    if !["com", "net", "org", "io"].contains(&first.as_str()) {
        return None;
    }
    if last != "android" && last != "ios" {
        return None;
    }
    let mid = labels[1].to_lowercase();
    if mid.is_empty() || mid.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    Some(format!("{mid}.{first}"))
}

/// Bare famous names → domain (`Instagram` → `instagram.com`). Used when
/// neither the URL nor the title parses as a host (mobile-import titles,
/// 2FA issuers). Human sentences with spaces never match.
pub fn famous_domain(name: &str) -> Option<&'static str> {
    let t = name.trim();
    if t.is_empty() || t.contains(char::is_whitespace) || t.contains('.') {
        return None;
    }
    match t.to_lowercase().as_str() {
        "google" | "gmail" | "youtube" => Some("google.com"),
        "github" => Some("github.com"),
        "facebook" | "meta" => Some("facebook.com"),
        "instagram" => Some("instagram.com"),
        "discord" => Some("discord.com"),
        "bitwarden" => Some("bitwarden.com"),
        "apple" | "icloud" => Some("apple.com"),
        "microsoft" | "outlook" | "hotmail" | "xbox" => Some("microsoft.com"),
        "amazon" | "aws" => Some("amazon.com"),
        "x" | "twitter" => Some("x.com"),
        "proton" | "protonmail" | "protonvpn" | "protondrive" => Some("proton.me"),
        "dropbox" => Some("dropbox.com"),
        "slack" => Some("slack.com"),
        "cloudflare" => Some("cloudflare.com"),
        "gitlab" => Some("gitlab.com"),
        "npm" => Some("npmjs.com"),
        "docker" | "dockerhub" => Some("docker.com"),
        "steam" => Some("steampowered.com"),
        "epic" | "epicgames" => Some("epicgames.com"),
        "riot" | "riotgames" | "league" => Some("riotgames.com"),
        "binance" => Some("binance.com"),
        "coinbase" => Some("coinbase.com"),
        "paypal" => Some("paypal.com"),
        "stripe" => Some("stripe.com"),
        "netflix" => Some("netflix.com"),
        "spotify" => Some("spotify.com"),
        "telegram" => Some("telegram.org"),
        "whatsapp" => Some("whatsapp.com"),
        "linkedin" => Some("linkedin.com"),
        "yahoo" => Some("yahoo.com"),
        _ => None,
    }
}

/// Collect distinct fetchable domains from (title, url) pairs (capped).
pub fn domains_for_items(pairs: &[(String, String)]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (title, url) in pairs {
        if let Some(d) = icon_domain(title, url) {
            if seen.insert(d.clone()) {
                out.push(d);
                if out.len() >= MAX_DOMAINS_PER_PASS {
                    break;
                }
            }
        }
    }
    out
}

/// Domains already attempted this session (hit or miss) — no refetch storms.
fn attempted() -> &'static Mutex<HashSet<String>> {
    static ATTEMPTED: std::sync::OnceLock<Mutex<HashSet<String>>> = std::sync::OnceLock::new();
    ATTEMPTED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Drop RAM caches (decoded bytes + attempted set) — called on lock and on
/// factory reset so a fresh vault refetches cleanly. Disk cache is keyed by
/// domain (never by secret) and survives: icons aren't sensitive.
pub fn clear_memory_cache() {
    // Bytes live in main.rs (Slint-adjacent); attempted lives here.
    attempted().lock().unwrap_or_else(|p| p.into_inner()).clear();
}

fn hibp_style_client() -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10));
    if let Some(proxy_url) = crate::sync::github_sync::effective_proxy() {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| format!("invalid proxy URL: {e}"))?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|e| format!("http client: {e}"))
}

async fn fetch_icon_bytes(domain: &str) -> Result<Vec<u8>, String> {
    let client = hibp_style_client()?;
    // Layer 3a: DuckDuckGo first (no tracking, no cookies).
    let ddg = fetch_one(&client, &format!("{DDG_ICON}{domain}.ico")).await;
    if let Ok(b) = ddg {
        return Ok(b);
    }
    // Layer 3b: Google S2 fallback (?sz=64 keeps it favicon-scale).
    fetch_one(&client, &format!("{GOOGLE_S2}{domain}&sz=64")).await
}

async fn fetch_one(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let resp = client
        .get(url)
        .header("User-Agent", "PhantomVault-favicon/1.0")
        .send()
        .await
        .map_err(|e| format!("fetch: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("http {}", resp.status()));
    }
    if let Some(ct) = resp.headers().get(reqwest::header::CONTENT_TYPE) {
        let ct = ct.to_str().unwrap_or("").to_lowercase();
        if !ct.contains("image") && !ct.contains("icon") && !ct.contains("octet-stream") {
            return Err(format!("not an image: {ct}"));
        }
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("read: {e}"))?;
    if bytes.len() as u64 > MAX_ICON_BYTES || bytes.is_empty() {
        return Err("bad size".to_string());
    }
    // Validate decodable before caching (never store junk on disk).
    image::load_from_memory(&bytes).map_err(|e| format!("decode: {e}"))?;
    Ok(bytes.to_vec())
}

/// Blocking prefetch: disk hits return immediately; misses fetch ONE batch
/// over a local runtime. `can_net` gates every request (kill-switch +
/// toggle are folded in by the caller). Returns (domain, png_bytes) hits.
pub fn prefetch_blocking(domains: &[String], can_net: impl Fn() -> bool) -> Vec<(String, Vec<u8>)> {
    let mut fresh: Vec<String> = Vec::new();
    {
        let mut att = attempted().lock().unwrap_or_else(|p| p.into_inner());
        for d in domains {
            if !att.contains(d) {
                att.insert(d.clone());
                fresh.push(d.clone());
            }
        }
    }
    if fresh.is_empty() {
        return Vec::new();
    }
    // Disk first — user overrides before fetched cache, zero network.
    let mut hits = Vec::new();
    let mut misses = Vec::new();
    for d in fresh {
        let p = icon_path(&d);
        match custom_icon_bytes(&d).or_else(|| std::fs::read(&p).ok().filter(|b| valid_icon_bytes(b))) {
            Some(b) => hits.push((d, b)),
            None => {
                if can_net() {
                    misses.push(d);
                }
            }
        }
    }
    if misses.is_empty() {
        return hits;
    }
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return hits,
    };
    rt.block_on(async {
        for d in misses {
            match fetch_icon_bytes(&d).await {
                Ok(bytes) => {
                    if let Some(parent) = icon_path(&d).parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::write(icon_path(&d), &bytes);
                    hits.push((d, bytes));
                }
                Err(_) => { /* letter fallback; already marked attempted */ }
            }
        }
    });
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    // LOCALAPPDATA jugglers must serialize: env vars are process-global,
    // so parallel tests would otherwise read each other's temp dirs.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn domain_extraction_skips_junk() {
        assert_eq!(domain_of_url("https://github.com/login").as_deref(), Some("github.com"));
        assert_eq!(domain_of_url("www.facebook.com").as_deref(), Some("facebook.com"));
        assert_eq!(domain_of_url("http://192.168.0.1/").as_deref(), None);
        assert_eq!(domain_of_url("localhost:3000").as_deref(), None);
        assert_eq!(domain_of_url("myprinter.local").as_deref(), None);
        assert_eq!(domain_of_url("not a url !!!!").as_deref(), None);
        assert_eq!(domain_of_url("").as_deref(), None);
        assert_eq!(domain_of_url("singleword").as_deref(), None);
    }

    #[test]
    fn icon_domain_prefers_url_falls_back_to_title() {
        assert_eq!(
            icon_domain("GitHub Personal Token", "https://github.com").as_deref(),
            Some("github.com")
        );
        // Empty URL + domain-like title (Bitwarden import shape).
        assert_eq!(
            icon_domain("2captcha.com", "").as_deref(),
            Some("2captcha.com")
        );
        assert_eq!(
            icon_domain("account.proton.me", "").as_deref(),
            Some("account.proton.me")
        );
        // Human titles and placeholders never yield domains.
        assert_eq!(icon_domain("GitHub Personal Token", "").as_deref(), None);
        assert_eq!(icon_domain("--", "").as_deref(), None);
        assert_eq!(icon_domain("192.168.0.1", "").as_deref(), None);
        // Bare famous names map (mobile-import titles, URL-less items).
        assert_eq!(icon_domain("Instagram", "").as_deref(), Some("instagram.com"));
        assert_eq!(icon_domain("  DISCORD ", "").as_deref(), Some("discord.com"));
        // Sentences with spaces never map, even with a famous word inside.
        assert_eq!(icon_domain("My Instagram account", "").as_deref(), None);
    }

    #[test]
    fn package_domain_unfolds_app_ids() {
        assert_eq!(
            package_domain("com.instagram.android").as_deref(),
            Some("instagram.com")
        );
        assert_eq!(package_domain("com.example.ios").as_deref(), Some("example.com"));
        assert!(package_domain("Instagram").is_none());
        assert!(package_domain("my.android.app").is_none());
        assert!(package_domain("com.android").is_none());
        assert!(package_domain("evil..android").is_none());
        // Full chain: package title beats the unfetchable raw host.
        assert_eq!(
            icon_domain("com.instagram.android", "").as_deref(),
            Some("instagram.com")
        );
    }

    #[test]
    fn custom_override_roundtrip() {
        let _g = env_guard();
        let tmp = std::env::temp_dir().join(format!("pv-fav-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let prev = std::env::var("LOCALAPPDATA").ok();
        std::env::set_var("LOCALAPPDATA", &tmp);
        // 1x1 PNG via the image crate (also proves the decoder chain).
        let img = image::DynamicImage::new_rgb8(1, 1);
        let mut buf = Vec::new();
        image::DynamicImage::write_to(&img, &mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png).unwrap();
        assert!(save_custom_icon("Example.COM", &buf).is_ok());
        assert_eq!(custom_icon_bytes("example.com").unwrap(), buf);
        assert_eq!(custom_count(), 1);
        assert!(save_custom_icon("example.com", b"junk").is_err());
        assert_eq!(clear_custom_icons(), 1);
        assert_eq!(custom_count(), 0);
        match prev {
            Some(v) => std::env::set_var("LOCALAPPDATA", v),
            None => std::env::remove_var("LOCALAPPDATA"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn prefetch_offline_never_fetches() {
        // Fixture domain: never fetched, never on disk (disk cache is
        // shared with real app runs under %LOCALAPPDATA%).
        let d = "favtest-nonexistent-xyz123.com".to_string();
        // can_net=false: only disk could answer; nothing cached.
        let out = prefetch_blocking(std::slice::from_ref(&d), || false);
        assert!(out.is_empty());
        // Second pass is a no-op via the attempted set (no storm) — still
        // offline so this asserts nothing about the network, only dedup.
        let out2 = prefetch_blocking(&[d], || false);
        assert!(out2.is_empty());
    }

    #[test]
    fn harvest_domain_sanitizer_rejects_traversal() {
        assert_eq!(sanitize_harvest_domain("GitHub.COM").as_deref(), Ok("github.com"));
        assert!(sanitize_harvest_domain("a-b.c_d").is_err());
        let long250 = "a".repeat(250);
        for evil in [
            "",
            "../../test.png",
            "..\\windows\\x",
            "a/b.com",
            "a\\b.com",
            "evil\u{0}.com",
            "evil\n.com",
            ".leading.com",
            "trailing.com.",
            "-lead.com",
            "nolabel",
            long250.as_str(),
        ] {
            assert!(sanitize_harvest_domain(evil).is_err(), "must reject: {evil:?}");
        }
        // 120 chars exactly (with a dot) passes.
        let max_ok = format!("{}.com", "a".repeat(116));
        assert_eq!(max_ok.len(), 120);
        assert!(sanitize_harvest_domain(&max_ok).is_ok());
    }

    #[test]
    fn harvest_save_roundtrip_and_caps() {
        let _g = env_guard();
        let tmp = std::env::temp_dir().join(format!("pv-fav-harvest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let prev = std::env::var("LOCALAPPDATA").ok();
        std::env::set_var("LOCALAPPDATA", &tmp);
        // Valid 4x4 PNG via the image crate.
        let img = image::DynamicImage::new_rgb8(4, 4);
        let mut buf = Vec::new();
        image::DynamicImage::write_to(&img, &mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png).unwrap();
        let d = save_harvested_icon("Harvest-Test.COM", &buf).unwrap();
        assert_eq!(d, "harvest-test.com");
        // Resolves from disk cache as normalized PNG.
        let back = std::fs::read(cache_dir().join("harvest-test.com.png")).unwrap();
        assert!(image::load_from_memory(&back).is_ok());
        // Oversize / corrupt / empty rejected, nothing new on disk.
        assert!(save_harvested_icon("x.com", &vec![0u8; HARVEST_MAX_BYTES + 1]).is_err());
        assert!(save_harvested_icon("x.com", b"definitely not an image").is_err());
        assert!(save_harvested_icon("x.com", b"").is_err());
        assert!(save_harvested_icon("../../evil.png", &buf).is_err());
        assert!(!cache_dir().join("x.com.png").exists());
        match prev {
            Some(v) => std::env::set_var("LOCALAPPDATA", v),
            None => std::env::remove_var("LOCALAPPDATA"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
