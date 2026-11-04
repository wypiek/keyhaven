//! Website icon fetcher. The server fetches favicons itself (so no third-party icon
//! service learns which sites you use) and caches them in SQLite.
//!
//! SSRF protections: https only on port 443, hostnames only (no IP literals or local
//! names), every hop's DNS answer must be a public address and the connection is pinned
//! to that address (no DNS rebinding), redirects are followed manually and re-checked,
//! bodies are size-capped and only real image formats are accepted.

use anyhow::{anyhow, bail, Result};
use reqwest::header::{ACCEPT, CONTENT_TYPE, LOCATION};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use url::Url;

const MAX_HTML: usize = 768 * 1024;
pub const MAX_ICON: usize = 1024 * 1024;
const OUT_SIZE: u32 = 64;

pub fn host_ok(host: &str) -> bool {
    let h = host.trim_end_matches('.');
    h.len() <= 253
        && h.contains('.')
        && !h.starts_with('.')
        && h.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-'))
        && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && h.parse::<IpAddr>().is_err()
        && !h.chars().all(|c| c.is_ascii_digit() || c == '.')
        && ![".localhost", ".local", ".internal", ".lan", ".home", ".arpa", ".test", ".invalid", ".onion"]
            .iter()
            .any(|s| h.ends_with(s))
}

fn ip_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_broadcast()
                || a.is_documentation()
                || a.is_unspecified()
                || a.is_multicast()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18))
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return ip_public(IpAddr::V4(v4));
            }
            let s0 = a.segments()[0];
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s0 & 0xfe00) == 0xfc00 // unique local
                || (s0 & 0xffc0) == 0xfe80 // link local
                || s0 == 0x2001 && a.segments()[1] == 0x0db8) // documentation
        }
    }
}

use std::sync::atomic::{AtomicBool, Ordering};

/// Outcome of an icon lookup.
pub enum Lookup {
    Found(Vec<u8>, &'static str),
    /// The site answered but has no usable icon (cacheable).
    Missing,
    /// Nothing answered at all (DNS/connect/timeout): try again later, don't cache.
    Unreachable,
}

/// GET a URL with SSRF checks on every hop. Returns (body, content-type, final URL).
/// `answered` is set once any server returns an HTTP response.
async fn safe_get(start: &str, max: usize, accept: &str, answered: &AtomicBool) -> Result<(Vec<u8>, String, Url)> {
    let mut url = Url::parse(start)?;
    for _ in 0..4 {
        if url.scheme() != "https" || url.port_or_known_default() != Some(443) {
            bail!("only https on port 443");
        }
        let host = url.host_str().ok_or_else(|| anyhow!("no host"))?.to_ascii_lowercase();
        if !host_ok(&host) {
            bail!("host not allowed");
        }
        let addrs: Vec<SocketAddr> =
            tokio::time::timeout(Duration::from_secs(4), tokio::net::lookup_host((host.as_str(), 443))).await??.collect();
        let addr = addrs.into_iter().find(|a| ip_public(a.ip())).ok_or_else(|| anyhow!("no public address"))?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .resolve(&host, addr)
            .connect_timeout(Duration::from_secs(4))
            .timeout(Duration::from_secs(8))
            .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36 KeyhavenIcons/1.1")
            .build()?;
        let mut resp = client.get(url.clone()).header(ACCEPT, accept).send().await?;
        answered.store(true, Ordering::Relaxed);
        if resp.status().is_redirection() {
            let loc = resp.headers().get(LOCATION).and_then(|v| v.to_str().ok()).ok_or_else(|| anyhow!("bad redirect"))?;
            url = url.join(loc)?;
            continue;
        }
        if !resp.status().is_success() {
            bail!("status {}", resp.status());
        }
        if resp.content_length().map(|l| l as usize > max).unwrap_or(false) {
            bail!("too large");
        }
        let ctype = resp.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            body.extend_from_slice(&chunk);
            if body.len() > max {
                bail!("too large");
            }
        }
        return Ok((body, ctype, url));
    }
    bail!("too many redirects")
}

/// Identify an image by its bytes; never trust the server's Content-Type alone.
pub fn sniff(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("image/png");
    }
    if b.starts_with(&[0, 0, 1, 0]) {
        return Some("image/x-icon");
    }
    if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    if b.starts_with(&[0xff, 0xd8, 0xff]) {
        return Some("image/jpeg");
    }
    if b.len() > 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    let head = String::from_utf8_lossy(&b[..b.len().min(1024)]).to_ascii_lowercase();
    let head = head.trim_start_matches('\u{feff}').trim_start();
    if (head.starts_with("<svg") || head.starts_with("<?xml")) && head.contains("<svg") {
        return Some("image/svg+xml");
    }
    None
}

/// Extract (href, rel, sizes, type) from <link> tags.
fn link_tags(html: &str) -> Vec<(String, String, String, String)> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(i) = lower[pos..].find("<link") {
        let start = pos + i;
        let Some(end) = lower[start..].find('>') else { break };
        let tag = &html[start..start + end];
        pos = start + end;
        let attr = |name: &str| -> String {
            let tl = tag.to_ascii_lowercase();
            let mut search = 0;
            while let Some(j) = tl[search..].find(name) {
                let k = search + j;
                search = k + name.len();
                let before_ok = k == 0 || tl.as_bytes()[k - 1].is_ascii_whitespace();
                let rest = tl[k + name.len()..].trim_start();
                if !before_ok || !rest.starts_with('=') {
                    continue;
                }
                let off = tag.len() - rest.len() + 1;
                let v = tag[off..].trim_start();
                let (q, body) = match v.chars().next() {
                    Some(c @ ('"' | '\'')) => (Some(c), &v[1..]),
                    _ => (None, v),
                };
                return match q {
                    Some(c) => body[..body.find(c).unwrap_or(body.len())].trim().to_string(),
                    None => {
                        let end = body.find(char::is_whitespace).unwrap_or(body.len());
                        let v = &body[..end];
                        // `href=/x.png/>`: the trailing slash belongs to the self-closing tag
                        (if end == body.len() && v.len() > 1 { v.trim_end_matches('/') } else { v }).to_string()
                    }
                };
            }
            String::new()
        };
        let rel = attr("rel").to_ascii_lowercase();
        if rel.split_whitespace().any(|r| r == "icon" || r == "apple-touch-icon" || r == "apple-touch-icon-precomposed") {
            out.push((attr("href"), rel, attr("sizes").to_ascii_lowercase(), attr("type").to_ascii_lowercase()));
        }
    }
    out
}

fn decode_entities(s: &str) -> String {
    s.replace("&amp;", "&").replace("&#x2F;", "/").replace("&#47;", "/").replace("&quot;", "\"")
}

/// Lower score = better candidate.
fn score(rel: &str, sizes: &str, ty: &str, href: &str) -> u32 {
    let size = sizes.split_whitespace().filter_map(|s| s.split('x').next()?.parse::<u32>().ok()).max();
    if ty.contains("svg") || href.ends_with(".svg") {
        return 20;
    }
    if rel.contains("apple-touch-icon") {
        return 30;
    }
    match size {
        Some(s) if (32..=192).contains(&s) => s.abs_diff(64),
        Some(_) => 60,
        None => 40,
    }
}

/// Decode any supported raster format (incl. multi-size .ico) and re-encode as a small PNG.
/// SVGs are passed through (they scale and are tiny). Returns None for anything undecodable.
pub fn normalize(bytes: Vec<u8>) -> Option<(Vec<u8>, &'static str)> {
    normalize_to(bytes, OUT_SIZE)
}

/// Like `normalize`, with a custom maximum edge length.
pub fn normalize_to(bytes: Vec<u8>, size: u32) -> Option<(Vec<u8>, &'static str)> {
    let mime = sniff(&bytes)?;
    if mime == "image/svg+xml" {
        return (bytes.len() <= 100 * 1024).then_some((bytes, mime));
    }
    let mut reader = image::ImageReader::new(std::io::Cursor::new(&bytes)).with_guessed_format().ok()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(4096);
    limits.max_image_height = Some(4096);
    limits.max_alloc = Some(64 * 1024 * 1024);
    reader.limits(limits);
    let img = reader.decode().ok()?;
    if img.width() < 8 || img.height() < 8 {
        return None;
    }
    let img = if img.width() > size || img.height() > size {
        img.resize(size, size, image::imageops::FilterType::Lanczos3)
    } else {
        img
    };
    let mut out = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png).ok()?;
    Some((out, "image/png"))
}

/// Try the host itself, then its parent domain (iam.example.com → example.com).
pub async fn fetch_icon(host: &str) -> Lookup {
    let answered = AtomicBool::new(false);
    if let Some((d, m)) = fetch_icon_for(host, &answered).await {
        return Lookup::Found(d, m);
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() >= 3 && labels[labels.len() - 2].len() > 3 {
        let parent = labels[1..].join(".");
        if host_ok(&parent) {
            if let Some((d, m)) = fetch_icon_for(&parent, &answered).await {
                return Lookup::Found(d, m);
            }
        }
    }
    if answered.load(Ordering::Relaxed) { Lookup::Missing } else { Lookup::Unreachable }
}

async fn fetch_icon_for(host: &str, answered: &AtomicBool) -> Option<(Vec<u8>, &'static str)> {
    let mut candidates: Vec<(u32, Url)> = Vec::new();
    let mut origins = vec![Url::parse(&format!("https://{host}/")).ok()?];
    if let Ok((html, ctype, final_url)) = safe_get(&format!("https://{host}/"), MAX_HTML, "text/html,*/*;q=0.5", answered).await {
        if ctype.contains("html") || ctype.is_empty() {
            let text = String::from_utf8_lossy(&html);
            let head_end = text.to_ascii_lowercase().find("</head>").unwrap_or(text.len());
            for (href, rel, sizes, ty) in link_tags(&text[..head_end]) {
                let href = decode_entities(&href);
                if href.is_empty() || href.starts_with("data:") {
                    continue;
                }
                if let Ok(u) = final_url.join(&href) {
                    candidates.push((score(&rel, &sizes, &ty, u.path()), u));
                }
            }
        }
        if final_url.host_str() != Some(host) {
            origins.push(final_url);
        }
    }
    candidates.sort_by_key(|c| c.0);
    for o in &origins {
        if let Ok(u) = o.join("/favicon.ico") {
            candidates.push((100, u));
        }
    }
    let mut tried = 0;
    for (_, u) in candidates {
        if tried >= 5 {
            break;
        }
        tried += 1;
        if let Ok((img, _, _)) = safe_get(u.as_str(), MAX_ICON, "image/*,*/*;q=0.5", answered).await {
            if let Some(icon) = normalize(img) {
                return Some(icon);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert!(host_ok("github.com"));
        assert!(!host_ok("localhost"));
        assert!(!host_ok("127.0.0.1"));
        assert!(!host_ok("printer.local"));
        assert!(!host_ok("a..b"));
        assert!(!ip_public("10.0.0.1".parse().unwrap()));
        assert!(!ip_public("::1".parse().unwrap()));
        assert!(!ip_public("::ffff:192.168.1.1".parse().unwrap()));
        assert!(ip_public("140.82.121.4".parse().unwrap()));
    }

    #[test]
    fn links() {
        let l = link_tags(r#"<link rel="stylesheet" href="a.css"><link rel="icon" sizes="32x32" href="/f32.png"><LINK REL='apple-touch-icon' HREF=/t.png>"#);
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].0, "/f32.png");
        assert_eq!(l[1].0, "/t.png");
    }
}
