//! keyhaven-server — self-hosted, zero-knowledge sync server for Keyhaven.

mod admin;
mod api;
mod db;
mod icons;
mod ratelimit;

use api::{AppState, Signups};
use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderValue, Request, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::Router;
use rust_embed::RustEmbed;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(RustEmbed)]
#[folder = "static/"]
struct WebVault;

const USAGE: &str = "\
keyhaven-server — self-hosted Keyhaven sync server

USAGE:
  keyhaven-server [serve] [--bind ADDR] [--data DIR]
  keyhaven-server invite [--days N] [--data DIR]   Create a one-time signup invite code
  keyhaven-server users [--data DIR]               List accounts
  keyhaven-server delete-user EMAIL [--data DIR]   Permanently delete an account
  keyhaven-server promote EMAIL [--data DIR]       Make an account an instance admin
  keyhaven-server demote EMAIL [--data DIR]        Make an admin a regular user

ENVIRONMENT:
  KEYHAVEN_BIND         Listen address              (default 127.0.0.1:8743)
  KEYHAVEN_DATA         Data directory (SQLite db)  (default ./data)
  KEYHAVEN_SIGNUPS      open | invite | closed      (default invite; the first account is always allowed)
  KEYHAVEN_TRUST_PROXY  1 to trust X-Forwarded-For / X-Real-IP from a reverse proxy
";

struct Args {
    cmd: String,
    positional: Vec<String>,
    bind: String,
    data: PathBuf,
    days: i64,
}

fn parse_args() -> Args {
    let mut a = Args {
        cmd: "serve".into(),
        positional: vec![],
        bind: std::env::var("KEYHAVEN_BIND").unwrap_or_else(|_| "127.0.0.1:8743".into()),
        data: std::env::var_os("KEYHAVEN_DATA").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("data")),
        days: 7,
    };
    let mut it = std::env::args().skip(1);
    let mut first = true;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--bind" => a.bind = it.next().unwrap_or_default(),
            "--data" => a.data = PathBuf::from(it.next().unwrap_or_default()),
            "--days" => a.days = it.next().and_then(|d| d.parse().ok()).unwrap_or(7),
            "-h" | "--help" | "help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("keyhaven-server {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            _ if first && !arg.starts_with('-') => a.cmd = arg,
            _ => a.positional.push(arg),
        }
        first = false;
    }
    a
}

async fn security_headers(req: Request<Body>, next: Next) -> Response {
    let is_api = req.uri().path().starts_with("/api/");
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    let set = |h: &mut axum::http::HeaderMap, k: &'static str, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    set(h, "x-content-type-options", "nosniff");
    set(h, "x-frame-options", "DENY");
    set(h, "referrer-policy", "no-referrer");
    set(h, "cross-origin-opener-policy", "same-origin");
    set(h, "permissions-policy", "camera=(), microphone=(), geolocation=()");
    set(
        h,
        "content-security-policy",
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; \
         connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    );
    if is_api {
        set(h, "cache-control", "no-store");
    }
    res
}

async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match WebVault::get(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            let cache = if path == "index.html" { "no-cache" } else { "public, max-age=300" };
            (
                [(header::CONTENT_TYPE, mime.as_ref().to_string()), (header::CACHE_CONTROL, cache.to_string())],
                file.data.into_owned(),
            )
                .into_response()
        }
        None if path.starts_with("api/") => {
            (StatusCode::NOT_FOUND, axum::Json(serde_json::json!({"error": "Not found"}))).into_response()
        }
        None => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/config", get(api::config))
        .route("/api/prelogin", post(api::prelogin))
        .route("/api/register", post(api::register))
        .route("/api/login", post(api::login))
        .route("/api/logout", post(api::logout))
        .route("/api/account", get(api::account))
        .route("/api/account/password", post(api::change_password))
        .route("/api/account/delete", post(api::delete_account))
        .route("/api/sync", get(api::sync))
        .route("/api/items/batch", post(api::put_items_batch))
        .route("/api/items/{id}", put(api::put_item).delete(api::delete_item))
        .route("/api/icon", get(api::icon))
        .route("/api/instance", get(admin::instance))
        .route("/api/admin/overview", get(admin::overview))
        .route("/api/admin/settings", get(admin::get_settings).put(admin::put_settings))
        .route("/api/admin/logo", put(admin::put_logo).delete(admin::delete_logo))
        .route("/api/admin/verified", put(admin::put_verified))
        .route("/api/admin/users", get(admin::users))
        .route("/api/admin/users/{id}", delete(admin::delete_user))
        .route("/api/admin/users/{id}/role", put(admin::set_role))
        .route("/api/admin/users/{id}/signout", post(admin::sign_out_user))
        .route("/api/admin/invites", get(admin::invites).post(admin::create_invite))
        .route("/api/admin/invites/{id}", delete(admin::delete_invite))
        .route("/api/sessions", get(api::sessions))
        .route("/api/sessions/{id}", delete(api::revoke_session))
        .fallback(static_handler)
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = parse_args();
    let conn = db::open(&args.data)?;

    match args.cmd.as_str() {
        "invite" => {
            let code = api::create_invite(&conn, args.days.clamp(1, 365))?;
            println!("{code}");
            eprintln!("One-time invite code, valid for {} day(s).", args.days.clamp(1, 365));
            return Ok(());
        }
        "users" => {
            for (email, created, items) in db::list_users(&conn)? {
                println!("{email}\t{items} items\tcreated {}", created / 1000);
            }
            return Ok(());
        }
        "delete-user" => {
            let email = args.positional.first().map(|s| s.trim().to_lowercase()).unwrap_or_default();
            match db::user_by_email(&conn, &email)? {
                Some(u) => {
                    db::delete_user(&conn, &u.id)?;
                    println!("Deleted {email} and all of their data.");
                }
                None => {
                    eprintln!("No account with email '{email}'.");
                    std::process::exit(1);
                }
            }
            return Ok(());
        }
        "promote" | "demote" => {
            let email = args.positional.first().map(|s| s.trim().to_lowercase()).unwrap_or_default();
            let Some(u) = db::user_by_email(&conn, &email)? else {
                eprintln!("No account with email '{email}'.");
                std::process::exit(1);
            };
            let role = if args.cmd == "promote" { "admin" } else { "user" };
            if role == "user" && u.role == "admin" && db::admin_count(&conn)? <= 1 {
                eprintln!("{email} is the last admin; promote someone else first.");
                std::process::exit(1);
            }
            db::set_role(&conn, &u.id, role)?;
            println!("{email} is now {role}.");
            return Ok(());
        }
        "serve" => {}
        other => {
            eprintln!("Unknown command '{other}'.\n\n{USAGE}");
            std::process::exit(2);
        }
    }

    let signups = match std::env::var("KEYHAVEN_SIGNUPS").unwrap_or_default().to_lowercase().as_str() {
        "open" => Signups::Open,
        "closed" => Signups::Closed,
        _ => Signups::Invite,
    };
    let trust_proxy = matches!(std::env::var("KEYHAVEN_TRUST_PROXY").as_deref(), Ok("1") | Ok("true"));
    let secret = db::server_secret(&conn)?;
    let state = Arc::new(AppState {
        db: Mutex::new(conn),
        secret,
        signups,
        trust_proxy,
        limiter: Default::default(),
        icon_slots: tokio::sync::Semaphore::new(6),
    });

    let addr: SocketAddr = args.bind.parse().map_err(|_| anyhow::anyhow!("invalid bind address '{}'", args.bind))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!(
        "keyhaven-server {} listening on http://{addr} (data: {}, signups: {:?}, trust proxy: {trust_proxy})",
        env!("CARGO_PKG_VERSION"),
        args.data.display(),
        signups
    );
    axum::serve(listener, router(state).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            eprintln!("shutting down");
        })
        .await?;
    Ok(())
}
