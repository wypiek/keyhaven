//! In-memory sliding-window failure counter used to slow down online guessing.

use crate::api::ApiError;
use axum::http::StatusCode;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Limiter {
    inner: Mutex<HashMap<String, (u32, Instant)>>,
}

const WINDOW: Duration = Duration::from_secs(3600);

impl Limiter {
    /// Fail if `key` has recorded `max` or more failures within `window`.
    pub fn check(&self, key: &str, max: u32, window: Duration) -> Result<(), ApiError> {
        let mut m = self.inner.lock().unwrap();
        if m.len() > 100_000 {
            m.retain(|_, (_, t)| t.elapsed() < WINDOW);
        }
        if let Some((count, start)) = m.get(key) {
            if start.elapsed() > window {
                m.remove(key);
            } else if *count >= max {
                let wait = window.saturating_sub(start.elapsed()).as_secs() / 60 + 1;
                return Err(ApiError::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    format!("Too many attempts. Try again in about {wait} minute(s)."),
                ));
            }
        }
        Ok(())
    }

    pub fn fail(&self, key: &str) {
        let mut m = self.inner.lock().unwrap();
        let e = m.entry(key.to_string()).or_insert((0, Instant::now()));
        e.0 += 1;
    }

    pub fn reset(&self, key: &str) {
        self.inner.lock().unwrap().remove(key);
    }
}
