//! Internal utilities

/// Try reading the body size from the content length header
pub fn body_size(headers: &rocket::http::HeaderMap) -> Option<usize> {
    headers
        .get_one("Content-Length")
        .and_then(|len| len.parse().ok())
}
