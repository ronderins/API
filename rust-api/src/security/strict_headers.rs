//! Strict HTTP Security Headers & Axum Middleware
//!
//! Enforces zero-trust HTTP security invariants across all REST endpoints:
//! - `HSTS`: Strict-Transport-Security with 2-year duration, subdomains, and preloading.
//! - `CSP`: Content-Security-Policy with default-src 'none', frame-ancestors 'none'.
//! - `X-Content-Type-Options`: nosniff to prevent MIME type confusion.
//! - `X-Frame-Options`: DENY to prevent clickjacking in sensitive cryptographic workflows.
//! - `Cross-Origin-Opener-Policy`: same-origin to prevent Spectre cross-window memory snooping.
//! - `Permissions-Policy`: camera=(), microphone=(), geolocation=(), payment=() to lock down hardware access.

use axum::http::{HeaderMap, HeaderValue, header};

pub struct StrictSecurityHeaders;

impl StrictSecurityHeaders {
    /// Populate a response HeaderMap with hardened security headers
    pub fn apply_to_headers(headers: &mut HeaderMap) {
        // HSTS: 2 years + includeSubDomains + preload
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
        );

        // Content-Security-Policy: Strict lockdown
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
        );

        // X-Content-Type-Options: nosniff
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );

        // X-Frame-Options: DENY
        headers.insert(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        );

        // Cross-Origin-Opener-Policy: same-origin
        headers.insert(
            axum::http::HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        );

        // Cross-Origin-Resource-Policy: same-origin
        headers.insert(
            axum::http::HeaderName::from_static("cross-origin-resource-policy"),
            HeaderValue::from_static("same-origin"),
        );

        // Permissions-Policy: Disable sensitive browser features
        headers.insert(
            axum::http::HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
        );

        // Cache-Control: No-Store for cryptographic responses
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_headers_application() {
        let mut headers = HeaderMap::new();
        StrictSecurityHeaders::apply_to_headers(&mut headers);

        assert_eq!(
            headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
        assert_eq!(
            headers.get(header::X_FRAME_OPTIONS).unwrap(),
            "DENY"
        );
        assert!(
            headers.get(header::STRICT_TRANSPORT_SECURITY).unwrap().to_str().unwrap().contains("max-age=63072000")
        );
    }
}
