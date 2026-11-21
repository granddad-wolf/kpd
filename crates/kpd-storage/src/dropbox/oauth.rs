//! OAuth2 + PKCE (RFC 7636) helpers for the Dropbox backend.
//!
//! Pure, allocation-only helpers for the client-side authorization flow. The
//! interactive browser-open + code-paste + token exchange is a follow-up CLI
//! and out of scope here.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::StorageError;

/// Number of random bytes in a PKCE code verifier (RFC 7636 §4.1).
const CODE_VERIFIER_LEN: usize = 32;

/// The Dropbox OAuth2 authorization endpoint.
const AUTHORIZE_URL: &str = "https://www.dropbox.com/oauth2/authorize";

/// Generate a PKCE `code_verifier`: 32 random bytes, base64url-encoded without
/// padding (43 characters). RFC 7636 §4.1.
///
/// # Errors
///
/// Returns [`StorageError::Io`] when the operating system's random source fails.
pub fn generate_code_verifier() -> Result<String, StorageError> {
    let mut bytes = [0u8; CODE_VERIFIER_LEN];
    getrandom::getrandom(&mut bytes).map_err(|e| StorageError::Io(std::io::Error::from(e)))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Compute the S256 PKCE `code_challenge` for `verifier`:
/// `base64url(sha256(verifier))` without padding. RFC 7636 §4.2.
#[must_use]
pub fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The Dropbox OAuth2 authorization URL for the PKCE flow.
#[must_use]
pub fn authorize_url(client_id: &str, code_challenge: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", client_id)
        .append_pair("response_type", "code")
        .append_pair("token_access_type", "offline")
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    format!("{AUTHORIZE_URL}?{query}")
}

/// The `application/x-www-form-urlencoded` body for `POST /oauth2/token`.
#[must_use]
pub fn token_request_body(client_id: &str, code: &str, verifier: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("code", code)
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", client_id)
        .append_pair("code_verifier", verifier)
        .finish()
}

#[cfg(test)]
mod tests {
    use super::{authorize_url, code_challenge, generate_code_verifier, token_request_body};

    #[test]
    fn code_verifier_is_43_chars_base64url() {
        let verifier = generate_code_verifier().expect("OS random source must work");
        assert_eq!(verifier.len(), 43);
        assert!(
            verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "verifier must be base64url without padding: {verifier:?}"
        );
    }

    #[test]
    fn code_verifier_is_random() {
        let a = generate_code_verifier().expect("OS random source must work");
        let b = generate_code_verifier().expect("OS random source must work");
        assert_ne!(a, b);
    }

    #[test]
    fn code_challenge_matches_rfc7636_vector() {
        // RFC 7636 Appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(code_challenge(verifier), expected);
    }

    #[test]
    fn code_challenge_is_base64url_no_pad() {
        let challenge = code_challenge("some-verifier-value");
        assert_eq!(challenge.len(), 43);
        assert!(!challenge.contains('='));
        assert!(challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    }

    #[test]
    fn authorize_url_contains_expected_params() {
        let url = authorize_url("client123", "challengeABC");
        assert!(url.starts_with("https://www.dropbox.com/oauth2/authorize?"));
        assert!(url.contains("client_id=client123"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("token_access_type=offline"));
        assert!(url.contains("code_challenge=challengeABC"));
        assert!(url.contains("code_challenge_method=S256"));
    }

    #[test]
    fn token_request_body_contains_expected_fields() {
        let body = token_request_body("client123", "the-code", "the-verifier");
        assert_eq!(
            body,
            "code=the-code&grant_type=authorization_code&client_id=client123&code_verifier=the-verifier"
        );
    }

    #[test]
    fn token_request_body_form_encodes_spaces() {
        let body = token_request_body("client id", "the code", "the verifier");
        assert_eq!(
            body,
            "code=the+code&grant_type=authorization_code&client_id=client+id&code_verifier=the+verifier"
        );
    }
}
