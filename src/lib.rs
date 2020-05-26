//! An implementation of OAuth 1.0a. This is intended to be completely agnostic to all application
//! details, so you might need to do some parts yourself. A minimal example is included.

#![warn(missing_docs)]

use hmac::{Hmac, Mac};
use http_types::{Method, Url};
use percent_encoding::{AsciiSet, PercentEncode, NON_ALPHANUMERIC};
use rand::distributions::Alphanumeric;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

const PERCENT_ENCODING_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn percent_encode<T: ?Sized + AsRef<[u8]>>(data: &T) -> PercentEncode<'_> {
    percent_encoding::percent_encode(data.as_ref(), PERCENT_ENCODING_SET)
}

/// Encode OAuth parameters for an Authorization header.
#[must_use]
pub fn encode_auth_parameters(params: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    let params: BTreeMap<String, String> = params
        .iter()
        .map(|(x, y)| (percent_encode(x).collect(), percent_encode(y).collect()))
        .collect();
    let mut params = params.iter();
    if let Some((k, v)) = params.next() {
        out.push_str(k);
        out.push_str("=\"");
        out.push_str(v);
        out.push('"');
    }
    for (k, v) in params {
        out.push_str(", ");
        out.push_str(k);
        out.push_str("=\"");
        out.push_str(v);
        out.push('"');
    }
    out
}

fn encode_url_parameters(params: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    let params: BTreeMap<String, String> = params
        .iter()
        .map(|(x, y)| (percent_encode(x).collect(), percent_encode(y).collect()))
        .collect();
    let mut params = params.iter();
    if let Some((k, v)) = params.next() {
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }
    for (k, v) in params {
        out.push('&');
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }
    out
}

/// An OAuth token.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct Token(pub String);

/// A client ID.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct ClientId(pub String);

/// A client secret.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct ClientSecret(pub String);

/// A token secret.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct TokenSecret(pub String);

/// A signing key for OAuth.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SigningKey {
    /// The client secret.
    pub client_secret: ClientSecret,
    /// The token secret.
    pub token_secret: Option<TokenSecret>,
}

impl SigningKey {
    /// Create a signing key while already having a token.
    #[must_use]
    pub fn with_token(client_secret: ClientSecret, token_secret: TokenSecret) -> Self {
        Self {
            client_secret,
            token_secret: Some(token_secret),
        }
    }

    /// Create a signing key before receiving a token.
    #[must_use]
    pub fn without_token(client_secret: ClientSecret) -> Self {
        Self {
            client_secret,
            token_secret: None,
        }
    }
}

impl fmt::Display for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(token_secret) = &self.token_secret {
            write!(f, "{}&{}", self.client_secret.0, token_secret.0)
        } else {
            write!(f, "{}&", self.client_secret.0)
        }
    }
}

fn normalize_url(mut url: Url) -> Url {
    if let Some(host) = url.host_str() {
        let host = host.to_lowercase();
        url.set_host(Some(&host))
            .expect("lowercasing shouldn't change host validity");
    }
    url.set_fragment(None);
    url.set_query(None);
    url
}

/// The components of an HTTP request that must be signed.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct SignableRequest {
    /// The request method.
    #[serde(with = "serde_with::rust::display_fromstr")]
    pub method: Method,
    normalized_url: Url,
    /// The request parameters from all sources.
    pub parameters: BTreeMap<String, String>,
}

impl SignableRequest {
    /// Creates a new `SignableRequest`, normalizing the URL.
    #[must_use]
    pub fn new(method: Method, url: Url, parameters: BTreeMap<String, String>) -> Self {
        let normalized_url = normalize_url(url);
        Self {
            method,
            normalized_url,
            parameters,
        }
    }

    /// Get the normalized URL.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.normalized_url
    }
}

/// Data that can be signed.
pub trait Signable {
    /// Get the raw bytes to be signed.
    fn to_bytes(&self) -> Cow<'_, [u8]>;
}

impl Signable for String {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

impl Signable for &str {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

impl Signable for SignableRequest {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let method = self.method.to_string().into_bytes();
        let url = percent_encode(self.url().as_str());
        let parameters = encode_url_parameters(&self.parameters).into_bytes();
        let mut vec =
            Vec::with_capacity(method.len() + self.url().as_str().len() + parameters.len() + 10);
        vec.extend_from_slice(&method);
        vec.push(b'&');
        for x in url {
            vec.extend_from_slice(x.as_bytes());
        }
        vec.push(b'&');
        for x in percent_encode(&parameters) {
            vec.extend_from_slice(x.as_bytes());
        }
        Cow::Owned(vec)
    }
}

/// A signing method. RSA-SHA1 is not currently supported.
#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureMethod {
    /// The HMAC-SHA1 signing method.
    HmacSha1,
    /// The PLAINTEXT signing method.
    Plaintext,
}

impl SignatureMethod {
    /// Sign data using this method and a key.
    pub fn sign(self, data: &impl Signable, key: &SigningKey) -> String {
        let key = key.to_string();
        match self {
            Self::HmacSha1 => {
                let data = data.to_bytes();
                let mut mac = Hmac::<Sha1>::new_varkey(key.as_bytes())
                    .expect("HMAC has no key length restrictions");
                mac.input(&data);
                base64::encode(&mac.result().code())
            }
            Self::Plaintext => key,
        }
    }
}

impl fmt::Display for SignatureMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string = match self {
            Self::HmacSha1 => "HMAC-SHA1",
            Self::Plaintext => "PLAINTEXT",
        };
        write!(f, "{}", string)
    }
}

/// A nonce.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct Nonce(String);

impl Nonce {
    /// Generate a new nonce.
    #[must_use]
    pub fn generate() -> Self {
        Self(thread_rng().sample_iter(Alphanumeric).take(16).collect())
    }
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Bad system time!")
        .as_secs()
}

/// The main entrypoint to the API. Non-sensitive data required for all authenticated requests.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OAuthData {
    /// The client ID.
    pub client_id: ClientId,
    /// The OAuth token.
    pub token: Option<Token>,
    /// The signature method.
    pub signature_method: SignatureMethod,
    /// The nonce.
    pub nonce: Nonce,
}

/// The type of endpoint to generate an Authorization header for.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorizationType {
    /// A request to the request token endpoint.
    RequestToken {
        /// The callback URL to be redirected to.
        callback: String,
    },
    /// A request to the access token endpoint.
    AccessToken {
        /// The oauth_verifier received from authorization.
        verifier: String,
    },
    /// A standard request made after authentication.
    Request,
}

impl OAuthData {
    /// Generate an HTTP Authorization header.
    #[must_use]
    pub fn authorization(
        &self,
        mut req: SignableRequest,
        typ: AuthorizationType,
        key: &SigningKey,
    ) -> String {
        req.parameters.extend(self.parameters());
        match typ {
            AuthorizationType::RequestToken { callback } => {
                req.parameters.insert("oauth_callback".into(), callback);
            }
            AuthorizationType::AccessToken { verifier } => {
                req.parameters.insert("oauth_verifier".into(), verifier);
            }
            AuthorizationType::Request => {}
        }
        let signature = self.signature_method.sign(&req, key);
        req.parameters.insert("oauth_signature".into(), signature);
        format!("OAuth {}", encode_auth_parameters(&req.parameters))
    }

    /// Get the OAuth parameters.
    #[must_use]
    pub fn parameters(&self) -> BTreeMap<String, String> {
        let mut params = BTreeMap::new();
        params.insert("oauth_consumer_key".into(), self.client_id.0.clone());
        if let Some(token) = &self.token {
            params.insert("oauth_token".into(), token.0.clone());
        }
        params.insert(
            "oauth_signature_method".into(),
            self.signature_method.to_string(),
        );
        params.insert("oauth_timestamp".into(), timestamp().to_string());
        params.insert("oauth_nonce".into(), self.nonce.0.clone());
        params
    }

    /// Regenerate the nonce. This should be done at least between each identical request made
    /// within a second.
    pub fn regen_nonce(&mut self) {
        self.nonce = Nonce::generate();
    }
}

/// Updates an `OAuthData` and `SigningKey` with the response from either the access token or request
/// token endpoints.
///
/// # Errors
/// Returns an error if the response is invalid.
pub fn receive_token<'a>(
    data: &'a mut OAuthData,
    key: &mut SigningKey,
    resp: &str,
) -> Result<&'a Token, serde_urlencoded::de::Error> {
    #[derive(Deserialize)]
    struct Response {
        pub oauth_token: Token,
        pub oauth_token_secret: TokenSecret,
    }

    let resp: Response = serde_urlencoded::from_str(resp)?;
    let _ = data.token.take();
    let token = &*data.token.get_or_insert(resp.oauth_token);
    key.token_secret = Some(resp.oauth_token_secret);
    Ok(token)
}

/// Gets the verifier string from a callback URL.
///
/// # Errors
/// Returns an error if the query string is invalid or missing.
pub fn get_verifier(callback: &Url) -> Result<String, serde_urlencoded::de::Error> {
    #[derive(Deserialize)]
    struct Response {
        pub oauth_token: Token,
        pub oauth_verifier: String,
    }

    let query = callback.query().unwrap_or("");
    let resp: Response = serde_urlencoded::from_str(query)?;
    Ok(resp.oauth_verifier)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    #[test]
    fn encode_auth_parameters() {
        let mut params = BTreeMap::new();
        params.insert("hello".into(), "World!".into());
        params.insert("abc".into(), "def".into());
        params.insert("zzz".into(), "aaa".into());
        assert_eq!(
            super::encode_auth_parameters(&params),
            r#"abc="def", hello="World%21", zzz="aaa""#
        );
    }

    #[test]
    fn encode_url_parameters() {
        // example from spec (3.4.1.3.2) without repeated keys (since we don't support those)
        let mut params = BTreeMap::new();
        params.insert("b5".into(), "=%3D".into());
        params.insert("a3".into(), "a".into());
        params.insert("c@".into(), "".into());
        params.insert("a2".into(), "r b".into());
        params.insert("oauth_consumer_key".into(), "9djdj82h48djs9d2".into());
        params.insert("oauth_token".into(), "kkk9d7dh3k39sjv7".into());
        params.insert("oauth_signature_method".into(), "HMAC-SHA1".into());
        params.insert("oauth_timestamp".into(), "137131201".into());
        params.insert("oauth_nonce".into(), "7d8f3e4a".into());
        params.insert("c2".into(), "".into());
        assert_eq!(
            super::encode_url_parameters(&params),
            r#"a2=r%20b&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"#
        );
    }

    #[test]
    fn encode_request() {
        // example from spec (3.4.1.1) without repeated keys
        use super::Signable;
        use http_types::{Method, Url};
        let mut params = BTreeMap::new();
        params.insert("b5".into(), "=%3D".into());
        params.insert("a3".into(), "a".into());
        params.insert("c@".into(), "".into());
        params.insert("a2".into(), "r b".into());
        params.insert("oauth_consumer_key".into(), "9djdj82h48djs9d2".into());
        params.insert("oauth_token".into(), "kkk9d7dh3k39sjv7".into());
        params.insert("oauth_signature_method".into(), "HMAC-SHA1".into());
        params.insert("oauth_timestamp".into(), "137131201".into());
        params.insert("oauth_nonce".into(), "7d8f3e4a".into());
        params.insert("c2".into(), "".into());
        let url = Url::parse("http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b").unwrap();
        let req = super::SignableRequest::new(Method::Post, url, params);
        assert_eq!(
            std::str::from_utf8(&*req.to_bytes()).unwrap(),
            r#"POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7"#
        );
    }

    #[test]
    fn nonce() {
        for _ in 0..20 {
            let nonce = super::Nonce::generate();
            assert_eq!(nonce.0.len(), 16);
            assert!(!nonce.0.chars().any(|x| !x.is_ascii_alphanumeric()));
        }
    }

    #[test]
    fn sign_plaintext() {
        use super::*;
        let client_secret = ClientSecret("client".into());
        let token_secret = TokenSecret("token".into());
        let without_token = SigningKey::without_token(client_secret.clone());
        let with_token = SigningKey::with_token(client_secret, token_secret);
        let data = "";
        let sig_without = SignatureMethod::Plaintext.sign(&data, &without_token);
        let sig_with = SignatureMethod::Plaintext.sign(&data, &with_token);
        assert_eq!(&sig_without, "client&");
        assert_eq!(&sig_with, "client&token");
    }

    #[test]
    fn sign_hmac() {
        use super::*;
        let client_secret = ClientSecret("client".into());
        let token_secret = TokenSecret("token".into());
        let without_token = SigningKey::without_token(client_secret.clone());
        let with_token = SigningKey::with_token(client_secret, token_secret);
        let data = "Hello, world!";
        let sig_without = SignatureMethod::HmacSha1.sign(&data, &without_token);
        let sig_with = SignatureMethod::HmacSha1.sign(&data, &with_token);
        assert_eq!(&sig_without, "QtZYxkuvnXbp2Pj0dE4nqYXdR5A=");
        assert_eq!(&sig_with, "4e3uNt5iHa7cMOSKMeY6mil2jew=");
    }
}
