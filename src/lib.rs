use hmac::{Hmac, Mac};
use http_types::{Method, Url};
use percent_encoding::{AsciiSet, PercentEncode, NON_ALPHANUMERIC};
use rand::distributions::Alphanumeric;
use rand::prelude::*;
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

pub fn encode_url_parameters(params: &BTreeMap<String, String>) -> String {
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

#[derive(Clone)]
pub struct Token(pub String);

#[derive(Clone)]
pub struct ClientId(pub String);

#[derive(Clone)]
pub struct ClientSecret(pub String);

#[derive(Clone)]
pub struct TokenSecret(pub String);

pub struct SigningKey {
    pub client_secret: ClientSecret,
    pub token_secret: Option<TokenSecret>,
}

impl SigningKey {
    pub fn with_token(client_secret: ClientSecret, token_secret: TokenSecret) -> Self {
        Self {
            client_secret,
            token_secret: Some(token_secret),
        }
    }

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

pub struct SignableRequest {
    pub method: Method,
    normalized_url: Url,
    pub parameters: BTreeMap<String, String>,
}

impl SignableRequest {
    pub fn new(method: Method, url: Url, parameters: BTreeMap<String, String>) -> Self {
        let normalized_url = normalize_url(url);
        Self {
            method,
            normalized_url,
            parameters,
        }
    }

    pub fn url(&self) -> &Url {
        &self.normalized_url
    }
}

pub trait Signable {
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

pub enum SignatureMethod {
    HmacSha1,
    Plaintext,
}

impl SignatureMethod {
    pub fn sign(&self, data: &impl Signable, key: &SigningKey) -> String {
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

pub struct Nonce(String);

impl Nonce {
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

pub struct OAuthData {
    pub client_id: ClientId,
    pub token: Option<Token>,
    pub signature_method: SignatureMethod,
    pub nonce: Nonce,
}

pub enum AuthorizationType {
    RequestToken { callback: String },
    AccessToken { verifier: String },
    Request,
}

impl OAuthData {
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

    pub fn regen_nonce(&mut self) {
        self.nonce = Nonce::generate();
    }
}

pub fn receive_token<'a>(
    data: &'a mut OAuthData,
    key: &mut SigningKey,
    resp: &str,
) -> Result<&'a Token, serde_urlencoded::de::Error> {
    #[derive(serde::Deserialize)]
    struct Response {
        pub oauth_token: String,
        pub oauth_token_secret: String,
    }
    let resp: Response = serde_urlencoded::from_str(resp)?;
    let _ = data.token.take();
    let token = &*data.token.get_or_insert(Token(resp.oauth_token));
    key.token_secret = Some(TokenSecret(resp.oauth_token_secret));
    Ok(token)
}

pub fn get_verifier(callback: &Url) -> Result<String, serde_urlencoded::de::Error> {
    let query = callback.query().unwrap_or("");
    #[derive(serde::Deserialize)]
    struct Response {
        pub oauth_token: String,
        pub oauth_verifier: String,
    }
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
