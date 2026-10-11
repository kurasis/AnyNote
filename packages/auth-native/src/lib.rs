//! Fixed HTTPS issuer, maintained OAuth2 PKCE, system browser and ephemeral literal loopback.
//! Credentials remain in memory. P07 supplies persistent custody. Debug never exposes secrets.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, EndpointNotSet, EndpointSet, HttpRequest,
    HttpResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, TokenResponse,
    TokenUrl, basic::BasicClient,
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener},
    thread,
    time::{Duration, Instant},
};
use url::Url;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Random,
    Callback,
    Timeout,
    Transport,
    Denied,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
type Client = BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;
fn random(n: usize) -> Result<String, Error> {
    let mut b = Zeroizing::new(vec![0u8; n]);
    getrandom::fill(&mut b).map_err(|_| Error::Random)?;
    Ok(B64.encode(&*b))
}
fn origin(text: &str) -> Result<Url, Error> {
    let u = Url::parse(text).map_err(|_| Error::Configuration)?;
    if u.scheme() != "https"
        || u.origin().ascii_serialization() != text
        || !u.username().is_empty()
        || u.password().is_some()
    {
        return Err(Error::Configuration);
    }
    Ok(u)
}
fn binary(text: &str, n: usize) -> bool {
    B64.decode(text)
        .is_ok_and(|b| b.len() == n && B64.encode(b) == text)
}

pub struct Loopback {
    listener: TcpListener,
    redirect: Url,
    deadline: Instant,
    consumed: bool,
}
impl Loopback {
    pub fn bind(ipv6: bool, timeout: Duration) -> Result<Self, Error> {
        if timeout > Duration::from_secs(300) || timeout.is_zero() {
            return Err(Error::Configuration);
        }
        let ip = if ipv6 {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        let listener = TcpListener::bind((ip, 0)).map_err(|_| Error::Callback)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| Error::Callback)?;
        let address = listener.local_addr().map_err(|_| Error::Callback)?;
        let redirect = Url::parse(&format!("http://{address}/callback/{}", random(16)?))
            .map_err(|_| Error::Callback)?;
        Ok(Self {
            listener,
            redirect,
            deadline: Instant::now() + timeout,
            consumed: false,
        })
    }
    pub fn redirect(&self) -> &Url {
        &self.redirect
    }
    pub fn receive(&mut self, state: &str, issuer: &str) -> Result<Zeroizing<String>, Error> {
        if self.consumed || !binary(state, 32) {
            return Err(Error::Callback);
        }
        loop {
            if Instant::now() >= self.deadline {
                return Err(Error::Timeout);
            }
            let (mut stream, peer) = match self.listener.accept() {
                Ok(x) => x,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => return Err(Error::Callback),
            };
            if !peer.ip().is_loopback() {
                continue;
            }
            let remaining = self
                .deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(2));
            stream
                .set_read_timeout(Some(remaining))
                .map_err(|_| Error::Callback)?;
            stream
                .set_write_timeout(Some(remaining))
                .map_err(|_| Error::Callback)?;
            let mut bytes = Zeroizing::new(Vec::with_capacity(8192));
            let mut b = [0u8; 1024];
            while bytes.len() < 8192 {
                match stream.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        bytes.extend_from_slice(&b[..n]);
                        if bytes.windows(4).any(|x| x == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
            let code = self.parse(&bytes, state, issuer);
            let response = if code.is_ok() {
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 37\r\nCache-Control: no-store\r\nConnection: close\r\n\r\nSign-in received. Return to AnyNote.\r\n"
            } else {
                "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
            };
            let _ = stream.write_all(response.as_bytes());
            if let Ok(code) = code {
                self.consumed = true;
                return Ok(code);
            }
        }
    }
    fn parse(&self, bytes: &[u8], state: &str, issuer: &str) -> Result<Zeroizing<String>, Error> {
        if bytes.len() >= 8192 {
            return Err(Error::Callback);
        }
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut r = httparse::Request::new(&mut headers);
        let size = match r.parse(bytes).map_err(|_| Error::Callback)? {
            httparse::Status::Complete(n) => n,
            _ => return Err(Error::Callback),
        };
        if size != bytes.len() || r.method != Some("GET") || r.version != Some(1) {
            return Err(Error::Callback);
        }
        let hosts: Vec<_> = r
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("host"))
            .collect();
        let expected =
            self.redirect[url::Position::BeforeHost..url::Position::AfterPort].to_string();
        if hosts.len() != 1
            || hosts[0].value != expected.as_bytes()
            || r.headers.iter().any(|h| {
                [
                    "content-length",
                    "transfer-encoding",
                    "authorization",
                    "cookie",
                ]
                .iter()
                .any(|n| h.name.eq_ignore_ascii_case(n))
            })
        {
            return Err(Error::Callback);
        }
        let target = r.path.ok_or(Error::Callback)?;
        if !target.starts_with('/')
            || target.starts_with("//")
            || target.contains('#')
            || target.contains('\\')
            || target.split('?').next() != Some(self.redirect.path())
        {
            return Err(Error::Callback);
        }
        let u = self.redirect.join(target).map_err(|_| Error::Callback)?;
        if u.path() != self.redirect.path() || u.origin() != self.redirect.origin() {
            return Err(Error::Callback);
        }
        let mut params = BTreeMap::new();
        for (k, v) in u.query_pairs() {
            if !["code", "state", "iss"].contains(&k.as_ref())
                || params.insert(k.to_string(), v.to_string()).is_some()
            {
                return Err(Error::Callback);
            }
        }
        if params.len() != 3
            || params.get("state").map(String::as_str) != Some(state)
            || params.get("iss").map(String::as_str) != Some(issuer)
        {
            return Err(Error::Callback);
        }
        let code = params.remove("code").ok_or(Error::Callback)?;
        if code.is_empty() || code.len() > 7000 || !code.is_ascii() {
            return Err(Error::Callback);
        }
        Ok(Zeroizing::new(code))
    }
}

pub struct Credentials {
    pub access: Zeroizing<String>,
    pub refresh: Zeroizing<String>,
    pub session_id: String,
    pub state: String,
}
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials(REDACTED)")
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    version: u8,
    authorization_id: String,
    consent_url: String,
}
pub struct Adapter {
    issuer: String,
    app: String,
    http: reqwest::blocking::Client,
}
pub struct Pending {
    loopback: Loopback,
    client: Client,
    verifier: PkceCodeVerifier,
    state: CsrfToken,
    authorization_id: String,
    consent: Url,
}
impl Pending {
    pub fn consent_url(&self) -> &Url {
        &self.consent
    }
}
impl Adapter {
    /// Only compiled into the explicit synthetic integration harness, never production builds.
    #[cfg(feature = "integration-harness")]
    pub fn synthetic_local(issuer: &str, app: &str, ca: &[u8]) -> Result<Self, Error> {
        if issuer != "https://api.anynote.test:18443" || app != "https://app.anynote.test:18443" {
            return Err(Error::Configuration);
        }
        let mut adapter = Self::with_additional_ca(issuer, app, ca)?;
        adapter.http = reqwest::blocking::Client::builder()
            .https_only(true)
            .no_proxy()
            .resolve(
                "api.anynote.test",
                "127.0.0.1:18443"
                    .parse()
                    .map_err(|_| Error::Configuration)?,
            )
            .add_root_certificate(
                reqwest::Certificate::from_pem(ca).map_err(|_| Error::Configuration)?,
            )
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| Error::Transport)?;
        Ok(adapter)
    }
    pub fn new(issuer: &str, app: &str) -> Result<Self, Error> {
        Self::configured(issuer, app, None)
    }
    /// Additional private CA comes only from independently trusted installation configuration.
    /// Certificate/hostname verification stays enabled; never accept CA bytes from API responses.
    pub fn with_additional_ca(issuer: &str, app: &str, ca: &[u8]) -> Result<Self, Error> {
        Self::configured(issuer, app, Some(ca))
    }
    fn configured(issuer: &str, app: &str, ca: Option<&[u8]>) -> Result<Self, Error> {
        let i = origin(issuer)?;
        let a = origin(app)?;
        if i.host_str() == a.host_str() {
            return Err(Error::Configuration);
        }
        let mut builder = reqwest::blocking::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15));
        if let Some(ca) = ca {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(ca).map_err(|_| Error::Configuration)?,
            );
        }
        let http = builder.build().map_err(|_| Error::Transport)?;
        Ok(Self {
            issuer: issuer.to_string(),
            app: app.to_string(),
            http,
        })
    }
    fn client(&self, redirect: Option<&Url>) -> Result<Client, Error> {
        let c = BasicClient::new(ClientId::new("anynote-windows".to_string()))
            .set_auth_uri(
                AuthUrl::new(format!("{}/api/v1/auth/native/authorize", self.issuer))
                    .map_err(|_| Error::Configuration)?,
            )
            .set_token_uri(
                TokenUrl::new(format!("{}/api/v1/auth/native/token", self.issuer))
                    .map_err(|_| Error::Configuration)?,
            )
            .set_auth_type(oauth2::AuthType::RequestBody);
        Ok(if let Some(u) = redirect {
            c.set_redirect_uri(RedirectUrl::new(u.to_string()).map_err(|_| Error::Configuration)?)
        } else {
            c
        })
    }
    /// Launches the actual system browser. No WebView or JS receives the native bearer credential.
    pub fn login(&self, device_commitment: &str, ipv6: bool) -> Result<Credentials, Error> {
        let pending = self.begin(device_commitment, ipv6)?;
        webbrowser::open(pending.consent_url().as_str()).map_err(|_| Error::Transport)?;
        self.complete(pending)
    }
    /// Caller may show progress and cancel by dropping Pending; the callback port closes on drop.
    pub fn begin(&self, device_commitment: &str, ipv6: bool) -> Result<Pending, Error> {
        if !binary(device_commitment, 32) {
            return Err(Error::Configuration);
        }
        let loopback = Loopback::bind(ipv6, Duration::from_secs(300))?;
        let client = self.client(Some(loopback.redirect()))?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, state) = client
            .authorize_url(|| CsrfToken::new_random_len(32))
            .set_pkce_challenge(challenge)
            .add_extra_param("device_commitment", device_commitment)
            .url();
        let response = self.http.get(url).send().map_err(|_| Error::Transport)?;
        if !response.status().is_success() {
            return Err(Error::Denied);
        }
        let data: Authorization =
            serde_json::from_reader(response.take(8193)).map_err(|_| Error::Denied)?;
        if data.version != 1 || !binary(&data.authorization_id, 16) {
            return Err(Error::Denied);
        }
        let u = Url::parse(&data.consent_url).map_err(|_| Error::Denied)?;
        if u.origin().ascii_serialization() != self.app
            || u.path() != "/auth/"
            || u.query() != Some(format!("authorization={}", data.authorization_id).as_str())
            || u.fragment().is_some()
        {
            return Err(Error::Denied);
        }
        Ok(Pending {
            loopback,
            client,
            verifier,
            state,
            authorization_id: data.authorization_id,
            consent: u,
        })
    }
    pub fn complete(&self, mut pending: Pending) -> Result<Credentials, Error> {
        // A Pending created by another issuer/adapter cannot redeem against this adapter.
        if pending.consent.origin().ascii_serialization() != self.app {
            return Err(Error::Configuration);
        }
        let code = pending
            .loopback
            .receive(pending.state.secret(), &self.issuer)?;
        self.exchange(
            &pending.client,
            &code,
            pending.verifier,
            &pending.authorization_id,
        )
    }
    fn exchange(
        &self,
        client: &Client,
        code: &str,
        verifier: PkceCodeVerifier,
        authorization: &str,
    ) -> Result<Credentials, Error> {
        let transport = JsonTransport {
            adapter: self,
            authorization: Some(authorization),
        };
        let token = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(verifier)
            .request(&transport)
            .map_err(|_| Error::Denied)?;
        transport.credentials(token)
    }
    pub fn refresh(&self, credentials: &Credentials) -> Result<Credentials, Error> {
        let client = self.client(None)?;
        let transport = JsonTransport {
            adapter: self,
            authorization: None,
        };
        let token = client
            .exchange_refresh_token(&RefreshToken::new(credentials.refresh.to_string()))
            .request(&transport)
            .map_err(|_| Error::Denied)?;
        transport.credentials(token)
    }
}
struct JsonTransport<'a> {
    adapter: &'a Adapter,
    authorization: Option<&'a str>,
}
impl oauth2::SyncHttpClient for JsonTransport<'_> {
    type Error = Error;
    fn call(&self, request: HttpRequest) -> Result<HttpResponse, Error> {
        if request.uri().to_string() != format!("{}/api/v1/auth/native/token", self.adapter.issuer)
        {
            return Err(Error::Configuration);
        }
        let mut body = serde_json::Map::new();
        for (k, v) in url::form_urlencoded::parse(request.body()) {
            if body
                .insert(k.into_owned(), serde_json::Value::String(v.into_owned()))
                .is_some()
            {
                return Err(Error::Configuration);
            }
        }
        body.insert("version".to_string(), serde_json::json!(1));
        body.insert("issuer".to_string(), serde_json::json!(self.adapter.issuer));
        if let Some(id) = self.authorization {
            body.insert("authorization_id".to_string(), serde_json::json!(id));
        }
        let response = self
            .adapter
            .http
            .post(request.uri().to_string())
            .json(&body)
            .send()
            .map_err(|_| Error::Transport)?;
        if !response.status().is_success() {
            return Err(Error::Denied);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        response
            .take(16385)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Transport)?;
        if bytes.len() > 16384 {
            return Err(Error::Denied);
        }
        let dto: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| Error::Denied)?;
        if dto.get("version") != Some(&serde_json::json!(1))
            || !dto
                .get("session")
                .is_some_and(|s| binary(s.get("id").and_then(|v| v.as_str()).unwrap_or(""), 16))
        {
            return Err(Error::Denied);
        }
        oauth2::http::Response::builder()
            .status(200)
            .header("Content-Type", "application/json")
            .body(bytes.to_vec())
            .map_err(|_| Error::Transport)
    }
}
impl JsonTransport<'_> {
    fn credentials(&self, token: oauth2::basic::BasicTokenResponse) -> Result<Credentials, Error> {
        // Bearer session authority is fetched from the fixed server, never from client-decoded JWTs.
        let access = Zeroizing::new(token.access_token().secret().to_string());
        let refresh = Zeroizing::new(
            token
                .refresh_token()
                .ok_or(Error::Denied)?
                .secret()
                .to_string(),
        );
        let response = self
            .adapter
            .http
            .get(format!("{}/api/v1/me", self.adapter.issuer))
            .bearer_auth(&*access)
            .send()
            .map_err(|_| Error::Transport)?;
        if !response.status().is_success() {
            return Err(Error::Denied);
        }
        let dto: serde_json::Value =
            serde_json::from_reader(response.take(8193)).map_err(|_| Error::Denied)?;
        let session = dto.get("session").ok_or(Error::Denied)?;
        let id = session
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or(Error::Denied)?;
        let state = session
            .get("state")
            .and_then(|v| v.as_str())
            .ok_or(Error::Denied)?;
        if !binary(id, 16) || !["restricted", "trusted"].contains(&state) {
            return Err(Error::Denied);
        }
        Ok(Credentials {
            access,
            refresh,
            session_id: id.to_string(),
            state: state.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn callback(listener: &Loopback, state: &str, issuer: &str) -> String {
        let mut u = listener.redirect.clone();
        u.query_pairs_mut()
            .append_pair("code", "synthetic-public-code")
            .append_pair("state", state)
            .append_pair("iss", issuer);
        format!(
            "GET {}?{} HTTP/1.1\r\nHost: {}\r\n\r\n",
            u.path(),
            u.query().unwrap(),
            &u[url::Position::BeforeHost..url::Position::AfterPort]
        )
    }
    #[test]
    fn actual_ipv4_and_ipv6_one_use_callback() {
        for ipv6 in [false, true] {
            let mut listener = Loopback::bind(ipv6, Duration::from_secs(3)).unwrap();
            let state = random(32).unwrap();
            let raw = callback(&listener, &state, "https://api.example.test");
            let address = listener.listener.local_addr().unwrap();
            let t = thread::spawn(move || {
                let mut s = std::net::TcpStream::connect(address).unwrap();
                s.write_all(raw.as_bytes()).unwrap();
                let mut out = String::new();
                s.read_to_string(&mut out).unwrap();
                assert!(out.starts_with("HTTP/1.1 200"));
            });
            assert_eq!(
                &*listener
                    .receive(&state, "https://api.example.test")
                    .unwrap(),
                "synthetic-public-code"
            );
            assert_eq!(
                listener
                    .receive(&state, "https://api.example.test")
                    .unwrap_err(),
                Error::Callback
            );
            t.join().unwrap();
        }
    }
    #[test]
    fn callback_attack_matrix() {
        let listener = Loopback::bind(false, Duration::from_secs(3)).unwrap();
        let state = random(32).unwrap();
        let raw = callback(&listener, &state, "https://api.example.test");
        assert!(
            listener
                .parse(raw.as_bytes(), &state, "https://api.example.test")
                .is_ok()
        );
        for bad in [
            raw.replace("GET ", "POST "),
            raw.replace(&state, &random(32).unwrap()),
            raw.replace("api.example.test", "other.example.test"),
            raw.replace("/callback/", "/elsewhere/"),
            raw.replace(" HTTP/1.1", "&access_token=secret HTTP/1.1"),
            raw.replace(" HTTP/1.1", "&state=duplicate HTTP/1.1"),
            raw.replace("\r\n\r\n", "\r\nHost: evil.test\r\n\r\n"),
            raw.replace("\r\n\r\n", "\r\nContent-Length: 1\r\n\r\nx"),
            raw.replace("Host: 127.0.0.1", "Host: 0.0.0.0"),
        ] {
            assert_eq!(
                listener
                    .parse(bad.as_bytes(), &state, "https://api.example.test")
                    .unwrap_err(),
                Error::Callback
            );
        }
    }
    #[test]
    fn trusted_origin_and_deadline() {
        for origin in [
            "http://api.example.test",
            "https://user@api.example.test",
            "https://api.example.test/path",
            "https://api.example.test#x",
        ] {
            assert_eq!(
                Adapter::new(origin, "https://app.example.test")
                    .err()
                    .unwrap(),
                Error::Configuration
            );
        }
        let mut l = Loopback::bind(false, Duration::from_millis(30)).unwrap();
        assert_eq!(
            l.receive(&random(32).unwrap(), "https://api.example.test")
                .unwrap_err(),
            Error::Timeout
        );
    }
    #[test]
    fn maintained_pkce_and_state() {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        assert_eq!(
            PkceCodeChallenge::from_code_verifier_sha256(&verifier).as_str(),
            challenge.as_str()
        );
        assert_eq!(challenge.method().as_str(), "S256");
        assert!(binary(CsrfToken::new_random_len(32).secret(), 32));
    }
}
