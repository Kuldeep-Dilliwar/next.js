use std::{hash::Hash, sync::LazyLock};

use anyhow::Result;
use quick_cache::sync::Cache;
use turbo_rcstr::RcStr;
use turbo_tasks::{ReadRef, Vc, duration_span, mark_session_dependent};

use crate::{FetchError, FetchResult, HttpResponse, HttpResponseBody};

const MAX_CLIENTS: usize = 16;
static CLIENT_CACHE: LazyLock<Cache<ReadRef<FetchClientConfig>, reqwest::Client>> =
    LazyLock::new(|| Cache::new(MAX_CLIENTS));

/// Represents the configuration needed to construct a [`reqwest::Client`].
///
/// This is used to cache clients keyed by their configuration, so the configuration should contain
/// as few fields as possible and change infrequently.
///
/// This is needed because [`reqwest::ClientBuilder`] does not implement the required traits. This
/// factory cannot be a closure because closures do not implement `Eq` or `Hash`.
#[turbo_tasks::value(shared)]
#[derive(Hash, Default)]
pub struct FetchClientConfig {}

impl FetchClientConfig {
    /// Returns a cached instance of `reqwest::Client` it exists, otherwise constructs a new one.
    ///
    /// The cache is bound in size to prevent accidental blowups or leaks. However, in practice,
    /// very few clients should be created, likely only when the bundler configuration changes.
    ///
    /// Client construction is largely deterministic, aside from changes to system TLS
    /// configuration.
    ///
    /// The reqwest client fails to construct if the TLS backend cannot be initialized, or the
    /// resolver cannot load the system configuration. These failures should be treated as
    /// cached for some amount of time, but ultimately transient (e.g. using
    /// [`turbo_tasks::mark_session_dependent`]).
    pub fn try_get_cached_reqwest_client(
        self: ReadRef<FetchClientConfig>,
    ) -> reqwest::Result<reqwest::Client> {
        CLIENT_CACHE.get_or_insert_with(&self, {
            let this = ReadRef::clone(&self);
            move || this.try_build_uncached_reqwest_client()
        })
    }

    fn try_build_uncached_reqwest_client(&self) -> reqwest::Result<reqwest::Client> {
        #[allow(unused_mut)]
        let mut builder = reqwest::Client::builder();
        #[cfg(any(target_os = "linux", target_os = "android", all(windows, not(target_arch = "aarch64"))))]
        {
            use std::sync::Once;
            static ONCE: Once = Once::new();
            ONCE.call_once(|| {
                rustls::crypto::ring::default_provider()
                    .install_default()
                    .unwrap()
            });
            builder = builder.tls_backend_rustls();
        }
        #[cfg(all(windows, target_arch = "aarch64"))]
        {
            builder = builder.tls_backend_native();
        }
        #[cfg(target_os = "linux")]
        {
            // Add webpki_root_certs on Linux (in addition to reqwest's default
            // `rustls-platform-verifier`), in case the user is building in a bare-bones docker
            // image that does not contain any root certs (e.g. `oven/bun:slim`).
            builder = builder.tls_certs_merge(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().map(
                |der| {
                    reqwest::Certificate::from_der(der)
                        .expect("webpki_root_certs should parse correctly")
                },
            ))
        }
        #[cfg(target_os = "android")]
        {
            let termux_path = std::path::Path::new("/data/data/com.termux/files/usr/etc/tls/cert.pem");
            let env_var = std::env::var("TURBO_SSL_CERT_FILE");

            // --- BRANCH A: TERMUX MODE (Fix the Crash) ---
            if termux_path.exists() {
                println!("[Turbopack] Termux environment detected.");
                
                let mut root_store = rustls::RootCertStore::empty();
                let mut paths_to_load = vec![termux_path.to_path_buf()];

                // If user also provided a custom cert, add it to our manual list
                if let Ok(p) = env_var {
                    paths_to_load.push(std::path::PathBuf::from(p));
                }

                for cert_path in paths_to_load {
                    if let Ok(pem_bytes) = std::fs::read(&cert_path) {
                        let content = String::from_utf8_lossy(&pem_bytes);
                        // ... (Reuse the parsing logic from before) ...
                        let header = "-----BEGIN CERTIFICATE-----";
                        let footer = "-----END CERTIFICATE-----";
                        let mut current_idx = 0;
                        while let Some(start_offset) = content[current_idx..].find(header) {
                            let start = current_idx + start_offset + header.len();
                            if let Some(end_offset) = content[start..].find(footer) {
                                let end = start + end_offset;
                                let base64_str = content[start..end].lines().map(|l| l.trim()).collect::<String>();
                                if let Ok(der_bytes) = simple_base64_decode(&base64_str) {
                                    let cert = rustls::pki_types::CertificateDer::from(der_bytes);
                                    let _ = root_store.add(cert);
                                }
                                current_idx = end + footer.len();
                            } else { break; }
                        }
                    }
                }
                
                // REPLACEMENT: We bypass the system entirely because the system crashes in Termux.
                let tls_config = rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();
                builder = builder.use_preconfigured_tls(tls_config);
            }
            // --- BRANCH B: REAL APP MODE (Add, don't Replace) ---
            else if let Ok(p) = env_var {
                // We are NOT in Termux, but we have a custom cert.
                // We want to KEEP the Android System certs and ADD this one.
                println!("[Turbopack] Custom cert env var detected (Android App mode).");
                
                if let Ok(pem_bytes) = std::fs::read(&p) {
                    let content = String::from_utf8_lossy(&pem_bytes);
                    // ... (Reuse the same parsing logic) ...
                    let header = "-----BEGIN CERTIFICATE-----";
                    let footer = "-----END CERTIFICATE-----";
                    let mut current_idx = 0;
                    while let Some(start_offset) = content[current_idx..].find(header) {
                        let start = current_idx + start_offset + header.len();
                        if let Some(end_offset) = content[start..].find(footer) {
                            let end = start + end_offset;
                            let base64_str = content[start..end].lines().map(|l| l.trim()).collect::<String>();
                            
                            if let Ok(der_bytes) = simple_base64_decode(&base64_str) {
                                // ADDITION: We use reqwest's API to add to the existing system list.
                                if let Ok(cert) = reqwest::Certificate::from_der(&der_bytes) {
                                    builder = builder.add_root_certificate(cert);
                                }
                            }
                            current_idx = end + footer.len();
                        } else { break; }
                    }
                }
            }
            // --- BRANCH C: STANDARD MODE ---
            // No Termux, No Env Var. Do nothing. 
            // reqwest will automatically use Android System Certs via JNI.
        }
        builder.build()
    }
}

#[turbo_tasks::value_impl]
impl FetchClientConfig {
    #[turbo_tasks::function(network)]
    pub async fn fetch(
        self: Vc<FetchClientConfig>,
        url: RcStr,
        user_agent: Option<RcStr>,
    ) -> Result<Vc<FetchResult>> {
        let url_ref = &*url;
        let this = self.await?;
        let response_result: reqwest::Result<HttpResponse> = async move {
            let reqwest_client = this.try_get_cached_reqwest_client()?;

            let mut builder = reqwest_client.get(url_ref);
            if let Some(user_agent) = user_agent {
                builder = builder.header("User-Agent", user_agent.as_str());
            }

            let response = {
                let _span = duration_span!("fetch request", url = url_ref);
                builder.send().await
            }
            .and_then(|r| r.error_for_status())?;

            let status = response.status().as_u16();

            let body = {
                let _span = duration_span!("fetch response", url = url_ref);
                response.bytes().await?
            }
            .to_vec();

            Ok(HttpResponse {
                status,
                body: HttpResponseBody(body).resolved_cell(),
            })
        }
        .await;

        match response_result {
            Ok(resp) => Ok(Vc::cell(Ok(resp.resolved_cell()))),
            Err(err) => {

                #[cfg(target_os = "android")]
                {
                    // --- DEBUGGING START ---
                    eprintln!("\n[Turbopack] NETWORK ERROR DEBUG:");
                    eprintln!("URL: {}", url_ref);
                    eprintln!("Error: {:?}", err); // Prints the high level error
                    if let Some(source) = std::error::Error::source(&err) {
                        eprintln!("Caused by: {:?}", source); // Prints the deep TLS error
                    }
                    // --- DEBUGGING END ---
                }
                
                // the client failed to construct or the HTTP request failed
                mark_session_dependent();
                Ok(Vc::cell(Err(
                    FetchError::from_reqwest_error(&err, &url).resolved_cell()
                )))
            }
        }
    }
}


#[cfg(target_os = "android")]
fn simple_base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    let mut buffer = Vec::new();
    let mut bits: u32 = 0;
    let mut bit_count = 0;
    for byte in input.bytes() {
        let val = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => continue,
            _ => continue,
        };
        bits = (bits << 6) | (val as u32);
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            buffer.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }
    Ok(buffer)
}

#[doc(hidden)]
pub fn __test_only_reqwest_client_cache_clear() {
    CLIENT_CACHE.clear()
}

#[doc(hidden)]
pub fn __test_only_reqwest_client_cache_len() -> usize {
    CLIENT_CACHE.len()
}
