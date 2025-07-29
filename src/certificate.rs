use std::sync::Arc;

use moka::future::Cache;
use rand::Rng;
use rcgen::{
    string::Ia5String, CertificateParams, DistinguishedName, DnType, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use time::{Duration, OffsetDateTime};
#[cfg(feature = "native-tls")]
use tokio_native_tls::{native_tls, TlsAcceptor as NativeTlsAcceptor};
#[cfg(feature = "rust-tls")]
use tokio_rustls::{rustls::ServerConfig, TlsAcceptor as RustlsAcceptor};
#[cfg(feature = "native-tls")]
type CacheData = Arc<NativeTlsAcceptor>;
#[cfg(feature = "rust-tls")]
type CacheData = Arc<ServerConfig>;

lazy_static! {
    static ref CERT_NOT_BEFORE: OffsetDateTime = OffsetDateTime::now_utc() - Duration::days(7);
    static ref CERT_NOT_AFTER: OffsetDateTime = OffsetDateTime::now_utc() + Duration::days(356);
    static ref CACHE_CAPACITY: u64 = 1500;
    static ref CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60 * 60 * 24 * 7);
}

pub(crate) struct CertificateAuthority {
    cert: CertificateDer<'static>,
    private_key: PrivateKeyDer<'static>,
    cache: Cache<String, CacheData>,
}

impl CertificateAuthority {
    pub fn new(cert: CertificateDer<'static>, private_key: PrivateKeyDer<'static>) -> Self {
        CertificateAuthority {
            cert,
            private_key,
            cache: Cache::builder()
                .max_capacity(*CACHE_CAPACITY)
                .time_to_live(*CACHE_TTL)
                .build(),
        }
    }

    pub fn gen_cert(&self, host: &str) -> Vec<u8> {
        let mut rng = rand::rng();
        let mut params = CertificateParams::default();
        params.serial_number = Some(rng.random::<u64>().into());

        params.not_before = *CERT_NOT_BEFORE;
        params.not_after = *CERT_NOT_AFTER;

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, host);
        params.distinguished_name = distinguished_name;
        params.use_authority_key_identifier_extension = true;

        params
            .subject_alt_names
            .push(SanType::DnsName(Ia5String::try_from(host).unwrap()));

        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);

        let key_pair =
            KeyPair::try_from(&self.private_key.clone_key()).expect("Failed to parse private key");
        let issuer =
            Issuer::from_ca_cert_der(&self.cert, key_pair).expect("Failed to create the Issuer");

        let key_pair = KeyPair::try_from(&self.private_key).expect("Failed to parse private key");
        let cert = params.signed_by(&key_pair, &issuer).unwrap();

        #[cfg(feature = "native-tls")]
        let cert = cert.pem().into_bytes();
        #[cfg(feature = "rust-tls")]
        let cert = cert.der().to_vec();
        cert
    }

    #[cfg(feature = "native-tls")]
    pub async fn get_tls_acceptor(&self, host: &str) -> Arc<NativeTlsAcceptor> {
        self.cache
            .get_with(host.to_string(), async move {
                let id = native_tls::Identity::from_pkcs8(
                    &self.gen_cert(host),
                    KeyPair::try_from(&self.private_key)
                        .expect("Failed to parse private key")
                        .serialize_pem()
                        .as_bytes(),
                )
                .expect("Failed to create indentity for the nativate-tls acceptor");

                let acceptor =
                    native_tls::TlsAcceptor::new(id).expect("Failed to create a nativate-tls");

                Arc::new(NativeTlsAcceptor::from(acceptor))
            })
            .await
    }

    #[cfg(feature = "rust-tls")]
    pub async fn get_tls_acceptor(&self, host: &str) -> RustlsAcceptor {
        let server_cfg = self
            .cache
            .get_with(host.to_string(), async move {
                let certs = vec![CertificateDer::from(self.gen_cert(host))];

                let mut server_cfg = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, self.private_key.clone_key())
                    .expect("Failed to build ServerConfig");
                server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

                Arc::new(server_cfg)
            })
            .await;

        RustlsAcceptor::from(server_cfg)
    }
}
