use std::{sync::Arc, time::Duration};

use opnsense_client::{Certificate, Client, Error};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
};

struct Fixture {
    ca: &'static [u8],
    cert: &'static [u8],
    key: &'static [u8],
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        ca: include_bytes!("fixtures/secp384r1-ca.pem"),
        cert: include_bytes!("fixtures/secp384r1-server.pem"),
        key: include_bytes!("fixtures/secp384r1-server-key.pem"),
    },
    Fixture {
        ca: include_bytes!("fixtures/secp521r1-ca.pem"),
        cert: include_bytes!("fixtures/secp521r1-server.pem"),
        key: include_bytes!("fixtures/secp521r1-server-key.pem"),
    },
];

async fn server(fixture: &Fixture) -> (u16, JoinHandle<()>) {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from_pem_slice(fixture.cert).unwrap()],
        PrivateKeyDer::from_pem_slice(fixture.key).unwrap(),
    )
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        // Verification failures are expected in the negative tests.
        let Ok(mut stream) = acceptor.accept(stream).await else {
            return;
        };
        let mut request = Vec::new();
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let mut bytes = [0; 1024];
            let Ok(n) = stream.read(&mut bytes).await else {
                return;
            };
            if n == 0 {
                return;
            }
            request.extend_from_slice(&bytes[..n]);
        }
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}").await;
        let _ = stream.shutdown().await;
    });
    (port, task)
}

#[tokio::test]
async fn accepts_sha512_signatures_from_p384_and_p521_issuers() {
    for fixture in FIXTURES {
        let (port, task) = server(fixture).await;
        let client = Client::builder(format!("https://localhost:{port}"), "key", "secret")
            .add_root_certificate(Certificate::from_pem(fixture.ca).unwrap())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        assert_eq!(client.firmware_info().await.unwrap()["status"], "ok");
        task.await.unwrap();
    }
}

#[tokio::test]
async fn rejects_untrusted_sha512_certificates() {
    for fixture in FIXTURES {
        let (port, task) = server(fixture).await;
        let client = Client::new(&format!("https://localhost:{port}"), "key", "secret").unwrap();
        assert!(matches!(
            client.firmware_info().await,
            Err(Error::Transport(_))
        ));
        task.await.unwrap();
    }
}

#[tokio::test]
async fn rejects_wrong_hostname_even_with_trusted_sha512_issuer() {
    for fixture in FIXTURES {
        let (port, task) = server(fixture).await;
        // The certificate is valid for localhost, not the IP address.
        let client = Client::builder(format!("https://127.0.0.1:{port}"), "key", "secret")
            .add_root_certificate(Certificate::from_pem(fixture.ca).unwrap())
            .build()
            .unwrap();
        assert!(matches!(
            client.firmware_info().await,
            Err(Error::Transport(_))
        ));
        task.await.unwrap();
    }
}
