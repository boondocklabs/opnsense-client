use std::time::Duration;

use opnsense_client::{Client, Error, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

// A real local HTTP exchange verifies headers, encoding, and body handling.
async fn server(
    status: &str,
    body: &str,
    extra_headers: &str,
    delay: Duration,
) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n{body}",
        body.len()
    );
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        loop {
            let mut chunk = [0; 1024];
            let n = stream.read(&mut chunk).await.unwrap();
            assert_ne!(n, 0, "request ended early");
            bytes.extend_from_slice(&chunk[..n]);
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                let length = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .map(|s| s.parse::<usize>().unwrap())
                    .unwrap_or(0);
                if bytes.len() >= end + 4 + length {
                    break;
                }
            }
        }
        tokio::time::sleep(delay).await;
        let _ = stream.write_all(response.as_bytes()).await;
        String::from_utf8(bytes).unwrap()
    });
    (url, handle)
}

fn client(url: &str) -> Client {
    Client::builder(url, "key", "secret")
        .allow_http(true)
        .build()
        .unwrap()
}

#[derive(Debug, Deserialize, PartialEq)]
struct Info {
    product: String,
}

#[tokio::test]
async fn authenticates_and_decodes_typed_get() {
    let (url, task) = server("200 OK", r#"{"product":"OPNsense"}"#, "", Duration::ZERO).await;
    let info: Info = client(&url)
        .get(&["core", "firmware", "info"])
        .await
        .unwrap();
    assert_eq!(
        info,
        Info {
            product: "OPNsense".into()
        }
    );
    let request = task.await.unwrap().to_lowercase();
    assert!(request.starts_with("get /api/core/firmware/info http/1.1\r\n"));
    assert!(request.contains("authorization: basic a2v5onnly3jlda==\r\n"));
    assert!(request.contains("accept: application/json\r\n"));
}

#[tokio::test]
async fn encodes_query_parameters_and_keeps_proxy_prefix() {
    let (url, task) = server("200 OK", "{}", "", Duration::ZERO).await;
    let _: Value = client(&format!("{url}/proxy/api/"))
        .get_with_query(
            &["firewall", "alias", "search_item"],
            &[("searchPhrase", "LAN & WAN"), ("current", "1")],
        )
        .await
        .unwrap();
    assert!(task.await.unwrap().starts_with(
        "GET /proxy/api/firewall/alias/search_item?searchPhrase=LAN+%26+WAN&current=1 HTTP/1.1"
    ));
}

#[tokio::test]
async fn posts_json_and_encodes_arguments_as_segments() {
    let (url, task) = server("200 OK", r#"{"result":"saved"}"#, "", Duration::ZERO).await;
    let body = json!({"address": "192.0.2.1"});
    let value: Value = client(&url)
        .post(&["firewall", "alias_util", "add", "name/a?b#c%"], &body)
        .await
        .unwrap();
    assert_eq!(value["result"], "saved");
    let request = task.await.unwrap();
    assert!(request.starts_with("POST /api/firewall/alias_util/add/name%2Fa%3Fb%23c%25 HTTP/1.1"));
    assert!(
        request
            .to_lowercase()
            .contains("content-type: application/json")
    );
    assert_eq!(
        serde_json::from_str::<Value>(request.split_once("\r\n\r\n").unwrap().1).unwrap(),
        body
    );
}

#[tokio::test]
async fn firmware_helpers_use_documented_methods() {
    let (url, task) = server("200 OK", "{}", "", Duration::ZERO).await;
    client(&url).firmware_info().await.unwrap();
    assert!(
        task.await
            .unwrap()
            .starts_with("GET /api/core/firmware/info ")
    );
    let (url, task) = server("200 OK", "{}", "", Duration::ZERO).await;
    client(&url).firmware_status().await.unwrap();
    assert!(
        task.await
            .unwrap()
            .starts_with("POST /api/core/firmware/status ")
    );
}

#[tokio::test]
async fn preserves_http_error_body_and_does_not_follow_redirects() {
    for (status, expected, headers) in [
        ("401 Unauthorized", StatusCode::UNAUTHORIZED, ""),
        (
            "302 Found",
            StatusCode::FOUND,
            "Location: http://127.0.0.1:1/login\r\n",
        ),
        (
            "500 Internal Server Error",
            StatusCode::INTERNAL_SERVER_ERROR,
            "",
        ),
    ] {
        let (url, task) = server(status, "diagnostic", headers, Duration::ZERO).await;
        let error = client(&url).firmware_info().await.unwrap_err();
        match error {
            Error::Http { status, body } => {
                assert_eq!(status, expected);
                assert_eq!(body, "diagnostic");
            }
            other => panic!("unexpected error: {other}"),
        }
        task.await.unwrap();
    }
}

#[tokio::test]
async fn malformed_json_is_a_decode_error() {
    let (url, task) = server("200 OK", "<html>login</html>", "", Duration::ZERO).await;
    assert!(matches!(
        client(&url).firmware_info().await,
        Err(Error::Decode(_))
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn bounds_response_bodies_including_error_bodies() {
    for status in ["200 OK", "500 Internal Server Error"] {
        let (url, task) = server(status, "12345", "", Duration::ZERO).await;
        let client = Client::builder(url, "key", "secret")
            .allow_http(true)
            .max_response_bytes(4)
            .build()
            .unwrap();
        assert!(matches!(
            client.firmware_info().await,
            Err(Error::ResponseTooLarge)
        ));
        task.await.unwrap();
    }
}

#[tokio::test]
async fn times_out_while_waiting_for_response() {
    let (url, task) = server("200 OK", "{}", "", Duration::from_secs(5)).await;
    let client = Client::builder(url, "key", "secret")
        .allow_http(true)
        .timeout(Duration::from_millis(50))
        .build()
        .unwrap();
    assert!(matches!(client.firmware_info().await, Err(Error::Timeout)));
    task.abort();
}

#[tokio::test]
async fn rejects_path_traversal_before_network_access() {
    let client = Client::new("https://opnsense.invalid", "key", "secret").unwrap();
    for endpoint in [
        vec!["core", "firmware"],
        vec!["core", "..", "info"],
        vec!["core", ".", "info"],
        vec!["core", "", "info"],
    ] {
        assert!(matches!(
            client.get::<Value>(&endpoint).await,
            Err(Error::InvalidEndpoint)
        ));
    }
}

#[test]
fn rejects_invalid_configuration_and_redacts_debug() {
    for url in [
        "not a URL",
        "http://opnsense.local",
        "ftp://opnsense.local",
        "https://user:password@opnsense.local",
        "https://opnsense.local?foo=bar",
        "https://opnsense.local#fragment",
    ] {
        assert!(
            matches!(
                Client::new(url, "key", "secret"),
                Err(Error::Configuration(_))
            ),
            "{url}"
        );
    }
    for (key, secret) in [("", "secret"), ("key", ""), ("key:invalid", "secret")] {
        assert!(Client::new("https://opnsense.local", key, secret).is_err());
    }
    assert!(
        Client::builder("https://opnsense.local", "key", "secret")
            .timeout(Duration::ZERO)
            .build()
            .is_err()
    );
    assert!(
        Client::builder("https://opnsense.local", "key", "secret")
            .max_response_bytes(0)
            .build()
            .is_err()
    );
    let builder = Client::builder("https://opnsense.local", "private-key", "private-secret");
    let debug = format!("{builder:?}");
    assert!(!debug.contains("private-key") && !debug.contains("private-secret"));
    let debug = format!("{:?}", builder.build().unwrap());
    assert!(!debug.contains("private-key") && !debug.contains("private-secret"));
}
