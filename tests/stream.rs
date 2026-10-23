use std::time::Duration;

use opnsense_client::{Client, Error};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

async fn server(
    status: &str,
    content_type: &str,
    parts: Vec<(Duration, Vec<u8>)>,
) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let headers =
        format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let mut buffer = [0; 1024];
            let n = stream.read(&mut buffer).await.unwrap();
            assert_ne!(n, 0);
            request.extend_from_slice(&buffer[..n]);
        }
        stream.write_all(headers.as_bytes()).await.unwrap();
        for (delay, bytes) in parts {
            tokio::time::sleep(delay).await;
            if stream.write_all(&bytes).await.is_err() {
                break;
            }
        }
        String::from_utf8(request).unwrap()
    });
    (url, task)
}

fn client(url: &str) -> Client {
    Client::builder(url, "key", "secret")
        .allow_http(true)
        .build()
        .unwrap()
}

#[tokio::test]
async fn yields_split_events_with_query_and_auth_then_reports_eof() {
    let parts = vec![
        (
            Duration::ZERO,
            b"\xef\xbb\xbf: hello\r\nid: 7\r\nevent: cpu\r\ndata: {\"busy\":".to_vec(),
        ),
        (Duration::from_millis(5), b"42}\r\n\r".to_vec()),
        (
            Duration::ZERO,
            b"\ndata: {\"busy\":43}\n\ndata: incomplete".to_vec(),
        ),
    ];
    let (url, task) = server("200 OK", "text/event-stream; charset=utf-8", parts).await;
    let mut stream = client(&url)
        .stream_with_query(
            &["diagnostics", "cpu_usage", "stream"],
            &[("filter", "a & b")],
        )
        .await
        .unwrap();
    let event = stream.next_event().await.unwrap().unwrap();
    assert_eq!(event.event, "cpu");
    assert_eq!(event.id, "7");
    assert_eq!(event.json::<Value>().unwrap(), json!({"busy": 42}));
    assert_eq!(
        stream.next_json::<Value>().await.unwrap(),
        Some(json!({"busy": 43}))
    );
    assert!(stream.next_event().await.unwrap().is_none());
    assert!(stream.next_event().await.unwrap().is_none());
    let request = task.await.unwrap().to_lowercase();
    assert!(request.starts_with("get /api/diagnostics/cpu_usage/stream?filter=a+%26+b "));
    assert!(request.contains("authorization: basic a2v5onnly3jlda==\r\n"));
    assert!(request.contains("accept: text/event-stream\r\n"));
    assert!(!request.contains("accept: application/json"));
}

#[tokio::test]
async fn checks_status_content_type_and_error_body_limit() {
    let (url, task) = server(
        "403 Forbidden",
        "text/plain",
        vec![(Duration::ZERO, b"denied".to_vec())],
    )
    .await;
    match client(&url).cpu_usage_stream().await.err().unwrap() {
        Error::Http { status, body } => {
            assert_eq!(status.as_u16(), 403);
            assert_eq!(body, "denied");
        }
        other => panic!("unexpected: {other}"),
    }
    task.await.unwrap();
    let (url, task) = server("200 OK", "application/json", vec![]).await;
    assert!(matches!(
        client(&url).cpu_usage_stream().await,
        Err(Error::InvalidStreamContentType)
    ));
    task.await.unwrap();
    let (url, task) = server(
        "500 Error",
        "text/plain",
        vec![(Duration::ZERO, b"too long".to_vec())],
    )
    .await;
    let client = Client::builder(url, "key", "secret")
        .allow_http(true)
        .max_response_bytes(4)
        .build()
        .unwrap();
    assert!(matches!(
        client.cpu_usage_stream().await,
        Err(Error::ResponseTooLarge)
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn caps_frame_size_and_terminates_after_error() {
    let (url, task) = server(
        "200 OK",
        "text/event-stream",
        vec![(Duration::ZERO, b"data: 123456789".to_vec())],
    )
    .await;
    let client = Client::builder(url, "key", "secret")
        .allow_http(true)
        .max_response_bytes(10)
        .build()
        .unwrap();
    let mut stream = client.cpu_usage_stream().await.unwrap();
    assert!(matches!(
        stream.next_event().await,
        Err(Error::ResponseTooLarge)
    ));
    assert!(stream.next_event().await.unwrap().is_none());
    task.await.unwrap();
}

#[tokio::test]
async fn bad_json_does_not_poison_later_events() {
    let (url, task) = server(
        "200 OK",
        "text/event-stream",
        vec![(Duration::ZERO, b"data: bad\n\ndata: {}\n\n".to_vec())],
    )
    .await;
    let mut stream = client(&url).cpu_usage_stream().await.unwrap();
    assert!(matches!(
        stream.next_json::<Value>().await,
        Err(Error::Decode(_))
    ));
    assert_eq!(stream.next_json::<Value>().await.unwrap(), Some(json!({})));
    task.await.unwrap();
}

#[tokio::test]
async fn waits_for_event_deadline_and_survives_external_cancellation() {
    let (url, task) = server(
        "200 OK",
        "text/event-stream",
        vec![
            (Duration::ZERO, b"data: {\"busy\":".to_vec()),
            (Duration::from_millis(100), b"1}\n\n".to_vec()),
        ],
    )
    .await;
    let mut stream = client(&url).cpu_usage_stream().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), stream.next_event())
            .await
            .is_err()
    );
    assert_eq!(
        stream.next_json::<Value>().await.unwrap(),
        Some(json!({"busy": 1}))
    );
    task.await.unwrap();

    let (url, task) = server(
        "200 OK",
        "text/event-stream",
        vec![
            (Duration::ZERO, b": heartbeat\n\n".to_vec()),
            (Duration::from_secs(100), b": heartbeat\n\n".to_vec()),
        ],
    )
    .await;
    let client = Client::builder(url, "key", "secret")
        .allow_http(true)
        .build()
        .unwrap();
    let mut stream = client.cpu_usage_stream().await.unwrap();
    // Use paused time only after the local TCP connection has been opened.
    tokio::time::pause();
    assert!(matches!(stream.next_event().await, Err(Error::Timeout)));
    assert!(stream.next_event().await.unwrap().is_none());
    task.abort();
    tokio::time::resume();
}

#[tokio::test]
async fn total_stream_lifetime_can_exceed_timeout_and_helpers_use_right_paths() {
    let (url, task) = server(
        "200 OK",
        "text/event-stream",
        vec![
            (Duration::ZERO, b"data: 1\n\n".to_vec()),
            (Duration::from_millis(10), b"data: 2\n\n".to_vec()),
        ],
    )
    .await;
    let client = Client::builder(url, "key", "secret")
        .allow_http(true)
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();
    assert!(matches!(
        client.traffic_stream(0).await,
        Err(Error::Configuration(_))
    ));
    let mut stream = client.traffic_stream(1).await.unwrap();
    assert_eq!(stream.next_json::<u32>().await.unwrap(), Some(1));
    // Time spent in the caller must not expire the connection.
    tokio::time::sleep(Duration::from_millis(550)).await;
    assert_eq!(stream.next_json::<u32>().await.unwrap(), Some(2));
    assert!(
        task.await
            .unwrap()
            .starts_with("GET /api/diagnostics/traffic/stream/1 ")
    );
}
