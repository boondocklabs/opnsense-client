use opnsense_client::{Client, Error, insight::*};
use serde_json::json;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

async fn server(status: &str, content_type: &str, body: &[u8]) -> (Client, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let mut response = format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    response.extend_from_slice(body);
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let mut buffer = [0; 1024];
            let n = stream.read(&mut buffer).await.unwrap();
            assert_ne!(n, 0);
            request.extend_from_slice(&buffer[..n]);
        }
        stream.write_all(&response).await.unwrap();
        String::from_utf8(request).unwrap()
    });
    (
        Client::builder(url, "key", "secret")
            .allow_http(true)
            .build()
            .unwrap(),
        task,
    )
}

fn range() -> TimeRange {
    TimeRange::new(1_700_000_000, 1_700_003_600).unwrap()
}

#[tokio::test]
async fn metadata_retains_provider_names_resolutions_and_sync_time() {
    let body = br#"{"aggregators":{"FlowInterfaceTotals":{"resolutions":[30,300,3600,86400]},"FutureProvider":{"resolutions":[60]}},"last_sync":1700003600}"#;
    let (client, task) = server("200 OK", "application/json", body).await;
    let metadata = client.insight().metadata().await.unwrap();
    assert_eq!(metadata.last_sync, Some(1_700_003_600));
    assert_eq!(
        metadata.aggregators[Dataset::InterfaceTotals.as_str()].resolutions,
        [30, 300, 3600, 86400]
    );
    assert!(metadata.aggregators.contains_key("FutureProvider"));
    assert!(
        task.await
            .unwrap()
            .starts_with("GET /api/diagnostics/networkinsight/get_metadata ")
    );
}

#[tokio::test]
async fn handles_empty_php_maps_without_swallowing_malformed_responses() {
    let (client, task) = server("200 OK", "application/json", b"[]").await;
    assert!(
        client
            .insight()
            .metadata()
            .await
            .unwrap()
            .aggregators
            .is_empty()
    );
    task.await.unwrap();
    let (client, task) = server("200 OK", "application/json", b"[]").await;
    assert!(client.insight().interfaces().await.unwrap().is_empty());
    task.await.unwrap();
    let (client, task) = server("200 OK", "application/json", b"[123]").await;
    assert!(matches!(
        client.insight().metadata().await,
        Err(Error::Decode(_))
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn reads_interface_protocol_and_service_maps() {
    let (client, task) = server("200 OK", "application/json", br#"{"igc0":"WAN"}"#).await;
    assert_eq!(client.insight().interfaces().await.unwrap()["igc0"], "WAN");
    task.await.unwrap();
    let (client, task) = server("200 OK", "application/json", br#"{"6":"tcp","17":"udp"}"#).await;
    assert_eq!(client.insight().protocols().await.unwrap()["6"], "tcp");
    assert!(
        task.await
            .unwrap()
            .starts_with("GET /api/diagnostics/networkinsight/get_protocols ")
    );
    let (client, task) = server("200 OK", "application/json", br#"{"443":"https"}"#).await;
    assert_eq!(client.insight().services().await.unwrap()["443"], "https");
    assert!(
        task.await
            .unwrap()
            .starts_with("GET /api/diagnostics/networkinsight/get_services ")
    );
}

#[tokio::test]
async fn time_series_uses_positional_arguments_and_preserves_milliseconds() {
    let body = br#"[{"key":"igc0,in","interface":"WAN","direction":"in","values":[[1700000000000,1.5],[1700000030000,0]]}]"#;
    let (client, task) = server("200 OK", "application/json", body).await;
    let query = TimeSeriesQuery::new(Dataset::InterfaceTotals, range(), 30).unwrap();
    let series = client.insight().time_series(&query).await.unwrap();
    assert_eq!(series[0].values[0].timestamp_millis, 1_700_000_000_000);
    assert_eq!(series[0].values[0].value, 1.5);
    assert_eq!(series[0].values[1].value, 0.0);
    assert_eq!(series[0].interface.as_deref(), Some("WAN"));
    let request = task.await.unwrap();
    assert!(request.starts_with("GET /api/diagnostics/networkinsight/timeserie/FlowInterfaceTotals/bps/1700000000/1700003600/30/if,direction "), "{request}");
    assert!(
        request
            .to_lowercase()
            .contains("authorization: basic a2v5onnly3jlda==")
    );
}

#[tokio::test]
async fn custom_grouping_and_measure_are_sent_without_changing_units() {
    let (client, task) = server("200 OK", "application/json", b"[]").await;
    let query = TimeSeriesQuery::new(Dataset::SourceAddressTotals, range(), 300)
        .unwrap()
        .measure(Measure::PacketsPerSecond)
        .group_by(&[Field::SourceAddress])
        .unwrap();
    assert!(
        client
            .insight()
            .time_series(&query)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(task.await.unwrap().starts_with("GET /api/diagnostics/networkinsight/timeserie/FlowSourceAddrTotals/packets_ps/1700000000/1700003600/300/src_addr "));
}

#[tokio::test]
async fn top_sources_filters_are_paired_and_url_encoded() {
    let body = br#"[{"src_addr":"2001:db8::1","total":123.5,"last_seen":"2026-10-23 12:00:00"},{"src_addr":"","total":4,"last_seen":""}]"#;
    let (client, task) = server("200 OK", "application/json", body).await;
    let query = TopQuery::sources(range())
        .limit(1)
        .unwrap()
        .interface("igc0")
        .unwrap()
        .filter(Field::SourceAddress, "2001:db8::1")
        .unwrap();
    let rows = client.insight().top(&query).await.unwrap();
    assert_eq!(rows.len(), 2); // The server may append an "other" row beyond the limit.
    assert_eq!(rows[0].total, 123.5);
    assert_eq!(rows[0].source_address.as_deref(), Some("2001:db8::1"));
    assert!(!rows[0].is_other());
    assert!(rows[1].is_other());
    let request = task.await.unwrap();
    assert!(request.starts_with("GET /api/diagnostics/networkinsight/top/FlowSourceAddrTotals/1700000000/1700003600/src_addr/octets/1?filter_field=if%2Csrc_addr&filter_value=igc0%2C2001%3Adb8%3A%3A1 "), "{request}");
}

#[tokio::test]
async fn top_ports_accepts_numeric_and_text_fields_and_packet_totals() {
    let body = br#"[{"dst_port":443,"protocol":"6","label":"https (tcp)","last_seen":1700000000,"total":5}]"#;
    let (client, task) = server("200 OK", "application/json", body).await;
    let query = TopQuery::ports(range()).measure(TotalMeasure::Packets);
    let rows = client.insight().top(&query).await.unwrap();
    assert_eq!(rows[0].destination_port.as_deref(), Some("443"));
    assert_eq!(rows[0].protocol.as_deref(), Some("6"));
    assert_eq!(rows[0].last_seen.as_deref(), Some("1700000000"));
    assert!(task.await.unwrap().starts_with("GET /api/diagnostics/networkinsight/top/FlowDstPortTotals/1700000000/1700003600/dst_port,protocol/packets/25 "));
}

#[tokio::test]
async fn details_supports_source_destination_service_and_direction_filters() {
    let (client, task) = server("200 OK", "application/json", b"[]").await;
    let query = TopQuery::details(range())
        .filter(Field::DestinationAddress, "192.0.2.1")
        .unwrap()
        .filter(Field::ServicePort, "443")
        .unwrap()
        .filter(Field::Direction, "in")
        .unwrap();
    assert!(client.insight().top(&query).await.unwrap().is_empty());
    assert!(task.await.unwrap().contains("/top/FlowSourceAddrDetails/1700000000/1700003600/if,direction,src_addr,dst_addr,service_port,protocol/octets/25?"));
}

#[tokio::test]
async fn csv_export_returns_text_and_checks_encoding_and_http_errors() {
    let csv = b"if,direction,octets\r\nigc0,in,123\r\n";
    let (client, task) = server("200 OK", "application/octet-stream", csv).await;
    assert_eq!(
        client
            .insight()
            .export_csv(Dataset::InterfaceTotals, range(), 300)
            .await
            .unwrap()
            .as_bytes(),
        csv
    );
    let request = task.await.unwrap();
    assert!(request.starts_with(
        "GET /api/diagnostics/networkinsight/export/FlowInterfaceTotals/1700000000/1700003600/300 "
    ));
    assert!(request.to_lowercase().contains("accept: */*"));
    let (client, task) = server("200 OK", "application/octet-stream", &[0xff]).await;
    assert!(matches!(
        client
            .insight()
            .export_csv(Dataset::InterfaceTotals, range(), 30)
            .await,
        Err(Error::InvalidText(_))
    ));
    task.await.unwrap();
    let (client, task) = server("403 Forbidden", "text/plain", b"denied").await;
    assert!(matches!(
        client
            .insight()
            .export_csv(Dataset::InterfaceTotals, range(), 30)
            .await,
        Err(Error::Http { .. })
    ));
    task.await.unwrap();
}

#[test]
fn invalid_queries_are_rejected_before_requests() {
    assert!(TimeRange::new(10, 10).is_err());
    assert!(TimeRange::new(20, 10).is_err());
    assert!(TimeRange::new(0, u64::MAX).is_err());
    assert!(TimeRange::last(Duration::ZERO).is_err());
    assert!(TimeRange::last(Duration::from_secs(u64::MAX)).is_err());
    assert!(TimeSeriesQuery::new(Dataset::InterfaceTotals, range(), 0).is_err());
    assert!(TopQuery::sources(range()).limit(0).is_err());
    assert!(TopQuery::sources(range()).group_by(&[]).is_err());
    assert!(
        TopQuery::sources(range())
            .group_by(&[Field::SourceAddress, Field::SourceAddress])
            .is_err()
    );
    assert!(
        TopQuery::sources(range())
            .filter(Field::DestinationPort, "443")
            .is_err()
    );
    assert!(
        TopQuery::interfaces(range())
            .group_by(&[Field::SourceAddress])
            .is_err()
    );
    for value in [
        "",
        "igc0,igc1",
        "a=b",
        "a'b",
        "a b",
        "$(test)",
        "a\nb",
        "a/b",
    ] {
        assert!(
            TopQuery::sources(range()).interface(value).is_err(),
            "{value}"
        );
    }
    let point: TimePoint = serde_json::from_value(json!([1700000000000_u64, 0.5])).unwrap();
    assert_eq!(
        serde_json::to_value(point).unwrap(),
        json!([1700000000000_u64, 0.5])
    );
    assert!(serde_json::from_value::<TopRow>(json!({"src_addr":"192.0.2.1"})).is_err());
    assert!(serde_json::from_value::<TopRow>(json!({"total":1,"protocol":{}})).is_err());
}
