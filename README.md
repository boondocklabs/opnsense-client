# opnsense-client

An unofficial OPNsense API client for Rust, with async JSON requests and live
CPU/traffic streams. This project is not affiliated with the OPNsense project.

Async Rust client for the OPNsense API, using Reqwest with Rustls on Tokio.
Reqwest 0.13 uses AWS-LC for cryptography, supporting ECDSA-with-SHA-512
certificate signatures (including P-384 and P-521 signing keys). Certificate
chain and hostname verification remain enabled; private CAs still need to be
trusted through `OPNSENSE_CA_CERT` or `add_root_certificate`. Verification uses
WebPKI with bundled public roots plus your explicitly configured certificates.
It shares a connection pool across clones and does not create a runtime or block
the calling thread during requests.

```rust,no_run
use opnsense_client::Client;
use serde_json::{Value, json};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(
        &std::env::var("OPNSENSE_URL")?,
        std::env::var("OPNSENSE_API_KEY")?,
        std::env::var("OPNSENSE_API_SECRET")?,
    )?;

    println!("{}", client.firmware_info().await?);
    let aliases: Value = client.get(&["firewall", "alias", "get"]).await?;
    let search: Value = client.post(
        &["firewall", "alias", "search_item"],
        &json!({"current": 1, "rowCount": 20, "searchPhrase": "LAN"}),
    ).await?;
    Ok(())
}
```

To use a local checkout in another application, add:

```toml
[dependencies]
opnsense-client = { path = "../opnsense-client" }
serde_json = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Adjust the path to your checkout. `get`, `get_with_query`, and `post` deserialize into
any owned Serde type, including `serde_json::Value`. Endpoint slices contain
module, controller, command, then optional path arguments; every element is
encoded independently. Use query parameters through `get_with_query`.

Create a key/secret pair for a user with the required API privileges under
**System → Access → Users**. Authentication uses HTTP Basic with that pair,
as described in the [OPNsense API guide](https://docs.opnsense.org/development/how-tos/api.html).
The base URL can be an origin (`https://firewall.local:8443`), a reverse-proxy
prefix, or a URL ending in `/api/`.

HTTPS certificate verification is enabled. For a private CA or self-signed
certificate, add a trusted PEM certificate:

```rust,no_run
use opnsense_client::{Certificate, Client};
use std::time::Duration;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::builder("https://firewall.local", "key", "secret")
    .add_root_certificate(Certificate::from_pem(&std::fs::read("OPNsense.pem")?)?)
    .timeout(Duration::from_secs(10))
    .max_response_bytes(4 * 1024 * 1024)
    .build()?;
# Ok(())
# }
```

Defaults are a 30-second deadline for the whole request and an 8 MiB response
limit, including error bodies. Redirects are disabled and the client does not
retry requests. Plain HTTP requires explicit `allow_http(true)` and exposes
credentials to the network. Debug output redacts credentials.

`Error` distinguishes configuration, transport, timeout, HTTP status, response
size, and JSON decoding failures. HTTP errors retain their body for inspection
but omit it from their display message. A successful HTTP status returns the
endpoint's JSON unchanged: inspect `result`, `status`, and validation fields
according to that endpoint. Responses vary between OPNsense versions and
plugins, so this crate does not claim comprehensive typed endpoint coverage.
Empty/non-JSON success responses produce `Error::Decode`.

The firmware helpers follow the [current firmware reference](https://docs.opnsense.org/development/api/core/firmware.html):
`firmware_info` uses GET and `firmware_status` uses POST. Generic methods allow
you to choose methods and command spellings for your installed version.

The examples load `.env` from the current directory or its
parents using `dotenvy`. Existing environment variables take precedence. A
missing `.env` is allowed; other loading errors are reported. The library itself
does not load environment files.

From the repository root, copy `.env.example` to `.env` and fill
in your URL, key, and secret. Optionally set `OPNSENSE_CA_CERT` to a PEM file.
`.env` is ignored by Git.

```sh
cp .env.example .env
cargo run --example firmware
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Tests use local HTTP servers; no firewall or credentials are required.

## Live streams

`cpu_usage_stream()` and `traffic_stream(poll_interval_seconds)` open OPNsense's
live CPU and interface traffic feeds. `stream(endpoint)` and
`stream_with_query(endpoint, query)` support other Server-Sent Events endpoints.
Authentication and TLS verification are the same as for ordinary requests.

```rust,no_run
# use opnsense_client::{Client, Result};
# use serde_json::Value;
# async fn example(client: &Client) -> Result<()> {
let mut stream = client.cpu_usage_stream().await?;
while let Some(sample) = stream.next_json::<Value>().await? {
    println!("{sample}");
}
# Ok(())
# }
```

Use `next_event()` to access raw data, event type, ID, and retry hints; use
`event.json::<T>()` or `next_json::<T>()` for typed payloads. EOF returns `None`;
unterminated events at EOF are discarded. Dropping the reader disconnects.
Transport failures, oversized frames, and timeouts terminate the stream.
JSON decoding failures consume that message and allow subsequent reads.
There are no automatic reconnects or `Last-Event-ID` replay requests.

The configured timeout limits opening the stream and each wait for a complete
event, rather than the total stream lifetime. Heartbeats do not reset that
deadline. Choose a timeout longer than the traffic poll interval. The response
size limit applies per SSE frame, including comments and metadata; complete
messages are yielded incrementally. Reads preserve parser state if externally
cancelled (for example with `tokio::select!`).

From the directory containing your `.env`, run:

```sh
cargo run --example stream -- cpu
cargo run --example stream -- traffic 5
```

The optional sample count stops the example after that many messages; otherwise
it runs until EOF, an error, or Ctrl-C.

## Development

Use stable Rust. Building AWS-LC requires a native C/C++ toolchain and CMake.
CI checks formatting, Clippy, tests, documentation, and packaging on GitHub;
the test suite runs on Linux and macOS without firewall access or credentials.
See [CONTRIBUTING.md](CONTRIBUTING.md) for local checks.

The certificates and keys under `tests/fixtures/` are deliberately public test
data. Real credentials, `.env` files, and local certificate/key files are
excluded from Git. The crate package also uses an explicit file allowlist.

## License

Licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
