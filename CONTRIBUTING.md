# Contributing

Use stable Rust with the Rustfmt and Clippy components installed. AWS-LC builds
native code, so a C/C++ toolchain and CMake are needed (Xcode Command Line Tools
on macOS, or the usual development tools on Linux).

From the repository root:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --doc
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
cargo package --locked
```

Tests use local HTTP/TLS servers and public test certificates. A real firewall
and `.env` are only needed to run the live examples. Never include real API
credentials or private certificates in issues, pull requests, or test fixtures.

For behavioral changes, include a focused regression test where appropriate.
Document changes to timeouts, authentication, certificate verification, or SSE
behavior. Keep requests and streams cancellation-safe and memory-bounded.

By contributing, you agree to license your contributions under either the MIT
license or Apache License 2.0, at the recipient's option.
