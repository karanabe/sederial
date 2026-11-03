# Sederial

A lightweight DNS forwarder and local A-record responder for Linux.
Supports UDP/TCP, domain-based forwarding, and operation without upstream DNS.

## Install

```sh
cargo install sederial --locked
```

For Debian/Ubuntu, download the `.deb` for your architecture from
[GitHub Releases](https://github.com/karanabe/sederial/releases/latest):

```sh
sudo apt install ./sederial_0.3.0_amd64.deb
```

Use `_arm64.deb` on arm64. The service stays stopped until configured and enabled.

## Configure and run

Create `/etc/sederial/sederial.toml` using the commented
[configuration example](packaging/sederial.toml), or edit the file installed by
the Debian package.

Use `[[route]]` for domain-based forwarding and `[[local]]` for local A records.
The most specific matching domain wins, including its subdomains. Omit
`[default]` for operation without a default upstream. Local names without data
for the requested type return NODATA; unmatched names without an upstream return
NXDOMAIN.

For the Debian package, validate the configuration and enable the service:

```sh
sederial --check
sudo systemctl enable --now sederial
```

For a foreground process with a custom configuration:

```sh
sederial --config ./sederial.toml
```

Restrict access to trusted clients. There is no ACL, response cache, or DNSSEC
validation. See [protocol support and limits](RFC-COMPLIANCE.md).

## Development

Rust 1.98.1 is pinned in `rust-toolchain.toml`.

```sh
cargo test --locked
cargo build --release --locked
```

## License

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE). Contributions are licensed
under the same terms unless explicitly stated otherwise.
