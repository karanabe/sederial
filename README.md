<br />
<h1 align="center">Sederial</h1>
<h3 align="center">A lightweight DNS forwarder for split-DNS environments. Route internal domains to private DNS servers and everything else to your default upstream.</h3>
<br />
<br />

Sederial is a lightweight DNS forwarder for split-DNS networks on Linux. It
forwards UDP and TCP queries to different DNS servers by domain suffix. The
most specific matching route wins; other queries use the default servers.

## Configure

Create `sederial.toml`:

```toml
listen = "127.0.0.1:5300"

[default]
servers = ["1.1.1.1", "1.0.0.1"]

[[route]]
domain = "example.test"
servers = ["192.168.100.10"]
```

This sends queries for `example.test` and its subdomains to `192.168.100.10`.
IP addresses without a port use port 53. Choose a listener address reachable by
your clients and restrict access to trusted networks; Sederial has no client
access control.

## Run

Rust 1.98.1 is specified in `rust-toolchain.toml`. To validate the configuration
and start a local instance:

```sh
cargo run --locked -- --config ./sederial.toml --check
cargo run --locked -- --config ./sederial.toml
```

Query it with `dig -p 5300 @127.0.0.1 host.example.test`. Stop the process with
Ctrl+C. To run the tests, use `cargo test --locked`.

The default configuration path for the installed binary is
`/etc/sederial/sederial.toml`. The packaged systemd service can be started with
`sudo systemctl enable --now sederial` after editing that file.

### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version 2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
