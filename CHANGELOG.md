# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.1.0] - 2026-11-28

Changes since [v1.0].

### Upgrading from 1.0

These changes can break an existing setup:

- **Listen address.** Servers listen on `127.0.0.1` instead of `0.0.0.0`. Set
  `bind_address = "0.0.0.0"` to stay reachable from outside.
- **UTNP config.** In `[[protocols]]`, `version` is now a list and
  `default-version` (a 1-based position in it) is required: `version = "1.0"`
  becomes `version = ["1.0"]` plus `default-version = 1`.
- **Protocol 2.0.** UTNP, TMUTP and TBIP 2.0 are the default. Clients that speak
  1.0 are refused unless `support_first_version = true`.
- **Unknown config keys** in the main, `security` and protocol sections are an
  error.
- **Private keys** readable by group or others stop the server from starting
  (`security.strict_key_permissions = false` turns this into a warning).
- **Request limits.** TMUTP bodies are limited to 1 MiB by default (`max_body`),
  `Transfer-Encoding` is rejected, and TBIP requests must not have a body.
- **Script errors** are no longer sent to the client; details go to the log.
- **Building** needs Rust 1.89+.

### Added

- `tcurl`, a client for `tmutp://` and `tbip://` URIs with UTNP discovery,
  decompression and `FILE-SHA256` verification.
- UTNP, TMUTP and TBIP 2.0, with 1.0 compatibility as an option.
- UTNP `EXPLORE` and version negotiation with `Supported-Versions`; the same
  commands in `utnp-client`.
- TLS and SSH transports on the same port as TCP, and `require_secure`.
- Byte ranges and gzip/zstd compression with an in-memory and an on-disk cache.
- Connection limits (total, per address, lifetime), file size and cache limits.
- Script limits: running time, Lua memory, number of concurrent scripts.
- Graceful shutdown on SIGINT and SIGTERM.
- The UTNP port is configurable (`port`, default 34).

### Changed

- The servers are asynchronous (Tokio) instead of one thread per connection, and
  cache file contents and compressed responses in memory.
- The source is split into modules, with shared code in `src/common/`; the
  project uses the Rust 2024 edition.

### Security

- Requests cannot leave `root` through `..`, percent-encoding or symlinks.
- Lua runs with a restricted standard library; file helpers stay inside `root`
  and cannot write or remove scripts.
- Plain-text fallback in the clients needs an explicit flag.
- `url` is at least 2.5.9.

## [1.0] - 2026-11-17

First release: UTNP, TMUTP and TBIP 1.0 servers over TCP, `utnp-client`, and
Lua/Rhai scripting.

[2.1.0]: https://github.com/TextNet-Foundation/tnet-tools/compare/v1.0...v2.1
[v1.0]: https://github.com/TextNet-Foundation/tnet-tools/releases/tag/v1.0
[1.0]: https://github.com/TextNet-Foundation/tnet-tools/releases/tag/v1.0
