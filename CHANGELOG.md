# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.1.0] - 2026-11-28

Changes since [v1.0].

### Upgrading from 1.0

These changes can break an existing setup.

Servers and configuration:

- **Listen address.** Servers listen on `127.0.0.1` instead of `0.0.0.0`. Set
  `bind_address = "0.0.0.0"` to stay reachable from outside.
- **UTNP config.** In `[[protocols]]`, `version` is now a list and
  `default-version` (a 1-based position in it) is required: `version = "1.0"`
  becomes `version = ["1.0"]` plus `default-version = 1`.
- **Unknown config keys** are an error (except inside `[scripting]`).
- **Compression cache.** TMUTP and TBIP create `./compression_cache` next to the
  config file at startup. They refuse to start if it cannot be created or if it
  lies inside `root` (for example, `root` is the directory of the config file).
  See `compression_cache` and `compression_cache_enable`.

Protocols and clients:

- **Protocol 2.0.** UTNP, TMUTP and TBIP 2.0 are the default. Clients that speak
  1.0 are refused unless `support_first_version = true`.
- **Connections stay open** after a response and are closed after 15 seconds of
  silence. A client that reads until end of stream, including the 1.0
  `utnp-client`, now waits those 15 seconds.
- **`utnp-client` uses TLS by default.** Against a server without TLS, use `--v1`
  (the server needs `support_first_version = true`) or
  `--allow-insecure-fallback`.
- **`utnp-client negotiate`** takes one protocol name, not a comma-separated list.
- **Request limits.** TMUTP bodies are limited to 1 MiB by default (`max_body`),
  `Transfer-Encoding` is rejected, TBIP requests must not have a body, and the
  size and number of headers, query and form fields are limited. Malformed
  header lines and extra words in the request line get `30`.
- **Connection limits.** By default 256 connections, 32 per address, and at most
  one hour per connection.
- **File size.** Files over 256 MiB (`max_file_size`) are not served.

Content:

- **Hidden files.** Dotfiles, dot-directories and `*.toml`, `*.pem`, `*.key`
  files are no longer served (`31`). Script sources are never served (`32`).
- **TBIP types.** `.txt` files are sent as `application/octet-stream` instead of
  `text/plain`.

Scripts:

- **File names.** The script suffix is appended to the whole name: `/api.v2` uses
  `api.v2.script.lua`, not `api.script.lua`. A request for `/index.tmkup` no
  longer runs `index.script.lua`; it looks for `index.tmkup.script.lua`.
- **Lua standard library** is restricted: `io`, `require`, `package`, `load`,
  `loadfile`, `dofile` and `collectgarbage` are gone, and `os` has only `time`
  and `clock`. Large inputs to `string` pattern functions are rejected.
- **Rhai** has no `eval` or `import` and limits operations and the size of
  strings, arrays and maps. `request.body` is a blob when it is not valid UTF-8.
- **Limits.** By default a script may run for 5 seconds, a Lua script may use
  64 MiB, and 32 scripts run at once.
- **File helpers** refuse `..` and symlinks leading outside `root`, cannot write
  or remove `.lua`, `.rhai` or script-suffix files, and read at most 16 MiB and
  write at most 8 MiB.
- **Responses.** The status must be a code known to the protocol, the headers
  that the server sets itself (such as `Content-Length`) are not allowed, and in
  Rhai every header value must be a string.
- **Script errors** are no longer sent to the client; details go to the log.

Building needs Rust 1.89+, and the project uses the Rust 2024 edition.

### Upgrading from the main branch before 2.1

For builds of the unreleased 2.0 code (commit `a9f2929`). The notes above on the
listen address, unknown configuration keys, the compression cache, connection and
file size limits, hidden files and scripts apply too. In addition:

- The TMUTP request body limit is 1 MiB by default instead of 16 MiB.
- A relative `compression_cache` is resolved against the config file's directory,
  not the current directory.
- TLS and SSH private keys accessible by group or others stop the server from
  starting (`security.strict_key_permissions = false` turns this into a warning).
- `tcurl` and `utnp-client` no longer fall back to plain TCP on their own; use
  `--allow-insecure-fallback`.
- `tcurl` ignores a different host announced over unprotected UTNP
  (`--trust-utnp-host` accepts it) and does not send `-H` headers to another
  host without that option.
- `tcurl` exits with a non-zero code for a status other than 2x and then does not
  write `--output` (`--output-on-error` does).
- `tcurl` decompresses gzip and zstd bodies and verifies `FILE-SHA256`; `--raw`
  keeps the body as received.

### Added

- `tcurl`, a client for `tmutp://` and `tbip://` URIs with UTNP discovery,
  decompression and `FILE-SHA256` verification.
- UTNP, TMUTP and TBIP 2.0, with 1.0 compatibility as an option.
- UTNP `EXPLORE` and version negotiation with `Supported-Versions`; `explore`
  and `negotiate --versions` in `utnp-client`.
- TLS and SSH transports on the same port as TCP, and `require_secure`.
- Byte ranges and gzip/zstd compression with an in-memory and an on-disk cache.
- Configurable connection, request, file size and cache limits.
- Limits on script running time, Lua memory and the number of concurrent scripts.
- Graceful shutdown on SIGINT and SIGTERM.
- The UTNP port is configurable (`port`, default 34).

### Changed

- The servers are asynchronous (Tokio) instead of one thread per connection, and
  cache file contents and compressed responses in memory.
- `[scripting]` may be left out of the TMUTP and TBIP configs.
- TBIP serves `index.tmkup` for `/` and other directory paths.
- Logs are written through `tracing` and filtered with `RUST_LOG`.
- The source is split into modules, with shared code in `src/common/`.

### Fixed

- TMUTP sends static files byte for byte instead of converting them to UTF-8.
- Lua scripts receive the request body byte for byte.
- `write_file` in Rhai can be called with a path and the data.
- `scripting.hot_reload = false` takes effect.

### Security

- Requests cannot leave `root` through `..`, percent-encoding or symlinks.
- Lua runs with a restricted standard library; file helpers stay inside `root`
  and cannot write or remove scripts.
- The minimum version of the `url` dependency is 2.5.9.

## [1.0] - 2026-11-17

First release: UTNP, TMUTP and TBIP 1.0 servers over TCP, `utnp-client`, and
Lua/Rhai scripting.

[2.1.0]: https://github.com/TextNet-Foundation/tnet-tools/compare/v1.0...v2.1
[v1.0]: https://github.com/TextNet-Foundation/tnet-tools/releases/tag/v1.0
[1.0]: https://github.com/TextNet-Foundation/tnet-tools/releases/tag/v1.0
