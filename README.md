<h1 align="center">TNet Tools</h1>

<p align="center"><em>Servers and command-line clients for the TNet text network, written in Rust</em></p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.1.0-brightgreen" alt="Version 2.1.0">
  <img src="https://img.shields.io/badge/rust-1.89%2B-orange" alt="Rust 1.89+">
  <img src="https://img.shields.io/badge/transport-TCP%20%7C%20TLS%20%7C%20SSH-blue" alt="TCP, TLS, SSH">
  <img src="https://img.shields.io/badge/scripting-Lua%20%7C%20Rhai-yellow" alt="Lua and Rhai">
  <img src="https://img.shields.io/badge/license-GPL--3.0--or--later-red" alt="GPL-3.0-or-later">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#tcurl">tcurl</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#scripting">Scripting</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="#русская-версия">По-русски</a>
</p>

----

**TNet Tools is everything needed to run and browse a TNet node.** A client asks
the UTNP server where a protocol lives, then talks to the TMUTP server for
documents or to the TBIP server for files. Every server accepts plain TCP, TLS
and SSH on one port.

| Binary | Conventional port | Purpose |
|--------|-------------------|---------|
| `utnp-server` | 34 | Protocol discovery: returns host and port for a requested protocol |
| `tmutp-server` | 100 | Serves TMkUp documents and handles forms, with Lua/Rhai scripting |
| `tbip-server` | 81 | Serves binary files (images, audio, video), with Lua/Rhai scripting |
| `tcurl` | - | Fetches `tmutp://` and `tbip://` URIs, finds the server through UTNP |
| `utnp-client` | - | Queries a UTNP server (`list`, `explore`, `negotiate`) |

----

## Quick start

Requirements: Rust 1.89+, a C compiler, `pkg-config` and the Lua 5.4
development files (on Debian and Ubuntu: `build-essential pkg-config
liblua5.4-dev`). Lua is **not** bundled: the TMUTP and TBIP servers link to the
system `liblua5.4`, so the machine that runs them needs it too.

```bash
cargo build --release
```

Binaries are placed in `target/release/`. The example below uses ports above
1024, so it needs no root, and plain TCP, so it needs no certificate.

```bash
mkdir -p demo/www
echo '# Hello, TNet' > demo/www/index.tmkup

cat > demo/utnp-config.toml <<'EOF'
port = 2034

[[protocols]]
name = "tmutp"
version = ["2.0"]
default-version = 1
host = "localhost"
port = 2100

[[protocols]]
name = "tbip"
version = ["2.0"]
default-version = 1
host = "localhost"
port = 2081
EOF

printf 'port = 2100\nroot = "demo/www"\n' > demo/tmutp-config.toml
printf 'port = 2081\nroot = "demo/www"\n' > demo/tbip-config.toml

./target/release/utnp-server  -c demo/utnp-config.toml  &
./target/release/tmutp-server -c demo/tmutp-config.toml &
./target/release/tbip-server  -c demo/tbip-config.toml  &
sleep 2

./target/release/tcurl -t --utnp-port 2034 tmutp://localhost/
./target/release/tcurl -t --utnp-port 2034 tbip://localhost/index.tmkup -o demo/copy.tmkup
```

Stop the servers with `kill %1 %2 %3`.

> `root`, the TLS paths and `ssh_host_key_path` are resolved against the current
> directory. A relative `compression_cache` is resolved against the config
> file's directory.

----

## tcurl

```bash
tcurl tmutp://example.org/                       # ask UTNP (port 34), then fetch
tcurl tmutp://example.org:u2034/                 # UTNP on port 2034
tcurl tmutp://example.org:2100/                  # skip UTNP, connect directly
tcurl tbip://example.org/photo.png -o photo.png  # download a file
tcurl tbip://example.org/photo.png --head        # headers only (TBIP)
tcurl --post -d 'name=bob' tmutp://example.org/form
tcurl -H 'Accept-Compression: zstd' tbip://example.org/big.txt -o big.txt
```

The status line, headers and transport messages go to stderr, the body to stdout
or to `--output`. When the server is looked up through UTNP, one
`Resolving ...` line also goes to stdout before the body, so use `-o` if you
need the exact body. On a terminal, control characters in the body are escaped.
The exit code is `0` for a 2x status and non-zero otherwise. For a 2x status,
gzip and zstd bodies are decompressed, and `FILE-SHA256` is verified when the
whole file was received (`--raw` turns both off). `tcurl` does not ask for
compression by itself: add `-H 'Accept-Compression: ...'`. Response bodies are
limited to 256 MiB.

With the default TLS transport, and with `-s`, the UTNP entry of the protocol
must advertise it (see [TLS and SSH](#tls-and-ssh)); otherwise `tcurl` stops
with a "security mismatch" error.

| Option | Effect |
|--------|--------|
| *(none)* | TLS. Plain TCP is **not** tried if TLS fails |
| `-s`, `--ssh` | Use SSH. The host key must be in `~/.ssh/known_hosts`. TLS is tried only if the connection is refused, or after other SSH failures with `--allow-insecure-fallback`; an untrusted host key is always fatal |
| `-t`, `--tcp` | Plain TCP (cannot be combined with `-s`) |
| `--us` `--ts` `--bs` | SSH for UTNP, TMUTP or TBIP only |
| `--utcp` `--ttcp` `--btcp` | Plain TCP for UTNP, TMUTP or TBIP only |
| `--allow-insecure-fallback` | Allow falling back to plain TCP when TLS/SSH cannot be established |
| `--ca-cert <PEM>` | Trust an additional CA (for example your own) |
| `--verify-for-sni <NAME>` | Name used for TLS SNI and certificate verification |
| `-i`, `--ignore-utnp-security` | Connect even if UTNP does not advertise the wanted transport |
| `--trust-utnp-host` | Accept a different host announced over unprotected UTNP. Also required to send `-H` headers to any host other than the one in the URI, even if UTNP was protected |
| `--post`, `-d`, `--data-file` | POST with a text or file body (TMUTP) |
| `--head` | HEAD request (TBIP) |
| `-H`, `--header` | Add a request header (`Host` and `Content-Length` are set by `tcurl`) |
| `-o`, `--output` | Save the body (only for 2x, unless `--output-on-error`) |
| `--output-header <FILE>` | Save the complete response as received, headers included, whatever the status |
| `--raw` | Do not decompress the body and do not check `FILE-SHA256` |
| `--utnp-port <PORT>` | UTNP port when the URI names none (default 34) |
| `--timeout <SECONDS>` | Connect and handshake timeout (default 15) |
| `--v1` | Protocol 1.0 everywhere, plain TCP (cannot be combined with SSH options or `--ca-cert`) |
| `--uv1` `--tv1` `--bv1` | Protocol 1.0 for UTNP (always plain TCP), TMUTP or TBIP only |

## utnp-client

```bash
utnp-client -H example.org list
utnp-client -H example.org negotiate tmutp --versions 2.0
utnp-client -H example.org explore
```

It uses TLS by default and SSH with `-s` (same host key and fallback rules as
`tcurl`). `-H` sets the host (default `localhost`), `-p` the port (default 34).
`--ca-cert`, `--verify-for-sni`, `--allow-insecure-fallback` and `--timeout`
work as in `tcurl`. `negotiate` takes exactly one protocol name. `--v1` speaks
UTNP/1.0 over plain TCP; it has no `explore` and ignores `--versions`. The
request, the transport and the response are printed to stdout.

----

## Configuration

Each server reads a TOML file. Pass its path with `-c` / `--config`; otherwise
the server looks for `./utnp-config.toml`, `./tmutp-config.toml` or
`./tbip-config.toml`. Unknown keys are an error everywhere except in
`[scripting]`, where they are silently ignored.

### UTNP

```toml
port = 34

[[protocols]]
name = "tmutp"
version = ["2.0"]
default-version = 1
host = "localhost"
port = 100

[[protocols]]
name = "tbip"
version = ["2.0"]
default-version = 1
host = "localhost"
port = 81
```

`version` lists the supported protocol versions; `default-version` is the
1-based position in that list used when the client names no version. When the
client sends `Supported-Versions`, the highest common version is chosen. `tcurl`
always sends one (`2.0`, or `1.0` with `--tv1`, `--bv1` or `--v1`). A protocol
may also set `security = ["tls", "ssh"]`: only the transports enabled in
`[security]` are advertised.

| Key | Description |
|-----|-------------|
| `port` | Listening port (default 34) |
| `protocols` | Required. Each entry: `name`, `version`, `default-version`, `host`, `port`, optional `security` |
| `explore.nodes` | Other UTNP nodes returned by `EXPLORE`: `version`, `host`, `description` |

`bind_address`, `support_first_version`, `max_connections`,
`max_connections_per_ip`, `max_connection_secs` and `[security]` work as
described below. In addition, `utnp-server` refuses to start with
`require_secure = true` when neither TLS nor SSH is enabled.

### TMUTP / TBIP

```toml
port = 100
root = "./www"

[scripting]
enabled = true
lua_extension = ".script.lua"
rhai_extension = ".script.rhai"
order = ["lua", "rhai"]
hot_reload = true
hide_scripts_behind = true
```

| Key | Description |
|-----|-------------|
| `port` | Listening port (required) |
| `root` | Root directory for static files and scripts (required) |
| `scripting.enabled` | Enable Lua/Rhai script execution (default `false`; required if the `[scripting]` section is present) |
| `scripting.lua_extension` | Suffix of Lua scripts (default `.script.lua`) |
| `scripting.rhai_extension` | Suffix of Rhai scripts (default `.script.rhai`) |
| `scripting.order` | Order in which engines are checked (default `["lua", "rhai"]`); an engine that is not listed is not used |
| `scripting.hot_reload` | Re-read the script from disk on every request (default `true`); `false` caches it until its modification time or size changes |
| `scripting.hide_scripts_behind` | Strip a script suffix from the request path, so `/foo.script.lua` runs the script of `/foo` (default `true`). Script sources are never served, whatever this is set to |
| `scripting.timeout_ms` | Time limit of one script run (default 5000) |
| `scripting.memory_limit_mb` | Memory limit of one Lua script, MiB (default 64) |
| `scripting.max_concurrent` | Scripts running at once, process-wide (default 32) |
| `scripting.queue_timeout_ms` | How long a request waits for a free script slot (default 5000) |
| `bind_address` | Address to listen on (default `127.0.0.1`) |
| `compression_cache` | Directory of the on-disk compression cache (default `./compression_cache`). Relative paths are resolved against the config file's directory. It must not lie inside `root`: the server refuses to start otherwise. Created with mode 0700 |
| `max_file_size` | Larger files are not served, bytes (default 256 MiB) |
| `file_cache_budget` | Total bytes of file content kept in the in-memory cache (default 256 MiB) |
| `support_first_version` | Also accept protocol 1.0 clients (default `false`) |
| `compression_minimum` | Smaller responses are not compressed, bytes (default 1024) |
| `compression_cache_enable` | Use the on-disk compression cache (default `true`) |
| `compression_cache_source_maximum` | Larger files are not written to the disk cache, bytes (default 64 MiB) |
| `max_connections` | Simultaneous connections (default 256) |
| `max_connections_per_ip` | Simultaneous connections per client IP (default 32) |
| `max_connection_secs` | Maximum lifetime of one connection, seconds (default 3600) |
| `max_body` | TMUTP only: largest request body, bytes (default 1 MiB, at most 256 MiB). TBIP requests never carry a body, and `tbip-server` rejects this key |

### TLS and SSH

```toml
[security]
enable_tls = true
tls_public_path = "certs/server.pem"
tls_private_path = "certs/server.key"
enable_ssh = true
ssh_host_key_path = "certs/ssh_host_ed25519_key"
require_secure = false
```

| Key | Description |
|-----|-------------|
| `security.enable_tls` | Accept TLS (default `false`); needs both TLS paths |
| `security.tls_public_path` | TLS certificate chain, PEM |
| `security.tls_private_path` | TLS private key, PEM |
| `security.enable_ssh` | Accept SSH (default `false`) |
| `security.ssh_host_key_path` | SSH host key (default `./ssh_host_ed25519_key`) |
| `security.require_secure` | Refuse plain TCP requests (default `false`) |
| `security.strict_key_permissions` | Refuse to start if a private key is accessible by group or others (default `true`; `false` only logs a warning) |

Add `security = ["tls", "ssh"]` to the UTNP protocol entries so that clients
learn which transports are available.

----

## Running

```bash
./target/release/utnp-server   -c ./utnp-config.toml
./target/release/tmutp-server  -c ./tmutp-config.toml
./target/release/tbip-server   -c ./tbip-config.toml
```

Servers listen on `127.0.0.1` unless `bind_address` says otherwise. Set
`bind_address = "0.0.0.0"` to accept connections from outside.

On SIGINT (Ctrl+C) or SIGTERM a server stops accepting connections and waits up
to 15 seconds for the active ones to finish. `docker stop` waits only 10
seconds by default; use `docker stop -t 20` to give the server its full time.
The log level is set with `RUST_LOG`.

### Connections

A connection is not closed after a response: it can carry further requests, and
the server closes it after 15 seconds of silence. A TMUTP or TBIP client should
read the body by `Content-Length` instead of waiting for end of stream. UTNP
responses have no length: over TCP or TLS, close the sending side after the
request and read to the end, as the bundled clients do.

----

## Static files

When no script handles a request, the file under `root` is served. A path that
ends in `/` means `index.tmkup` in that directory.

- Dotfiles, dot-directories and `*.toml`, `*.pem`, `*.key` files are answered
  with `31`, as if they did not exist.
- Files with a configured script suffix are never served (`32`).
- A path that leaves `root`, through `..` or a symlink, is answered with `32`.

TMUTP sends files as `text/tmkup`. TBIP picks `Content-Type` from the file
extension and falls back to `application/octet-stream`.

----

## Status codes

| Code | Meaning |
|------|---------|
| 20 | OK |
| 21 | Moved (see `Location`) |
| 22 | OK, empty |
| 23 | Multiple choices (TMUTP only, returned by scripts) |
| 30 | Bad request |
| 31 | Not found |
| 32 | Forbidden |
| 40 | Server error |
| 41 | Not implemented (TMUTP only, returned by scripts) |
| 42 | Service unavailable (connection limit or no free script slot) |
| 50 | Method not allowed |
| 51 | Version not supported |
| 52 | Invalid range |
| 53 | Range not satisfiable |
| 54 | Unsupported range |
| 55 | Secure transport required |

These codes are used by TMUTP and TBIP; UTNP reports errors as text
(`UTNP/2.0 ERROR ...`).

Ranges are single and closed, for `GET`: `Range: bytes=0-99`; an end past the
file is cut to its size. Compression is requested with
`Accept-Compression: gzip, zstd` (q-values are honored) and applied to bodies of
at least `compression_minimum` bytes. TBIP sends ranges larger than 256 KiB
uncompressed.

----

## Scripting

Scripts live in the `root` directory and are looked up by request path:

- `/submit`  → `submit.script.lua` (or `.script.rhai`)
- `/api.v2`  → `api.v2.script.lua` (the suffix is appended to the name)
- `/docs/`   → `docs/index.script.lua`
- `/`        → `index.script.lua`

If a script exists for a path, it always runs. Static files are served only when
no script matches. Scripting is off unless `scripting.enabled = true`.

### Handler signature

Every script must define `handle(request)` that returns a response (a Lua table
or a Rhai object map).

`request` fields:

| Field | Type | Description |
|-------|------|-------------|
| `protocol` | string | `"tmutp"` or `"tbip"` |
| `method` | string | `GET`, `POST` (TMUTP); `GET`, `HEAD` (TBIP) |
| `path` | string | Percent-decoded, normalized request path without the query |
| `query` | map | Parsed query parameters |
| `body` | string | Raw request body (empty for TBIP). In Rhai it is a blob if it is not valid UTF-8 |
| `form` | map | The body of a TMUTP `POST` parsed as `application/x-www-form-urlencoded`, whatever its `Content-Type` is (empty for TBIP) |
| `headers` | map | Request headers (lower-case keys) |

Response fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `status` | int | yes | A code from [Status codes](#status-codes) |
| `body` | string; blob in Rhai | no | Response body. Lua strings may hold any bytes |
| `headers` | map of strings | no | Extra headers (e.g. `Location`, `Content-Type`) |

`Content-Length`, `Content-Encoding`, `Content-Range`, `FILE-SHA256` and
`Supported-Compression` are set only by the server. A response that sets one of
them, has a malformed header or uses a code unknown to the protocol is replaced
by an error with status `50`. A number outside 20–55 is a script error (`40`).
TMUTP adds `Content-Type: text/tmkup` if the script sets none; TBIP adds no
`Content-Type`.

### Helper functions

Available in both Lua and Rhai:

- `ok(body)` → `{ status = 20, body = body }`
- `empty()` → `{ status = 22 }`
- `redirect(location)` → `{ status = 21, headers = { Location = location } }`
- `error(status, body)` → `{ status = status, body = body }` (in Rhai the function is `err`). In Lua, any call other than a number followed by a string, such as `error("message")`, is the standard Lua `error`

File helpers (restricted to `root`):

- `read_file(path)`: up to 16 MiB; in Rhai the file must be valid UTF-8
- `write_file(path, data)`: up to 8 MiB, creates missing directories; in Rhai `data` is a string
- `exists(path)`
- `remove_file(path)`

Paths are relative to `root`; `..` and symlinks that lead outside are refused.
`write_file` and `remove_file` also refuse files ending in `.lua`, `.rhai` or a
configured script suffix. Reading is not restricted like
[static files](#static-files): a script can read any file inside `root`.

### Limits

- Both engines: `scripting.timeout_ms`, `scripting.max_concurrent`,
  `scripting.queue_timeout_ms`. A script file may be up to 1 MiB.
- Lua: only the base functions, `table`, `string`, `math`, `utf8`, `coroutine`,
  `os.time` and `os.clock`. There is no `io`, `require`, `package`, `load`,
  `loadfile`, `dofile`, `debug` or `collectgarbage`. Memory is limited by
  `scripting.memory_limit_mb`. `string.find`, `match`, `gmatch` and `gsub` limit
  the subject to 1 MiB, the pattern to 256 bytes and 16 quantifiers.
- Rhai: no `eval` or `import`; 1,000,000 operations per run, strings up to
  1 MiB, arrays and maps up to 10,000 elements. `memory_limit_mb` does not apply.

### Example — Lua

```lua
function handle(request)
    if request.protocol ~= "tmutp" then
        return error(40, "Invalid protocol")
    end

    if request.method == "POST" then
        local params = request.form or {}
        local body = "---tmk-meta\ntitle: \"Form Result\"\n---tmk-meta\n\n"
        for key, value in pairs(params) do
            body = body .. key .. ": " .. value .. "\n"
        end
        return ok(body)
    elseif request.method == "GET" then
        return error(30, "GET not allowed. Use POST.")
    else
        return error(50, "Method not supported.")
    end
end
```

### Example — Rhai

```rhai
fn handle(request) {
    if request.protocol != "tmutp" {
        return err(40, "Invalid protocol");
    }

    if request.method == "POST" {
        let params = request.form;
        let body = "---tmk-meta\ntitle: \"Form Result\"\n---tmk-meta\n\n";
        for key in params.keys() {
            body += key + ": " + params[key] + "\n";
        }
        return ok(body);
    } else if request.method == "GET" {
        return err(30, "GET not allowed. Use POST.");
    } else {
        return err(50, "Method not supported.");
    }
}
```

### Script behaviour

- Script exists → it runs. Returning `nil` / `()` produces `22 OK EMPTY`.
- No script → static file is served.
- Script error or timeout → `40 SERVER ERROR` with the generic text `The script could not be executed.`; details are written to the server log only.
- No free script slot within `scripting.queue_timeout_ms` → `42 SERVICE UNAVAILABLE`.

----

## Security model

- The SSH transport accepts any client (auth `none`): traffic is encrypted, but there is no client authentication. This is deliberate.
- `Transfer-Encoding` is not supported: any request carrying that header is rejected with `30 BAD REQUEST` before its body is read.
- Scripts run with the [limits](#limits) above, but treat them as trusted code of the server owner: the sandbox guards against mistakes and runaway scripts, not against a hostile script author.
- Private keys (TLS and SSH host key) must not be accessible by group or others (`chmod 600`); with the default `strict_key_permissions = true` the server will not start otherwise.

----

## Development

```bash
cargo test --no-fail-fast
cargo clippy --all-targets
cargo fmt --check
```

Code rules are in [STYLE.md](STYLE.md), changes in [CHANGELOG.md](CHANGELOG.md).

----

## Project layout

```
tnet-tools/
├── Cargo.toml
├── CHANGELOG.md
├── STYLE.md         # code rules
├── deny.toml        # cargo-deny: licenses and advisories
└── src/
    ├── common/          # shared server code: framing, request parsing, paths,
    │                    # compression, file cache, connection handling, TLS/SSH config
    │                    # (utnp-server uses only the connection handling)
    ├── script_engine/   # Lua and Rhai engines, sandbox and limits
    ├── server/          # utnp-server
    ├── client/          # utnp-client
    ├── tmutp/           # tmutp-server
    ├── tbip/            # tbip-server
    └── tcurl/           # tcurl
```

Config files and the content directory (`root`) are not part of the repository.

----

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

----

## Русская версия

**TNet Tools: всё, чтобы поднять узел TNet и ходить по нему.** Клиент
спрашивает у сервера UTNP, где находится нужный протокол, а затем обращается к
серверу TMUTP за документами или к серверу TBIP за файлами. Каждый сервер
принимает обычный TCP, TLS и SSH на одном порту.

| Программа | Обычный порт | Назначение |
|-----------|--------------|------------|
| `utnp-server` | 34 | Обнаружение протоколов: отдаёт хост и порт |
| `tmutp-server` | 100 | Документы TMkUp и формы, скрипты Lua/Rhai |
| `tbip-server` | 81 | Бинарные файлы (картинки, звук, видео), скрипты Lua/Rhai |
| `tcurl` | - | Загружает адреса `tmutp://` и `tbip://`, находит сервер через UTNP |
| `utnp-client` | - | Запросы к UTNP (`list`, `explore`, `negotiate`) |

### Быстрый старт

Нужны Rust 1.89+, компилятор C, `pkg-config` и файлы разработки Lua 5.4 (в
Debian и Ubuntu: `build-essential pkg-config liblua5.4-dev`). Lua **не**
встроен: серверы TMUTP и TBIP используют системную `liblua5.4`, поэтому она
нужна и на машине, где они работают. Соберите проект командой
`cargo build --release` и выполните команды из раздела
[Quick start](#quick-start): они поднимают все три сервера на портах выше 1024
без сертификатов.

### tcurl

```bash
tcurl tmutp://example.org/                       # спросить UTNP (порт 34) и загрузить
tcurl tmutp://example.org:u2034/                 # UTNP на порту 2034
tcurl tmutp://example.org:2100/                  # без UTNP, напрямую
tcurl tbip://example.org/photo.png -o photo.png  # скачать файл
tcurl --post -d 'name=bob' tmutp://example.org/form
```

По умолчанию используется TLS, и при неудаче `tcurl` **не** переходит на
открытый TCP. Для TCP есть `-t`, для своего сертификата `--ca-cert`, для SSH
`-s` (ключ сервера должен быть в `~/.ssh/known_hosts`). С `-s` переход на TLS
происходит, только если в соединении отказано, а после других сбоев SSH лишь с
`--allow-insecure-fallback`.

Без `-t` и `-i` запись протокола в конфиге UTNP должна объявлять нужный
транспорт (`security = ["tls", "ssh"]`). Статус и заголовки выводятся в stderr,
тело в stdout, но при поиске через UTNP перед телом в stdout попадает ещё строка
`Resolving ...`: если нужно точное тело, используйте `-o`. Код выхода `0` только
для статусов 2x. Все ключи описаны в [таблице выше](#tcurl) и в `tcurl --help`.

`utnp-client` по умолчанию тоже использует TLS (`-s` для SSH, `--v1` для
UTNP/1.0 по открытому TCP).

### Настройка и запуск

- Конфиг задаётся ключом `-c`; ключи описаны в разделе
  [Configuration](#configuration).
- В конфиге UTNP `version` это список, а `default-version` это номер версии в
  нём, начиная с 1.
- По умолчанию серверы слушают только `127.0.0.1`. Чтобы принимать соединения
  снаружи, укажите `bind_address = "0.0.0.0"`.
- `root`, пути к сертификатам и ключам считаются от текущего каталога, а
  относительный `compression_cache` от каталога конфига. Кэш не должен лежать
  внутри `root`, и при включённом кэше у сервера должно быть право создать этот
  каталог.
- Приватные ключи не должны быть доступны группе и остальным (`chmod 600`),
  иначе сервер не запустится (если не задано `strict_key_permissions = false`).
- Клиенты протоколов 1.0 принимаются только при `support_first_version = true`.
- По SIGINT и SIGTERM сервер перестаёт принимать соединения и до 15 секунд ждёт
  завершения активных. `docker stop` по умолчанию ждёт лишь 10 секунд, поэтому
  используйте `docker stop -t 20`.
- После ответа соединение не закрывается: сервер закрывает его после 15 секунд
  тишины. Клиент TMUTP и TBIP должен читать тело по `Content-Length`.
- Скрытые файлы и каталоги (с точки), а также `*.toml`, `*.pem`, `*.key` не
  отдаются (`31`), исходники скриптов тоже (`32`).

### Скрипты и безопасность

Скрипты Lua и Rhai лежат в каталоге `root` и включаются через
`scripting.enabled = true`; формат запроса и ответа, коды статусов и ограничения
описаны в разделах [Scripting](#scripting) и [Status codes](#status-codes).
Ограничены время и число одновременных скриптов, память Lua и число операций и
размеры данных Rhai. В Lua нет `io`, `require` и `load`. Это защита от ошибок:
скрипты считаются доверенным кодом владельца сервера, и читать они могут любой
файл внутри `root`.

SSH пускает любого клиента: он шифрует канал, но не проверяет, кто подключился.
Запросы с заголовком `Transfer-Encoding` отклоняются.

История изменений и то, что может сломаться при обновлении:
[CHANGELOG.md](CHANGELOG.md). Лицензия: GPL-3.0-or-later.
