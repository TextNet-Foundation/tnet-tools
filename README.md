# TNet Tools Package

A collection of Rust tools for the TNet text network: three TCP servers (UTNP, TMUTP, TBIP) and two clients.

## Contents

| Binary | Default port | Purpose |
|--------|--------------|---------|
| `utnp-server` | 34 | Protocol discovery. Returns host:port for a requested protocol. |
| `tmutp-server` | 100 | Serves TMkUp documents, handles forms. Lua/Rhai scripting. |
| `tbip-server` | 81 | Serves binary files (images, audio, video). Lua/Rhai scripting. |
| `utnp-client` | — | CLI client for UTNP (LIST / EXPLORE / NEGOTIATE). |
| `tcurl` | — | CLI client for TMUTP and TBIP; finds the server through UTNP. |

## Requirements

- Rust 1.89+ (edition 2024; required by `russh`)
- No external runtime dependencies (Lua is bundled via `mlua`)

## Build

```bash
cargo build --release
```

Binaries are placed in `target/release/`.

## Configuration

Each server reads a TOML file. Pass a custom path with `-c` / `--config`; otherwise it looks for `./<name>-config.toml`.

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

`version` lists the supported protocol versions; `default-version` is the 1-based position in that list used when the client names no version. A protocol may also set `security = ["tls", "ssh"]`: only the transports enabled in `[security]` are advertised.

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
| `port` | Listening port |
| `root` | Root directory for static files and scripts |
| `scripting.enabled` | Enable Lua/Rhai script execution |
| `scripting.lua_extension` | Suffix used to recognize Lua scripts |
| `scripting.rhai_extension` | Suffix used to recognize Rhai scripts |
| `scripting.order` | Order in which engines are checked |
| `scripting.hot_reload` | Re-read script from disk on every request |
| `scripting.hide_scripts_behind` | If true, `/foo.script.lua` is treated as `/foo` (executes the script instead of serving source) |
| `scripting.timeout_ms` | Time limit of one script run (default 5000) |
| `scripting.memory_limit_mb` | Memory limit of one Lua script, MiB (default 64) |
| `scripting.max_concurrent` | Scripts running at once, process-wide (default 32) |
| `scripting.queue_timeout_ms` | How long a request waits for a free script slot (default 5000) |
| `bind_address` | Address to listen on (default `127.0.0.1`) |
| `compression_cache` | Directory of the on-disk compression cache (default `./compression_cache`). Relative paths are resolved against the config file's directory. It must not lie inside `root`: the server refuses to start otherwise. Created with mode 0700 |
| `max_file_size` | Larger files are not served, bytes (default 256 MiB) |
| `file_cache_budget` | Total bytes of file content kept in the in-memory cache (default 256 MiB) |
| `security.strict_key_permissions` | Refuse to start if the TLS key or SSH host key is readable by group/others (default `true`; `false` only logs a warning) |
| `max_connections` | Simultaneous connections (default 256) |
| `max_connections_per_ip` | Simultaneous connections per client IP (default 32) |
| `max_connection_secs` | Maximum lifetime of one connection, seconds (default 3600) |
| `max_body` | TMUTP only: largest request body, bytes (default 1 MiB, was 16 MiB). TBIP requests never carry a body |

Unknown keys are rejected. UTNP accepts `max_connections`, `max_connections_per_ip`, `max_connection_secs` and `security.strict_key_permissions` as well.

## Running

```bash
./target/release/utnp-server   -c ./utnp-config.toml
./target/release/tmutp-server  -c ./tmutp-config.toml
./target/release/tbip-server   -c ./tbip-config.toml
```

On SIGINT (Ctrl+C) or SIGTERM a server stops accepting connections and waits up to 15 seconds for the active ones to finish.

## Scripting

Scripts live in the `root` directory and are looked up by request path:

- `/submit`  → `submit.script.lua` (or `.script.rhai`)
- `/docs/`   → `docs/index.script.lua`
- `/`        → `index.script.lua`

If a script exists for a path, it always runs. Static files are served only when no script matches.

### Handler signature

Every script must export `handle(request)` returning a response object.

`request` fields:

| Field | Type | Description |
|-------|------|-------------|
| `protocol` | string | `"tmutp"` or `"tbip"` |
| `method` | string | `GET`, `POST` (TMUTP); `GET`, `HEAD` (TBIP) |
| `path` | string | Request path without query |
| `query` | map | Parsed query parameters |
| `body` | string | Raw request body |
| `form` | map | Parsed form fields (application/x-www-form-urlencoded) |
| `headers` | map | Request headers (lower-case keys) |

Response fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `status` | int | yes | TMUTP/TBIP status code |
| `body` | string / bytes | no | Response body |
| `headers` | map | no | Extra headers (e.g. `Location`, `Content-Type`) |

### Helper functions

Available in both Lua and Rhai:

- `ok(body)` → `{ status = 20, body = body }`
- `empty()` → `{ status = 22 }`
- `redirect(location)` → `{ status = 21, headers = { Location = location } }`
- `error(status, body)` → `{ status = status, body = body }` (note: in Rhai the function is `err` to avoid a name clash)

File helpers (restricted to `root`):

- `read_file(path)`
- `write_file(path, data)`
- `exists(path)`
- `remove_file(path)`

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
        let mut body = "---tmk-meta\ntitle: \"Form Result\"\n---tmk-meta\n\n";
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
- Script error → `40 SERVER ERROR` with the generic text `The script could not be executed.`; details are written to the server log only.

## Security model

- The SSH transport accepts any client (auth `none`): traffic is encrypted, but there is no client authentication. This is deliberate.
- `Transfer-Encoding` is not supported: any request carrying that header is rejected with `30 BAD REQUEST` before its body is read.
- Scripts are limited in time and memory (`scripting.timeout_ms`, `scripting.memory_limit_mb`) and in concurrency.
- Private keys (TLS and SSH host key) must be mode 0600; with the default `strict_key_permissions = true` the server will not start otherwise.

## Project layout

```
tnet-tools/
├── Cargo.toml
└── src/
    ├── common/          # shared by the servers: framing, request parsing, paths,
    │                    # compression, file cache, connection handling, TLS/SSH config
    ├── script_engine/   # Lua and Rhai engines, sandbox and limits
    ├── server/          # utnp-server
    ├── client/          # utnp-client
    ├── tmutp/           # tmutp-server
    ├── tbip/            # tbip-server
    └── tcurl/           # tcurl
```

Config files and the content directory (`root`) are not part of the repository.

## License

GNU General Public License v3.0 or later (GPL-3.0-or-later)
