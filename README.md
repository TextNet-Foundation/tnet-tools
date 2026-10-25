# TNet Tools Package

A collection of Rust tools for the TNet text network: three TCP servers (UTNP, TMUTP, TBIP) and a UTNP client.

## Contents

| Binary | Default port | Purpose |
|--------|--------------|---------|
| `utnp-server` | 34 | Protocol discovery. Returns host:port for a requested protocol. |
| `tmutp-server` | 100 | Serves TMkUp documents, handles forms. Lua/Rhai scripting. |
| `tbip-server` | 81 | Serves binary files (images, audio, video). Lua/Rhai scripting. |
| `utnp-client` | — | CLI client for UTNP (LIST / NEGOTIATE). |

## Requirements

- Rust 1.70+
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
[[protocols]]
name = "tmutp"
version = "1.0"
host = "localhost"
port = 100

[[protocols]]
name = "tbip"
version = "1.0"
host = "localhost"
port = 81
```

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

## Running

```bash
./target/release/utnp-server   -c ./utnp-config.toml
./target/release/tmutp-server  -c ./tmutp-config.toml
./target/release/tbip-server   -c ./tbip-config.toml
```

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
- Script error → `40 SERVER ERROR` with the error text in the body.

## Project layout

```
tnet-tools/
├── Cargo.toml
├── utnp-config.toml
├── tmutp-config.toml
├── tbip-config.toml
├── src/
│   ├── server.rs          # UTNP server
│   ├── client.rs          # UTNP client
│   ├── tmutp.rs           # TMUTP server
│   ├── tbip.rs            # TBIP server
│   └── script_engine/
│       ├── mod.rs
│       ├── lua.rs
│       └── rhai.rs
└── www/                   # content and scripts
```

## License

GNU GPL v3.0
