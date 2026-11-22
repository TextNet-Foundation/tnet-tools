# Style & Architecture Rules (tnet-tools)

## File & directory limits
- No directory may contain more than 4-5 source files. Group into subdirectories when exceeded.
- No source file may exceed ~450 lines (target 250-300). Split into focused modules.
- One responsibility per file/module (KISS, DRY, SOLID).

## Tests
- Tests must live in separate files from implementation code.
- Unit tests: `*_tests.rs` sibling included via `#[cfg(test)] #[path = "..._tests.rs"] mod tests;`.
- Integration tests: `tests/` directory at crate root.
- Never mix test code with production logic in the same file.

## Modules
- Shared logic goes to `src/common/` (path resolution, compression, file serving, framing).
- Protocol-specific code goes to `src/<protocol>/` (tmutp, tbip, utnp).
- Clients (tcurl, utnp-client) in their own directories.

## Rust conventions
- Edition 2024.
- Async code uses tokio::fs, never std::fs in async context; blocking work via spawn_blocking.
- No unwrap() in production paths; use ? with context.
- tracing for observability, not eprintln!.
- cargo fmt + cargo clippy clean before commit.
- No dead code / unused allows; remove unused items instead.

## Performance
- In-memory LRU for hot compressed responses; disk cache as fallback.
- File content cached by (mtime, size) -> Bytes.
- Canonicalize results cached per root.
