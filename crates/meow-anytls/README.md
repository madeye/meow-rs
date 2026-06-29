# meow-anytls

Vendored copy of the [madeye fork](https://github.com/madeye/anytls-rs) of
`anytls-rs` — an async TLS proxy protocol implementation — pinned at the commit
that adds `Stream::close()` (`madeye/anytls-rs#1`,
`e6134889d3abbfaa2cb7439969dbda2ef6930611`).

## Why it's vendored

The `anytls-rs` crate on crates.io (`0.5.4`) is jxo-me's **upstream** project,
which does **not** provide `Stream::close()`. meow-proxy's anytls adapter calls
`close()` (the fd/stream-leak fix for issue #201 item 4), which only exists in
the madeye fork — and merged *after* the fork's own `v0.5.4` tag. As a result
meow-proxy could not compile the `anytls` feature against the registry
(see [issue #262](https://github.com/madeye/meow-rs/issues/262)).

Vendoring the fork's library source in-tree removes the external/registry
dependency entirely, so the `anytls` feature builds from a clean checkout and
meow-rs stays publishable to crates.io.

## Layout

- Library source only (`src/`); the upstream `src/bin`, `benches/`, `tests/`,
  and example/script files are intentionally omitted.
- The package is named `meow-anytls` (to avoid a crates.io name collision with
  upstream `anytls-rs`), but the library name is `anytls_rs`, so dependents'
  `use anytls_rs::...` paths are unchanged.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2024 Mickey and AnyTLS Contributors,
with fork modifications. This differs from the GPL-3.0 license of the rest of
the meow-rs workspace.

## Updating

This is a point-in-time vendor. To refresh, re-copy `src/` from the madeye fork
at the desired commit and update the pinned hash referenced above and in
`Cargo.toml`.
