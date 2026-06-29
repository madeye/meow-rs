# Releasing meow-rs

meow-rs ships as **12 crates** published together to [crates.io](https://crates.io)
at a single workspace version. This is the checklist for cutting a release.

> [!IMPORTANT]
> **crates.io is append-only.** A published version can never be deleted, only
> *yanked*. You can never re-publish the same version number. Every release must
> bump the version. `0.15.0` is already taken — the next release is `0.15.1` (or
> `0.16.0`).

## One-time setup

1. Create a crates.io API token at <https://crates.io/settings/tokens> with the
   **publish-new** and **publish-update** scopes.
2. Add it to the repo as the **`CARGO_REGISTRY_TOKEN`** Actions secret
   (`Settings → Secrets and variables → Actions`). The
   [`publish.yml`](../.github/workflows/publish.yml) workflow reads it.
3. Confirm you own all 12 crate names on crates.io (you own 11 as of `0.15.0`;
   `meow-anytls` is new in this release and must be claimable under your account).

## The crates & publish order

All crates share the workspace version (`[workspace.package] version` in the root
`Cargo.toml`). `meow-bench` is **not** published. The publish order is dictated by
dependencies — including **dev-dependencies**, which crates.io validates at publish
time (e.g. `meow-tunnel` dev-depends on `meow-config`, so config goes first):

```
meow-common  meow-trie  meow-anytls  meow-transport   (leaves, no internal deps)
meow-rules   meow-dns                        (→ common, trie)
meow-proxy                                   (→ common, dns, transport, anytls)
meow-config                                  (→ common, trie, dns, rules, proxy)
meow-tunnel                                  (→ …, + dev-dep on config)
meow-listener  meow-api                      (→ tunnel, config)
meow-app                                     (→ everything)
```

## Release steps

1. **Green CI on `main`.** The release does not run the test suite; make sure
   [`test.yml`](../.github/workflows/test.yml) is passing first.

2. **Bump the version.** Edit `[workspace.package] version` in the root
   `Cargo.toml`. Because the internal deps are pinned to that version (e.g.
   `meow-common = { path = "…", version = "0.15.0" }`), bump those entries in
   `[workspace.dependencies]` to match the new version too.

3. **Refresh the lockfile.**
   ```bash
   cargo update -w        # re-resolve workspace members to the new version
   cargo check --workspace
   ```

4. **PR & merge to `main`** with the version bump (e.g. `chore(release): 0.15.1`).

5. **Tag and push** from the merged commit on `main`:
   ```bash
   git checkout main && git pull --ff-only
   git tag v0.15.1
   git push origin v0.15.1
   ```
   The tag push triggers [`publish.yml`](../.github/workflows/publish.yml), which
   verifies the tag matches the workspace version and publishes all 12 crates in
   order. (The workflow is idempotent — a re-run skips versions already on the
   registry, so a partial release can resume.)

6. **Dry-run option.** To rehearse without uploading, run the workflow manually
   (`Actions → Publish to crates.io → Run workflow`) with **dry-run** left ticked.

7. **Post-release.**
   - Verify: `cargo install meow-app` (or `cargo info meow-app`).
   - Cut a GitHub Release for the tag with notes / prebuilt binaries.

## Rate limits

- **New crate names:** burst of ~5, then ~1 per 10 minutes. This only bit the
  *first* publish (0.15.0). It does **not** apply to new versions of existing
  crates.
- **New versions of existing crates:** a much higher limit, so a normal release
  publishes all 11 crates back-to-back without throttling.

## `anytls-rs`

`anytls-rs` is an **opt-in, non-default** dependency (the `anytls` feature) pinned
to its crates.io release in `[workspace.dependencies]` — crates.io forbids `git`
dependencies, so it must stay a registry version, not the `madeye/anytls-rs` git
fork. If you need a newer fork change, publish it to crates.io first, then bump the
version here.

## Manual fallback

If the workflow is unavailable, publish locally (logged in via `cargo login`):

```bash
for c in meow-common meow-trie meow-transport \
         meow-rules meow-dns meow-proxy \
         meow-config meow-tunnel meow-listener meow-api \
         meow-app; do
  cargo publish -p "$c" || break   # waits for index propagation between crates
done
```
