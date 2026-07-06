# Releasing Sordino

A release is cut by pushing a `vX.Y.Z` tag, which triggers
[`.github/workflows/release.yml`](../.github/workflows/release.yml). The first
job (`verify`) is a cheap gate that fails in seconds if any of the tracked
versions disagree with the tag, *before* the multi-platform build matrix burns
CI minutes.

## Single source of truth

The workspace version lives in **one** place:

```toml
# Cargo.toml
[workspace.package]
version = "X.Y.Z"
```

Every crate inherits it via `version.workspace = true`, and the inter-crate
path-deps no longer carry their own `version = "..."` literals — bumping the
version is a one-line edit here. (Binaries ship as compiled artifacts built with
`--bin`, not via crates.io, so the path-dep version fields were dead weight that
desynced on every bump.)

Three plugin manifests still carry their own copy of the version (they are not
Cargo crates), and the release gate asserts all three match the tag:

- `sordino-plugin/.claude-plugin/plugin.json` — the Claude Code plugin manifest.
- `.claude-plugin/marketplace.json` — the `sordino` entry's `version` field.
- `codex-sordino-plugin/.codex-plugin/plugin.json` — the Codex plugin manifest.

## Release steps

1. **Bump the version** in `Cargo.toml` `[workspace.package] version` — the
   single source of truth.
2. **Match the plugin manifests** to the new version (all three the gate checks):
   - `sordino-plugin/.claude-plugin/plugin.json` (`.version`)
   - `.claude-plugin/marketplace.json` (the `sordino` plugin entry's `.version`)
   - `codex-sordino-plugin/.codex-plugin/plugin.json` (`.version`)
3. **Regenerate the lockfile** so `Cargo.lock` reflects the bumped workspace
   version:

   ```sh
   cargo build
   ```

   Commit the `Cargo.lock` change along with the version bumps.
4. **Tag and push**:

   ```sh
   git tag vX.Y.Z
   git push --tags
   ```

   The tag push triggers `release.yml`.

## What the verify gate enforces

The `verify` job asserts the tag matches every tracked version:

```
tag == Cargo.toml [workspace.package] version
    == sordino-plugin/.claude-plugin/plugin.json version
    == .claude-plugin/marketplace.json (sordino entry) version
    == codex-sordino-plugin/.codex-plugin/plugin.json version
```

Any mismatch fails the release with a `::error::` annotation naming the offending
file. The job has no Rust toolchain, so the Cargo version is parsed with `sed`
(not `cargo metadata`) and the JSON versions with `jq`.

After `verify` passes, the workflow tests the workspace, builds release binaries
for every supported platform, and ships them three ways: a force-pushed
`plugin-dist` branch (Claude Code plugin + per-platform binaries), a
force-pushed `codex-plugin-dist` branch (Codex plugin + binaries), and
per-platform tarballs/checksums attached to the GitHub Release.
