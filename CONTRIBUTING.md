# Contributing to Sordino

Thanks for your interest in contributing.

## Contributor License Agreement (required)

Sordino is licensed under the Business Source License 1.1, which converts to
AGPL-3.0-or-later on the schedule set in [LICENSE](LICENSE). Issuing under
BUSL and honoring that conversion requires the Licensor to hold sufficient
rights over the whole codebase, so every contribution requires agreement to
the short [Contributor License Agreement](CLA.md). You keep your copyright;
you grant the Licensor the license needed to keep the project's licensing
coherent.

To agree, add one signature line to [CONTRIBUTORS.md](CONTRIBUTORS.md) in
your first pull request, in the format described there. Pull requests from
contributors without a signature on file will not be merged.

If a contribution includes work that is not your original creation (vendored
code, ported snippets), say so in the pull request and identify its source
and license — the CLA does not cover third-party work.

## Development

Requires Rust ≥ 1.91.

```sh
cargo build --workspace
cargo test --workspace
```

Both must pass before a pull request is reviewed. Keep changes focused: one
concern per pull request.

## Submitting changes

1. Fork and branch from `main`.
2. Make your change, with tests for any behavior change.
3. Sign the CLA in `CONTRIBUTORS.md` (first pull request only).
4. Open a pull request describing what the change does and why.
