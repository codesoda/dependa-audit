# dependa-audit

A [Claude Code](https://docs.claude.com/en/docs/claude-code) skill that runs a
**supply-chain audit of a Dependabot PR**. For every dependency the PR bumps —
direct *and* transitive — it diffs the current version against the target version
and surfaces anything sketchy: new install hooks, new dependencies, a changed
publisher/maintainer, missing provenance, new network endpoints, or suspicious
code. The expensive per-package work runs in **parallel Sonnet subagents (max 5
concurrent)**, and the result is posted to the PR as inline findings on the
changed dependency lines plus an idempotent summary comment (verdict table +
written report) — the same report is also shown to you in the conversation.

This is a **defensive security tool**. The goal is to catch a compromised or
malicious dependency release *before it merges*. It is built to be skeptical, to
cite evidence for every flag, and to never invent findings.

## How it works

1. **Resolve & gate the PR** — fetch it, stop if it's closed/merged, and confirm
   the author is `app/dependabot`.
2. **Build the upgrade work-list** — the manifest/lockfile diff is ground truth.
   The PR body lists *direct* bumps but often omits transitive ones; the lockfile
   shows everything that actually changes. Transitive bumps are exactly where a
   malicious release hides, so they're included.
3. **Form audit units** — one unit per package (monorepo packages that move in
   lockstep to the same version may be grouped to save agents).
4. **Fan out** — dispatch units in batches of ≤5 parallel Sonnet subagents. Each
   runs the relevant bundled auditor, cross-checks the official changelog,
   verifies any publisher/maintainer change, and returns a structured verdict.
5. **Aggregate** — roll the unit verdicts into one recommendation for the PR.
6. **Post the audit** — each non-clean unit gets an inline review comment anchored
   to the line in the diff that declares its bump; the PR also gets one idempotent
   summary comment (verdict table + report). Hidden markers
   (`dependa-audit:finding:<pkg>` and `dependa-audit:summary`) let re-runs update
   in place and skip unchanged findings rather than nagging.

## Helper scripts

Three bundled scripts in [`scripts/`](scripts/) do the per-ecosystem registry and
tarball work. Each prints a **bounded, structured report** (no raw bundle dumps)
ending with an INTERPRETATION GUIDE, and is designed to be read by a subagent.

| Script | Ecosystem | Key checks |
|--------|-----------|------------|
| [`npm-audit.sh`](scripts/npm-audit.sh) `<pkg> <from> <to>` | npm / pnpm | publisher + SLSA provenance, install lifecycle hooks, dependency diff, maintainers, network-endpoint diff, suspicious-pattern scan over added code, string-literal diff (catches minified bundles), file/size deltas |
| [`crate-audit.sh`](scripts/crate-audit.sh) `<crate> <from> <to>` | Rust / cargo | `build.rs` add/change (the highest-risk Rust vector), proc-macro status, ownership, dependency diff, suspicious-pattern scan, embedded-payload heuristics |
| [`docker-audit.sh`](scripts/docker-audit.sh) `<image> <from-digest> <to-digest> [tag]` | Docker Hub | **tag integrity** (does the new digest match what the registry serves for the tag?), entrypoint/cmd/user/env/label diff, layer-command history. Prints a `docker buildx imagetools inspect` fallback for non-Docker-Hub registries |

All three use anonymous registry APIs — no daemon, no auth, no package install.

## Verdict levels

| Verdict | Meaning |
|---------|---------|
| ✅ **CLEAN** | Nothing notable. |
| 🟡 **NOTE** | Safe to merge, but the team should know something (e.g. publisher moved to a new owner, no provenance on a data-collecting SDK). |
| 🟠 **SUSPICIOUS** | A real anomaly that needs a human to look before merge. |
| 🔴 **BLOCK** | Evidence of a malicious or compromised release. |

The PR-level recommendation is the worst single verdict: any BLOCK → *do not
merge*; else any SUSPICIOUS → *hold for human review*; else any NOTE → *safe to
merge (notes below)*; else *safe to merge*.

## Installation

This repo is the canonical home of the skill. To make it available to Claude Code,
symlink it into your skills directory so every repo can use it:

```sh
ln -s "$PWD" ~/.skills/.agents/skills/dependa-audit
```

Claude Code discovers the skill via its `SKILL.md`, and the `allowed-tools` globs
match the scripts by the `/dependa-audit/scripts/...` path fragment, so the skill
works the same whether it's reached through the symlink or directly.

## Usage

Invoke the skill with a PR number or URL:

```
/dependa-audit 1234
/dependa-audit https://github.com/owner/repo/pull/1234
```

With no argument it lists open Dependabot PRs (`gh pr list --author
"app/dependabot" --state open`) and asks which to audit, or audits the PR for the
current branch if there is one. It audits **one PR per invocation**.

## Requirements

- [`gh`](https://cli.github.com/) — authenticated; used for all GitHub I/O
  (reading the PR, posting the comment).
- `curl` and `jq` — used by all three scripts for registry I/O.
- `npm` and `tar` — used by `npm-audit.sh` to pack and extract package tarballs.
- Network access to the relevant registries (npm registry, crates.io, Docker Hub).

If a script can't fetch a version, its metadata section still prints and the
verdict says so rather than guessing.

## What it deliberately does *not* flag

To stay useful, the audit avoids the false positives that burn reviewers:
`process.env.TZ` reads and `function exec(){}` helpers are benign; minified
single-line bundles make line-diffs noisy (the endpoint and string-literal diffs
are trusted over raw line counts); 40–64-char hex strings in test fixtures are
hashes/vectors, not payloads; documentation URLs are not exfiltration; and
`provenance: NONE` is a weakness to *note*, not a reason to block. A real finding
is **new, unexplained, and runtime-reachable**.

## Layout

```
.
├── SKILL.md            # the skill definition Claude Code loads
├── README.md           # this file
└── scripts/
    ├── npm-audit.sh
    ├── crate-audit.sh
    └── docker-audit.sh
```
