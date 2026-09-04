# dependa-audit

Switching on Dependabot is good practice. It files the version bumps and closes
CVEs without anyone having to babysit a lockfile. The catch is that a Dependabot
PR tells you a number went up; it says nothing about what changed inside the
package. You're trusting that `1.2.3 → 1.2.4` is the same maintainer shipping the
same kind of code they shipped last time.

Usually it is. When it isn't, the PR looks identical to a routine bump:

- October 2021: an attacker took over the npm account behind
  [`ua-parser-js`](https://www.bleepingcomputer.com/news/security/popular-npm-library-hijacked-to-install-password-stealers-miners/),
  a parser pulled roughly 7 million times a week, and published three patch
  releases (0.7.29, 0.8.0, 1.0.0) whose `preinstall` script fetched a Monero miner
  and a password stealer the moment you ran `npm install`.
- March 2025: a stolen token re-pointed every version tag of
  [`tj-actions/changed-files`](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066)
  (v1 all the way through v45) at one malicious commit that dumped CI secrets into
  the build log. It reached more than 23,000 repositories (CVE-2025-30066), and
  anyone pinning the action by tag rather than commit SHA picked it up silently.

Neither announced itself in the PR title. Both are the kind of thing a reviewer
would catch given time to read the actual diff, the changelog, and the git history
behind every package — which nobody has, which is the whole reason Dependabot is
switched on in the first place.

dependa-audit reads that diff for you. For every package a PR bumps, direct and
transitive, it pulls both versions straight from the registry, compares them,
checks the change against the upstream changelog and the git tag/SHA it claims to
come from, and goes looking for the specific move each ecosystem gets attacked
through: a new install hook on npm or PyPI, a moved tag on a GitHub Action, a
`build.rs` on a crate, an `init()` or cgo block on a Go module. It also performs a
separate, read-only CI/build suitability review: it reconstructs the initial
Dependabot commit versus the final head, preserves human/reverted dependency
decisions, compares toolchain and image pins across CI/build/release paths, and
maps those relationships to existing test contracts. It deliberately does not
run a full API or desktop regression. The heavy per-package work runs in parallel
Sonnet subagents, five at a time. What comes back is a two-track verdict on the
PR: inline comments on flagged security or suitability findings, plus one summary
comment carrying both tables and a written report. You get the same report in the
conversation.

It's a defensive tool. The job is to catch a compromised or malicious release
before it merges, so it stays skeptical and cites a concrete fact for everything
it flags; it won't manufacture findings to look busy.

## How it works

1. **Resolve and gate the PR.** Fetch it, stop if it's already closed or merged,
   and confirm the author really is `app/dependabot`.
2. **Build the upgrade work-list from the lockfile.** The PR body lists the direct
   bumps and usually omits the transitive ones; the manifest/lockfile diff is
   ground truth, so that's what gets parsed. Transitive releases are exactly where
   a malicious version likes to hide, so they're in scope.
3. **Reconstruct PR decisions and context.** Compare the initial Dependabot
   commit with the final head and inspect later human commits/comments so reverted
   toolchain or image changes remain visible.
4. **Form audit units.** One per package, plus one CI/build suitability unit per
   PR. Monorepo packages that move in lockstep to the same version can share a
   package unit to save agents.
5. **Fan out.** Units run in batches of five parallel Sonnet subagents. Each
   security unit runs the right bundled auditor and reads the official changelog;
   the suitability unit inventories version relationships, compatibility signals,
   and existing CI/test coverage.
6. **Aggregate** the security and suitability verdicts into one recommendation.
7. **Post the audit.** Every non-clean security or non-clear suitability unit gets
   a review comment anchored to the relevant diff line when possible, and the PR
   gets one idempotent summary comment. Hidden markers
   (`dependa-audit:finding:<pkg>`, `dependa-audit:suitability:<scope>`, and
   `dependa-audit:summary`) let a re-run update old comments in place instead of
   stacking duplicates.

## Helper scripts

Seven scripts in [`scripts/`](scripts/) do the per-ecosystem registry, archive, and
read-only repository-context work. Each prints a bounded, structured report (no raw
bundle dumps) that ends in an INTERPRETATION GUIDE or suitability result, written to
be read by a subagent.

| Script | Ecosystem | Key checks |
|--------|-----------|------------|
| [`npm-audit.sh`](scripts/npm-audit.sh) `<pkg> <from> <to>` | npm / pnpm | publisher + SLSA provenance, install lifecycle hooks, dependency diff, maintainers, network-endpoint diff, suspicious-pattern scan over added code, string-literal diff (catches minified bundles), file/size deltas |
| [`crate-audit.sh`](scripts/crate-audit.sh) `<crate> <from> <to>` | Rust / cargo | `build.rs` add/change (the highest-risk Rust vector), proc-macro status, ownership, dependency diff, suspicious-pattern scan, embedded-payload heuristics |
| [`python-audit.sh`](scripts/python-audit.sh) `<pkg> <from> <to>` | PyPI (pip/poetry/uv) | `setup.py` / build-backend install hooks (these run on `pip install` from an sdist, the highest-risk Python vector), PEP 740 provenance + Trusted-Publishing source repo, author/maintainer change, dependency diff, plus sdist endpoint / suspicious-pattern / string-literal / embedded-payload scans |
| [`docker-audit.sh`](scripts/docker-audit.sh) `<image> <from-digest> <to-digest> [tag]` | Docker Hub | **tag integrity** (does the new digest match what the registry serves for the tag?), entrypoint/cmd/user/env/label diff, layer-command history. Prints a `docker buildx imagetools inspect` fallback for other registries |
| [`gha-audit.sh`](scripts/gha-audit.sh) `<owner/repo> <from-ref> <to-ref>` | GitHub Actions | **ref/tag integrity** (does the new SHA map to a real published tag, or did a tag move under you, as in the tj-actions case), `action.yml` execution-model change (node/docker/composite) and diff, env-injection into `$GITHUB_ENV`/`$GITHUB_PATH`, changed-file classification, known advisories |
| [`go-audit.sh`](scripts/go-audit.sh) `<module> <from> <to>` | Go modules | checksum transparency-log presence (`sum.golang.org`) and VCS-origin/tag match, the surfaces Go actually runs code through (`init()`, cgo/`#cgo`, `//go:generate`, `//go:linkname`), `go.mod` require/replace diff, new network hosts, embedded-payload scan |
| [`suitability-audit.sh`](scripts/suitability-audit.sh) `<pr> [owner/repo]` | CI/build suitability | initial-vs-final PR history, human/reverted decisions, CI/toolchain/image/package-manager version matrix, build/release paths, and targeted existing test-contract coverage; read-only, no checkout/build/test |

npm, crate, python, docker, and go hit anonymous public registry APIs; gha-audit
goes through your authenticated `gh` so it can read the Actions repo and its
advisories. The suitability script uses authenticated GitHub API reads for the PR
and its final tree. Pass `owner/repo` when invoking it outside the target checkout,
or provide a full GitHub PR URL so it can resolve the repository itself. None of
these scripts installs a package, checks out a branch, runs a build/test, or needs
a daemon.

Suitability is intentionally a separate track from supply-chain security. A
major/minor mismatch, unsupported engine/MSRV, unexplained human revert, or
changed production build path without suitable coverage is a `CONCERN`; an
explained patch-level drift or low-risk coverage gap is a `NOTE`. The reviewer
must cite the relevant pins, human rationale, and existing CI/test contract rather
than treating every version difference as a failure.

## Verdict levels

Security verdicts:

| Verdict | Meaning |
|---------|---------|
| ✅ **CLEAN** | Nothing notable. |
| 🟡 **NOTE** | Safe to merge, but the team should know something (e.g. publisher moved to a new owner, no provenance on a data-collecting SDK). |
| 🟠 **SUSPICIOUS** | A real anomaly that needs a human to look before merge. |
| 🔴 **BLOCK** | Evidence of a malicious or compromised release. |

Suitability verdicts:

| Verdict | Meaning |
|---------|---------|
| ✅ **CLEAR** | Relevant CI/build relationships are aligned or explicitly justified and covered. |
| 🟡 **NOTE** | An explained skew or low-risk coverage gap should be recorded, but does not block merging. |
| 🟠 **CONCERN** | An unresolved compatibility relationship, unsupported engine/MSRV, unexplained decision, or changed production build path lacks suitable coverage. |

The PR-level recommendation is the stricter of the two tracks: any security BLOCK
means *do not merge*; any security SUSPICIOUS or suitability CONCERN means *hold for
human review*; security or suitability NOTE means *safe to merge, notes below*;
otherwise *safe to merge*. A missing compatibility test alone is not evidence of a
compromised dependency.

## Installation

Install it straight from GitHub with the [`skills`](https://github.com/vercel-labs/skills)
CLI. Any public repo with a `SKILL.md` at its root is a valid source, and this one
qualifies:

```sh
npx skills add codesoda/dependa-audit
```

That downloads the repo, detects the skill, and copies it into your agent's skills
directory (Claude Code, Codex, Cursor, and 50+ others are supported). Manage it
with:

```sh
npx skills list                   # show installed skills
npx skills update dependa-audit   # pull the latest version
npx skills remove dependa-audit   # uninstall
```

The GitHub CLI's `gh skill` (v2.90+) reads the same Agent Skills format if you'd
rather use a native tool. It can also pin the install to a commit, which is worth
doing for a security tool: a tag can move, a commit hash can't. (That's not
theoretical: moving a tag is exactly how the tj-actions attack above landed.)

Claude Code discovers the skill through its `SKILL.md`, and the `allowed-tools`
globs match the bundled scripts by their `/dependa-audit/scripts/...` path
fragment, so the auditors run no matter where the skill ends up installed.

### Local development

Working on the skill itself? `skills` takes a local path, so install from a clone:

```sh
git clone https://github.com/codesoda/dependa-audit
npx skills add ./dependa-audit
```

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

- [`gh`](https://cli.github.com/), authenticated. It handles all GitHub I/O:
  reading PR metadata/history/tree, posting comments, and the Actions repo/advisory
  calls inside `gha-audit.sh`.
- `curl` and `jq` for the registry I/O every script does.
- `npm` for the `npm pack` that `npm-audit.sh` runs.
- `tar` to extract the npm, cargo, and PyPI archives. `go-audit.sh` wants `unzip`
  (or `bsdtar`) instead, since Go modules ship as zips.
- Network to whatever the audit touches: the npm registry, crates.io, PyPI, Docker
  Hub, the GitHub API, and the Go proxy plus its checksum database.

When a script can't fetch a version, its metadata section still prints and the
verdict says so rather than guessing.

## What it deliberately does *not* flag

A tool that cries wolf gets turned off, so the audit swallows the false positives
that burn reviewers. `process.env.TZ` reads and `function exec(){}` helpers are
benign. Minified single-line bundles make line-diffs useless, so the endpoint and
string-literal diffs are trusted over raw line counts. A 40–64-char hex string in
a test fixture is a hash or vector, not a payload; a documentation URL is not
exfiltration; `provenance: NONE` is a weakness worth a NOTE, not a block. For
Python, `re.compile(...)`, doctest `>>>` lines, an HTTP library opening its own
sockets, and a `setup.py` that just reads its version file or moves to a `src/`
layout are all expected. A `node16→node20` runtime bump on a GitHub Action is
housekeeping, and the hundreds of `unsafe`/asm/`//go:linkname` sites in a Go
syscall package are that package doing its job. A real finding is **new,
unexplained, and runtime-reachable**.

## Layout

```
.
├── SKILL.md            # the skill definition Claude Code loads
├── README.md           # this file
└── scripts/
    ├── npm-audit.sh
    ├── crate-audit.sh
    ├── docker-audit.sh
    ├── python-audit.sh
    ├── gha-audit.sh
    ├── go-audit.sh
    └── suitability-audit.sh
```
