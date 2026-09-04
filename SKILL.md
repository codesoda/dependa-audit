---
name: dependa-audit
description: Supply-chain and CI/build suitability audit of a Dependabot PR. For every dependency the PR bumps, diff the current vs target version for supply-chain risk, then review version alignment, build-image/toolchain compatibility, PR-history decisions, and existing CI coverage using parallel Sonnet subagents. Post a PR comment with both verdicts and a written report.
allowed-tools:
  - Bash(gh pr view:*)
  - Bash(gh pr list:*)
  - Bash(gh pr diff:*)
  - Bash(gh pr comment:*)
  - Bash(gh api:*)
  - Bash(git rev-parse:*)
  - Bash(git log:*)
  - Bash(*/dependa-audit/scripts/npm-audit.sh*)
  - Bash(*/dependa-audit/scripts/crate-audit.sh*)
  - Bash(*/dependa-audit/scripts/docker-audit.sh*)
  - Bash(*/dependa-audit/scripts/python-audit.sh*)
  - Bash(*/dependa-audit/scripts/gha-audit.sh*)
  - Bash(*/dependa-audit/scripts/go-audit.sh*)
  - Bash(*/dependa-audit/scripts/suitability-audit.sh*)
  - Bash(curl:*)
  - Bash(npm pack:*)
  - Bash(npm view:*)
  - Bash(jq:*)
---

# dependa-audit — supply-chain and CI/build suitability review of a Dependabot PR

Audit every dependency a Dependabot PR upgrades. For each package, diff the
**current version against the target version** and surface anything sketchy:
new install hooks, new dependencies, changed publisher/maintainer, missing
provenance, new network endpoints, or suspicious code. Separately review whether
the proposed change is suitable for this repository's build and CI contracts:
version skew between CI, toolchain declarations, Docker images, package managers,
and release paths; human decisions or reverted updates in the PR history; and
compatibility checks not covered by existing test scenarios. This is a focused
static suitability review, not a replacement for full API or desktop regression
coverage. The expensive work runs in **parallel Sonnet subagents (max 5 concurrent)**.
The result is a PR comment with security and suitability verdicts plus a written
report, and the same report shown to the user.

This is a defensive security task: the goal is to catch a compromised or malicious
dependency release before it merges. Be skeptical, cite evidence, never invent findings.

## Arguments

A PR number or URL. If none is given, run `gh pr list --author "app/dependabot"
--state open` and ask the user which one (or audit the PR for the current branch
if there is one). Audit **one PR per invocation**.

## Helper scripts

Seven bundled scripts live in `scripts/` next to this SKILL.md. Resolve their
**absolute paths** (the directory this SKILL.md was loaded from) and pass them to
each subagent. Each prints a bounded, structured report and ends with an
INTERPRETATION GUIDE.

- `scripts/npm-audit.sh <package> <from> <to>` — npm/pnpm packages.
- `scripts/crate-audit.sh <crate> <from> <to>` — Rust/cargo crates.
- `scripts/docker-audit.sh <image> <from-digest> <to-digest> [tag]` — Docker Hub
  images (anonymous registry API; verifies the new digest matches the live tag,
  diffs entrypoint/cmd/user/env/labels and layer history). For non-Docker-Hub
  registries it prints a `docker buildx imagetools inspect` fallback.
- `scripts/python-audit.sh <package> <from> <to>` — PyPI packages (pip/poetry/uv).
  Surfaces `setup.py`/build-backend install hooks, PEP 740 provenance (Trusted
  Publishing) with its source repo, dependency/author changes, and an sdist code diff.
- `scripts/gha-audit.sh <owner/repo> <from-ref> <to-ref>` — GitHub Actions (refs may
  be tags or SHAs). Verifies ref/tag integrity (does the new commit map to a real
  published tag?), owner/archived status, the `action.yml` execution model + diff,
  changed-file classification, and known advisories. Uses the GitHub API (`gh`).
- `scripts/go-audit.sh <module> <from> <to>` — Go modules. Confirms the checksum
  transparency log (`sum.golang.org`) notarises both versions and the VCS origin ties
  each to a real tag+commit, then diffs the reachable build/runtime surfaces Go
  actually has — `init()`, cgo/`#cgo`, `//go:generate`, `//go:linkname` — plus
  `go.mod` `require`/`replace` changes and new network hosts. Uses the Go proxy
  (`proxy.golang.org`); no build, no `go` toolchain required.
- `scripts/suitability-audit.sh <pr> [owner/repo]` — read-only repository-context
  review. Reconstructs the initial Dependabot change versus the final head,
  surfaces human/reverted dependency decisions, inventories CI/toolchain/image
  pins, and reports nearby test-contract coverage. It does not checkout, build,
  or run the target project's tests.

## Steps

Make a todo list first.

1. **Resolve & gate the PR.** Use a Haiku agent to fetch the PR (`gh pr view <n>
   --json state,isDraft,author,title,body,baseRefName,baseRefOid,headRefName,
   headRefOid,commits,url`). Stop if it is closed or merged. Confirm the author is
   `app/dependabot` (if not, tell the user this isn't a Dependabot PR and ask
   whether to continue). Draft is fine. The suitability helper may be run against
   a closed/merged PR for regression validation, but that is not an audit posting
   bypass.

2. **Build the upgrade work-list — the manifest/lockfile diff is ground truth.**
   The PR body table lists *direct* bumps but often omits transitive ones; the
   lockfile shows everything that actually changes. Use a Haiku agent to read the
   PR diff (`gh pr diff <n>`) and extract every `{ecosystem, package, from, to,
   direct|transitive}` from the changed manifests/lockfiles:
   - npm/pnpm: `package.json` + `pnpm-lock.yaml` (or `package-lock.yaml`)
   - cargo: `Cargo.toml` + `Cargo.lock`
   - docker: `Dockerfile*` / `*.yml` image digests or tags
   - pypi: `pyproject.toml` / `requirements*.txt` / `setup.py` + lock (`poetry.lock`,
     `uv.lock`, `Pipfile.lock`, `pdm.lock`)
   - github-actions: `.github/workflows/*.yml` (and `action.yml`) `uses: owner/repo@ref`
     pins — the bumped `ref` is a tag or commit SHA, usually with a `# vX` comment
   - gomod: `go.mod` + `go.sum` — each `require` line is `<module> <version>`; the
     `go.sum` has two hashes per module (`<module> <v>` and `<module> <v>/go.mod`)
   Include transitive bumps — those are exactly where a malicious release hides.

3. **Reconstruct the PR decision history and context.** Run the bundled
   suitability auditor once for the PR:
   `/absolute/path/to/dependa-audit/scripts/suitability-audit.sh <pr> <owner/repo>`.
   Read its full output. It compares the first Dependabot commit with the final
   head, so a human-reverted image or toolchain bump cannot disappear merely
   because it is absent from the final net diff. Treat a reverted update as a
   reviewed decision (not a final package to audit) and preserve its rationale,
   final value, and compatibility implications in the suitability report.

4. **Form supply-chain audit units.** One unit per package. You MAY group packages
   from the same monorepo that move in lockstep to the same version (e.g. all
   `@statsig/*` 3.33.0→3.33.1, or all `@typescript-eslint/*`) into a single unit
   to save agents — but never group unrelated packages. Each unit names its
   ecosystem.

5. **Form one CI/build suitability unit per PR** in addition to the package
   units. It covers the related version matrix and build/release paths, not a
   second full package diff. Include it even when a proposed dependency update
   was reverted or the final diff contains only a test assertion.

6. **Make a todo entry per supply-chain and suitability unit** so progress is
   visible.

7. **Fan out — parallel Sonnet subagents, at most 5 running at once.** Dispatch
   units in batches of ≤5 (multiple Agent calls in one message = concurrent), wait
   for the batch, then dispatch the next, until all units are done. Every audit
   subagent uses model **sonnet** (the latest Sonnet) and `subagent_type:
   general-purpose`. Give each subagent this brief (filled in for its unit):

   > You are auditing a dependency upgrade in a Dependabot PR for supply-chain
   > risk. Package(s): `<names>`. Ecosystem: `<npm|cargo|docker|pypi|gha|gomod>`. Versions:
   > `<from>` → `<to>`.
   >
   > a. Run the bundled auditor and read its full output:
   >    - npm:    `<abs>/scripts/npm-audit.sh <pkg> <from> <to>`
   >    - cargo:  `<abs>/scripts/crate-audit.sh <crate> <from> <to>`
   >    - docker: `<abs>/scripts/docker-audit.sh <image> <from-digest> <to-digest> <tag>`
   >    - pypi:   `<abs>/scripts/python-audit.sh <pkg> <from> <to>`
   >    - gha:    `<abs>/scripts/gha-audit.sh <owner/repo> <from-ref> <to-ref>`
   >    - gomod:  `<abs>/scripts/go-audit.sh <module> <from> <to>`
   >    (For a monorepo group, run it once per package.)
   > b. Cross-check the **official changelog/release notes** for this exact version
   >    range (the package's GitHub releases/CHANGELOG via `gh release`/WebFetch).
   >    Does the code/size/dependency delta match what the release claims? A diff
   >    far larger than the changelog implies, or undocumented new behavior, is a flag.
   > c. If the **publisher, maintainer, or owner changed** between versions, decide
   >    whether it is explained (account rename, org transfer, public acquisition)
   >    or suspicious. Use WebSearch to verify before concluding. An unexplained
   >    publisher change on a package that reads secrets or makes network calls is
   >    a serious flag.
   > d. (docker only) Run `docker-audit.sh` with the image, both digests, and the
   >    tag (parse `image:tag@sha256:...` from the Dockerfile). The key check is
   >    TAG INTEGRITY — the new digest should match what the registry serves for
   >    that tag. Also confirm the image's `source` label points at the expected
   >    upstream repo. Flag a tag mismatch, a changed entrypoint/cmd/user, new ENV
   >    pointing at unexpected hosts, a base-image major jump, or a source-label
   >    change. (Non-Docker-Hub registry → use the `docker buildx imagetools
   >    inspect` fallback the script prints.)
   > e. (github-actions only) Run `gha-audit.sh <owner/repo> <from-ref> <to-ref>` with
   >    the old/new pins from the `uses:` line. The key check is REF/TAG INTEGRITY —
   >    the new commit SHA must map to a real published tag matching Dependabot's
   >    `# vX` comment; an untagged or moved-tag pin is a flag. Also flag an
   >    execution-model change (node↔docker↔composite), a new `image: docker://`
   >    external container, an added pre/post hook, env-injection (writes to
   >    `$GITHUB_ENV`/`$GITHUB_PATH`, `::set-env`), or secret reads paired with new
   >    network egress. If the script lists an advisory, check whether the upgrade
   >    crosses its fix — that is a reason to merge, not to block.
   > f. (gomod only) Run `go-audit.sh <module> <from> <to>`. Go has no install
   >    scripts, so the surfaces that run code are narrower and specific: a NEW
   >    `init()` (runs on import), a NEW cgo/`#cgo` block (compiles C at build time),
   >    or a NEW `//go:linkname`/`unsafe`/asm reach. The script reports these as
   >    per-version COUNTS plus the ADDED lines — judge the *added* ones, not the
   >    baseline (a syscall/crypto module legitimately carries hundreds). Confirm both
   >    versions are `present in transparency log` and the VCS origin URL is unchanged;
   >    a missing checksum entry or a changed origin is a serious flag. Also flag a new
   >    `replace` pointing at a fork and any new external network host.
   >
   > Apply this judgment (do not over-flag — these are the false positives that
   > burned a prior reviewer): `process.env.TZ` reads and `function exec(){}`
   > helpers are benign; minified single-line bundles make line-diffs noisy, so
   > trust the script's ENDPOINT diff and string-literal diff over raw line counts;
   > 40–64-char hex strings in test fixtures are hashes/vectors, not payloads;
   > documentation URLs (the package's own site, MDN) are not exfiltration;
   > `provenance: NONE` is a weakness to NOTE, not a reason to block; an HTTP
   > client inside an HTTP library is expected. (Python) a `setup.py` that only
   > reads `__version__.py` or moves to a `src/` layout is benign — flag a setup.py
   > doing network/subprocess/exec or reading credentials; `os.environ` config reads
   > and `.netrc`/`pickle` inside a library's own auth/serialization code are not
   > exfiltration. (GitHub Actions) big `node_modules`/`dist` churn and the action's
   > own `GITHUB_TOKEN`/GitHub-API use are expected, and a `node16→node20` runtime
   > bump is routine — flag new EXTERNAL egress, env-injection, or a SHA no tag points
   > at. (Go) high baseline counts of `unsafe`/asm/`//go:linkname` are expected in a
   > syscall or crypto module and a `//go:generate` only runs on explicit `go generate`;
   > judge what the bump ADDS — a new `init()`/cgo block doing network/exec/file I/O, a
   > new `replace` to a fork, or a version missing from the checksum log. A real finding
   > is NEW, unexplained, and runtime-reachable.
   >
   > Return ONLY this structure, no prose around it:
   > ```
   > UNIT: <package(s)>
   > ECOSYSTEM: <npm|cargo|docker|pypi|gha|gomod>
   > VERSIONS: <from> -> <to>   (<direct|transitive>)
   > VERDICT: CLEAN | NOTE | SUSPICIOUS | BLOCK
   > install_hooks: <none | details>
   > new_dependencies: <none | list>
   > publisher_change: <no | old -> new — explanation/verification>
   > provenance: <slsa-v1 | none | n/a>
   > network_endpoints: <unchanged | new: ...>
   > code_diff: <one line: size delta + nature of change + any suspicious pattern>
   > changelog_match: <consistent | mismatch: ...>
   > evidence: <the 1–3 facts that justify the verdict, with sources>
   > note: <one line for the report, or empty>
   > ```

   **Suitability review (one per PR).** In a separate Sonnet agent, run
   `/absolute/path/to/dependa-audit/scripts/suitability-audit.sh <pr> <owner/repo>`
   and read its full output. This is a static CI/build review, not a second package
   security scan and not a full application regression. Check all of the following:

   - Compare the initial Dependabot commit, the final net diff, later human commits,
     and review/comment rationale. A dependency or image update that was reverted
     must remain visible as a decision with its proposed value, final value, and
     explanation; do not silently drop it because it is absent from the final diff.
   - Build a version matrix across changed and related paths: `rust-toolchain.toml`,
     `Cargo.toml` `rust-version`, CI toolchain actions and environment variables,
     Docker `FROM` images and build args, Node/npm/pnpm pins, package `engines` and
     `packageManager`, GitHub Action runtimes, Terraform/deployment image tags,
     and release/build scripts. Compare the role and scope of each pin, not only
     literal equality.
   - Evaluate compiler/MSRV and target/ABI compatibility, builder-versus-runtime
     image compatibility, native-module/runtime compatibility, architecture/base-OS
     changes, floating versus immutable tags, and whether the changed version is
     used in production, release, or CI-only paths. Verify official compatibility
     claims when the matrix or release notes requires it.
   - Inventory existing CI/test contracts for each signal. Identify the exact test
     or job that covers it, whether it actually exercises the affected build/image,
     and any uncovered cross-document invariant. Lack of a test is a coverage gap
     to report, not proof that the dependency is broken.
   - Treat a major/minor toolchain or runtime mismatch, an unsupported engine/MSRV,
     an unexplained reverted decision, or a changed production build path without
     suitable coverage as `CONCERN`. Treat an explained decision, an acceptable
     patch-level drift, or a known uncovered-but-low-risk invariant as `NOTE`.
     Use `CLEAR` only when the relevant relationships are either aligned or
     explicitly justified and covered. Do not call a compatibility issue
     `SUSPICIOUS` or `BLOCK` without separate supply-chain evidence.

   Return only this structure:
   ```
   SUITABILITY_UNIT: CI/build compatibility for <repo>#<pr>
   SUITABILITY_VERDICT: CLEAR | NOTE | CONCERN
   version_matrix: <relevant declarations and observed values>
   history_decisions: <proposed/reverted changes, rationale, or none>
   compatibility_signals: <signals and why they are acceptable or concerning>
   coverage: <covered | partial | not covered — paths/jobs and gaps>
   evidence: <the 1–3 concrete facts supporting the verdict, with sources>
   note: <one line for the report, or empty>
   ```

   **Supply-chain verdict meaning:** CLEAN = nothing notable. NOTE = safe to merge
   but the team should know something (e.g. publisher moved to a new owner, no
   provenance on a data-collecting SDK). SUSPICIOUS = a real anomaly that needs a
   human to look before merge. BLOCK = evidence of a malicious/compromised release.

8. **Aggregate.** Collect all supply-chain and suitability results separately.
   The security recommendation remains:
   - any BLOCK → **Do not merge — investigate.**
   - else any SUSPICIOUS → **Hold for human review.**
   - else any NOTE → **Safe to merge (security notes below).**
   - else → **Safe to merge.**

   Then apply the suitability result without conflating it with compromise:
   - `CONCERN` → **Hold for human review** until the compatibility issue is
     resolved or explicitly accepted by an owner.
   - `NOTE` → retain **Safe to merge**, but include the version skew, decision
     rationale, and coverage gap in the report.
   - `CLEAR` → no suitability qualification.
   The overall recommendation is the stricter of these two tracks. A missing
   compatibility test alone is not a security finding and must not become
   `SUSPICIOUS` or `BLOCK`.

9. **Re-confirm** the PR is still open (Haiku agent) before posting.

10. **Post the audit — anchored review comments for findings + an idempotent
   summary** (mirrors pr-code-review: things needing attention thread inline under
   "Files changed"; the overview is a separate summary comment).

   a. **Build the anchor map.** Get the head sha
      (`gh pr view <n> --json headRefOid -q .headRefOid`) and parse `gh pr diff <n>`
      to find, for each unit, the `{path, line}` of the changed line in the NEW file
      that declares its bump — a `+` line inside a diff hunk. Prefer the
      human-readable manifest (`package.json` / `Cargo.toml` / `Dockerfile`) over the
      lockfile. For a monorepo group, use the first member's line. For a cargo bump
      that only touches `Cargo.lock`, anchor to the `+version = "<to>"` line under
      that crate's `name = "<crate>"` block. For docker, the changed `FROM …` line.
      `line` is the new-file (RIGHT-side) line number and must fall inside a hunk.

   b. **Inline finding comment for every non-CLEAN security unit** (NOTE /
      SUSPICIOUS / BLOCK) and every non-CLEAR suitability unit (NOTE / CONCERN).
      A CLEAN security unit with CLEAR suitability is not a finding — it appears
      only in the summary table. Anchor each finding to the changed line that
      declares the relevant bump when possible:
      `gh api -X POST /repos/{owner}/{repo}/pulls/{n}/comments -f commit_id=<sha>
      -f path=<path> -F line=<line> -f side=RIGHT -f body=<finding>`.
      Use the security or suitability finding format below and its matching hidden
      marker. If a suitability decision was reverted and has no final changed line,
      use a top-level issue comment or the summary's compatibility section rather
      than inventing an invalid anchor.

   c. **Idempotency.** Before posting, fetch existing review comments
      (`gh api /repos/{owner}/{repo}/pulls/{n}/comments`) and match security findings
      by `dependa-audit:finding:{package}` and suitability findings by
      `dependa-audit:suitability:{scope}`. If a prior result has the same verdict,
      skip it. If the verdict changed, post a fresh comment stating what changed at
      the new head sha. If a result returns to CLEAN/CLEAR, reply on the prior
      thread that it is resolved. Re-runs must not stack duplicate findings.

   d. **Summary comment (always, even all-CLEAN/CLEAR).** Search issue comments for
      `<!-- dependa-audit:summary -->`. PATCH it if present
      (`gh api -X PATCH /repos/{owner}/{repo}/issues/comments/{id} -f body=…`), else
      POST a new one (`gh pr comment <n> --body-file …`). Body = the security table,
      suitability status/version matrix, coverage gaps, and text report (format
      below), ending with the marker. Link each non-clean/non-clear unit to its
      inline finding comment when one exists. Re-runs update the summary in place.

11. **Show the user** the same text report in the conversation, and link the PR
   comment(s).

## Finding comment format (inline, anchored to the dependency's diff line)

```
**[<emoji> <VERDICT>] `<package>` <from> → <to>**

<1–2 lines: the signal + why it matters + the recommendation, with sources.>

<sub>`dependa-audit` · reply to resolve</sub>
<!-- dependa-audit:finding:<package> -->
```

Example:

```
**[🟡 NOTE] `@statsig/*` 3.33.0 → 3.33.1**

Publisher moved to `sdk.dev@amplitude.com` (Amplitude's [May 2026 Statsig takeover](https://amplitude.com/blog/amplitude-and-statsig-partnership)). The diff is benign — one `FlushType` enum→const fix, identical endpoints — and `sdk.dev` was already a maintainer. But these SDKs record user sessions, now ship under new ownership, and carry no provenance: scrutinize future bumps.

<sub>`dependa-audit` · reply to resolve</sub>
<!-- dependa-audit:finding:@statsig -->
```

## Suitability finding comment format

For a non-CLEAR compatibility result, use a separate marker so a compatibility
note is not confused with a supply-chain finding:

```
**[<emoji> SUITABILITY <CLEAR|NOTE|CONCERN>] <scope>**

<1–3 lines: the version relationship or human decision, why it is acceptable or
concerning, which existing CI/test contract covers it, and the recommendation.>

<sub>`dependa-audit` · compatibility review</sub>
<!-- dependa-audit:suitability:<scope> -->
```

Use 🟡 for `NOTE` and 🟠 for `CONCERN`. A reverted-only decision with no final
changed line may be a top-level issue comment instead of an inline review comment.

## Summary comment body format

````
## 🔍 dependa-audit — <overall recommendation>

Audited <N> package(s) upgraded by this PR. Each was checked for install hooks,
dependency changes, publisher/provenance, network endpoints, and code diff.
The separate CI/build suitability review checked PR-history decisions, related
version pins, compatibility signals, and existing test coverage.

| Package | From → To | Eco | Hooks | New deps | Provenance | Publisher Δ | Security |
|---------|-----------|-----|-------|----------|-------------|-------------|----------|
| `@base-ui/react` | 1.4.1 → 1.5.0 | npm | none | none | SLSA v1 | no | ✅ CLEAN |
| `@statsig/*` (4) | 3.33.0 → 3.33.1 | npm | none | none | none | ⚠️ acq. | 🟡 NOTE |
| … | | | | | | | | |

### CI/build suitability

| Scope | Suitability | Version relationship / decision | Coverage |
|-------|-------------|----------------------------------|----------|
| CI/build toolchain | CLEAR | aligned or explicitly justified | covered |
| … | NOTE/CONCERN | <short signal> | partial/not covered |

<Include reverted decisions, relevant pins, and uncovered invariants here even
when they have no final diff anchor.>

### Summary

<2–5 TL;DR bullets: the cross-cutting facts — e.g. "No install hooks added
anywhere", "No new external dependencies", "No new network endpoints", "Most
packages publish with SLSA provenance". State the reassuring negatives explicitly.>

### Worth knowing

<Include one short paragraph for every security NOTE/SUSPICIOUS/BLOCK or
suitability NOTE/CONCERN: what it is, why it is flagged, the existing coverage,
and the recommendation. Cite sources (release notes, acquisition news, PR
history, or the specific CI/build path). If all security units are CLEAN and
suitability is CLEAR, write "Nothing notable — safe to merge.">

<!-- dependa-audit:summary -->
````

Security verdict emoji: ✅ CLEAN, 🟡 NOTE, 🟠 SUSPICIOUS, 🔴 BLOCK. Suitability
uses ✅ CLEAR, 🟡 NOTE, and 🟠 CONCERN. Keep the security table compact
(abbreviate publisher-change as "no" / "⚠️ <reason>"). The text report shown to the
user in the conversation is the same Summary + CI/build suitability + Worth-knowing
content, led by the overall recommendation — written in plain prose like a security
reviewer briefing a teammate.

## Notes

- **Parallelism is capped at 5** concurrent subagents; audit model is the **latest
  Sonnet**. Cheap orchestration fetches (steps 1, 2, 3, 9) may use Haiku.
- Use `gh` for all GitHub I/O; the bundled scripts handle registry and read-only
  repository-context I/O.
- Do not run the project's own build/tests, checkout its PR branch, or modify the
  target PR/repository. The suitability pass inventories existing CI/test coverage;
  it does not replace or execute full API/desktop regression scenarios.
- Trust the scripts' endpoint/string-literal diffs over raw line counts on minified
  bundles. When a signal is ambiguous, prefer NOTE/SUSPICIOUS over silently
  dropping it — but back every flag with a concrete, verifiable fact.
- The scripts need network (npm registry / crates.io / PyPI / Docker Hub / GitHub API
  / Go proxy + checksum db). If one can't fetch a version, its metadata section still
  prints; say so in the verdict rather than guessing.
- Idempotent: re-running on the same PR updates the existing comment in place.
