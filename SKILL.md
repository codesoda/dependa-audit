---
name: dependa-audit
description: Supply-chain audit of a Dependabot PR. For every dependency the PR bumps, diff the current vs target version (install hooks, new deps, publisher/provenance, network endpoints, code) using parallel Sonnet subagents, then post a PR comment with a verdict table + text report. Use when reviewing a Dependabot PR for anything sketchy in the dependency updates.
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
  - Bash(curl:*)
  - Bash(npm pack:*)
  - Bash(npm view:*)
  - Bash(jq:*)
---

# dependa-audit — supply-chain review of a Dependabot PR

Audit every dependency a Dependabot PR upgrades. For each package, diff the
**current version against the target version** and surface anything sketchy:
new install hooks, new dependencies, changed publisher/maintainer, missing
provenance, new network endpoints, or suspicious code. The expensive per-package
work runs in **parallel Sonnet subagents (max 5 concurrent)**. The result is a PR
comment with a verdict table + text report, plus the same report shown to the user.

This is a defensive security task: the goal is to catch a compromised or malicious
dependency release before it merges. Be skeptical, cite evidence, never invent findings.

## Arguments

A PR number or URL. If none is given, run `gh pr list --author "app/dependabot"
--state open` and ask the user which one (or audit the PR for the current branch
if there is one). Audit **one PR per invocation**.

## Helper scripts

Three bundled scripts live in `scripts/` next to this SKILL.md. Resolve their
**absolute paths** (the directory this SKILL.md was loaded from) and pass them to
each subagent. Each prints a bounded, structured report and ends with an
INTERPRETATION GUIDE.

- `scripts/npm-audit.sh <package> <from> <to>` — npm/pnpm packages.
- `scripts/crate-audit.sh <crate> <from> <to>` — Rust/cargo crates.
- `scripts/docker-audit.sh <image> <from-digest> <to-digest> [tag]` — Docker Hub
  images (anonymous registry API; verifies the new digest matches the live tag,
  diffs entrypoint/cmd/user/env/labels and layer history). For non-Docker-Hub
  registries it prints a `docker buildx imagetools inspect` fallback.

## Steps

Make a todo list first.

1. **Resolve & gate the PR.** Use a Haiku agent to fetch the PR (`gh pr view <n>
   --json state,isDraft,author,title,body,headRefName,url`). Stop if it is closed
   or merged. Confirm the author is `app/dependabot` (if not, tell the user this
   isn't a Dependabot PR and ask whether to continue). Draft is fine.

2. **Build the upgrade work-list — the manifest/lockfile diff is ground truth.**
   The PR body table lists *direct* bumps but often omits transitive ones; the
   lockfile shows everything that actually changes. Use a Haiku agent to read the
   PR diff (`gh pr diff <n>`) and extract every `{ecosystem, package, from, to,
   direct|transitive}` from the changed manifests/lockfiles:
   - npm/pnpm: `package.json` + `pnpm-lock.yaml` (or `package-lock.yaml`)
   - cargo: `Cargo.toml` + `Cargo.lock`
   - docker: `Dockerfile*` / `*.yml` image digests or tags
   Include transitive bumps — those are exactly where a malicious release hides.

3. **Form audit units.** One unit per package. You MAY group packages from the
   same monorepo that move in lockstep to the same version (e.g. all `@statsig/*`
   3.33.0→3.33.1, or all `@typescript-eslint/*`) into a single unit to save
   agents — but never group unrelated packages. Each unit names its ecosystem.

4. **Make a todo entry per unit** so progress is visible.

5. **Fan out — parallel Sonnet subagents, at most 5 running at once.** Dispatch
   units in batches of ≤5 (multiple Agent calls in one message = concurrent), wait
   for the batch, then dispatch the next, until all units are done. Every audit
   subagent uses model **sonnet** (the latest Sonnet) and `subagent_type:
   general-purpose`. Give each subagent this brief (filled in for its unit):

   > You are auditing a dependency upgrade in a Dependabot PR for supply-chain
   > risk. Package(s): `<names>`. Ecosystem: `<npm|cargo|docker>`. Versions:
   > `<from>` → `<to>`.
   >
   > a. Run the bundled auditor and read its full output:
   >    - npm:    `<abs>/scripts/npm-audit.sh <pkg> <from> <to>`
   >    - cargo:  `<abs>/scripts/crate-audit.sh <crate> <from> <to>`
   >    - docker: `<abs>/scripts/docker-audit.sh <image> <from-digest> <to-digest> <tag>`
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
   >
   > Apply this judgment (do not over-flag — these are the false positives that
   > burned a prior reviewer): `process.env.TZ` reads and `function exec(){}`
   > helpers are benign; minified single-line bundles make line-diffs noisy, so
   > trust the script's ENDPOINT diff and string-literal diff over raw line counts;
   > 40–64-char hex strings in test fixtures are hashes/vectors, not payloads;
   > documentation URLs (the package's own site, MDN) are not exfiltration;
   > `provenance: NONE` is a weakness to NOTE, not a reason to block; an HTTP
   > client inside an HTTP library is expected. A real finding is NEW, unexplained,
   > and runtime-reachable.
   >
   > Return ONLY this structure, no prose around it:
   > ```
   > UNIT: <package(s)>
   > ECOSYSTEM: <npm|cargo|docker>
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

   **Verdict meaning:** CLEAN = nothing notable. NOTE = safe to merge but the team
   should know something (e.g. publisher moved to a new owner, no provenance on a
   data-collecting SDK). SUSPICIOUS = a real anomaly that needs a human to look
   before merge. BLOCK = evidence of a malicious/compromised release.

6. **Aggregate.** Collect all unit verdicts. The PR's overall recommendation:
   - any BLOCK → **Do not merge — investigate.**
   - else any SUSPICIOUS → **Hold for human review.**
   - else any NOTE → **Safe to merge (notes below).**
   - else → **Safe to merge.**

7. **Re-confirm** the PR is still open (Haiku agent) before posting.

8. **Post the audit — anchored review comments for findings + an idempotent
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

   b. **Inline finding comment for every NON-CLEAN unit** (NOTE / SUSPICIOUS /
      BLOCK). A CLEAN unit is not a finding — it appears only in the summary table,
      exactly as pr-code-review does not comment on clean code. Post each as a review
      comment anchored to its line:
      `gh api -X POST /repos/{owner}/{repo}/pulls/{n}/comments -f commit_id=<sha>
      -f path=<path> -F line=<line> -f side=RIGHT -f body=<finding>` (finding body =
      the per-unit format below, ending with `<!-- dependa-audit:finding:{package} -->`).
      If a unit's line cannot be resolved, fall back to a top-level issue comment for
      that finding.

   c. **Idempotency.** Before posting, fetch existing review comments
      (`gh api /repos/{owner}/{repo}/pulls/{n}/comments`) and match by the
      `dependa-audit:finding:{package}` marker. If a prior finding for the same unit
      exists with an unchanged verdict → skip (don't nag). If the verdict changed →
      post a fresh comment stating what changed at the new head sha. If a unit is now
      CLEAN but had a prior non-CLEAN finding → reply on that thread that it's resolved.

   d. **Summary comment (always, even all-CLEAN).** Search issue comments for
      `<!-- dependa-audit:summary -->`. PATCH it if present
      (`gh api -X PATCH /repos/{owner}/{repo}/issues/comments/{id} -f body=…`), else
      POST a new one (`gh pr comment <n> --body-file …`). Body = the table + text
      report (format below), ending with the marker; link each non-CLEAN unit to its
      inline finding comment. Re-runs update the summary in place.

9. **Show the user** the same text report in the conversation, and link the PR
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

## Summary comment body format

````
## 🔍 dependa-audit — <overall recommendation>

Audited <N> package(s) upgraded by this PR. Each was checked for install hooks,
dependency changes, publisher/provenance, network endpoints, and code diff.

| Package | From → To | Eco | Hooks | New deps | Provenance | Publisher Δ | Verdict |
|---------|-----------|-----|-------|----------|-----------|-------------|---------|
| `@base-ui/react` | 1.4.1 → 1.5.0 | npm | none | none | SLSA v1 | no | ✅ CLEAN |
| `@statsig/*` (4) | 3.33.0 → 3.33.1 | npm | none | none | none | ⚠️ acq. | 🟡 NOTE |
| … | | | | | | | |

### Summary

<2–5 TL;DR bullets: the cross-cutting facts — e.g. "No install hooks added
anywhere", "No new external dependencies", "No new network endpoints", "Most
packages publish with SLSA provenance". State the reassuring negatives explicitly.>

### Worth knowing

<Only if any NOTE/SUSPICIOUS/BLOCK units exist. One short paragraph per notable
unit: what it is, why it's flagged, and the recommendation. Cite sources
(release notes, acquisition news, the specific signal). If everything is CLEAN,
write "Nothing notable — safe to merge.">

<!-- dependa-audit:summary -->
````

Verdict emoji: ✅ CLEAN, 🟡 NOTE, 🟠 SUSPICIOUS, 🔴 BLOCK. Keep the table compact
(abbreviate publisher-change as "no" / "⚠️ <reason>"). The text report shown to the
user in the conversation is the same Summary + Worth-knowing content, led by the
overall recommendation — written in plain prose like a security reviewer briefing
a teammate.

## Notes

- **Parallelism is capped at 5** concurrent subagents; audit model is the **latest
  Sonnet**. Cheap orchestration fetches (steps 1, 2, 7) may use Haiku.
- Use `gh` for all GitHub I/O; the bundled scripts handle registry I/O.
- Do not run the project's own build/tests, and do not modify the PR or repo.
- Trust the scripts' endpoint/string-literal diffs over raw line counts on minified
  bundles. When a signal is ambiguous, prefer NOTE/SUSPICIOUS over silently
  dropping it — but back every flag with a concrete, verifiable fact.
- The scripts need network (npm registry / crates.io). If one can't fetch a
  version, its metadata section still prints; say so in the verdict rather than
  guessing.
- Idempotent: re-running on the same PR updates the existing comment in place.
