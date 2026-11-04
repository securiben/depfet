# C1 Finding Record — Dependabot Updater Command Injection (RCE)

**Registered:** 2026-11-03 in engagement `2026-11-01-093223-googlecloud` (Vigil registry)
**Registering agent:** `vulnerability-analyst` (dispatch `va910-911-verify`)

---

## Assigned Finding ID

**`VA-914`** (registry finding id 1351, engagement 810)

## Verification Status

- **`verification_status` = `unreviewed`** — the Vigil registry's only record-time value; this is the backend-equivalent of **UNVERIFIED / CANDIDATE (not confirmed)**.
- **`triage_bucket` = `candidate`** (primitive proven in source with exactly one bounded prerequisite left: live reachability).
- **`evidence_type` = `code-inferred`** (static/dataflow analysis, no runtime proof).
- Attempted transition to `pending_runtime_proof` (the state that would express "parked awaiting runtime proof") was **blocked by the running backend**: `POST /findings/VA-914/verify` returns 422 `body.next_test: Extra inputs are not permitted` — the deployed `FindingVerifyRequest` model does not accept the `next_test` plan key that the CLI's `--next-test-file` flag requires. The plan is written, however, at `c1_next_test_plan.json`.
- `workflow_status` = **`active`**.
- `submission_status` = **`none`** — nothing submitted to GitHub/HackerOne; code not modified.

---

## Fingerprint

```
TARGET           = GitHub Dependabot (dependabot-core) v0.403.0 commit cc2be3e976d5106b02a65b01d0d9bf3a0f7b6ed5
COMPONENT        = updater workspace git (Workspace::Git)
ENTRY POINT      = group_update_creation.rb:744 (store_change memo: "Updating #{dependency.name}"); stash path at :76
SINK             = workspace/git.rb:133-137 — `git commit -m "#{msg}"` via run_shell_command(allow_unsafe_shell_command: true) → IO.popen (command_helpers.rb:243); git.rb:119-123 stash same pattern
ROOT CAUSE       = attacker-controlled dependency name interpolated into double-quoted shell string without escaping/sanitization (Dependency#name unvalidated)
CWE              = CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
IMPACT           = RCE / arbitrary command execution in the Dependabot updater container (code execution, file write, env/token exfiltration) — strictly more severe than VA-912's read-only arbitrary host file read
PREREQUISITES    = grouped-update job configured (groups: in dependabot.yml); job.clone? true; DEPENDABOT_REPO_CONTENTS_PATH set; malicious dependency updated (changes.any? true); ecosystem parser passes dependency name verbatim
```

**Exact source references (from `c1_rce_report.md`):**
- `common/lib/dependabot/workspace/git.rb:133-137` — `git commit -m "#{msg}"` with `allow_unsafe_shell_command: true`
- `common/lib/dependabot/workspace/git.rb:119-123` — `git stash push --all -m "#{msg}"` (memo from `capture_failed_change_attempt`)
- `updater/lib/dependabot/updater/group_update_creation.rb:744` — memo `"Updating #{dependency.name}"` via `Workspace.store_change`
- `updater/lib/dependabot/updater/group_update_creation.rb:76` — `stash(memo)` path
- `common/lib/dependabot/command_helpers.rb:243` — `IO.popen` raw shell string when `allow_unsafe_shell_command: true`
- `common/lib/dependabot/dependency.rb` — no name validation/sanitization

## Evidence Artifacts (linked to VA-914)

| Artifact ID | Path | Kind |
|---|---|---|
| 993257 | `c1_rce_report.md` | report (evidence_ref) |
| 993330 | `deep_dependabot_analysis.md` | source analysis |

Both registered in the artifact index and linked to VA-914 (`related_finding_slug=VA-914`).

## Link to VA-912

`variant-of` link (id 5221) → VA-912: distinct sink (shell execution vs `File.read`), distinct impact (RCE/write vs arbitrary host file read), distinct boundary (Workspace git layer vs file fetcher clone mode). **Not a duplicate.**

---

## Status Statement

**C1 is an UNVERIFIED static-analysis candidate.** The injection mechanics (dependency name → double-quoted shell string → `IO.popen`) are unambiguous from source, but **reachability is not yet confirmed live**. It **must not be submitted to GitHub/HackerOne until live reachability verification** is performed (real or faithfully sandboxed grouped-update Dependabot updater job). Severity **critical** (CVSS 9.8 from `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`); the report's earlier 9.1 estimate was corrected to 9.8 to match the vector.

No source code was modified. No live/production target was touched.
