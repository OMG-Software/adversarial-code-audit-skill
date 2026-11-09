# Phase 2 – Lead generation

Goal: collect cheap, broad signals that point hunters at likely bugs. A **lead** is a location and a hypothesis. A lead is never a finding. Phase 3 must trace it.

Output: `leads.md`. Each lead maps to a coverage unit, or creates a new unit.

At T0, do sections 2.2, 2.4 and 2.5 only. At T1 and above, do all sections.

## 2.1 Static tools (T1+)

Run only tools that are already installed. Do not install tools. Do not let a tool fetch rules, databases or packages from the network unless the user allows it. Record each tool, its version, its command and its result count in `leads.md`, including tools that failed or were absent. The report lists them.

| Language or area | Tools to try (if present) | Notes |
|---|---|---|
| C, C++ | compiler with `-Wall -Wextra -Wconversion -Wsign-conversion -Wshadow -Wformat=2`, `clang-tidy` (`bugprone-*`, `cert-*`, `clang-analyzer-*`, `cppcoreguidelines-*`), `cppcheck`, `scan-build` | Use the project's compile database if present (`compile_commands.json`). |
| Rust | `cargo clippy`, `cargo geiger` (unsafe count), `cargo audit` (offline DB only), `cargo deny check --disable-fetch` | |
| Go | `go vet`, `staticcheck`, `gosec`, `govulncheck` (needs DB) | |
| Python | `bandit`, `pip-audit` (needs DB), `mypy` | |
| JS/TS | `eslint` with security plugins, `tsc --noEmit`, `npm audit` (needs network) | |
| JVM | `spotbugs` with `find-sec-bugs`, `pmd` | |
| .NET | Roslyn analyzers through `dotnet build` (with the project's analyzer settings) | |
| PHP | `php -l`, `phpstan`, `psalm` (taint analysis), `phpcs` with security rules | |
| Ruby | `brakeman`, `rubocop`, `bundler-audit` (offline DB only) | |
| Swift, Objective-C | `swiftlint`; Clang static analyser through `xcodebuild analyze` | |
| Lua | `luacheck` | |
| Shell | `shellcheck`; `PSScriptAnalyzer` for PowerShell | |
| SQL | `sqlfluff` | Linting only. Read stored code for logic. |
| Multi-language | `semgrep` with local rule files and `--metrics=off`; `codeql` if a database can be built offline | `semgrep --config auto` uses the network. Do not use it without permission. |
| Secrets | `gitleaks`, `trufflehog --no-verification` | Verification sends secrets to live services. Never verify. Never copy secret values into audit files. |
| Dependencies | `osv-scanner` with an offline database, or the lockfile itself | Without a vulnerability database, list pinned versions of security-relevant dependencies as leads for phase 6 to mark `needs-validation`. |

Treat every tool result as a lead. Most alerts are noise. Do not copy alerts into `leads.md` one by one when there are many. Group them by rule and location, and keep the groups that touch an entry surface or boundary from `threat-model.md`.

**Suppressed warnings are strong leads.** Search for suppression comments and attributes (`NOLINT`, `nolint`, `# nosec`, `// eslint-disable`, `@SuppressWarnings`, `#[allow(`, `#pragma warning(disable`, `NOSONAR`, `[[maybe_unused]]` on results of security calls). A developer silenced a tool there. Check why.

## 2.2 Pattern sweeps

Each domain and language file lists sink and anti-pattern searches. Run the searches for the selected files. At T0, use the agent's own search tool with the same patterns.

Keep a hit only if it is on or near a path from an entry surface. Record the pattern, the hit and the unit.

## 2.3 History (T1+, git available)

The history of a codebase shows where it was weak before. Bugs cluster, and fixes are often incomplete.

1. **Security fixes.** `git log --oneline -i -E --grep='secur|vuln|cve|exploit|overflow|inject|xss|csrf|ssrf|bypass|auth|permission|sanitiz|escape|leak|dos|crash|fuzz|race'`. For each relevant commit, read the diff. Record the root cause as a **variant seed**: phase 3 searches for the same root cause in other places, and checks that the fix covers all paths.
2. **Reverts.** `git log --oneline -i --grep='revert'`. A reverted security fix can leave the bug in place.
3. **Removed checks.** `git log -S '<central control name>' --oneline` for each central control in `threat-model.md`. Read commits that remove a call.
4. **Churn.** `git log --since='1 year ago' --name-only --format='' | sort | uniq -c | sort -rn | head -30`. High churn in security code is a priority signal.
5. **Secrets in history.** If a secrets tool is present, scan history too. Record the commit, path and type only.

Use history as leads only. A commit message is not evidence of a current bug.

## 2.4 Developer signals

Search for:
- `TODO`, `FIXME`, `HACK`, `XXX`, `BUG` near security words (auth, check, verify, validate, sanitize, escape, permission, trust, unsafe, insecure, temporary, bypass, skip);
- disabled code: `#if 0`, commented-out checks, `if (false)`, early `return true` in check functions;
- debug and test switches: `debug`, `insecure`, `skip_verify`, `allow_all`, `dev_mode`, `NO_AUTH`, `disable_*`;
- disabled or skipped tests on security code;
- comments that claim safety ("safe because", "cannot happen", "trusted", "already validated"). Phase 3 must check each claim.

## 2.5 Test gaps

For each central control in `threat-model.md`, look for negative tests: tests that send a bad token, a wrong user, a wrong tenant, an oversized input, a malformed message. A control with only positive tests is a lead. A path with no tests at all is a priority signal.

If fuzz harnesses exist, record what each one covers. Parsers on an entry surface without a fuzz harness are leads for the memory-safety and input-parsing domains. Existing crash corpora or open fuzz findings are strong leads.

## 2.6 Known weakness classes for this product type

List the weakness classes that comparable software has had. Examples: a protocol implementation had signature canonicalisation bugs; a similar web framework had a path-normalisation bypass. Sources:
- the security considerations sections of specifications the code implements;
- the project's own security advisories and changelog;
- if the agent has web access and the user allows it: CVEs and advisories for comparable implementations.

Without web access, you may list classes from your own knowledge. Mark each one "unverified knowledge". Never cite a CVE ID from memory as fact.

Each class becomes a lead on the units it can affect.

## 2.7 `leads.md` layout

```markdown
# Leads

## Tools run
| Tool | Version | Command | Result | Notes |

## Leads
| ID | Source | Location | Hypothesis | Unit | Status |
|----|--------|----------|------------|------|--------|
| L001 | history: a1b2c3d | src/fed/keys.cpp:210 | fix for key-expiry check covers fetch path only, not cache path | U014 | open |
```

Lead statuses: `open`, `merged` (same as another lead), `dropped` (with reason), `traced` (phase 3 checked it: write the result or the finding ID).

Before phase 3 ends, every lead must be `traced`, `merged` or `dropped`. Phase 4 checks this.
