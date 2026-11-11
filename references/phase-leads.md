# Phase 2 – Lead generation

Goal: collect cheap, broad signals that point hunters at likely bugs. A **lead** is a location and a hypothesis. A lead is never a finding. Phase 3 must trace it.

Output: `leads.md`. Each lead maps to a coverage unit, or creates a new unit.

At T0, do sections 2.2, 2.4 and 2.5 only. At T1 and above, do all sections.

## 2.1 Static tools (T1+)

Run tools that are already installed, plus tools the user approved in phase 0 ([execution.md section 5.1](execution.md#51-missing-static-tools)). Never install a tool, or let a tool fetch rules, databases or packages from the network, without that approval. Record each tool, its version, its command and its result count in `leads.md`, including tools that failed or were absent. The report lists them.

Every tool that fits the target but did not run gets exactly one reason in the `leads.md` tool table:

| Reason | Meaning |
|---|---|
| `absent` | Not installed, and not offered (say why: no official artefact, no checksum, wrong OS). |
| `absent-declined` | Offered in phase 0; the user declined or did not answer. |
| `T2-skipped` | The tool runs target code (build scripts, plugins, executable configuration), and the execution choice does not allow it. |
| `network-declined` | Installed, but needs a network fetch the user did not approve and no local database exists. |
| `failed` | Ran and did not complete. Give the error. |

Do not merge reasons. `cargo audit` reads only `Cargo.lock`: if it is missing, its reason is `absent` or `absent-declined`, never `T2-skipped`.

**Dependency fallback (required).** If no advisory scanner ran against a lockfile, write the pinned versions of the security-relevant dependencies (TLS, crypto, parsers, archive and compression, HTTP, serialisation, auth) as leads, and state in the report: "Dependency advisories were not checked against a vulnerability database." Phase 6 marks any version-based claim `needs-validation`.

Some analysers load the target's build or configuration, which runs target code (see [execution.md](execution.md) section 1). The Notes column marks them **T2**: run them only at the isolation level the user chose, or skip them at T1. Never run tools from inside the target (`node_modules/.bin`, `vendor/bin`, wrappers).

**Run tools from outside the target.** Start each tool in a working directory outside the target (the output directory is a good choice) and pass the target path as an argument. Toolchain launchers act on files in the working directory:

- rustup downloads the toolchain named in `rust-toolchain.toml`;
- corepack downloads the package manager named by `packageManager` in `package.json`;
- `yarn` runs the script that `yarnPath` names;
- `go` downloads the toolchain named in `go.mod`;
- version managers may switch or install versions from `.tool-versions`, `.python-version` or `.nvmrc`.

A download that a target file starts still needs approval (SKILL.md section 3, rule 5), and a script from the target is target code. If a tool only works inside the target, pin the toolchain first (`RUSTUP_TOOLCHAIN=<an installed toolchain>`, `GOTOOLCHAIN=local`, `COREPACK_ENABLE_NETWORK=0`), or treat the tool as **T2**.

**Target files can also blind a tool.** Ignore files, baselines and allow-lists in the target make a scanner skip paths or rules without saying so: `.gitleaks.toml`, `.gitleaksignore`, `.semgrepignore`, `.shellcheckrc`, `.bandit`, `.eslintignore`, `.trivyignore`, baseline files. Where the tool allows it, run it with your own configuration and record that in the tool table. Otherwise read the ignore file as data, and treat each excluded path or rule that touches an entry surface as a lead, like a suppression comment.

| Language or area | Tools to try (if present) | Notes |
|---|---|---|
| C, C++ | compiler with `-Wall -Wextra -Wconversion -Wsign-conversion -Wshadow -Wformat=2`, `clang-tidy` (`bugprone-*`, `cert-*`, `clang-analyzer-*`, `cppcoreguidelines-*`), `cppcheck`, `scan-build` | Use the project's compile database if present (`compile_commands.json`). `scan-build` runs the build: **T2**. |
| Rust | `cargo clippy`, `cargo geiger` (unsafe count), `cargo audit` (offline DB only), `cargo deny check --disable-fetch` | `cargo clippy` and `cargo geiger` run `build.rs` and procedural macros: **T2**. Call the lockfile scanners as their own programs (`cargo-audit audit --no-fetch -f <target>/Cargo.lock`) with `RUSTUP_TOOLCHAIN` set, so that rustup does not fetch the target's toolchain. |
| Go | `go vet`, `staticcheck`, `gosec`, `govulncheck` (needs DB) | With cgo, loading packages can run the C toolchain and `#cgo` flags: treat as **T2**. |
| Python | `bandit`, `pip-audit` (needs DB), `mypy` | `mypy` loads plugins named in the project's config: **T2** unless run with a clean config. |
| JS/TS | `eslint` with security plugins, `tsc --noEmit`, `npm audit` (needs network) | A JavaScript ESLint config (`eslint.config.js`, `.eslintrc.js`) is target code: **T2**, or use your own config with `--no-config-lookup`. Do not start `yarn` or `pnpm` in the target: `yarnPath` and corepack make them run or download what the target names. |
| JVM | `spotbugs` with `find-sec-bugs`, `pmd` | SpotBugs needs compiled classes; building them with Maven or Gradle is **T2**. |
| .NET | Roslyn analyzers through `dotnet build` (with the project's analyzer settings) | `dotnet build` runs MSBuild targets, analyzers and source generators: **T2**. |
| PHP | `php -l`, `phpstan`, `psalm` (taint analysis), `phpcs` with security rules | PHPStan and Psalm load the project's autoloader and bootstrap files: **T2**. |
| Ruby | `brakeman`, `rubocop`, `bundler-audit` (offline DB only) | `rubocop` loads `require:` entries from `.rubocop.yml`: **T2** unless run with your own config. |
| Swift, Objective-C | `swiftlint`; Clang static analyser through `xcodebuild analyze` | `xcodebuild` runs build phases and plugins: **T2**. |
| Lua | `luacheck` | |
| Shell | `shellcheck`; `PSScriptAnalyzer` for PowerShell | |
| CI workflows | `actionlint -no-color`; `zizmor --offline` | Both read workflow files as data. `actionlint` calls `shellcheck` on `run:` blocks if it is installed. |
| SQL | `sqlfluff` | Linting only. Read stored code for logic. |
| Multi-language | `semgrep` with local rule files and `--metrics=off`; `codeql` if a database can be built offline | `semgrep --config auto` uses the network. Do not use it without permission. Do not use rule files from the target. Building a CodeQL database for a compiled language runs the build: **T2**. |
| Secrets | `gitleaks` with `--redact`, `trufflehog --no-verification` | Both print the matched secret unless told not to. Always pass `--redact` to `gitleaks`. For any other scanner, do not save or quote its raw output: keep the file, line, commit and rule only. Verification sends secrets to live services. Never verify. Never copy secret values into audit files. |
| Dependencies | `osv-scanner` in offline mode with a local database (the flag differs between versions: check `--help`); per-ecosystem lockfile scanners (`cargo audit --no-fetch`, `cargo deny check advisories --disable-fetch`, `bundler-audit check --no-update`), or the lockfile itself | Lockfile scanners read the lockfile as data (T1). Scanners that query an online service send the dependency list to a third party: only with the user's approval. Without a vulnerability database, apply the dependency fallback above. |

Treat every tool result as a lead. Most alerts are noise. Do not copy alerts into `leads.md` one by one when there are many. Group them by rule and location, and keep the groups that touch an entry surface or boundary from `threat-model.md`.

**Suppressed warnings are strong leads.** Search for suppression comments and attributes (`NOLINT`, `nolint`, `# nosec`, `// eslint-disable`, `@SuppressWarnings`, `#[allow(`, `#pragma warning(disable`, `NOSONAR`, `[[maybe_unused]]` on results of security calls). A developer silenced a tool there. Check why.

## 2.2 Pattern sweeps

Each domain and language file lists sink and anti-pattern searches. Run the searches for the selected files. At T0, use the agent's own search tool with the same patterns.

Keep a hit only if it is on or near a path from an entry surface. Record the pattern, the hit and the unit.

## 2.3 History (T1+, git available)

The history of a codebase shows where it was weak before. Bugs cluster, and fixes are often incomplete.

Every command below uses the safe Git form from [execution.md section 1](execution.md#1-what-counts-as-target-code). Set it first in each shell, and run from the target root:

```sh
G="git -c core.fsmonitor=false -c core.hooksPath=/dev/null --no-pager --no-optional-locks"
```

1. **Security fixes.** `$G log --oneline -i -E --grep='secur|vuln|cve|exploit|overflow|inject|xss|csrf|ssrf|bypass|auth|permission|sanitiz|escape|leak|dos|crash|fuzz|race'`. For each relevant commit, read the diff with `$G show --no-ext-diff --no-textconv <commit>`. Record the root cause as a **variant seed**: phase 3 searches for the same root cause in other places, and checks that the fix covers all paths.
2. **Reverts.** `$G log --oneline -i --grep='revert'`. A reverted security fix can leave the bug in place.
3. **Removed checks.** `$G log --no-ext-diff --no-textconv -S '<central control name>' --oneline` for each central control in `threat-model.md`. Read commits that remove a call.
4. **Churn.** `$G log --since='1 year ago' --name-only --format='' | sort | uniq -c | sort -rn | head -30`. High churn in security code is a priority signal.
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
- if the agent has web access and the user allows it: CVEs and advisories for comparable implementations. Search by product, library and weakness class; never put target source, secrets or findings into a query.

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
