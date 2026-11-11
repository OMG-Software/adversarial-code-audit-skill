# adversarial-code-audit-skill

An agent skill for adversarial, white-box security audits of source code. It turns a coding agent into an auditor that hunts for real trust-boundary failures, tries to disprove its own findings, and reports only what the evidence supports.

A finding here is a demonstrated boundary failure: a lower-trust actor crosses a real trust boundary, along a path traced from entry to sink, past a named control that fails. A missing best practice or a plausible-looking pattern is not a finding.

## What it does

- **Three modes.** *Answer* explains methodology without touching files. *Focused* checks one finding, file, function or diff, including PR regression reviews. *Full* runs the complete audit workflow over a codebase, or over one subsystem or one domain with a restricted scope.
- **A phased workflow** that keeps all state in files, so any agent can stop and resume:
  0. Setup → 1. Recon and threat model → 2. Lead generation → 3. Hunt → 4. Coverage critique → 5. Chain → 6. Verify → 7. Report.
- **Independent verification.** The agent that verifies a finding is not the one that found it. Every candidate goes through a disprove pass before it can be `confirmed`.
- **Explicit evidence levels.** E1 (source-traced), E2 (tool-supported) and E3 (reproduced). Memory-safety, race and parser-differential claims need E3. Other source-only confirmations carry a written reproduction waiver. Findings that depend on facts outside the repository stay `needs-validation`, without a severity.
- **Domain and language guidance.** 33 domain files (authz, injection, memory safety, AI/LLM agents, federation, smart contracts and more) and 14 language files (C, C++, Rust, Go, Python, JS/TS, JVM, .NET, PHP, Ruby, Swift/Objective-C, Lua, shell, SQL). Recon selects only the ones the code needs.
- **Capability tiers.** The skill works with read-only access (T0) and gets stronger with a shell (T1), target execution (T2) and sub-agents. The tier changes how evidence is gathered, never the evidence bar.
- **Two questions, then it works alone.** Before it starts, the skill asks how target code may run and which read-only tools it may install. After recon, it shows the size of the run and asks you about facts it cannot see in the repository, such as what your reverse proxy does. Your answers can settle findings that would otherwise stay `needs-validation`.
- **Runs build on each other.** A later run carries every open finding forward, verifies it against the current code, and reports it as still open or as `fixed`.

## Safety model

- The target repository is treated as untrusted data. Instructions found in it are never followed.
- No traffic to live systems, and no export of source, secrets or findings to third-party services.
- **You choose how target code runs.** Builds, tests, build hooks, plugins and executable tool configuration all count as running target code. The skill detects what is available, explains the risks, and asks: a full sandbox (recommended), partial isolation such as WSL, the host with guards (last resort), or no execution.
- Nothing is downloaded or installed without your approval.
- Reproductions stop at the minimum effect: a wrong result, a dummy record or a sanitizer report. No weaponised exploits.
- Secret values are never copied into audit output, and the target source is never modified. A fix is described in its finding, or written as a patch file in the audit output if you ask for one.
- A credential that looks live, signs of an existing compromise, or a critical finding is reported to you at once, not at the end.

## Installation

Copy `SKILL.md`, `references/`, `assets/` and `scripts/audit_run.py` into your agent's skills directory, for example `~/.claude/skills/adversarial-code-audit/` for Claude Code. `audit_run.py` is an optional helper that needs Python 3.10 or later: it checks a finished run, counts coverage and exports JSON and SARIF.

Leave `evaluations/` out of an installed copy. It holds the scoring rubric, and fixtures that contain hostile instructions on purpose.

## Usage

Start your agent in the codebase and ask, for example:

- "Run a security audit of this repository."
- "Is the missing ownership check in `api/invoices.py:read_invoice` a real vulnerability?"
- "Review this PR for security regressions."
- "How do I spot SQL injection during source review?"

Full audits write their state and `REPORT.md` to `security-audit/<repo-name>/run-<N>/` in the directory that contains the target repository, not inside it. You can name another location. The files describe vulnerabilities, so treat them as confidential.

## Repository layout

| Path | Contents |
|---|---|
| `SKILL.md` | Entry point: modes, tiers, safety rules, workflow, finding contract |
| `references/phase-*.md` | One file per workflow phase |
| `references/focused.md` | Focused and diff-review workflow |
| `references/execution.md` | Isolation levels, sandbox detection and recipes, cleanup rules |
| `references/domain-*.md`, `references/lang-*.md` | Domain and language guidance |
| `assets/finding-template.md` | Template for one finding file per root cause |
| `assets/plan-template.md` | Template for `plan.md`, the control record of a run |
| `scripts/audit_run.py` | Optional helper: checks a run directory, counts coverage, exports JSON and SARIF |
| `evaluations/` | Behavioural test cases for maintainers (not part of an audit) |
| `scripts/validate_skill.py` | Checks frontmatter, local links and the shape of the reference files |
| `scripts/test_audit_run.py` | Unit tests for the helper |
| `CHANGELOG.md` | What changed in each version |

## Maintaining the skill

```bash
python scripts/validate_skill.py .
```

```bash
python -m unittest discover -s scripts -p "test_*.py"
```

The validator needs PyYAML and checks structure only. Both commands run in CI on every pull request. For behaviour, run the cases in [evaluations/README.md](evaluations/README.md) with a fresh agent. Keep `evaluations/evaluator-only/` out of the evaluated agent's workspace.

## Known limits

- The Windows Sandbox recipe and the container user flags in `references/execution.md` follow the tools' documentation. They have not been run as part of this project. The skill tells the agent to check each sandbox control before it relies on one.
- The version ranges in the language files stop at about mid-2025. The skill treats a version-specific statement about a newer release as a lead to check, not as a fact.
- No language file exists yet for Dart, Elixir, Erlang, Perl, Solidity or Zig. The audit continues without one and says so.
- The evaluations do not yet cover resuming a run, carrying findings across runs, chains, or real target execution in a sandbox.

## Inspiration

This skill was inspired by Cloudflare's [security-audit-skill](https://github.com/cloudflare/security-audit-skill), a coding-agent skill for multi-phase security audits with independently verified findings. This project is a separate implementation and is not affiliated with or endorsed by Cloudflare.

## License

[MIT](LICENSE)
