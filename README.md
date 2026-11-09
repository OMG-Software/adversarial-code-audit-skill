# adversarial-code-audit-skill

An agent skill for adversarial, white-box security audits of source code. It turns a coding agent into an auditor that hunts for real trust-boundary failures, tries to disprove its own findings, and reports only what the evidence supports.

A finding here is a demonstrated boundary failure: a lower-trust actor crosses a real trust boundary, along a path traced from entry to sink, past a named control that fails. A missing best practice or a plausible-looking pattern is not a finding.

## What it does

- **Three modes.** *Answer* explains methodology without touching files. *Focused* checks one finding, file, function, domain or diff, including PR regression reviews. *Full* runs the complete audit workflow over a codebase.
- **A phased workflow** that keeps all state in files, so any agent can stop and resume:
  0. Setup → 1. Recon and threat model → 2. Lead generation → 3. Hunt → 4. Coverage critique → 5. Chain → 6. Verify → 7. Report.
- **Independent verification.** The agent that verifies a finding is not the one that found it. Every candidate goes through a disprove pass before it can be `confirmed`.
- **Explicit evidence levels.** E1 (source-traced), E2 (tool-supported) and E3 (reproduced). Memory-safety, race and parser-differential claims need E3. Other source-only confirmations carry a written reproduction waiver. Findings that depend on facts outside the repository stay `needs-validation`, without a severity.
- **Domain and language guidance.** 33 domain files (authz, injection, memory safety, AI/LLM agents, federation, smart contracts and more) and 14 language files (C, C++, Rust, Go, Python, JS/TS, JVM, .NET, PHP, Ruby, Swift/Objective-C, Lua, shell, SQL). Recon selects only the ones the code needs.
- **Capability tiers.** The skill works with read-only access (T0) and gets stronger with a shell (T1), target execution (T2) and sub-agents. The tier changes how evidence is gathered, never the evidence bar.

## Safety model

- The target repository is treated as untrusted data. Instructions found in it are never followed.
- No traffic to live systems, and no export of source, secrets or findings to third-party services.
- **You choose how target code runs.** Builds, tests, build hooks, plugins and executable tool configuration all count as running target code. The skill detects what is available, explains the risks, and asks: a full sandbox (recommended), partial isolation such as WSL, the host with guards (last resort), or no execution.
- Nothing is downloaded or installed without your approval.
- Reproductions stop at the minimum effect: a wrong result, a dummy record or a sanitizer report. No weaponised exploits.
- Secret values are never copied into audit output, and the target source is never modified.

## Installation

Copy or clone this repository into your agent's skills directory, for example `~/.claude/skills/adversarial-code-audit/` for Claude Code. The skill needs only `SKILL.md`, `references/` and `assets/`.

## Usage

Start your agent in the codebase and ask, for example:

- "Run a security audit of this repository."
- "Is the missing ownership check in `api/invoices.py:read_invoice` a real vulnerability?"
- "Review this PR for security regressions."
- "How do I spot SQL injection during source review?"

Full audits write their state and `REPORT.md` to `./security-audit/<repo-name>/run-<N>/`, outside the target repository.

## Repository layout

| Path | Contents |
|---|---|
| `SKILL.md` | Entry point: modes, tiers, safety rules, workflow, finding contract |
| `references/phase-*.md` | One file per workflow phase |
| `references/focused.md` | Focused and diff-review workflow |
| `references/execution.md` | Isolation levels, sandbox detection and recipes, cleanup rules |
| `references/domain-*.md`, `references/lang-*.md` | Domain and language guidance |
| `assets/finding-template.md` | Template for one finding file per root cause |
| `evaluations/` | Behavioural test cases for maintainers (not part of an audit) |
| `scripts/validate_skill.py` | Checks frontmatter and local links |

## Maintaining the skill

```bash
python scripts/validate_skill.py .
```

The validator needs PyYAML and checks structure only. For behaviour, run the cases in [evaluations/README.md](evaluations/README.md) with a fresh agent. Keep `evaluations/evaluator-only/` out of the evaluated agent's workspace.

## Inspiration

This skill was inspired by Cloudflare's [security-audit-skill](https://github.com/cloudflare/security-audit-skill), a coding-agent skill for multi-phase security audits with independently verified findings. This project is a separate implementation and is not affiliated with or endorsed by Cloudflare.

## License

[MIT](LICENSE)
