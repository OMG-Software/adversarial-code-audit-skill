# Changelog

## 0.11.0 – 2026-11-11

Result of a full review of the skill. The evidence bar and the execution-consent model are unchanged.

### Fixed

- **Output directory.** The default was written as `./security-audit/...` and described as outside the target, which is false when the agent starts in the target. SKILL.md section 4 now gives a resolution order, and a self-ignoring `.gitignore` for the case where the user chooses a directory inside the target.
- **Open findings disappeared from later reports.** An earlier confirmed finding was hidden from hunters, re-verified only if its source changed, and absent from a report built from the new run's files. Phase 1.9 now carries every open finding forward, phase 6 gives it a verdict against the current source, and a new status `fixed` records a finding that the code no longer has.
- **Git hardening was defined but not used.** The commands in phase 1 and phase 2 now use the safe form from execution.md section 1. That section also covers `git status`, tools that call Git themselves, embedded bare repositories and a first read of `.git/config`.
- **Domain-file sections were not tied to phases.** SKILL.md section 5 maps each section to the phase that reads it. "Recon additions" now go to a new file, `domain-notes.md`, so `threat-model.md` can keep its word limit. All 33 domain files point there.
- **Tool rules.** Toolchain launchers that download or run what a target file names (rustup, corepack, `yarnPath`, `go`, version managers) count as target-controlled. Target ignore files that narrow a scanner's results are leads. `gitleaks` runs with `--redact`. The container recipe runs as the user's own unprivileged user and limits file size.
- **Safety rules 6 and 9** overlapped and disagreed on patches. Rule 6 now holds the whole rule: a patch is a new file in the output directory. Rule 9 is new: urgent discoveries are reported at once.
- **Undefined terms.** Phase 6.3 defines the three claim types that need a reproduction: memory-safety, race and parser-differential.
- **Chains.** Phase 6 verifies component findings before chains, and a chain with a rejected or fixed link is rejected unless another primitive gives the same step.
- **Dangling references** to a CWE catalogue and an export script that did not exist are gone. The export script now exists.
- Phase 1.9 listed `needs-validation` as a unit status. It is a finding status.

### Added

- `assets/plan-template.md`: a layout for `plan.md`, with a progress log that a resumed run reads first.
- Scoped Full audits for a subsystem, a directory or one domain.
- `root-cause-at` and `first-seen` in the finding template. `root-cause-at` is the key for finding duplicates; phases 3, 4 and 5 compare it.
- A checkpoint after phase 1 (phase-recon.md section 1.12): the agent shows the size of the run and asks the owner about external assumptions. An owner-attested fact can settle a finding (phase-verify.md section 6.3).
- A definition of where dependency behaviour may come from, and permission to read the pinned dependency's source or documentation.
- A countable definition of "budget". A resumed run resets orphaned `in-progress` units.
- Windows: host guards for PowerShell, and a Windows Sandbox recipe.
- `scripts/audit_run.py` with `check`, `stats` and `export` (JSON and SARIF), and unit tests.
- The validator checks that SKILL.md lists every reference file, that each reference file has the standard sections, and that the product-type table names real domains.
- Evaluations: `secret-handling`, `memory-safety-source-only`, `scanner-triage`, `external-assumption`, `full-mini`, a list of trigger queries, and `evaluations/tools/workspace_inventory.py` for the mechanical checks.
- CI workflow, `.gitignore`, this changelog, `license` in the frontmatter.

### Not done

- The five new evaluation cases have not been run against an agent yet.
- The Windows Sandbox recipe and the container user flags are untested (see "Known limits" in the README).
- The version ranges in the language files were not refreshed, and no new language files were written.
- No CWE catalogue is bundled, so the validator does not check CWE numbers.
- The 45 domain and language files that the review did not read line by line still need a fact check.

## 0.10.0 and earlier

See the Git history.
