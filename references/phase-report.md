# Phase 7 – Report

Goal: give the code owner a report they can act on and check. Build it only from the files of this run. The report never changes a status, evidence level, severity or blocker. If the report and a finding file disagree, the finding file is right: fix the report.

Normally start this phase after every finding is verified. If a budget or context limit stops verification, issue a partial report: leave each unverified candidate `proposed`, list it as "unverified" without severity, and state the unfinished checks. Do not present it as a vulnerability.

Outputs:
- `REPORT.md` – always.
- `findings.json` and `findings.sarif` – if the user asks, or if a script in `scripts/` can produce them.

Focused mode writes a report only when requested and uses the relevant sections below. Omit full-audit ledgers and counts that were not collected. Do not invent coverage numbers.

## 7.1 Writing rules

- Write for an engineer who owns the code and did not see the audit.
- Use repository-relative paths and line numbers.
- Give inputs as test inputs for a local test, not as attacks against a deployment.
- No secret values. No weaponised exploits. No steps beyond the minimum effect.
- State uncertainty where it exists. Do not round `needs-validation` up to a vulnerability or down to nothing.

## 7.2 `REPORT.md` layout

### 1. Scope and method

- Target, commit, dirty state, and the date of the run.
- Mode, profile, scope, capability tier, budget used against budget planned.
- Domain and language files used, and the excluded ones with reasons.
- Tools run, with versions. Each tool that fits the target but did not run, with its one reason from [phase-leads.md section 2.1](phase-leads.md#21-static-tools-t1) (`absent`, `absent-declined`, `T2-skipped`, `network-declined`, `failed`), and what that means for coverage. If no advisory scanner ran, include the sentence "Dependency advisories were not checked against a vulnerability database."
- Execution: the isolation level the user chose (I0–I3), missing controls, approval mode, and how many reproductions ran at each level, completed or not. If any ran at I1 or I2, say so in one plain sentence. Never call host guards a sandbox.
- Verification: independent sub-agents, or a separate pass by the same agent.
- Scratch cleanup: what was removed and what was kept (execution.md section 8).
- Earlier runs used as input.
- One sentence if the run is partial: quick profile, scoped, budget-limited, context-limited or with deferred units.

### 2. How to read the evidence

Copy this section into every report unchanged, then add the counts. It summarises [phase-verify.md sections 6.3–6.5](phase-verify.md#63-evidence-level-and-reproduction-waiver); if the two ever differ, phase-verify is right and this text must be fixed.

> Each confirmed finding has an evidence level.
>
> - **E3 – Reproduced.** We ran a test or harness and saw the effect. Aborted or timed-out runs do not count.
> - **E2 – Source-traced, tool-supported.** We traced every step in the source, and a static analysis tool or type check agrees.
> - **E1 – Source-traced.** We traced every step in the source by reading it.
>
> We confirm an E1 or E2 finding only when the source alone decides every step of the attack: no step depends on timing, memory layout, compiler behaviour, or configuration outside the repository. Each such finding has a **reproduction waiver** that says why the source is enough, what a reproduction would add, and the smallest test that would show the effect. Memory-safety, race-condition and parser-differential findings always need E3. Without it, they are listed under "Needs validation".
>
> Reproductions ran at the isolation level shown with each finding: I3 full sandbox, I2 partial isolation, I1 on the host with guards. The level describes the risk taken while testing, not the strength of the evidence.
>
> A finding is **needs validation** when the code path is real but one or more named facts outside the repository decide it. These have no severity.

Counts: confirmed findings by evidence level.

### 3. Summary

- Two to four sentences on the security posture: where the code is strong, where it is weak, the most important finding.
- Table of confirmed findings, sorted by overall severity, then confidence:

```markdown
| ID | Severity | Title | Boundary | Evidence | Confidence |
|----|----------|-------|----------|----------|------------|
```

### 4. Confirmed findings

For each, in table order:
- Title, fingerprint, CWE, overall severity, likelihood and impact with reasons.
- Summary: who can do what to whom.
- Attacker and conditions.
- Path, as an ordered list of file:line steps.
- Failing control, and the other controls checked.
- Impact, and the stronger effects **not** claimed.
- Evidence: what was read, which tools agreed, and the reproduction (E3) or the **reproduction waiver** (E1, E2), printed in full.
- Fix: invariant, change, regression test, variants.
- Chains this finding is part of.

### 5. Chains

For each chain: the attacker goal, the steps across component findings, the end-to-end impact, and the cheapest link to break.

### 6. Needs validation

Table, then details. No severity.

```markdown
| ID | Title | Boundary | Missing fact | Safe check |
|----|-------|----------|--------------|------------|
```

For each: path, why it matters if the fact is true, and the safe check. A safe check is a local test or an observation the owner makes on their own system. It is never a probe of a live deployment by the auditor.

### 7. Hardening notes

Weaknesses that another layer blocks today. For each: location, the layer that blocks it (file:line), and why fixing it still helps.

### 8. Controls that held

The important controls that hunters attacked and found sound, with the checks done. This tells the owner what not to break, and what the audit actually tested.

### 9. Coverage

- Units by status, from `coverage.md`.
- The coverage numbers from phase 4.4.
- Deferred and out-of-scope units, grouped by reason.
- Attacker goals not examined.
- The final critique result.
- This sentence, unchanged: "This audit does not show that the code has no other vulnerabilities. Further or deeper runs may find more."

### 10. Rejected candidates

Count only, plus the fingerprints, unless a rejection explains a coverage decision.

## 7.3 Consistency check

Before you finish, check:
1. Every finding file has exactly one primary detail or disposition entry matching its status, including an unverified entry for `proposed`. Summary and chain cross-references do not count as duplicate entries.
2. Severities, evidence levels and waivers in the report match the finding files word for word.
3. Counts in sections 2, 3 and 9 match the files.
4. No `needs-validation` or unverified finding has a severity in the report.
5. No secret value appears anywhere in the output directory.
6. Same principal, same boundary, same decision. Group every finding, hardening note and dropped lead by (attacker principal, boundary). Within a group, if one item is a finding and another was dropped or kept as hardening because of "same-user", "design authority" or "out of scope", the second must state the rule that separates it (for elevation, its class from [phase-recon.md "Elevation consent"](phase-recon.md#elevation-consent)). Otherwise write it as a candidate and send it back to phase 6 for a verdict; the report itself does not change its status. Check this too: a variant that needs more attacker steps than a dropped item must not be the only one raised.

Write the result of the check at the end of `REPORT.md` as one line: "Consistency check: passed" or the list of problems fixed.

## 7.4 Machine-readable output

**`findings.json`** – one object per finding file. Field names are the template's field names in lowercase with hyphens. Include all statuses. Keep the path as an ordered list of `{kind, file, line, scope, description}`.

**`findings.sarif`** (SARIF 2.1.0) – for code-scanning tools:
- one `run`, tool name `adversarial-code-audit`, with the skill version;
- one rule per fingerprint; rule `properties.tags` include the CWE and domain;
- one `result` per `confirmed` finding: `level` is `error` for critical and high, `warning` for medium, `note` for low and informational;
- `needs-validation` findings as results with `level: note` and `properties.status: "needs-validation"`, so tools do not show them as confirmed;
- `locations` is the sink; `codeFlows` holds the full path;
- `properties` hold evidence level, confidence and severity fields.

Do not include `rejected` findings in SARIF.
