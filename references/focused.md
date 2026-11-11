# Focused and diff reviews

Use this route for a named finding, file, function or diff, or for one question about one boundary. A report request does not expand that scope. A subsystem, a directory or a whole domain needs the coverage ledger: that is a scoped Full audit (SKILL.md section 1).

## Setup and scope

Use the output directory and snapshot rules in SKILL.md section 4. Write a short `plan.md` from [the plan template](../assets/plan-template.md): fill the sections that its first comment lists for Focused mode (scope, commit or file hashes, tier, execution choice or I0, output and scratch paths, relevant references), and write "n/a" in the rest. Do not create a full coverage ledger for one finding.

Write a small `threat-model.md` with the attacker, design authority, entry, asset, boundary, control and decisive external assumptions. It can contain one row. For multiple boundaries, assign local unit IDs there. Use these IDs as `coverage-units` in the finding template; do not reference a nonexistent `coverage.md`.

Select only relevant domain and language sections using SKILL.md section 5. Follow links to checks needed for the claim. Unchanged callers, middleware, dependencies and configuration are in scope when needed to establish or disprove the scoped path.

## Trace and verify

1. Read [phase-hunt.md section 3.2](phase-hunt.md#32-method). Use the scoped threat model instead of a full coverage row. Keep incomplete ideas as notes in `plan.md`; do not invent a candidate when the contract is incomplete.
2. Write one finding file per candidate root cause using [the template](../assets/finding-template.md). Describe fixes; do not change target source.
3. Read and apply [phase-verify.md](phase-verify.md), including its independent-agent or separate-pass rule. Record disprove attempts. Write proof tests as needed. Before running one, follow [execution.md](execution.md): without the user's choice, stay at I0 and keep the test as text.
4. If a new, unrelated boundary appears, record it as out of scope. Follow it only when it is necessary to decide this claim, or the user expands scope.

## Additional rules for diffs

- Record immutable base and head revisions, comparison type and changed paths using existing local inputs and safe read operations. Do not fetch, clone or change a checkout to obtain them. For a PR, use the available merge base unless the user specifies another baseline. Record its hash, not a moving branch name alone. For a commit, use its parent unless specified otherwise. For a working-tree diff, record the baseline and hashes of reviewed regular files; do not follow links outside scope.
- If the baseline is missing or ambiguous, inspect what is available. Do not claim that an issue is newly introduced until the comparison is resolved. Ask for the missing baseline if it is needed to complete the requested regression review.
- Compare the control and reachable effect before and after the change. Read unchanged code needed for both traces. A finding is reportable as a regression only if the change introduces the boundary failure or makes a previously unreachable failure reachable. A changed line near an existing defect is insufficient.
- Fill the `Regression origin` section of each diff candidate: base and head identities, before/after behavior with citations, changed code responsible, and why the failure is introduced or newly exposed. Keep pre-existing issues out of the regression results and counts. If you notice a serious pre-existing issue, mention it briefly in a separate, clearly labelled "pre-existing, not reviewed" note without a severity.
- Before finishing, confirm the reviewed inputs still match their recorded snapshot. Re-evaluate affected findings if they changed.

## Output

Give the user the verdict, evidence, relevant path, fix and limitations. If no candidate survives, state the scoped result and controls checked; do not imply the whole repository is safe. Mark unsupported candidates as unverified if work stops before verification.

Write `REPORT.md` only if requested. Use the relevant parts of [phase-report.md](phase-report.md), omitting full-audit coverage counts and empty sections. Keep findings, verdicts and evidence identical between the response, report and finding files.
