<!--
Finding template. Copy this file to findings/F-<fingerprint>.md and fill every field.
Keep the headings and field names exactly as written: scripts and other agents parse them.
Write "none" for an empty field. Do not delete a field.
Repository paths are relative to the target root. Never paste secret values.
-->

# <Title: one line, states the boundary failure, not the bug class>

## Header

- fingerprint: <domain>.<component>.<root-cause>
- status: proposed | confirmed | needs-validation | rejected
- evidence-level: E1 | E2 | E3
- domain: <primary domain file name, for example authz>
- cwe: <CWE-ID or "none">
- coverage-units: <IDs from coverage.md>
- found-by: <agent or pass ID>
- verified-by: <agent or pass ID, or "none">
- source-ref: <commit hash, plus "dirty" if the worktree had changes>

Fingerprint rules: lowercase letters, digits, hyphens and dots only. Derive it from the root cause and the component.
Do not include line numbers, dates, agent IDs, severity or status. Use the same fingerprint for the same root cause in every run.

## Summary

<Two or three sentences: who can do what to whom, through which interface, because which control fails.>

## Attacker

- principal: <for example: unauthenticated network client; authenticated user in tenant A; federated remote server>
- starting capability: <what this principal can already do by design>

## Path

Each step: kind (entry | step | sink), file:line, function or scope, what happens to attacker data.

1. entry – `path/to/file.ext:123` – `function()` – <attacker-controlled value enters>
2. step – `path/to/file.ext:456` – `function()` – <transformation or decision>
3. sink – `path/to/file.ext:789` – `function()` – <security effect>

## Control

- intended control: <the check, binding or limit that should stop this, with file:line, or "absent">
- why it fails: <wrong resource, wrong principal, wrong order, missing on this path, fail-open, bypassable encoding, ...>
- other controls checked: <every other visible layer on the path, with file:line, and why each does not stop the attack>

## Conditions

List every precondition. Mark each as source-visible or external.

- <condition> – source-visible | external

## Impact

- victim or resource: <named principal, tenant, resource or invariant>
- result: <the concrete effect: read X, write Y, act as Z, crash shared process, ...>
- not claimed: <stronger effects you did not show, for example "no code execution shown">

## Evidence

- read: <files and line ranges you read for each path step>
- tools: <commands, analyser rules or queries, and their result, or "none">
- reproduction: <for E3: isolation level (I1, I2 or I3), limits, exact input, exact command, observed output. Otherwise "none">

## Reproduction waiver

Required when status is `confirmed` and evidence-level is E1 or E2. Otherwise write "none".
The report prints this section unchanged, so write it for the code owner.

- deterministic steps: <for each path step, why the source alone fixes the behaviour: no branch on runtime data the attacker cannot control, no reliance on timing, memory layout, compiler output or code outside the repository>
- runtime dependencies checked: <framework, library or platform behaviour the path relies on, and where you confirmed it (vendored source, pinned version docs, type signatures)>
- what reproduction would add: <for example "confirms deployment config enables the route"; or "nothing: the check is absent on every path">
- recommended confirmation: <the smallest test the owner can run to see the effect>

## Disprove attempts

Filled by the verifier. Each attempt: the hypothesis that would make this a false positive, what you checked, and the result.

1. <hypothesis> – <what was checked> – <holds | refuted>

## Severity

Only for status `confirmed`. Otherwise write "none".

- likelihood: low | medium | high – <reason>
- impact: informational | low | medium | high | critical – <reason>
- overall: informational | low | medium | high | critical – <reason; never above impact>
- confidence: <0–100> – <reason>

## Blocker

Only for status `needs-validation`. Otherwise write "none".

- missing fact: <the fact that decides the verdict; if there are several independent ones, list each with its own safe check>
- why not observable: <outside the repository | needs tier T2 | needs deployment config | ...>
- safe check: <a local test or an owner-side observation that settles it; never live probing>

## Rejection

Only for status `rejected`. Otherwise write "none".

- reason: <the control, condition or fact that disproves the claim, with file:line>

## Fix

- invariant: <the rule the code must enforce>
- change: <the smallest source change at the last trusted decision point, with file:line>
- regression test: <the test that fails before the fix and passes after>
- variants: <other locations with the same root cause, or "searched: none found" with the search used>
