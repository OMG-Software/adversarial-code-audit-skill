# Phase 4 – Coverage critique

Goal: find what the hunt missed. The critic proposes coverage, not findings.

Use a fresh agent if you have sub-agents. Otherwise start a separate pass and read the files as if another team wrote them.

Inputs: `plan.md`, `threat-model.md`, `coverage.md`, `leads.md`, the list of finding files (titles and fingerprints only).

Output: changes to `coverage.md` (new units, reopened units) and a critique log at the end of `coverage.md`.

## 4.1 Checks

Do every check. Record the result of each, also when it finds nothing.

1. **Surfaces.** Every entry surface in `threat-model.md` has at least one unit. Search the code again for entry points that phase 1 missed (the language file lists registration patterns). Add units for new ones.
2. **Goals.** Every attacker goal in `threat-model.md` maps to at least one unit that is `covered` or `candidate`.
3. **Domains.** Every selected domain and language file has units. Every excluded file has a reason that is a fact about the code. Reopen weak exclusions.
4. **Thin evidence.** For each `covered` unit, check:
   - the paths read include the control **and** the sink, not only the handler;
   - the checks name sibling paths (batch, legacy, error, federation, background job) or say why none exist;
   - the checks include at least one sad-path test from phase 3, step 4.
   Reopen a unit that fails a check. Archive its earlier result in the Notes column with "reopened: <reason>".
5. **Leads.** Every lead is `traced`, `merged` or `dropped` with a reason.
6. **Variants.** Every finding lists a variant search. Every variant in another unit exists as a lead on that unit.
7. **Lifecycle.** Units exist for start-up and default configuration, upgrade and migration, error and recovery paths, shutdown and cleanup, where the code has them.
8. **Unread code (T1+).** Compare the union of all "paths read" with the list of in-scope files. Rank unread files by: reachable from an entry surface, size, churn, security words in the file. Add units for the top unread files that are reachable.
9. **Blocked units.** For each `blocked` unit, decide if another permitted approach can finish it. Use another starting point or smaller split without expanding scope. A different execution option requires the user's selection under execution.md; do not bypass a safety limit to improve coverage. Reopen feasible units with that approach in Notes.
10. **History.** Each variant seed from phase 2.3 has been checked.

## 4.2 Loop and stop

- **quick profile:** one critique. Add new units as `deferred` with reason "quick profile". Do not hunt again.
- **standard profile:** if the critique added or reopened units, go back to phase 3 for those units, then critique again. Stop when a critique adds nothing, or the budget ends.
- **deep profile:** as standard. When a critique adds nothing, run one more final critique with a fresh agent or pass. Stop only when that one also adds nothing.

When the budget or context ends first, set all remaining `planned` units to `deferred` with the reason. The report must state that coverage is incomplete.

## 4.3 Critique log

Append to `coverage.md`:

```markdown
## Critique <n> – <date>
| Check | Result | Units added or reopened |
|-------|--------|-------------------------|
| 1 Surfaces | 2 new routes in src/admin/ | U041, U042 |
| 4 Thin evidence | U007 read handler only, not membership store | U007 reopened |
| ... | | |
Stop: no | reason: units added
```

## 4.4 Coverage numbers

At the end of the last critique, add:
- units by status;
- in-scope files, files read at least once, percentage;
- entry surfaces with at least one `covered` or `candidate` unit, percentage;
- attacker goals covered, percentage.

These numbers go into the report. They describe effort, not safety. A file that was read is not proved safe.
