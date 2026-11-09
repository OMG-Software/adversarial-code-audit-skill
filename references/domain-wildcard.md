# Domain: Wildcard

## Scope

- **Load when:** always. Every audit loads this file. Use it on code that the other domain files do not describe: strange, old, experimental and half-finished code.
- **Covers:** surfaces that no normal client uses; legacy and compatibility code; experimental and stub code; combinations of features; assumptions about the environment (clock, DNS, case sensitivity, locale, encoding); comments that claim safety; behaviour that tests do not check; code that is live but looks dead.
- **Rule:** the same evidence bar applies as in every other domain. Strange code is a lead, not a finding. A candidate needs attacker, entry, path, failing control, impact and evidence (SKILL.md section 6). "This looks wrong" and "this is old" are not impact. If you cannot name the failing control and the victim, record a hardening note or nothing.
- **Hand off to:**
  - `domain-api.md` – the inventory of documented against undocumented endpoints, and mass assignment. This file covers code that is reachable but that no client calls.
  - `domain-secrets-config.md` – feature flags, config precedence and debug modes in depth.
  - `domain-input-parsing.md` – parser differentials, Unicode normalisation and case folding of identifiers.
  - `domain-supply-chain.md` – dependency and build questions.
  - `domain-concurrency.md` – races. This file may notice a race. That file owns the method.
  - `domain-business-logic.md` – state and limit rules.
  - The matching domain file for any boundary that the strange code touches. Open a new unit for it.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Reachability:** Every entry point that an untrusted <principal> can reach applies the same controls as the main path to the same effect.
2. **Legacy:** Compatibility and legacy code does not accept inputs, formats or versions that the current code rejects for security reasons.
3. **Completeness:** No security control is a stub, a placeholder or a partial implementation in a build that ships.
4. **Combination:** Enabling any allowed combination of features, modes and plugins keeps every invariant that each one holds alone.
5. **Environment:** The code keeps its security properties when the clock, name resolution, locale, case sensitivity, character set or file system differ from the developer's setup.
6. **Claims:** A comment, name or document that claims safety ("validated", "internal only", "cannot happen") is true on every path that reaches the code.
7. **Tests:** Each control that the threat model names has a test that fails when the control is removed.

## Recon additions

Add these to `threat-model.md` under a heading "Unusual code". Keep it short.

1. **Entry inventory against use.** Every route, command, message type, RPC method, handler and CLI option, against the callers in the shipped clients and documentation. List the ones that no known client uses.
2. **Version and compatibility layers.** Old API versions, old file and wire formats, migration code, shims, fallbacks for old clients, and the setting that enables each.
3. **Maturity markers.** Directories and names such as `experimental`, `legacy`, `deprecated`, `old`, `compat`, `unstable`, `beta`, `internal`, `wip`, and flags with the same meaning. Note whether the default build includes them.
4. **Feature and mode matrix.** The features, modes, roles, plans and plugins that can be combined, and the combinations the tests cover.
5. **Environment assumptions.** Reads of the clock, locale, host name, DNS, file-system case rules, path separators, character sets, CPU count, terminal and container facts, with the decision that each feeds.
6. **Safety claims.** Comments and documents that say a value is safe, trusted, validated, internal or impossible.
7. **Test coverage of controls.** For each control in the threat model: the test that fails without it, or "none".

## Lead searches

Adapt the patterns to the language.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| Handlers registered but absent from the documentation, the client code and the tests | Surface that no client uses (WD-01) | Internal health or hook routes may be fine. Check reach and authentication. |
| `legacy\|deprecated\|compat\|backwards?\|old_?(api\|version\|format\|client)\|v0\|v1\|fallback\|downgrade` | Compatibility path (WD-02) | Compare its checks with the current path. |
| `experimental\|unstable\|beta\|wip\|prototype\|not_?implemented\|unimplemented\|stub\|placeholder\|dummy\|mock` outside tests | Unfinished code that ships (WD-03) | A stub may be unreachable. Prove reach in both directions. |
| `return true\|return ok\|pass$\|{}\s*$\|NotImplemented` as the whole body of a check, verify or validate function | Empty control (WD-03) | |
| `feature\|flag\|enable\|disable\|toggle\|mode` combined in one condition, or read in separate modules for one decision | Feature interaction (WD-04) | |
| `tolower\|toLower\|lower()\|casefold\|equalsIgnoreCase\|strcasecmp\|normalize\|locale\|setlocale\|timezone\|gethostname\|getaddrinfo\|time(\|now(` near security comparisons | Environment assumption (WD-05) | Check the comparison on both sides. |
| `safe\|trusted\|already (validated\|checked\|sanitised\|sanitized\|verified)\|cannot happen\|never happens\|internal only\|should never\|assume` in comments | Safety claim (WD-06) | The claim may be correct. Check every caller. |
| Test files: skipped or disabled tests (`skip\|ignore\|xfail\|@Disabled\|t.Skip\|#\[ignore\]`) near security code; mocks that replace the control | Test gap (WD-07) | |
| `reflect\|getattr\|dlsym\|dispatch\|handlers\[\|Class\.forName\|__import__\|plugin\|registry\|autoload\|glob\(` with names built from strings | Live code that search misses (WD-08) | |
| Files that run but are not source: SQL migrations, hooks, install scripts, CI files, templates, generated code, macros | Hidden logic (WD-08) | |
| Suppressed warnings: `NOLINT\|nolint\|nosec\|eslint-disable\|SuppressWarnings\|#\[allow\|pragma warning` | A developer silenced a tool (WD-06) | Check why. |

## Attack classes

### WD-01 Surfaces that no client uses

- **What fails:** a reachable entry has weaker controls than the entries that clients use, because nobody tests or reviews it.
- **Where to look:** routes and methods missing from the documentation; message types and commands that only an old client sends; admin and operations routes; bulk, export and import endpoints; hidden CLI options; debug and test hooks; unlinked pages; handlers for events that the UI never raises; mobile or firmware commands that only a service tool uses.
- **Questions:**
  - Which entry reaches this effect without going through the shared checks?
  - Who can reach the entry: which network, which principal?
  - Does the entry call the same decision function with the same subject and resource?
  - Does the entry accept fields or modes that the main path hides?
- **Sad-path inputs:** a call by a lower principal; a call with fields that the UI never sends; a call that skips a prior step.
- **Evidence for confirmed:** the registration, the absent control on the full path, the reach by the named attacker, and the effect. Name the equivalent main-path check that proves the control is expected.
- **Not a finding:** an internal hook that only a trusted component can reach and that exposes nothing the caller lacks.
- **CWE:** CWE-420 (unprotected alternate channel); CWE-288 (authentication bypass using an alternate path or channel).

### WD-02 Legacy and compatibility code

- **What fails:** old code, formats or protocol versions stay active and accept what the current code rejects.
- **Where to look:** version negotiation and fallbacks; old API versions; old file, token and wire formats; migration code that runs on every start; "accept both" parsers; settings that allow old algorithms or cipher suites; deprecated endpoints kept for old clients; data from before a rule existed.
- **Questions:**
  - Can the caller choose the old path (a version field, a header, a format byte, a URL prefix)?
  - Does the old path have the checks added to the new path after a fix?
  - Is an old format still parsed, and does the parser trust more than the new one?
  - Can an attacker force a downgrade to the old path?
- **Sad-path inputs:** the oldest accepted version value; a version field that is missing, repeated or out of range; a record in the old format for a principal that exists in the new format.
- **Evidence for confirmed:** the selector the attacker controls, the old path without the fix, and the effect. Check the history for a fix that covered only the new path.
- **Not a finding:** old code that no input can reach in a shipped build; a downgrade that the operator controls and that is documented.
- **CWE:** CWE-757 (selection of less-secure algorithm during negotiation); scope: downgrade to old formats or versions.

### WD-03 Experimental, stub and half-finished code

- **What fails:** a security control is a placeholder, a partial implementation, or a feature that was started and never wired in.
- **Where to look:** `NotImplemented` and `TODO` bodies; functions that return a constant; validators that validate part of the input; features behind a flag that config can turn on; branches that log "not supported" and continue; half-removed features whose routes remain.
- **Questions:**
  - Does the build that ships include this code and can the attacker reach it?
  - If the control is a stub, what depends on it? What does the caller assume?
  - Is the flag on in the default configuration, in an example configuration or in a documented mode?
  - Does an error from the unfinished code fail open?
- **Sad-path inputs:** the input that the real control would reject; the flag turned on; the unsupported option.
- **Evidence for confirmed:** the stub, the caller that trusts it, the path from the entry, and the rejected input that passes. Show reach both ways: from the entry to the stub, and from the stub to the sink.
- **Not a finding:** a stub that no shipped path calls; a feature flag that only a developer build enables.
- **CWE:** no close CWE entry. Weakness in words: incomplete implementation of a security control; failing open.

### WD-04 Feature combinations

- **What fails:** two features that are safe alone break an invariant together.
- **Where to look:** mode times role times plan; plugin A with plugin B; import with sharing; caching with personalisation; compression with encryption; offline mode with sync; guest access with public links; admin impersonation with audit; multi-tenant mode with a global feature; each feature that adds an alternate path to an existing effect.
- **Questions:**
  - Which invariants does each feature assume? Does another feature break the assumption?
  - Which state does a feature write that another feature reads without checks?
  - Which combinations do the tests cover? Which combinations does the documentation forbid but the code allows?
  - Does one feature skip the check that a second feature relies on?
- **Sad-path inputs:** every flag on; every flag off; two modes at once; a mode switched in the middle of an operation; a plugin that registers a handler for an existing event.
- **Evidence for confirmed:** the combination, the assumption of feature A that feature B breaks, and the invariant that fails. Reproduce at E3 when the claim depends on runtime configuration.
- **Not a finding:** a combination that the product forbids and the code rejects; a conflict that only makes the product misbehave without crossing a boundary.
- **CWE:** no close CWE entry. Weakness in words: unexpected interaction between components; incomplete enforcement of an invariant.

### WD-05 Environment assumptions

- **What fails:** a check holds on the developer's setup and fails elsewhere.
- **Where to look:** clock reads and comparisons; DNS and host-name checks; case-insensitive file systems and case-folded comparisons; locale-dependent upper and lower casing; path separators and drive names; character sets and byte-order; integer width and endianness; time zone; random-number seeding at start-up in containers or embedded devices; behaviour with and without a terminal; proxy variables; read-only or full disks; low entropy at boot.
- **Questions:**
  - Which environment fact does the decision depend on? Can an attacker change it?
  - Do the check and the use see the same value after case folding, normalisation or resolution?
  - What happens when name resolution fails, returns more than one address, or changes between two lookups?
  - What happens when the clock is wrong, goes back, or is controlled by a peer?
- **Sad-path inputs:** mixed-case and Unicode identifiers; a host name that resolves differently over time; a clock skewed by hours; a locale with different case rules; a path with the other separator; an empty or unwritable directory.
- **Evidence for confirmed:** the assumption, the way the attacker moves it, and the control it breaks. Claims that depend on the platform need E3 on that platform, or `needs-validation` with the exact fact.
- **Not a finding:** a failure that the attacker cannot influence and that only breaks availability on odd setups.
- **CWE:** CWE-180 (validate before canonicalise); CWE-178 (improper handling of case sensitivity).

### WD-06 Comments and names that claim safety

- **What fails:** the code relies on a statement that is false on some path.
- **Where to look:** comments that say "validated", "trusted", "internal", "safe", "cannot be null", "already checked"; function names such as `safe_`, `secure_`, `validate_`, `sanitize_` that do less than the name says; analyser suppressions; documents that describe a control the code lacks.
- **Questions:**
  - Read the body of the called function. Does it do what its name and comment say?
  - Who else calls this code? Does every caller meet the assumption?
  - Did a later change break the assumption without changing the comment?
- **Sad-path inputs:** a caller that skips the earlier step; input at the edge of what the "validation" accepts; the empty value.
- **Evidence for confirmed:** the claim, the caller or input that violates it, and the resulting effect. The comment alone is never evidence.
- **Not a finding:** a claim that holds on every path; a stale comment with no security effect.
- **CWE:** no close CWE entry. Weakness in words: reliance on an unchecked assumption; improper input validation.

### WD-07 What the tests do not test

- **What fails:** a control has no negative test, so a break goes unseen. Or a test replaces the control with a mock, so the real control never runs.
- **Where to look:** test directories next to each control; tests with only valid input; mocks of authentication and policy layers; disabled and skipped tests; test configuration that differs from production; fuzz targets and what they cover.
- **Questions:**
  - Does a test send a bad token, a wrong tenant, an oversize input and a malformed message?
  - Does the test run the real control, or a mock?
  - Which paths have no tests? Those paths are priority units.
- **Sad-path inputs:** the input the missing test would send.
- **Evidence for confirmed:** a test gap is a lead only. Use it to choose where to hunt. A candidate still needs a real failing control that you trace in the code.
- **Not a finding:** a missing test is never a finding by itself.
- **CWE:** no close CWE entry. Weakness in words: not a weakness by itself.

### WD-08 Live code that looks dead

- **What fails:** code reachable by dynamic means escapes search and review, so the controls around it are unchecked.
- **Where to look:** reflection, dynamic dispatch and plugin loading by name; handlers registered from strings or tables; generated code and macros; code in migrations, hooks, templates, install scripts and CI files; configuration that selects a class or function; handlers added at run time; conditional compilation for another platform.
- **Questions:**
  - Which dynamic mechanism can reach this code? Who controls the name or key?
  - Is the code compiled in for a shipped platform or build?
  - What controls does the dynamic path apply before the call?
- **Sad-path inputs:** a name that matches a hidden handler; a key that selects an unexpected class; a platform or build flag that includes the code.
- **Evidence for confirmed:** the dynamic selector, the control the attacker influences, the reached code and its effect. If the selector is a constant in all builds, reject.
- **Not a finding:** truly dead code, which is a maintenance note only.
- **CWE:** CWE-470 (unsafe reflection); CWE-749 (exposed dangerous method or function).

## Variant search

When you find one issue in strange code:
1. **Same neighbours.** Read the files next to it and the other files in the same legacy or experimental directory.
2. **Same marker.** Search for the same maturity marker, comment or flag name elsewhere.
3. **Same era.** Check the history for commits from the same period or author that added related shortcuts.
4. **Same assumption.** Search for other uses of the same environment fact (the same clock read, the same case fold).
5. **Same gap.** List other controls that have no negative test.

## Chain primitives

This domain often **gives**:
- an entry that skips shared checks (a way in for other domains);
- a downgrade path to weak formats or algorithms;
- an unfinished control that always passes;
- knowledge of environment assumptions that other attacks need.

This domain often **needs**:
- the matching domain file to judge the boundary that the strange code touches;
- an inventory from recon of what clients actually call.

## Verification notes

- **Same bar:** every wildcard candidate meets SKILL.md section 6. The verifier uses the matching domain file for the sink.
- **E1 is usually enough** for WD-01, WD-03 and WD-08 when the registration, the stub or the selector, and the sink are all in the repository.
- **E3 is required** for WD-04 and WD-05 claims that depend on runtime configuration, platform behaviour, DNS or clock behaviour, and for any race claim. Otherwise use `needs-validation` and name the one missing fact.
- **WD-07 never yields a finding.** It yields leads and priority units.
- **Reachability:** prove that the default build includes the code and that the named attacker reaches the entry. Do not count a branch that only a developer flag enables, unless a shipped configuration enables it.
- **Disprove first:** for "dead" or "legacy" code, search for callers, registrations and configuration that enable it. For "stub" code, search for a real implementation that overrides it.
- **Severity examples:**
  - critical – an unauthenticated legacy or hidden entry gives full control or full data access;
  - high – a downgrade path or a stub control defeats authentication or isolation for any user;
  - medium – a feature combination exposes one class of data or action; an environment assumption that an attacker can move with real effort;
  - low – a weakness in rarely used legacy code with a narrow effect;
  - informational – a strange pattern with no boundary effect (record as a hardening note).

## Fix patterns

- **Remove, do not hide.** Delete unused entries, legacy paths and stubs. If one must stay, route it through the same decision function as the main path.
- **One path per effect.** Put controls in the shared layer that every entry uses.
- **Version floor.** Reject versions and formats below a stated minimum. Do not let the caller choose a weaker one.
- **Fail closed for unfinished features.** A feature that is not complete returns an error and does nothing else.
- **Test combinations.** Test the supported feature and mode matrix. Reject unsupported combinations at start-up.
- **Explicit environment.** Use explicit time zone, locale and encoding. Canonicalise before you compare. Resolve a name once and use the result.
- **Make claims checkable.** Express "validated" in the type system, or check at the point of use.
- **Looks right but is not:** commenting out a route but leaving its handler registered by a pattern; a flag that defaults off but that config files enable; renaming a legacy path; adding a comment that says the input is checked; a test that mocks the control it tests.

## Regression tests

- A route-parity test: every registered entry is on a reviewed list with its expected authentication. A new entry fails the test until someone reviews it.
- For each legacy path: a test that sends the old format or version and asserts the same refusal as the new path.
- For each security control: a negative test that fails when the control is removed. Use a mutation check if tooling exists.
- A matrix test over the supported feature combinations that asserts the invariants of each.
- An environment test with an injected clock, resolver and locale, and mixed-case and Unicode identifiers.
- A start-up test that fails the build when a stub, `NotImplemented` or a placeholder appears in a shipped security path.
