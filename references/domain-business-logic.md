# Domain: Business Logic

## Scope

- **Load when:** always. Every audit loads this file. Every product has rules about order, limits, time and state.
- **Covers:** workflow and state-machine rules that are not about who may act. Step order. Replay of completed flows. Partial failure. Limits and quotas. Quantity and boundary values. Time windows. Missing configuration and defaults. Trust in data that another path wrote.
- **Rule:** a rule violation is a finding only when it breaks an invariant that the product states or clearly needs, and a named party loses something (money, data, access, integrity, availability). "The code allows an odd order of steps" is a lead.
- **Hand off to:**
  - `domain-authz.md` – who may perform the action. Use this file when the principal is allowed and the rule is still broken.
  - `domain-financial.md` – money, balances, precision, idempotency for payments, ledgers. This file keeps the generic form.
  - `domain-concurrency.md` – race mechanics and locking. This file states the business invariant that the race breaks.
  - `domain-client-trust.md` – rules that only the client enforces.
  - `domain-resource-exhaustion.md` – limits that protect capacity. This file covers limits that protect a business rule.
  - `domain-abuse.md` – rate limits and scale abuse by many accounts.
  - `domain-data-lifecycle.md` – deletion, restore and retention rules.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Order:** <Entity> reaches state <S> only through the allowed transitions, and each transition checks the current state at the time it runs.
2. **Single use:** <One-time thing> (coupon, token, invite, reward, vote, licence key, firmware slot) takes effect at most once, even after retries and repeated requests.
3. **Atomicity:** A multi-step operation either completes all steps or leaves no visible partial result, and a failure leaves the system in a state that a retry can repair.
4. **Limits:** <Limit> applies to every path that produces the limited effect, and the limit counts the same unit on each path.
5. **Boundaries:** Every numeric input (quantity, count, size, duration, index, rate) is within its documented range, and the arithmetic stays correct at the edges.
6. **Time:** Every deadline, window and expiry uses one trusted clock and one documented time zone, and an actor cannot move the window.
7. **Defaults:** When configuration, a dependency or a field is missing, the result is the restrictive one.
8. **Derived data:** A value that one path wrote is not trusted by another path unless a check re-validates it for the new use.

## Recon additions

Add these to `domain-notes.md` under a heading "Business rules". Keep it short.

1. **State machines.** For each stateful entity (order, account, ticket, job, device, session, document, subscription): states, allowed transitions, who triggers each, and where the code stores the state.
2. **One-time effects.** Every coupon, token, invite, trial, reward, vote, claim and unlock, and where the code records that it was used.
3. **Limits table.** Each limit (quota, cap, cooldown, trial length, size, count): its value, its unit, the paths that count against it, and the paths that do not.
4. **Time rules.** Each expiry, window, schedule and cooldown: the clock source, the time zone and the stored format.
5. **Multi-step operations.** Each operation that touches two or more stores or services, and its failure handling.
6. **Feature and plan differences.** Free against paid, region, role and tier differences in the rules.
7. **Write paths per field.** For each state-bearing field: every code path that writes it (API, import, job, admin, migration).

## Lead searches

Adapt the patterns to the language. The language file adds framework-specific names.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `status\|state\|stage\|phase\|step` assigned or compared in handlers, with no read of the current value before the write | Missing transition check (BL-01) | A database constraint or enum transition table may enforce order. |
| `(used\|redeemed\|consumed\|claimed\|spent\|completed\|done)` flags set after the effect, not before or with it | Replay or single-use gap (BL-02) | A unique constraint on the use record holds. |
| Two or more writes or calls in one handler (database plus queue, database plus provider, two tables) with no transaction or compensation | Partial failure (BL-03) | A saga or outbox pattern may repair it. Read it. |
| `limit\|quota\|max_?\w*\|cap\|cooldown\|throttle\|trial` | Limit scope (BL-04) | Count the paths that bypass the check. |
| `quantity\|count\|amount\|size\|length\|offset\|index\|duration\|qty` read from input without a lower and upper bound | Boundary values (BL-05) | A typed range or schema may bound it. |
| `now()\|time()\|Date\.now\|clock\|utc\|timezone\|expires?_?(at\|in)\|valid_?(until\|from)\|ttl` | Time rule (BL-06) | Check the clock source and the comparison direction. |
| `getenv\|config\.get\|settings\.\w+\|\|\s*(0\|""\|null\|\[\]\|false)\|default[:=]` near limits, checks and feature switches | Missing config falls to permissive (BL-07) | A default of zero may mean "unlimited". Check each meaning. |
| `if\s*\(?\s*!?\s*\w+\.(verified\|approved\|paid\|active\|trusted\|validated)` where the field is written elsewhere | Trust of another path's data (BL-08) | Find every writer of the field. |
| `import\|restore\|sync\|migrate\|bulk\|batch\|replay\|retry` that write state fields | Alternate path with weaker rules (BL-01, BL-08) | |
| `TODO\|FIXME` near `limit\|state\|status\|retry\|cleanup\|rollback` | Known gap | |

## Attack classes

### BL-01 Step skipping and reordering

- **What fails:** a client reaches a late state without the earlier steps, or repeats and reorders steps so that a rule no longer holds.
- **Where to look:** multi-step flows (checkout, onboarding, approval, verification, provisioning, firmware update, quest chains); handlers that take the next state from the request; import, restore and admin paths that set state directly.
- **Questions:**
  - Does each transition handler read the current state and check that the transition is allowed?
  - Does the server hold the step state, or does the client carry it (hidden field, token, URL, local file)?
  - Can step N be called before step N−1, twice, or after the final step?
- **Sad-path inputs:** call the last step first; skip the verification step; repeat a middle step; call a step on an entity in a terminal, cancelled or deleted state; call two steps from two sessions.
- **Evidence for confirmed:** the state definition, the handler without a state check, the call order that reaches the late state, and the rule it breaks. E1 is enough when the state is stored and written only in the repository.
- **Not a finding:** a harmless skip that gives the principal nothing it could not get otherwise; a step the product documents as optional.
- **CWE:** CWE-841 (improper enforcement of behavioural workflow).

### BL-02 Replay and repeat of completed flows

- **What fails:** a one-time effect happens more than once, or a finished flow runs again.
- **Where to look:** redemption of coupons, invites, rewards and votes; "mark as used" written after the effect; retry handlers; consumers with at-least-once delivery; claim and download tokens; reconnect and resume logic.
- **Questions:**
  - Where does the code record that the effect happened? Is the record written in the same transaction as the effect, and before any external call?
  - Does a unique constraint enforce single use, or only an application check?
  - What happens when the same request arrives twice in sequence? Twice at the same time?
- **Sad-path inputs:** the same token twice; the same request after a timeout; the same message delivered twice; a token for entity A used on entity B; a token after the entity is reset.
- **Evidence for confirmed:** the effect, the absent or late "used" record, and the repeat that gives a second effect. A claim that needs concurrent requests needs E3 (SKILL.md section 6). A sequential repeat can be E1.
- **Not a finding:** a repeat that gives the same state (a true no-op); a documented repeatable action.
- **CWE:** CWE-837 (improper enforcement of a single, unique action); CWE-294 (capture-replay).

### BL-03 Partial failure without rollback

- **What fails:** one step of a multi-step operation fails after an earlier step has changed state. The system keeps a result that no rule allows.
- **Where to look:** handlers with several writes; external calls between writes; file plus database updates; caches or indexes updated apart from the store; jobs that stop in the middle; cancellation and timeout paths; cleanup blocks; migration steps.
- **Questions:**
  - What state remains if step 2 of N throws, times out or is cancelled?
  - Does the code roll back, compensate, or leave a marker that a retry can finish?
  - Can an attacker cause the failure on purpose (a bad field, a large input, a cancelled request, a dependency that is down)?
  - Does the failure leave a benefit (a free resource, a granted role) or lock a victim (a held reservation, a stuck state)?
- **Sad-path inputs:** a failure injected after each step; a client that disconnects mid-request; a provider that returns an error after it succeeded; a retry after a partial run.
- **Evidence for confirmed:** the step order, the failing step that an attacker can trigger, the state left behind, and the rule it breaks. Show the failure with a test double, not a live service.
- **Not a finding:** a partial state that a documented repair job fixes within the documented time.
- **CWE:** CWE-460 (improper cleanup on thrown exception); scope: multi-step operation left half-done.

### BL-04 Limits and quotas on one path only

- **What fails:** a limit protects one route, but another route produces the same effect without it.
- **Where to look:** caps on creation, invitation, export, trial use, seats, storage and attempts; limits in the UI or one API version; limits counted per request but not per batch item; limits keyed by a value the attacker can change; limits reset by account changes.
- **Questions:**
  - List every path that creates the limited thing. Does each one check the limit with the same unit?
  - Is the count read and updated atomically?
  - Does the key include all of: principal, tenant, resource and time window? Can the key be varied (case, whitespace, alias, a second account)?
- **Sad-path inputs:** the limit exactly; limit plus one in one batch; the same action through each path; a deleted and recreated entity; a changed key value.
- **Evidence for confirmed:** the limit check on path A, the path B that produces the same effect without it, and the effect beyond the limit that costs a named party. Check `domain-abuse.md` when many accounts are the only way.
- **Not a finding:** a soft limit that the product documents as advisory; a bypass that the attacker can use only on its own quota.
- **CWE:** CWE-799 (improper control of interaction frequency; class-level).

### BL-05 Negative, zero and boundary quantities

- **What fails:** an input at the edge of its range changes the meaning of the rule.
- **Where to look:** quantities, counts, sizes, durations, ranks, indexes and rates read from input; arithmetic and comparisons on them; conversions between units and integer widths; loops and allocations sized by them.
- **Questions:**
  - What happens at −1, 0, 1, the maximum and the maximum plus one?
  - Does a negative value reverse the direction of an effect (a refund, a transfer, a stock change, a score)?
  - Does zero skip a check, a fee or a division, or mean "unlimited"?
  - Do two valid values combine to overflow or wrap?
- **Sad-path inputs:** negative; zero; very large; fractional; the string form of a number; a number in exponent form; `NaN`; an empty list; duplicate list items.
- **Evidence for confirmed:** the unbounded input, the arithmetic or comparison, and the invariant that breaks. Use `domain-financial.md` for money, and `domain-memory-safety.md` for memory effects.
- **Not a finding:** an edge value that the schema or type rejects before use; a negative number that has a documented meaning.
- **CWE:** CWE-1284 (improper validation of specified quantity in input); CWE-190 (integer overflow or wraparound).

### BL-06 Time windows and clock skew

- **What fails:** a rule that depends on time can be moved, stretched or bypassed.
- **Where to look:** expiry of tokens, trials, offers and reservations; schedules and cooldowns; "valid from" and "valid until" checks; time zones and daylight saving; clocks set by clients or devices; timestamps taken from requests or peers.
- **Questions:**
  - Which clock decides: the server's, a database's, the client's or a peer's?
  - Does the code use wall-clock time for durations? A clock jump then changes the result.
  - Is the comparison direction and strictness right (`<` against `<=`) at the exact boundary?
  - Can a principal change its own time zone, locale or device clock to change a window?
- **Sad-path inputs:** the exact expiry second; a timestamp in the future; a timestamp before the epoch; a clock set back; a time zone change at renewal; a DST transition hour; 29 February.
- **Evidence for confirmed:** the clock source, the comparison, and the input or state that moves the window to give a benefit or deny a victim. Clock-dependent claims that need a real clock change need E3.
- **Not a finding:** a skew of seconds that the product documents; a client clock used only for display.
- **CWE:** no close CWE entry. Weakness in words: reliance on an untrusted time source; incorrect comparison.

### BL-07 Defaults when configuration or a dependency is missing

- **What fails:** a missing value, a failed lookup or an unavailable service gives a permissive result.
- **Where to look:** configuration reads with a fallback; `null`, `0` or empty meaning "no limit"; feature checks that treat "unknown" as "on"; calls to licence, risk, quota or policy services with a catch that continues; new fields on old records.
- **Questions:**
  - What does the code do when this value is absent, empty, zero, unparsable or of a wrong type?
  - Can an attacker cause the absence (a request that makes the lookup fail, an unusual key, a deleted dependency record)?
  - What is the default for records that existed before the field was added?
- **Sad-path inputs:** a missing key; an empty string; zero; a timed-out dependency; a record created before the migration.
- **Evidence for confirmed:** the fallback line, the way the attacker triggers it, and the permissive result. Failure-injection tests with a double give E3.
- **Not a finding:** a permissive default for a non-security feature; a default that only the operator can trigger.
- **CWE:** CWE-1188 (initialisation of a resource with an insecure default); CWE-636 (failing open; class-level).

### BL-08 Trust in data written by another path

- **What fails:** code reads a stored field and treats it as verified, but a weaker path wrote it.
- **Where to look:** status, flag and counter fields (`verified`, `approved`, `paid`); data from import, sync, admin tools, edit forms, partner feeds and migrations; denormalised copies; client-supplied values stored for later use.
- **Questions:**
  - List every writer of the field. Does each one apply the same rules?
  - Does the reader re-check what it relies on, or trust the stored value?
  - Can a user-editable field feed a decision that assumes it was set by the server?
- **Sad-path inputs:** a value written through the weakest path; an imported record with a server-owned field set; a stored value with unusual characters or case; an old record from before a rule existed.
- **Evidence for confirmed:** the weak writer, the stored value, the reader that trusts it, and the benefit. E1 is enough when all writers and the reader are in the repository.
- **Not a finding:** a field that only a trusted principal can write by every path.
- **CWE:** CWE-348 (use of less trusted source); scope: stored field written by a weaker path.

## Variant search

When you find one business-logic defect:
1. **Same entity.** List every handler, job and import that reads or writes the same state field. Check each for the same missing rule.
2. **Same rule.** Search for other places that must apply the same limit, transition or time check.
3. **Same effect.** List every path to the same effect (create, grant, redeem, extend, refund). Compare the checks.
4. **Same shape.** Search for other one-time tokens, multi-step handlers and limit counters built the same way.

## Chain primitives

This domain often **gives**:
- state that other checks trust (verified, approved, paid, active);
- extra resources, time or quota (trial extension, free tier);
- a stuck or inconsistent state that blocks a victim;
- repeated effects (double credit, double grant).

This domain often **needs**:
- an account of any kind (from authn or abuse flows);
- knowledge of internal IDs and states (from disclosure);
- concurrency for single-use claims (from `domain-concurrency.md`).

## Verification notes

- **E1 is usually enough** for BL-01, BL-04, BL-05 and BL-08 when the state, the handlers and the sink are in the repository.
- **E3 is required** for race and double-spend claims in BL-02 and BL-04 that need concurrent requests, and for BL-06 claims that need a real clock change. Use a deterministic schedule: a barrier in a test build, or two threads that wait at the check. A single sequential repeat can stay E1.
- **E3 is required** for BL-03 and BL-07 claims that depend on a dependency error that the repository does not show. Use a test double that returns the error.
- **Design authority:** read the documentation, tests and product text for the intended rule. If the documentation says the behaviour is intended, reject. If the documentation and the code disagree, report the disagreement and say which one you used.
- **Victim check:** name who loses what. A principal that exploits its own data or quota only is not a boundary failure.
- **Reachability:** confirm the entry exists in the default build, in the plan or tier the attacker holds.
- **Severity examples:**
  - critical – anyone gets a paid or privileged state without payment or approval at scale, with no limit (a verification step skipped for every account);
  - high – a single-use value gives repeated large benefit; a step skip gives a victim's resource or a privileged state to the attacker;
  - medium – a limit bypass with real cost to the operator; a partial failure that locks another principal's resource;
  - low – a small benefit with a high effort; an inconsistent state that repairs itself;
  - informational – a logic oddity that only serves a chain.

## Fix patterns

- **State machine in code.** Define allowed transitions in one table. Check the current state inside the transaction that changes it.
- **Atomic single use.** Use a conditional update (`set used where not used`) or a unique constraint on the use record. Check the number of rows changed.
- **Record first.** Write the "used" marker in the same transaction as the effect, before any external call.
- **Compensation.** Use a transaction, or an outbox with a retry, or a saga with an explicit undo for each step. Test each failure point.
- **One limit function.** Call the same limit check from every path that produces the effect. Count the same unit.
- **Typed ranges.** Parse input into types with bounds. Reject out of range values early. Do not clamp silently.
- **One clock.** Take time from the server, in UTC, with a monotonic source for durations. Never from the request.
- **Restrictive defaults.** A missing value means deny or zero. Make a missing required setting stop startup.
- **Re-validate on read.** A reader checks the facts it relies on, or reads from a source that only validated paths write.
- **Looks right but is not:** disabling a button; checking the step in the client; checking state before the transaction and writing inside it; a lock that does not cover the check; catching an error and continuing; a limit per request when the abuse is per item.

## Regression tests

- A state-machine test: for every state and every action, assert allowed or refused as the transition table says.
- A replay test: perform each one-time action twice in sequence, and twice in parallel, and assert one effect.
- A failure-injection test: make each step of a multi-step operation fail, then assert that the final state is valid and a retry works.
- A path-parity test: for each limit, call every path that produces the effect and assert that the limit holds.
- Boundary tests: −1, 0, 1, maximum and maximum plus one, for each numeric input.
- A clock test with an injected clock: the exact boundary, one tick before and after, a clock jump, and a time zone change.
- A missing-config test: unset each setting that a check reads and assert deny.
