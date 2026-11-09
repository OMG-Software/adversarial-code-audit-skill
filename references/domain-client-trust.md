# Domain: Client Trust

## Scope

- **Load when:** a server, service or authoritative store accepts state, results, positions, timing, files or decisions from a client that the operator does not control. Signs: multiplayer game servers; real-time simulation; offline-first and sync engines; mobile apps with a backend; IoT and device fleets that report readings; desktop clients with licence or entitlement checks; browser apps that validate in script; mods and plugins; anti-cheat or attestation components.
- **Covers:** client-reported state accepted as truth; missing server-side validation of actions; client-side checks without server checks; replay and forgery of client messages; offline sync and conflict resolution; information sent to clients that they must not hold; mod and plugin capabilities on the server; anti-cheat and attestation trust boundaries.
- **Core assumption:** the attacker controls the client. The attacker can change the client binary, memory, network traffic, local storage and clock. A finding does not say "the client can be modified". A finding says which server-side invariant fails, and which other principal, shared state or economy it damages.
- **Hand off to:**
  - `domain-api.md` – endpoint authorization, mass assignment and over-fetching on HTTP and RPC surfaces.
  - `domain-authz.md` – who may act, and field-level read rules for a known principal. This file covers state that the server replicates to many clients for rendering or prediction.
  - `domain-abuse.md` – scale abuse, farming and rate limits by many accounts.
  - `domain-sandbox.md` – the runtime that confines mods and plugins. This file covers what the server accepts from them and the capabilities it grants.
  - `domain-financial.md` – money, balances and ledgers, including in-game currency with real value.
  - `domain-crypto-protocols.md` – session protocols, signing and replay protection design.
  - `domain-concurrency.md` – race mechanics.
  - `domain-embedded.md` – device firmware and secure boot.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Authority:** The server (or the authoritative store) computes <state> (position, health, score, balance, inventory, reading validity, entitlement). It accepts from the client only <inputs> (intent, raw input), and never the result.
2. **Validation:** The server checks every client action against the rules of <system> (range, cost, cooldown, line of sight, ownership, prerequisites, rate) at the time it runs.
3. **Enforcement:** Every rule that the client displays or checks is also enforced on the server.
4. **Binding:** A client message is bound to its session, principal, sequence and time window, so a copy cannot work for another principal, session or time.
5. **Conflict:** When offline changes merge, the server applies the same rules as for online changes, and a client cannot set server-owned fields, clocks or versions.
6. **Need to know:** The server sends a client only data that this principal may hold. Hidden state does not leave the server.
7. **Capability:** A mod, plugin or script can only send and do what its granted capability allows, and the server validates its output like any client input.
8. **Attestation:** A server decision does not depend on a client's claim about its own integrity, unless a trusted third party signs the claim and the server verifies it.

## Recon additions

Add these to `threat-model.md` under a heading "Client authority". Keep it short.

1. **Authority map.** For each piece of state: who computes it (server, client, both), where the authoritative copy lives, and what the client may send about it.
2. **Message catalogue.** Every client-to-server message or call, its fields, the server validation of each field, and whether it changes shared state.
3. **Client-side rules.** Every check that only the client makes (limits, costs, cooldowns, entitlement, licence, form rules). Note whether the server repeats it.
4. **Time sources.** Every timestamp, tick, sequence number and clock reading that the client supplies, and how the server uses it.
5. **Replication scope.** What the server sends to each client: entities, fields, history. State why the client needs each field.
6. **Offline and sync.** Operations that the client queues, how the server merges them, and which fields the merge takes from the client.
7. **Extension points.** Mods, plugins, scripts, add-ons and custom clients, with the capabilities and message types each can use.
8. **Integrity claims.** Anti-cheat, attestation or integrity verdicts that the server consumes, and what each one gates.

## Lead searches

Adapt the patterns to the language. Search both the server code and the shared protocol or schema code.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| Message handlers that assign a field from the message straight into entity or store state (`pos\|position\|health\|hp\|score\|money\|coins\|inventory\|level\|xp\|reading\|value\|total\|price\|count`) | Result accepted as truth (CT-01) | A clamp, a delta check or a recompute after the assignment may hold. |
| Handlers with no cost, range, cooldown, ownership or state check before the effect | Missing action validation (CT-02) | The check can be in a shared dispatcher. |
| `client_?(time\|timestamp\|tick\|ts)`, `local_?time`, `Date.now()` sent in messages, `rewind\|lag_?comp\|interpolat` | Client-supplied time (CT-01, CT-05) | Display-only time is fine. |
| `isValid\|validate\|canAfford\|canUse\|checkLimit\|entitled\|isPremium\|isLicensed\|trial` in client code with no match on the server side | Client-side check only (CT-03) | Compare the rule on both sides. |
| `seq\|sequence\|nonce\|counter\|msg_?id\|request_?id` on messages, and the server code that tracks them | Replay or reorder gap (CT-04) | A sequence number that the server never checks is no control. |
| Signing or HMAC keys in client code or configuration that the client holds | Forgeable client signature (CT-04, CT-08) | A signature by a per-user key bound at login differs from a shared key. |
| `sync\|merge\|reconcile\|conflict\|last_?write\|lww\|vector_?clock\|version\|etag\|updated_?at` | Conflict handling (CT-05) | Check who sets the version or timestamp. |
| `broadcast\|replicate\|snapshot\|visible\|relevance\|interest\|scope\|serialize(All\|Full)\|to_?json` over entities for many clients | Over-replication (CT-06) | A per-client filter may exist. Read it. |
| `mod\|plugin\|addon\|script\|extension\|workshop` loaded by the server, with their callbacks and message types | Mod authority (CT-07) | |
| `attest\|integrity\|anticheat\|anti_?cheat\|tamper\|checksum\|hash` of the client binary, and `isTrusted\|verified_?client` | Integrity claim used as control (CT-08) | Check what decision the claim gates. |

## Attack classes

### CT-01 Client-reported state accepted as truth

- **What fails:** the server stores or acts on a result that the client computed or reported, instead of computing it from validated inputs.
- **Where to look:** position and movement updates; combat and hit reports; scores and match results; progress and save data; sensor and meter readings from devices; prices and totals sent by a form or app; timestamps and durations; inventory and balance values; "I finished the task" callbacks.
- **Questions:**
  - Which fields of this message are results, and not raw intent or input?
  - Does the server recompute the result, or check the new value against the old value and the rules (maximum speed, maximum delta, physical limits, monotonic counters)?
  - Does the server accept a client timestamp to rewind or to order events? How far can the client move it?
  - Does a missing field mean "unchanged" or "zero"?
- **Sad-path inputs:** an impossible delta (teleport, instant level-up, negative duration); a value at the type limit; a timestamp far in the past or future; a result without the action that must have produced it; a reading outside the physical range of the sensor.
- **Evidence for confirmed:** the handler, the field assigned from the message, the absent bound or recompute, and the damaged server invariant (another principal's state, a shared ranking, an economy, a bill). Show it with a local fixture server and a scripted dummy client. E1 is enough when the whole path is in the repository and no check exists.
- **Not a finding:** a value that only the sender sees (a local setting, a cosmetic choice); a result in an offline single-player mode that never reaches shared state.
- **CWE:** CWE-807 (reliance on untrusted inputs in a security decision); CWE-642 (external control of critical state data; class-level).

### CT-02 Missing server-side validation of actions

- **What fails:** the server accepts an action that the rules forbid, because only the client enforces the rule.
- **Where to look:** action and command handlers (use, buy, craft, move, fire, trade, place, upgrade, submit); cost and resource deduction; cooldowns and rate of actions; range, visibility and line-of-sight rules; ownership of targets; prerequisites and unlocks; state-machine preconditions; batch and macro commands.
- **Questions:**
  - List the rules the client enforces for this action. Does the server enforce each one?
  - Does the server read the cost, range and cooldown from its own data, or from the message?
  - Does the server check the target's existence, owner and state?
  - Can one message carry many actions, or an action repeated many times, in one tick?
- **Sad-path inputs:** an action with no resources; an action on a target that is out of range, dead, owned by another principal or in another zone; an action during a cooldown; an action in an invalid state; many actions in one message.
- **Evidence for confirmed:** the client rule, the server handler without the matching check, and the forbidden effect. Name the rule from documentation, design or the client code.
- **Not a finding:** an advantage that the design allows (a higher tier with more actions); a server check that is present in a shared layer.
- **CWE:** CWE-602 (client-side enforcement of server-side security; class-level).

### CT-03 Client-side checks without server checks

- **What fails:** a control exists only in code that the attacker controls: form validation, feature gating, entitlement, licence, paywall, parental or age gate, client-side "authentication".
- **Where to look:** client code that decides access (hidden menus, disabled controls, local licence files, trial counters in local storage, premium flags in app state); backend endpoints behind those gates; client-side input validation with no server twin; client-side filtering of data that the server returns in full.
- **Questions:**
  - For each client gate: which server endpoint does the gate protect? Does that endpoint check the same rule?
  - Does the server trust a flag the client sends (`is_premium`, `role`, `age_verified`)?
  - Is the entitlement state stored on the server, or in a token or file the client holds and can edit?
  - Does the client hold the data and only hide it?
- **Sad-path inputs:** a direct call to the endpoint without the client flow; an edited local flag or counter; a request with the gated field set by hand; an old client without the gate.
- **Evidence for confirmed:** the client gate, the server endpoint that lacks the rule, and the protected resource or feature obtained. Name the party that loses (revenue, other users, safety).
- **Not a finding:** a client check that is only for user experience when the server also enforces the rule; a gate on the user's own data with no effect on others.
- **CWE:** CWE-603 (use of client-side authentication); CWE-602 (client-side enforcement of server-side security; class-level).

### CT-04 Replay, reordering and forgery of client messages

- **What fails:** a captured or invented message works again, in another session, for another principal or out of order.
- **Where to look:** session and message envelopes; sequence numbers, nonces and tick numbers; message signing; resume and reconnect tokens; queued operations replayed after reconnect; action receipts and result tokens that the server issued earlier; keys that clients hold for signing.
- **Questions:**
  - Does each message bind to a session, a principal and a position in a sequence? Does the server reject old, duplicate and future values?
  - Does the signature cover every field the server uses (action, target, amount, time)?
  - Does a shared signing key sit in every client? Then the signature proves nothing about the sender.
  - Does a reconnect token expire, bind to the device and become invalid after use?
  - Does the server check the order of messages where order matters?
- **Sad-path inputs:** the same message twice; a message from session A in session B; sequence number zero, maximum and wrapped; a message with changed fields and the old signature; an old result token.
- **Evidence for confirmed:** the unbound or unchecked field, the replayed or forged message in a local test, and the effect. Race or double-use claims need E3 (SKILL.md section 6). A sequential replay can be E1.
- **Not a finding:** replay of an idempotent message with no effect; a replay that only the same principal in the same session can do and that gives no gain.
- **CWE:** CWE-294 (capture-replay); CWE-353 (missing support for integrity check).

### CT-05 Offline sync and conflict resolution

- **What fails:** the merge of offline changes lets a client override server rules, other users' data or time.
- **Where to look:** sync endpoints and upload queues; last-write-wins by client timestamp; client-chosen versions, vector clocks and revision IDs; merge of whole documents or records; tombstones and deletes; local database files that clients can edit; queued operations that run after access is revoked; conflict policy tables.
- **Questions:**
  - Who sets the timestamp or version that decides a conflict? Can a client win by claiming a later time or a higher version?
  - Does the server apply the authorization and business rules to each synced operation, as for an online call?
  - Can a sync payload set server-owned fields, or touch records the principal does not own?
  - Does a queued operation re-check access when it finally arrives?
  - Can an old deleted record come back (resurrection) or a delete wipe newer data?
- **Sad-path inputs:** a far-future timestamp; a version number at maximum; a payload with server-owned fields; a delete for another principal's record; an operation queued before a role was removed; the same batch uploaded twice.
- **Evidence for confirmed:** the merge rule, the client-controlled decider, and the overwritten, forged or resurrected state of a victim or of a server-owned field.
- **Not a finding:** a conflict result that only affects the sender's own data; a documented policy that favours the latest server-received change.
- **CWE:** CWE-807 (reliance on untrusted inputs in a security decision); scope: merged client changes.

### CT-06 Hidden state sent to clients

- **What fails:** the server sends data that the client must not have, and relies on the client not to show it.
- **Where to look:** world, entity and map replication (hidden units, other teams' positions, fog of war, loot tables, random seeds); sync payloads that carry full records; list endpoints that return all fields; serialisers that dump whole objects; debug fields in messages; precomputed answers or solutions sent to the client; other users' presence and metadata.
- **Questions:**
  - For each replicated field: does this principal need it to play, render or predict? If not, why does it receive it?
  - Does the server filter by relevance and visibility per client, or send the same state to all?
  - Does the client receive future state, random seeds or hidden values that let it predict outcomes?
  - Is hidden data encrypted with a key the client also holds?
- **Sad-path inputs:** a packet capture or a scripted client that logs every field; a client in a spectator or disconnected role; a client at the edge of a visibility range.
- **Evidence for confirmed:** the serialiser or replication path, the field in the message, and the advantage or exposure it gives. Name the party hurt (other players, other users, the operator). Confirm that the field reaches a client in a normal session.
- **Not a finding:** public state by design; low-value data that the design shows to everyone; data the user owns.
- **CWE:** CWE-201 (insertion of sensitive information into sent data).

### CT-07 Mod and plugin capabilities on the server

- **What fails:** a mod or plugin, or a modified client built from one, can do or send more than the server meant to allow.
- **Where to look:** server-side mod APIs and callbacks; message types that only mods use; mod-supplied scripts that act as the server; mod download and update paths; capability or permission lists; custom client protocol extensions; mod-to-mod interfaces; trust in mod-reported state.
- **Questions:**
  - Which capabilities does a mod get by default? Can the server operator limit them?
  - Does the server validate mod output and messages as it validates client input?
  - Can a client-side mod send server-side mod messages, or call hooks reserved for the server?
  - Can a mod change shared state, other players' data or the server's configuration?
- **Sad-path inputs:** a mod message with fields outside its schema; a message for a hook that the sender may not call; a mod that reports a result for another principal.
- **Evidence for confirmed:** the capability grant or the unvalidated mod message, the path to shared state, and the effect. Hand the sandbox escape itself to `domain-sandbox.md`.
- **Not a finding:** a mod action inside the capability that the operator granted, with effect only on the operator's own server.
- **CWE:** CWE-272 (least privilege violation).

### CT-08 Anti-cheat and attestation as a trust boundary

- **What fails:** the server treats a client claim of integrity as proof, or the anti-cheat is the only control for a rule.
- **Where to look:** "client verified" flags; integrity or attestation tokens from the platform (for example Android's Play Integrity API or Apple's App Attest) and the server code that verifies them; client-side hash checks; obfuscated checks; anti-tamper results sent in a message; device identifiers used as identity; bans that rely on client-sent data.
- **Questions:**
  - Does the server verify the attestation with the issuer's signature, a fresh nonce, the right app identity and a time limit?
  - Is the verdict bound to this session and request, or can one verdict serve many clients?
  - Does a server decision depend only on the claim? What happens when the claim is absent or says "failed"?
  - Is the rule also enforced by server logic, so a tampered client cannot break it even if the check is bypassed?
  - Can a banned principal return with a new identifier?
- **Sad-path inputs:** a missing token; an old token; a token from another app or session; a token with a changed field; a client that reports "clean" without any proof.
- **Evidence for confirmed:** the claim the server trusts, the lack of signature or binding checks, and the guarded rule that now breaks. Do not report "the anti-cheat can be bypassed" alone. Anti-cheat on the client is a deterrent. The finding is a server rule that depends on it.
- **Not a finding:** a client-side deterrent that guards nothing shared; a detection gap on a rule that the server also enforces.
- **CWE:** CWE-807 (reliance on untrusted inputs in a security decision); scope: client integrity claim.

## Variant search

When you find one client-trust defect:
1. **Same field.** List every handler and sync path that reads the same client-supplied field.
2. **Same message family.** Check every message type in the catalogue for the same missing validation.
3. **Same rule.** For each rule enforced only by the client, check all server paths that produce the effect.
4. **Same merge.** Check every sync, import and restore path against the same conflict rule.
5. **Same serialiser.** Check every place that serialises the same entity for clients.
6. **Same extension.** Check other mod and plugin hooks that share the capability model.

## Chain primitives

This domain often **gives**:
- forged shared state (rank, balance, entitlement, inventory) that other domains trust;
- free resources or time, which feed financial and abuse chains;
- other principals' hidden data, which feeds targeting and guessing;
- a trusted-client identity that the server treats as verified.

This domain often **needs**:
- a normal client session (from authn);
- the message format (from recon of the protocol);
- a way to run a modified or scripted client (assumed attacker capability).

## Verification notes

- **Attacker model:** a modified or scripted client is in scope by default. Do not reject because "a normal client cannot do it".
- **E1 is usually enough** for CT-01, CT-02, CT-03 and CT-06 when the handler, the absent check and the shared effect are in the repository and no outside layer validates.
- **E3 is required** for CT-04 and CT-05 claims that depend on concurrency or timing, and for any claim that depends on a platform attestation service behaviour that is outside the repository. Use a local fixture server and a scripted dummy client. Never send traffic to a live service.
- **Victim check:** name the victim: other players, other users, a shared ranking, the operator's economy, or a bill. A client that changes only its own offline state is not a boundary failure.
- **Reachability:** check that the handler exists in the shipped server build and mode, and that the attacker needs no more than a normal account.
- **Design authority:** check the design or rules document. If the documentation allows the action, reject.
- **Severity examples:**
  - critical – any client sets authoritative shared state or entitlement for all principals, or gains control of the server through a trusted message;
  - high – a client forges results, currency or inventory that have real value or that rank against others; a client reads other principals' private data through over-replication;
  - medium – a limit or cooldown bypass with a bounded advantage; a replay that repeats a small reward;
  - low – a hidden field with little advantage; a cosmetic entitlement bypass;
  - informational – a client-side deterrent weakness that guards nothing shared.

## Fix patterns

- **Server authority.** Send intent, not results. The server simulates or recomputes state and sends results back.
- **Validate every action.** Check range, cost, cooldown, ownership and state on the server, using server data. Centralise this in the dispatcher.
- **Plausibility bounds.** For values that the server cannot recompute (sensor readings, input timing), enforce physical and rate bounds, and flag outliers.
- **Server twin for every client rule.** Keep one rule definition and run it on both sides.
- **Bind messages.** Include session, principal, sequence number and a short validity window in every message. Reject duplicates and old values. Use per-session keys, never one key in all clients.
- **Merge on the server.** Use server time or server-issued versions to decide conflicts. Re-run authorization and rules on each synced operation, when it arrives.
- **Interest management.** Send each client only the entities and fields it may see. Do not send secrets and rely on the client to hide them.
- **Mod capability model.** Grant the least capability. Validate mod messages against a schema.
- **Attestation.** Verify with the issuer's public key. Use a fresh server nonce. Bind to the session. Treat a missing claim as failed. Keep server rules in place even with a valid claim.
- **Looks right but is not:** obfuscating the protocol; encrypting traffic with a key that the client holds; a checksum of the client binary sent by the client; hiding data in the client with a "do not render" flag; blocking only the known modified client; client-side rate limits.

## Regression tests

- A scripted-client test per message type: send out-of-range, impossible-delta, wrong-owner and wrong-state values, and assert refusal and unchanged state.
- A rule-parity test: for each client rule, call the server directly without the client flow and assert the same refusal.
- A replay test: send each message twice, in a second session and out of order, and assert refusal.
- A sync test: upload operations with far-future times, server-owned fields and revoked access, and assert the server rules win.
- A replication test: connect a client in each role and assert that no message holds a field outside its visibility.
- A mod test: send each mod message type without the capability and assert refusal.
- An attestation test: send missing, expired, reused and foreign tokens and assert refusal of the guarded action.
