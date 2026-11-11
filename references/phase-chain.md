# Phase 5 – Chain

Goal: find attacks that need more than one step. Units are hunted one at a time, so single-unit hunts miss attacks that cross units or domains. A chain of low-impact problems can have high impact.

Inputs: `threat-model.md` (attacker goals), all finding files (any status except `rejected` and `fixed`), `hardening.md`, the "Chain primitives" section of each selected domain file, the `coverage.md` checks.

Output: chained finding files, and links from component findings to chains.

## 5.1 Build the primitive list

A **primitive** is something a principal can do or learn. It can come from a finding, a hardening note, or a normal feature. Write `primitives.md`:

```markdown
| ID | Principal | Gives | Preconditions | Source |
|----|-----------|-------|---------------|--------|
| P01 | authenticated user | learns internal IDs of other users' private documents | none | F-api.document-search.leaks-private-ids |
| P02 | authenticated user | sets a URL the server fetches later | none | feature: profile picture import from URL (profile/avatar.go:88) |
| P03 | webhook sender | makes the server process a callback without a signature check | callback arrives on the legacy endpoint | F-messaging.legacy-webhook.signature-skipped (needs-validation) |
```

Include normal features that give an attacker control: setting URLs, uploading files with chosen names, writing content that other users or admins view, creating objects with chosen IDs, triggering background work, choosing the order or timing of requests. These are not bugs, but they are links in chains.

## 5.2 Search for chains

Work backward from each high-ranked attacker goal in `threat-model.md`:

1. What final step reaches the goal? Which primitive or sink gives it?
2. What does that step need (an ID, a token, a position, a state, a race win)?
3. Which primitive gives that? Repeat until the start needs only the attacker's design authority.

Then check common chain shapes:
- **Learn, then use:** disclosure of an ID, token, path or internal address enables an access-control or SSRF attack.
- **Store, then trigger:** data stored safely is later used in a different context (rendered, executed, parsed as a path, query, template, regex or policy). Check every reader of stored attacker data, not only the writer.
- **Confuse the deputy:** a low-trust principal makes a higher-trust component act for it (server fetches a URL, admin views content, CI runs code, model calls a tool, peer server relays data).
- **Weaken, then break:** a hardening gap (missing rate limit, verbose error, weak randomness) makes another attack practical (guessing, brute force, oracle).
- **Race into a state:** a race creates a state that another path trusts.
- **Downgrade:** force a fallback path (old protocol version, legacy auth, unsigned mode, cache) that lacks a check.
- **Cross-component gap:** component A guarantees less than component B assumes. Compare the exact guarantee at each hand-off: normalisation, truncation, type, tenant scope, signature coverage.

## 5.3 Rules for a chain finding

- Each link must be established: a `proposed` or `confirmed` finding, a documented feature, or a source-traced step. Do not assume a link.
- If any link is `needs-validation`, the chain is `needs-validation`, with that link's missing fact as the blocker.
- Chains are built here from findings that phase 6 has not verified yet. Phase 6 verifies the component findings first, then the chain. If it rejects a link, or finds a carried link `fixed`, look for another established primitive that gives the same step. If none exists, the chain is `rejected`, with the lost link as the reason.
- A chain gets its own finding file, fingerprint `chain.<goal>.<short-name>`, domain `chain`. Its path lists every step across all links, in order. Its Summary names the component findings.
- Add the chain fingerprint to each component finding under Fix → variants, with "part of chain".
- The chain's impact is the end-to-end result. A component's own severity does not change because it is in a chain.
- The fix section names the cheapest link to break, and the link that is the real root cause, if they differ.

## 5.4 Record

At the end of `primitives.md`, list each attacker goal and the result: "chain found: F-chain…", "no chain: <the missing link>", or "not examined: <reason>".
