# Domain: Cryptographic Protocols

## Scope

- **Load when:** the code combines cryptographic primitives into a protocol. Signs: handshakes, key exchange, session keys, end-to-end encryption, ratchets, device or key verification, group keys, version or cipher negotiation, signed or MACed message formats, key backup and recovery, canonical serialisation before signing, custom wire protocols, sender-authentication checks for email.
- **Covers:** handshake state machines; authentication of key exchange; downgrade and negotiation; transcript and context binding; replay and freshness; canonicalisation and what is signed; E2EE device and key verification; ratchets and forward secrecy; group key management; key backup and recovery; protocol side channels; SPF, DKIM and DMARC verification logic; custom protocol design errors.
- **Hand off to:**
  - `domain-crypto.md` – one primitive call: mode, nonce, randomness, key storage, comparison, verify-result handling. Protocols owns how calls combine.
  - `domain-federation.md` – trust between independent peers: peer key discovery, rotation and revocation, replicated state. Use both files when peers sign data for each other.
  - `domain-authn.md` – login tokens, OAuth, SAML and passkeys. They are protocols, but authn owns them.
  - `domain-input-parsing.md` – parser flaws. Protocols owns the question of which bytes get signed.
  - `domain-embedded.md`, `domain-messaging.md` – device update protocols and broker transport. They use this file for the cryptographic design.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Authenticated exchange:** The session keys of <protocol> are bound to the identities that the protocol authenticates. A party in the middle cannot hold keys that both ends accept.
2. **State:** The code processes each message type only in the states that allow it. A message that arrives before authentication cannot change authenticated state.
3. **Negotiation:** Version and algorithm choices are authenticated. Both sides enforce a minimum, and neither retries at a lower level because of a network error.
4. **Binding:** Every signature, MAC and derived key covers the whole transcript and a label for its purpose, parties and direction.
5. **Freshness:** A message accepted once is not accepted again in another session, direction, device, group or epoch.
6. **Signed bytes:** The bytes that the code verifies are the bytes that it uses. One logical message has one canonical byte form.
7. **Device trust:** A new device or changed key becomes trusted only through a step that the server cannot complete alone, and the user can see the change.
8. **Forward secrecy:** Compromise of current keys does not reveal past messages. Old keys are deleted on schedule. Where the design claims healing after compromise, it heals.
9. **Membership:** A removed member cannot read later messages. A new member cannot read earlier messages unless the design says so.
10. **Recovery:** Backup and recovery give no party a path to plaintext that the protocol denies.
11. **Side channels:** Message length, compression, timing and error differences do not reveal protected secrets.

## Recon additions

Add these to `domain-notes.md` under a heading "Protocol model". Keep it short.

1. **Parties and trust.** Who the endpoints are. What the server may do (relay only, store, see metadata, hold keys). The attacker positions: network, server, peer, other device.
2. **State machine table.** State | messages accepted | next state | what is authenticated at that point.
3. **Key schedule.** Key | derived from | used for | lifetime | deleted when.
4. **Negotiated parameters.** Versions and algorithms, who chooses, the minimum, and the fallback behaviour.
5. **Signed objects.** Object | fields signed | fields not signed but trusted | canonical form | verifier (file:line).
6. **Trust establishment.** How a device or peer key becomes trusted, and what the user sees when it changes.
7. **Group and backup flows.** Membership events, rekey rules, backup contents, recovery secrets.
8. **Specification.** The standard or design document, and every known deviation from it.

## Lead searches

Adapt the patterns to the language.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `(switch\|match\|case).*(msg\|message)_?type` with a default that continues; `state\s*(==\|=)`; handlers that run before an `authenticated` flag is set | Unchecked state (CP-01) | |
| `(handshake\|hello\|kex\|key_?exchange\|ecdh\|dh\|psk\|pake\|srp)` | Exchange code (CP-02) | |
| `(version\|min_?version\|cipher_?suite\|supported_?(versions\|algorithms)\|fallback\|legacy\|compat)` | Negotiation and downgrade (CP-03) | A legacy path may exist for reading old data only. |
| `(transcript\|handshake_?hash\|context\|label\|info\|domain\|channel_?binding)` in sign, MAC or derive calls | Binding (CP-04). Missing labels are leads. | |
| `(nonce\|counter\|sequence\|seq\|msg_?num\|timestamp\|window\|epoch\|replay)` | Freshness (CP-05) | |
| `(canonical\|serialize\|marshal\|to_?json\|sort_?keys\|c14n\|signed_?fields)`; signature calls over re-encoded data | Signed bytes (CP-06) | |
| `(device\|cross_?sign\|trusted\|verified\|fingerprint\|safety_?number\|key_?change\|identity_?key\|tofu)` | Device trust (CP-07) | |
| `(ratchet\|chain_?key\|message_?key\|skipped\|prekey\|one_?time\|session_?reset\|restore)` | Ratchet state (CP-08) | |
| `(member\|add_?user\|remove_?user\|leave\|rekey\|sender_?key\|group_?key\|epoch\|welcome\|commit)` | Group keys (CP-09) | |
| `(backup\|recovery_?(key\|phrase)\|escrow\|export_?keys\|import_?keys)` | Backup and recovery (CP-10) | |
| `(compress\|deflate\|gzip\|zlib\|brotli)` before encrypt; `pad(ding)?`; length fields in encrypted records | Compression and length leaks (CP-11) | |
| `(spf\|dkim\|dmarc\|arc\|authentication-results\|selector\|alignment\|envelope_?from\|header_?from)` | Sender authentication (CP-12) | |
| `(custom\|own\|home-?grown\|simple)\s+(protocol\|handshake\|crypto)`; comments that say "not standard" | Custom design (CP-13) | |

## Attack classes

### CP-01 Handshake state machine errors

- **What fails:** the code accepts a message in a state where it must not, or skips a required step.
- **Where to look:** message dispatch tables; handshake loops; state variables and flags; early-data and resumption paths; error handlers that reset state; code that handles several protocol versions.
- **Questions:**
  - Can a message of a later step arrive first and be processed? Does the default branch ignore, accept or reject?
  - Can an unauthenticated message change authenticated state (keys, identity, flags)?
  - Does any message get processed twice, or in two states, with different effects?
  - After an error, is state fully reset, or does it keep a half-set key?
- **Sad-path inputs:** the final message first; a repeated message; a skipped authentication message; a message of an unknown type; data sent before the handshake ends.
- **Evidence for confirmed:** the dispatch code, the out-of-order input that it accepts, and the state it reaches. E1 is normally enough when the state table is readable.
- **Not a finding:** a state that the code accepts and then discards, with no effect on keys or identity.
- **CWE:** CWE-304.

### CP-02 Authentication of key exchange

- **What fails:** the exchange gives a key to a party that was not authenticated, or does not tie the key to an identity.
- **Where to look:** ephemeral exchanges with no signature or password proof; trust-on-first-use; pre-shared-key identity handling; server-supplied peer keys; symmetric designs where both sides use one key for both directions.
- **Questions:**
  - Who proves identity, and over what data? Is the proof tied to this exchange's keys?
  - Can a party in the middle run two exchanges and relay messages?
  - Does the protocol use one key or one MAC for both directions, so that a reply can be reflected?
  - Does it accept a weak public value (zero, low order, identity point)?
  - If trust is on first use, does the user see the first contact, and any later change?
- **Sad-path inputs:** a relayed exchange; a reflected message; a zero or low-order public value; a swapped identity field; a key from the server instead of the peer.
- **Evidence for confirmed:** the exchange code and the position that lets an attacker hold accepted keys. E1 is enough when authentication is plainly missing. A claim that depends on library point validation needs the library code.
- **Not a finding:** an anonymous exchange whose design states that identity is verified at another layer (cite it).
- **CWE:** CWE-322, CWE-300 (class-level), CWE-301.

### CP-03 Downgrade and version negotiation

- **What fails:** an attacker causes the parties to use a weaker version, algorithm or mode than both support.
- **Where to look:** version fields and cipher lists; fallback or retry code that lowers the version after an error; "legacy" and "compat" flags; negotiation messages outside the authenticated transcript; capability fields from the peer; minimum-version settings.
- **Questions:**
  - Is the negotiation covered by the authenticated transcript?
  - Does an error or timeout cause a retry at a lower version?
  - Does each side enforce a minimum, or does one side accept anything the peer offers?
  - Can the peer or a configuration value switch on a weak mode?
- **Sad-path inputs:** a peer that offers only old versions; a dropped first attempt; an altered cipher list; a version field changed in transit.
- **Evidence for confirmed:** the negotiation code and the unauthenticated or lowering path. E1 is enough for a lowering retry or an unauthenticated list. Reachability from a network position is stated as a condition.
- **Not a finding:** a weak mode that is compiled out of the default build and has no switch, or one the design limits to local test use.
- **CWE:** CWE-757.

### CP-04 Transcript and context binding

- **What fails:** a signature, MAC or key is valid in a context other than the one the code assumes.
- **Where to look:** signatures over part of a handshake; MACs without a purpose label; key derivation with empty context; one key used in two protocols or directions; tokens with no audience; signed challenges with no verifier identity.
- **Questions:**
  - Does each signature cover the keys, identities, negotiated parameters and role? Or only a nonce?
  - Does each derived key carry a label for its purpose and direction?
  - Can a signature or MAC from one protocol, endpoint or session be replayed in another (cross-protocol, cross-session, unknown key share)?
  - Does the identity in the signed data match the identity the code then acts on?
- **Sad-path inputs:** a signature taken from another session; a message signed for a different recipient; a sender field that the signature does not cover; the same key used for two purposes.
- **Evidence for confirmed:** the signed or derived data, the missing field or label, and a second context in which the output is accepted. E1 is normally enough.
- **Not a finding:** a fixed context where the key is unique to that context and cannot be used elsewhere.
- **CWE:** CWE-347, CWE-345 (class-level).

### CP-05 Replay and freshness

- **What fails:** the system accepts an old valid message again, or in the wrong place.
- **Where to look:** sequence numbers and counters; timestamp windows; nonce caches; session resumption and early data; message IDs; epoch or generation numbers; state restored from backup; multi-device and multi-room delivery.
- **Questions:**
  - What makes a message unique? Is it checked on receipt?
  - Is the replay state kept across restart, failover and restore?
  - Is the window bounded? What happens at counter wrap?
  - Can a message for one session, device, direction or group be accepted in another?
- **Sad-path inputs:** the same message twice; a message from before a restart; a message from the opposite direction; a counter at the maximum; a timestamp at the window edge.
- **Evidence for confirmed:** the accept path with no uniqueness check, or with a check that fails across the stated boundary. E1 is enough for no check. A claim that depends on concurrent delivery needs E3.
- **Not a finding:** an idempotent message whose replay changes nothing.
- **CWE:** CWE-294.

### CP-06 Canonicalisation and what exactly is signed

- **What fails:** the signed bytes differ from the data the code trusts, or two encodings of one message verify differently.
- **Where to look:** signatures over serialised JSON, XML, CBOR or text; code that parses, then re-serialises, then verifies; field order, whitespace and Unicode handling; fields left out of the signature but read later; concatenation without length prefixes; redaction and pruning of signed objects.
- **Questions:**
  - Which fields does the signature cover? Which fields does the code read that it does not cover?
  - Does the verifier hash the original received bytes, or a re-encoded form?
  - Is the encoding deterministic (key order, number format, duplicate keys, Unicode form)?
  - Can two different field lists produce one concatenated string (missing delimiters or lengths)?
  - Can the code remove or change a field after signing and still pass?
- **Sad-path inputs:** duplicate keys; reordered keys; extra unsigned fields; a field moved between two concatenated values; numbers in two textual forms; Unicode in two normal forms.
- **Evidence for confirmed:** the signature input, the trusted field outside it, and the changed value accepted. E1 is enough when a trusted field is plainly outside the signed set. Claims that depend on two parsers or encoders disagreeing are parser-differential claims and need E3.
- **Not a finding:** an unsigned field that the code never trusts.
- **CWE:** CWE-347, CWE-345 (class-level).

### CP-07 E2EE device and key verification

- **What fails:** a party that should not hold a trusted key becomes trusted, or a key change goes unnoticed.
- **Where to look:** device and key lists from the server; cross-signing and trust chains; automatic trust of new devices; key-change handling; fingerprint, safety-number or QR verification; key transparency checks; account recovery that issues new identity keys.
- **Questions:**
  - Can the server add a device or replace a key without the user's action? Does the client notice?
  - Does a new device receive past keys or history without approval from a trusted device?
  - Does a key change block sending, warn, or pass silently?
  - Does the verification step bind to the right key, and is the result stored per identity?
  - Does recovery or reset create a path to new trusted keys with no user proof?
- **Sad-path inputs:** a device list with an extra device; a replaced identity key; a verification result for another user; a new device after account reset.
- **Evidence for confirmed:** the trust decision code, the action by the server or attacker that makes a key trusted, and the effect on message confidentiality. E1 is normally enough.
- **Not a finding:** a server that is trusted by design for this step, where the user chose that mode (cite the documentation).
- **CWE:** CWE-322, CWE-345 (class-level).

### CP-08 Ratchets, forward secrecy and post-compromise security

- **What fails:** old keys stay available, state rolls back, or keys repeat, so that forward secrecy or healing fails.
- **Where to look:** key-derivation chains; storage of skipped or old message keys; session and prekey stores; restore from backup or snapshot; session reset; one-time prekey use; long-lived static keys used to protect session keys.
- **Questions:**
  - When does each key get deleted, in memory and on disk? Is the number of stored skipped keys bounded?
  - Can a restore or rollback bring back an old chain state and repeat keys?
  - Is a one-time prekey removed on use? What happens when none is left?
  - Does a new Diffie-Hellman step happen as the design claims, so that a leaked state heals?
  - Can a session reset be forced by a peer, and does it lower security?
- **Sad-path inputs:** an old state file restored; a prekey used twice; a very large gap in message numbers; an attacker-triggered reset.
- **Evidence for confirmed:** the key storage or restore path and the key that remains or repeats. E1 is enough for kept keys in the source. Claims about memory erasure depend on compiler and runtime behaviour and need E3.
- **Not a finding:** keys kept for a documented, bounded out-of-order window.
- **CWE:** CWE-323, CWE-226.

### CP-09 Group key management

- **What fails:** group keys do not follow membership, or an unauthorised party changes membership.
- **Where to look:** member add and remove; rekey and epoch handling; sender-key distribution; welcome and commit messages; history sharing to new members; who may add members; large-group optimisations.
- **Questions:**
  - Does removal trigger a rekey that the removed member cannot follow?
  - Are key-distribution messages authenticated as coming from a current member?
  - Does a stale epoch's key still decrypt or sign new messages?
  - Who can add a member, and does the client check that authority?
  - Does the server alone decide the member list that the clients encrypt to?
- **Sad-path inputs:** a message in an old epoch; a removed member's late message; a forged add message; two concurrent membership changes.
- **Evidence for confirmed:** the membership event, the keys that stay valid, and the access that the wrong party keeps or gains. E1 is enough when rekey is plainly missing. Claims that depend on concurrent changes need E3.
- **Not a finding:** history sharing that the design states and the group members approve.
- **CWE:** CWE-324.

### CP-10 Key backup and recovery

- **What fails:** backup or recovery gives a party access that the protocol otherwise prevents.
- **Where to look:** key export and import; server-side encrypted backups; recovery phrases and keys; passphrase-derived keys; escrow and support recovery; device-to-device transfer; backup versions.
- **Questions:**
  - Who holds the backup key? Can the server decrypt the backup?
  - Is the backup key derived from a weak passphrase with a slow function? Is there an attempt limit that the server enforces, and can the server bypass it?
  - Is the backup authenticated, so that an attacker cannot swap it or roll it back to an old version?
  - Does recovery require proof that equals the proof of the account itself?
- **Sad-path inputs:** a swapped backup; an old backup version; a wrong passphrase repeated; a recovery with the account password only.
- **Evidence for confirmed:** the backup format and key source, and the party that can read or alter it. E1 is normally enough. Cost claims about passphrase guessing are `needs-validation` unless parameters are in the source.
- **Not a finding:** escrow that the design states and the user chose.
- **CWE:** CWE-522 (class-level), CWE-916, CWE-922 (class-level).

### CP-11 Protocol side channels

- **What fails:** length, compression, timing or error differences reveal a protected secret.
- **Where to look:** compression before encryption of data that mixes secrets with attacker-chosen text; variable-length records without padding; distinct error codes for bad MAC, bad padding and bad format; different work for valid and invalid inputs; traffic patterns that reveal content type.
- **Questions:**
  - Is compressed data encrypted when it contains both a secret and attacker input (header compression, body compression)? An attacker who observes sizes can learn the secret byte by byte.
  - Do error messages or timing distinguish between failure causes before authentication?
  - Is the attacker able to send many chosen inputs and observe sizes or timing?
- **Sad-path inputs:** an input that repeats part of a secret; inputs of growing length; a bad tag against a bad format.
- **Evidence for confirmed:** every side-channel claim needs E3: a harness that shows the observable difference under stated conditions. Without T2, the status is `needs-validation` with a measurement plan. Explicit distinct error codes that reach the attacker are E1.
- **Not a finding:** a length leak of a value that is public or fixed; an oracle the attacker cannot observe.
- **CWE:** CWE-208, CWE-204. For compression oracles, name the weakness in words (information leak through compressed size).

### CP-12 Email sender authentication (SPF, DKIM, DMARC)

- **What fails:** the verifier marks a message as authentic when the visible sender is not authenticated.
- **Where to look:** code that validates SPF, DKIM or DMARC; alignment of the checked domain with the `From` header; handling of several `From` headers or signatures; reading of `Authentication-Results` from outside the trust boundary; DNS key lookups; canonicalisation modes; body-length tags.
- **Questions:**
  - Does the verdict relate to the domain the user sees, or to a different domain (envelope, signing domain)?
  - Does the code verify the header it displays? Can a second `From` or a header outside the signature change what the user sees?
  - Does the code trust an `Authentication-Results` header from a hop it does not control?
  - Does the signature cover the body fully? Can content be appended?
  - Does a DNS failure, a missing record or a temporary error give a pass?
- **Sad-path inputs:** two `From` headers; a valid signature from an unrelated domain; a message with an added trailing body; an inbound result header; a DNS timeout.
- **Evidence for confirmed:** the verification code and a message shape that it passes. E1 is enough for logic errors. DNS and MTA behaviour outside the repository makes the claim `needs-validation`.
- **Not a finding:** a deliberate monitor-only policy mode.
- **CWE:** CWE-290, CWE-345 (class-level), CWE-347.

### CP-13 Custom protocol design errors

- **What fails:** a home-made protocol lacks a property that standard protocols give.
- **Where to look:** wire protocols with a bespoke handshake; token or message formats with "sign, then encrypt" or "encrypt, then sign" in custom order; protocols with no stated threat model or specification; copy of a standard protocol with parts removed.
- **Questions:**
  - Is there a specification that states goals and attacker model? Does the code match it?
  - Why not use a reviewed protocol? Which standard property does the custom design drop (authentication, replay protection, forward secrecy, binding)?
  - Do the parties derive keys in a way that gives each direction its own key?
  - Does an attacker who can modify, drop, replay or reorder messages break any goal?
- **Sad-path inputs:** dropped, reordered and duplicated messages; a message from the other direction; an old session's message.
- **Evidence for confirmed:** a named missing property, the attacker action that exploits it, and the code path. Do not report a custom design as a finding without a concrete failing property.
- **Not a finding:** a custom format for non-security data; a reduced protocol inside an authenticated channel that already gives the missing property.
- **CWE:** CWE-327 (class-level), CWE-325, CWE-358.

## Variant search

When you find one protocol failure:
1. **Same object.** Check every signed or MACed object for the same missing field or label.
2. **Same message handler.** Check every handler that shares the dispatch table or state flag.
3. **Same negotiation.** Check each protocol version and each transport that uses a similar negotiation.
4. **Same key.** List every use of the same key, to find cross-context reuse.
5. **Other implementations.** Check clients, servers, libraries and bindings that implement the same protocol. They often differ.

## Chain primitives

This domain often **gives**:
- impersonation of a peer, device or sender;
- decryption of recorded traffic;
- forged or replayed messages and state;
- silent trust of an attacker's device or key;
- a downgrade that enables a primitive-level attack (`domain-crypto.md`).

This domain often **needs**:
- a network, server or peer position (from the attacker model);
- control of a relay, an account or a device list (from authn, federation or data-lifecycle);
- a parser difference (from `domain-input-parsing.md`);

## Verification notes

- **E1 is usually enough** for CP-01, CP-02 (authentication plainly missing), CP-03, CP-04, CP-05 (no uniqueness check), CP-06 (trusted field outside the signature), CP-07, CP-08 (kept keys), CP-09 (rekey missing), CP-10, CP-12 (logic) and CP-13, when every step is in the repository.
- **E3 is required** for parser-differential and canonicalisation claims where two components must disagree (CP-06, CP-12), for race and concurrency claims (CP-05, CP-09), for erasure claims (CP-08), and for every side-channel claim (CP-11). Timing and size claims stay `needs-validation` without a measurement.
- **Attacker position:** state it for every finding (network, server, peer, other device). A claim that needs a position the design excludes is rejected.
- **Specification check:** compare the code with the cited standard or design document. State if the flaw is also in the specification.
- **Severity examples:**
  - critical – an unauthenticated network attacker impersonates a peer or reads all session traffic; forged messages are accepted as from any member;
  - high – a malicious server adds a trusted device and reads one user's messages; downgrade to a broken mode by a network attacker; a removed member keeps access to later messages;
  - medium – replay of a non-idempotent message with limited effect; a key backup that falls to a guess attack after a store leak; a side channel that leaks limited data;
  - low – a missing key-change notification with a verified-device fallback; a hardening gap in a legacy path;
  - informational – a deviation from the specification with no known attacker gain.

## Fix patterns

- **Use a reviewed protocol or library.** Prefer TLS 1.3 through a maintained library, the Noise framework, or an audited messaging and group protocol (for example MLS, RFC 9420) over new designs.
- **Write the state machine as a table.** Reject by default. Accept each message type in named states only.
- **Authenticate the negotiation.** Put all offered and chosen parameters in the transcript. Enforce a minimum on both sides. Do not retry at a lower version.
- **Hash the transcript and label every context.** Include purpose, role, direction, identities and keys. Use separate keys per direction and purpose.
- **Bind freshness.** Use per-direction counters or nonces with persisted state. Reject duplicates and old epochs.
- **Sign canonical bytes.** Verify the exact received bytes, or use a deterministic encoding with length prefixes. Sign every field that the code later trusts.
- **Make trust visible.** Require a verified path for new devices. Warn or block on key change. Do not let the server alone add keys.
- **Rekey on membership change.** Authenticate every key-distribution message as from a current member.
- **Authenticate backups.** Use a strong, slow derivation, version binding and server-enforced attempt limits that the server cannot bypass.
- **Avoid compression of secrets with attacker data.** Pad where length matters. Return one error for all pre-authentication failures.
- **Looks right but is not:** a version check done only after the exchange; signing a hash of the parsed object instead of the received bytes; a nonce with no persisted state; a "verified" badge set by the server; rekey only on member add; compressing, then encrypting, and calling it safe because the data is encrypted.

## Regression tests

- State tests: send every message type in every state and assert that only the allowed ones succeed.
- Downgrade tests: a peer that offers only old versions, a dropped first attempt and a changed list must fail, not retry lower.
- Binding tests: move a valid signature, MAC or derived key to another session, direction, recipient or protocol and assert refusal.
- Replay tests: send each accepted message twice, across restart and across sessions, and assert the second is refused.
- Canonicalisation tests: reorder keys, add unsigned fields and use duplicate keys. Assert refusal or an identical result.
- Device tests: a server-added device or a replaced key triggers the documented warning or block.
- Rollback tests: restore an old state and assert that no key or nonce repeats.
- Group tests: after removal, the removed member cannot read the next message; stale-epoch messages are refused.
- Sender-authentication tests: two `From` headers, an unrelated signing domain and a DNS error must not produce a pass.
