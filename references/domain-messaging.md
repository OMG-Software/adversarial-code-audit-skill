# Domain: Messaging

## Scope

- **Load when:** components exchange discrete messages or events. Signs: queues, brokers, publish and subscribe topics, event buses, webhook receivers, internal RPC, streaming (WebSocket, server-sent events, gRPC streams), job runners, device telemetry channels, actor mailboxes, message buses between processes of one product.
- **Covers:** producer authentication; webhook receipt and signature checks; topic and queue isolation; replay, duplicate delivery and ordering; dead-letter and retry stores; envelope identity against payload identity; internal RPC authentication; authorisation of each streamed message.
- **Hand off to:**
  - `domain-outbound-network.md` – webhooks that this system sends, and the choice of delivery targets (SSRF).
  - `domain-federation.md` – messages between independently operated peers, and signed data from peers. This file covers channels inside one operator's system and webhooks from partners.
  - `domain-crypto.md` – correct use of MAC and signature primitives, constant-time comparison.
  - `domain-crypto-protocols.md` – replay protection and canonicalisation inside a designed protocol or handshake.
  - `domain-authn.md` – how a token or client certificate proves identity. This file owns what the consumer does with the proven identity.
  - `domain-authz.md` – the decision rules. This file owns the question of when each message needs the decision (MSG-05).
  - `domain-concurrency.md` – races inside a consumer, and consensus in a cluster.
  - `domain-resource-exhaustion.md` – queue growth, poison-message cost and retry storms.
  - `domain-input-parsing.md` – deserialisation of payloads.
  - `domain-financial.md` – the business meaning of payment-provider events. This file owns the generic receipt checks.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Producer:** A consumer acts on a message only if the producer is authenticated and is allowed to publish this message type to this <topic | queue | endpoint>.
2. **Authenticity:** The signature or MAC covers every field the consumer trusts (payload, type, destination, tenant, timestamp, nonce). The consumer verifies it on the raw bytes before it uses any of those fields.
3. **Identity:** The identity used for a decision is the authenticated producer or the originator bound in the verified envelope. It is never a payload field that the producer can set freely.
4. **Isolation:** A principal can subscribe to, read from or write to only the <topics | queues | streams | partitions> it may. Client input cannot widen a name or a wildcard.
5. **Per message:** Each delivered item is authorised for its recipient at delivery time. A stream re-checks when access changes.
6. **Replay:** A message has its effect at most once within <window>, or its effect is idempotent. The consumer rejects stale and replayed messages.
7. **Order:** The security state that a consumer builds does not depend on delivery order, or the consumer enforces the order.
8. **Internal callers:** Internal RPC and broker endpoints authenticate their callers, also on private networks. The identity is the service identity or the user context, bound by signature or channel.
9. **Dead letters:** Dead-letter, retry and replay stores have the same access control, retention and verification as the source channel.
10. **Failure:** A message that fails verification, parsing or processing has no effect. The system does not fall back to "accept".

## Recon additions

Add these to `domain-notes.md` under a heading "Message flow map". Keep it short; hunters copy it.

1. **Channel table.** One row for each channel (queue, topic, webhook path, RPC method, stream). Columns: producers and how each authenticates | consumers | envelope fields | payload fields | privileged effect of the consumer | signature or MAC scope | replay defence | ordering assumption | delivery guarantee claimed | broker access rules | dead-letter or retry store.
2. **Identity carriers.** For each channel, where the originating principal comes from: connection identity, token, signed envelope, payload field, header.
3. **Webhook receivers.** For each: path, secret scope (per sender, per tenant, global), algorithm, what the code verifies, and where it parses.
4. **Broker and bus configuration.** Anonymous access, default users, topic and queue ACLs, wildcard rules, TLS, network exposure. Mark any rule outside the repository as an assumption.
5. **Internal RPC map.** Services, ports, authentication method, reflection or debug interfaces, and whether the ingress can reach them.
6. **Stream lifecycle.** When a stream authorises (connect, each message, on change), and what ends it.
7. **Replay tools.** Administrative tools that requeue, replay or re-sign messages, and their identity.

## Lead searches

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `webhook\|callback\|notify\|hook\|ipn\|events?` route registrations | Webhook receiver (MSG-02) | Compare with the receivers that verify a signature. |
| `hmac\|signature\|sig\b\|X-[A-Za-z-]*-Signature\|verify\w*\(` near a handler, and handlers with none | Missing or misplaced verification (MSG-02) | Verification may sit in middleware. |
| Parse or deserialise calls placed before the verification call | Use before authentication (MSG-02, MSG-10) | Parsing only to find the key identifier may be fine. Check what else is used. |
| `skip_?verify\|verify\s*=\s*(false\|False)\|insecure\|debug\|test_?mode` near signature or TLS code | Verification disabled (MSG-02, MSG-08) | Check whether production can set it. |
| `sender\|from\|user_?id\|author\|actor\|tenant` read from a message body and used in a decision | Payload identity (MSG-03) | Compare with the authenticated channel identity. |
| `subscribe\(\|consume\(\|on_?message\|handle_?event\|listener\|@\w*Listener\|channel\.on` | Consumer entry points (MSG-01, MSG-04) | List producers for each. |
| Topic, queue, channel, subject or routing key built from input: concatenation or template with `topic\|queue\|channel\|routing_?key\|subject` | Client-chosen name (MSG-04) | A fixed prefix with a checked suffix may be safe. |
| Wildcard characters in subscriptions: `#`, `*`, `>`, `+`, `.*` in topic filters | Over-wide subscription (MSG-04) | |
| `reply_?to\|callback_?url\|response_?topic\|return_?address` taken from the message | Reply to attacker destination (MSG-04) | |
| `anonymous\|allow_?anonymous\|guest\|default_?user\|no_?auth\|plaintext\|auth\s*[:=]\s*(none\|false)` in broker or bus configuration | Open broker (MSG-01) | Check the network scope. |
| `message_?id\|event_?id\|nonce\|timestamp\|idempotency\|dedup\|seen` | Replay and dedup logic (MSG-06) | Read what the key is made of. |
| `sequence\|version\|etag\|partition_?key\|last_?write` | Ordering assumption (MSG-07) | |
| `dead_?letter\|dlq\|retry_?queue\|poison\|requeue\|redeliver\|replay` | Failure stores and tools (MSG-09) | |
| RPC service definitions and handlers with no interceptor or authentication check; `reflection\|grpc_?health\|debug\|admin` services | Unauthenticated internal RPC (MSG-08) | |

## Attack classes

### MSG-01 Unauthenticated or weakly authenticated producers

- **What fails:** a principal that must not publish can publish, and the consumer acts on its messages.
- **Where to look:** brokers with anonymous access or default credentials; one shared credential for all producers; topics that any client can write; device ingestion that accepts any device identity; internal queues trusted because of network position; ingestion endpoints that take events from clients.
- **Questions:**
  - Who can connect to the broker or bus? How does each producer authenticate?
  - Can a producer write to a topic or type that belongs to another producer?
  - What does the consumer do with a message? Is the effect privileged?
- **Sad-path inputs:** a connection with no credential; a low-trust producer that publishes to a privileged topic; a device identity that belongs to another device; a message type that only an administrative service should send.
- **Evidence for confirmed:** the broker or listener configuration in the repository, the missing authentication or ACL, and the consumer path that acts on the message. A local test double (loopback) can show the effect.
- **Not a finding:** a broker that binds to loopback inside a single-process test setup; a channel whose consumer treats messages as untrusted data and checks each effect.
- **CWE:** CWE-306 (missing authentication for critical function); CWE-923 (class-level; improper restriction of communication channel to intended endpoints).

### MSG-02 Webhook receipt and signature checks

- **What fails:** a receiver accepts forged or altered events from a partner or provider because it does not verify the sender, or verifies the wrong thing.
- **Where to look:** webhook routes; verification code and its placement; secret selection (global, per tenant, per endpoint); handling of a missing signature header; verification over re-serialised data; algorithm taken from the message; timestamp tolerance; test switches; a secret URL as the only protection.
- **Questions:**
  - Does the receiver verify the signature on the raw request bytes, before any parsing that has effects?
  - What happens if the header is missing, empty, malformed, or has another algorithm?
  - Does the signature cover the body, the event type, the timestamp and the target tenant?
  - Is the secret specific to the sender and tenant, and separate from staging?
  - Does the code use a constant-time comparison? (See `domain-crypto.md` for the check itself.)
- **Sad-path inputs:** no signature header; an empty signature; a valid signature on another body; the same body with different whitespace or key order; a signature from another tenant's secret; an old timestamp; a different algorithm name.
- **Evidence for confirmed:** the receiver, the verification gap or ordering, and the state change that a forged event causes. E1 is normally enough for an absent or optional check.
- **Not a finding:** a receiver that verifies correctly in middleware you have not read yet (read it first); an event whose only effect is a read-only refresh from the provider.
- **CWE:** CWE-347 (improper verification of cryptographic signature); CWE-940 (improper verification of source of a communication channel). Replay is covered by MSG-06.

### MSG-03 Envelope against payload identity

- **What fails:** the consumer takes the identity, tenant or type from a payload field, while the authentication covers only the envelope or the connection. The producer, or an attacker who controls part of the payload, then acts as someone else.
- **Where to look:** messages with both a transport sender and a sender field inside the payload; signatures over the body but not over routing headers, or the reverse; consumers that route by a header while the signature covers the body; tenant, user, role or type fields in the payload; relays that re-publish messages under their own identity.
- **Questions:**
  - Which identity does the consumer use for the decision? Where does it come from?
  - Does the signature or authenticated channel cover that field?
  - Can a producer that is allowed to send for tenant A name tenant B in the payload?
- **Sad-path inputs:** payload actor different from the channel identity; a header that is not signed; a tenant field changed after signing; a message type that is valid for another producer.
- **Evidence for confirmed:** the identity source at the decision, the coverage of the authentication, and the path where they differ. Show the privileged effect for the named victim.
- **Not a finding:** a payload field that the consumer ignores or overwrites from the verified identity before use.
- **CWE:** CWE-807 (reliance on untrusted inputs in a security decision); CWE-302 (authentication bypass by assumed-immutable data).

### MSG-04 Topic, queue and stream isolation

- **What fails:** a principal reads or writes a channel that belongs to another principal, because the channel name or the subscription filter comes from input or is too wide.
- **Where to look:** subscribe endpoints that accept a topic or room name; names built by concatenation with a tenant or user identifier; wildcard subscriptions; shared consumer groups; reply-to or callback addresses read from a message; broker ACLs checked at connect time only.
- **Questions:**
  - Who chooses the channel name? Is the name checked against the principal's rights?
  - Can a separator, wildcard or encoding in the input change the channel (for example `tenant/../other`, `a.#`, a newline)?
  - Does a reply address from a message let a producer direct a reply to a channel it cannot read?
- **Sad-path inputs:** a topic name of another tenant; a wildcard filter; a name with separators; a reply address that points to another principal's queue; a subscription made before a role change.
- **Evidence for confirmed:** the code that builds or accepts the name, the missing check, and a message of another principal that the test client receives or sends.
- **Not a finding:** a name chosen by the server from the authenticated context; a public channel by design.
- **CWE:** CWE-639 (authorization bypass through user-controlled key). See `domain-authz.md`, AZ-02.

### MSG-05 Per-message and per-stream authorisation

- **What fails:** a stream or subscription authorises once, and later messages go to recipients who no longer may receive them, or carry fields that the recipient may not see.
- **Where to look:** WebSocket, server-sent-event and RPC streams; fan-out code that builds recipient lists; subscription filters evaluated on the client; snapshots and live updates that use different checks; events that contain full objects.
- **Questions:**
  - When does the code authorise: at connect, at subscribe, or for each message?
  - What happens to open streams when access is revoked?
  - Do live updates apply the same field-level rules as the read endpoint?
- **Sad-path inputs:** revoke access during an open stream; a subscription filter that names another principal's object; an update to a resource that the subscriber cannot read; a role downgrade.
- **Evidence for confirmed:** the authorisation point, the stale or missing check, and a message received after revocation or outside the grant. Timing needs E3 (see verification notes).
- **Not a finding:** a documented, bounded delay for closing streams; a message with no data beyond what the subscriber may read.
- **CWE:** CWE-863 (class-level; incorrect authorization); CWE-201 (insertion of sensitive information into sent data). For the decision itself see `domain-authz.md` (AZ-09).

### MSG-06 Replay and duplicate delivery

- **What fails:** a message, or a copy of it, has its effect more than once, or after it should have expired.
- **Where to look:** webhooks and signed messages without a nonce or event identifier; consumers of at-least-once queues that are not idempotent; deduplication windows shorter than the replay window; deduplication keys taken from the payload; the same signing secret in several environments or tenants; recorded messages that stay valid.
- **Questions:**
  - What stops a second delivery of the same signed message? What is the key and how long is it kept?
  - Does the timestamp tolerance match the dedup window? Is there a nonce?
  - Can an attacker choose the deduplication key and so suppress another principal's message?
  - Does a message signed for one endpoint, tenant or environment work in another?
- **Sad-path inputs:** the same message twice; a message after the tolerance window; the same event identifier from two different producers; a message from staging sent to production.
- **Evidence for confirmed:** the consumer, the effect that repeats (credit, grant, state change, notification), and the missing or short defence. E1 is enough for "no defence at all" on a non-idempotent effect. Races between check and record need E3.
- **Not a finding:** an idempotent effect (the same state results); a repeat that changes nothing.
- **CWE:** CWE-294 (authentication bypass by capture-replay); CWE-837 (improper enforcement of a single, unique action).

### MSG-07 Ordering, loss and stale messages

- **What fails:** the consumer builds security state from messages in the wrong order, or from stale messages, so that a revoked right comes back or a newer value is overwritten.
- **Where to look:** grant and revoke events on separate channels; last-write-wins using a timestamp from the producer; version fields that are not checked; replay of an event log to rebuild state; snapshots merged with live events; lost messages treated as "no change".
- **Questions:**
  - Does the result depend on delivery order? What order does the transport guarantee?
  - Who sets the timestamp or version that decides which message wins?
  - What happens if a revoke is lost, late or delivered before the grant?
- **Sad-path inputs:** revoke before grant; two updates delivered in reverse order; an old message with a large timestamp or version; a dropped revoke.
- **Evidence for confirmed:** the ordering assumption, the rule that decides the winner, and the input sequence that yields an unsafe state. This needs E3 with a deterministic order in a local test.
- **Not a finding:** state with a version check that rejects stale input; order that the transport guarantees and the repository pins.
- **CWE:** CWE-841 (improper enforcement of behavioral workflow); CWE-807 (reliance on untrusted inputs in a security decision).

### MSG-08 Internal RPC and service-to-service trust

- **What fails:** an internal service trusts the caller because of its network position, or acts for any caller with its own wide rights.
- **Where to look:** internal RPC and HTTP endpoints without authentication; services reachable through ingress or a proxy; user identity passed as a plain header or field; one service account with universal rights; administrative methods on the same port as normal ones; reflection and debug services; plain-text links between services.
- **Questions:**
  - How does the service know who calls? Can the caller be an outside client through the ingress?
  - How does the end-user identity travel? Can a caller set it freely?
  - Does the service check the end user's rights, or only its own?
  - Which methods are administrative? Who can call them?
- **Sad-path inputs:** a call with no credential; a call with the user header of another user; a call to an administrative method by a normal service; a call through the public route to an internal path.
- **Evidence for confirmed:** the service definition and handlers, the absent authentication, and a path from a low-trust principal to the method. Ingress rules outside the repository make the finding `needs-validation`.
- **Not a finding:** an endpoint on a loopback or socket protected by operating-system identity, where the code checks that identity; a documented trust boundary at a mutually authenticated link.
- **CWE:** CWE-306 (missing authentication for critical function); CWE-291 (reliance on IP address for authentication).

### MSG-09 Dead-letter, retry and replay stores

- **What fails:** failed or retried messages sit in a store with weaker control, or a replay tool puts them back with higher rights and without verification.
- **Where to look:** dead-letter queues and their readers; retry tables; "requeue all" tools; replay and re-drive commands; re-signing of messages by an administrative service; retention of failed payloads; retries after permission changes.
- **Questions:**
  - Who can read the dead-letter store? Does it hold full payloads, including secrets and personal data?
  - Does a replay tool verify the original authenticity, or does it re-sign and publish?
  - Is a message re-authorised when it is retried after a long delay?
  - Do failed messages expire?
- **Sad-path inputs:** a message that fails and lands in the store; a replay by a low-trust operator role; a retry after the producer lost its rights.
- **Evidence for confirmed:** the store access rule, or the tool's identity and missing verification, and the payload or effect obtained.
- **Not a finding:** an operator-only store with documented access and a short retention.
- **CWE:** CWE-213 (exposure of sensitive information due to incompatible policies); CWE-922 (class-level; insecure storage of sensitive information).

### MSG-10 Failure handling and consumer-side parsing

- **What fails:** an error in verification or processing leads to acceptance, partial effects, or an unsafe default.
- **Where to look:** exception handlers around signature checks that continue; consumers that parse and act before they verify; acknowledgement before the effect, or after a partial effect; unknown message types that go to a default handler; version fields that select a weaker path; poison messages that stop a queue.
- **Questions:**
  - What does the code do when verification throws, times out or returns an unknown value?
  - Does a side effect happen before verification or before the acknowledgement?
  - What happens to an unknown type or version?
  - Does a message that always fails block others (see `domain-resource-exhaustion.md`)?
- **Sad-path inputs:** a malformed signature; a verification library error; an unknown type; a payload that fails halfway through processing; a version field set to the oldest value.
- **Evidence for confirmed:** the failure branch, how to reach it with a message, and the effect that results.
- **Not a finding:** a failure branch that rejects and stores the message safely; a fail-open branch that no sender can reach.
- **CWE:** CWE-636 (class-level; not failing securely, failing open). For deserialisation, see `domain-input-parsing.md`.

## Variant search

When you find one messaging failure:
1. **Same channel.** List every consumer and producer of the channel.
2. **Same receiver shape.** List every webhook or handler built from the same template or helper. Check each for the same gap.
3. **Same identity field.** List every consumer that reads the same payload field for a decision.
4. **Same name builder.** List every place that builds a topic, queue or room name the same way.
5. **Same verification helper.** List every caller of the helper, and every handler that does not call it.
6. **Same tool.** List every administrative tool that publishes, requeues or replays.

## Chain primitives

This domain often **gives**:
- the ability to trigger privileged actions with a forged message (grant, credit, state change, command);
- messages and events of other tenants or users (identifiers, tokens, content);
- replayed effects (repeated credits or grants);
- a stale or restored right, through reordering.

This domain often **needs**:
- network or API access to a producer endpoint (from the API surface or cloud-deploy);
- a valid message to replay (from logs, captured traffic, or a data leak);
- a secret or tenant identifier (from logging-privacy, secrets-config or data-lifecycle).

## Verification notes

- **E1 is usually enough** for MSG-01, MSG-02 (absent or optional check), MSG-03, MSG-04, MSG-05 (missing per-message check), MSG-08 and MSG-09, when the registration, the consumer and the sink are in the repository and no layer outside decides. The waiver names every layer read: middleware, interceptors, broker configuration, base handlers.
- **E1 is enough** for MSG-06 only when no defence exists on a non-idempotent effect. Claims about a dedup window, a race between check and record, or delivery guarantees need E3.
- **E3 is required** for MSG-07 and for MSG-05 claims about timing after revocation. Use a deterministic order in a local test with an in-process double or a loopback broker. Do not use a live broker.
- **MSG-10 and MSG-02 claims that depend on library behaviour** (what a verify function returns on malformed input) need E3 or a documented, pinned behaviour.
- **External facts.** Broker ACLs, ingress rules and provider delivery behaviour that the repository does not show are external assumptions. The finding is `needs-validation`. State the one decisive fact.
- **E3 test shape:** create two dummy producers (A low-trust, B authorised) and two dummy tenants. Send a forged, altered, duplicated and out-of-order message as A. The expected result is rejection with no effect. Use local test doubles and dummy data. Record the observed result.
- **Design check.** A producer that the trust model makes trusted, and that sends a bad message, is not an attacker.
- **Severity examples:**
  - critical – an unauthenticated producer sends a message that a consumer runs as a privileged command or job; a forged webhook grants entitlements or changes accounts at scale;
  - high – a signature bypass on a webhook that changes state; any tenant reads another tenant's stream or topic; a payload identity field lets a producer act as any user;
  - medium – replay of an event with a limited but real effect; a revoked reader receives stream messages for hours; unreachable-by-default internal RPC without authentication;
  - low – a dead-letter store readable by a wider operator group with low-sensitivity data; an ordering fault with a small effect;
  - informational – missing replay defence on an idempotent effect (record as hardening).

## Fix patterns

- **Authenticate every producer.** Use a credential per producer or device, with broker ACLs per topic and per message type. Turn off anonymous access.
- **Verify first, on raw bytes.** Check the signature or MAC before parsing for effect. Reject missing, malformed or unknown-algorithm signatures. Fix the algorithm in code.
- **Sign what you trust.** Cover payload, type, destination, tenant, timestamp and nonce. Use a secret per sender, tenant and environment.
- **Take identity from the channel.** Use the verified producer or originator. Ignore sender fields in payloads, or compare them with the verified identity.
- **Server-chosen channels.** Map principals to channel names on the server. Validate any client-supplied part against an allow-list. Do not allow wildcards from clients.
- **Authorise each item.** Re-check on delivery, or close and rebuild streams when membership or roles change.
- **Replay defence.** Keep event identifiers for at least the timestamp tolerance, keyed by producer and channel. Make consumers idempotent. Reject stale timestamps.
- **Order by version.** Use a version or sequence per entity from the authoritative store. Reject lower versions. Do not trust producer clocks.
- **Authenticate internal calls.** Use mutual TLS or signed service tokens. Pass user context as a signed claim. Keep administrative methods on a separate listener with its own authentication.
- **Protect failure stores.** Give them the source's access control and retention. Make replay tools verify and use the original identity.
- **Fail closed.** Treat any verification error as a rejection. Acknowledge after the effect, or make the effect idempotent.
- **Looks right but is not:** an IP allow-list for the sender; a secret URL path; a signature check on parsed and re-serialised data; checking the signature only when the header is present; deduplication on a payload-supplied identifier; network segmentation as the only authentication; transport encryption as producer authentication; a timestamp window with no nonce; one signing secret for all environments; acknowledging before processing.

## Regression tests

- **Forgery matrix:** for each receiver, send no signature, an empty one, a wrong one, a valid one on another body, and a valid one from another tenant. Assert rejection and no effect.
- **Identity test:** send a payload whose actor differs from the channel identity. Assert that the decision uses the channel identity.
- **Isolation test:** as tenant A, subscribe to and publish on tenant B's names, with wildcards and separators. Assert denial.
- **Revocation test:** revoke during an open stream. Assert that the next message is not delivered.
- **Replay test:** send the same signed message twice, and after the tolerance window. Assert one effect, then rejection.
- **Order test:** deliver revoke before grant, and updates in reverse. Assert the final state is safe.
- **Internal call test:** call each internal method with no credential and with a normal service credential. Assert denial for administrative methods.
- **Failure-path test:** make verification throw. Assert rejection, and assert that the dead-letter record has the source's access control.
