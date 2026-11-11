# Domain: Federation and peer trust

## Scope

- **Load when:** the code exchanges data with servers or nodes run by **independent operators**, and acts on what they send. Signs: server-to-server APIs, peer discovery, fetching keys of other servers, verifying signatures from peers, replicating shared objects across operators, gossip, relays, allow and deny lists of servers. Examples: federated social and chat servers (ActivityPub, XMPP, Matrix and similar), email servers, peer-to-peer and blockchain node networking, multi-operator sync of shared documents, federated identity hubs, cross-organisation data exchange.
- **Covers:** peer identity and discovery, key discovery and trust, signature coverage of peer data, namespace authority (who may assert facts about which objects), relayed and third-party data, replicated state and conflict resolution as a security decision, peer-supplied metadata, split views, revocation and de-federation, peer-driven amplification, version and capability negotiation between peers.
- **Hand off to:**
  - `domain-crypto-protocols.md` – the cryptographic design of signatures and handshakes, canonicalisation algorithms, transcript binding. Federation owns *which* data must be signed and *whether* the code trusts unsigned data; crypto-protocols owns *how* the signing and canonicalisation work.
  - `domain-crypto.md` – use of primitives (verify result ignored, wrong algorithm, key storage).
  - `domain-authz.md` – what a verified peer, or a user on a peer, may do to local resources. Use both files for actions that peers request.
  - `domain-outbound-network.md` – SSRF and TLS checks when the server connects to a peer or fetches a peer-supplied URL.
  - `domain-messaging.md` – queues and webhooks between components of **one** operator. Federation is for components of **different** operators.
  - `domain-concurrency.md` – consensus inside one trusted cluster. Federation assumes some peers are hostile.
  - `domain-resource-exhaustion.md` – general CPU, memory and queue limits. Federation keeps amplification that a peer causes through the federation protocol (FD-10).
  - `domain-data-lifecycle.md` – deletion and retention of data that peers hold.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Peer identity:** The server treats a connection or message as coming from peer <P> only after it verifies <P>'s identity with <mechanism>, and the verified identity is the one used for every later decision.
2. **Key trust:** The server accepts a signature from peer <P> only with a key that <P> controls, as shown by <discovery and trust mechanism>, and that was valid at <the relevant time>.
3. **Signature coverage:** Every field that the server trusts in peer data is covered by a valid signature from the peer with authority over it. Unsigned fields are treated as untrusted input.
4. **Namespace authority:** A peer can only create or assert facts about objects and users in its own namespace (for example its own domain), unless <documented rule> allows more.
5. **Relayed data:** Data that peer <A> relays about objects of peer <B> is trusted only after the server verifies <B>'s signature, not <A>'s claim.
6. **Replicated state:** For shared state replicated across peers, every peer that follows the specification computes the same security-relevant result (membership, permissions, ownership) from the same inputs, and no single peer can change that result outside the rules.
7. **Metadata:** Peer-supplied timestamps, ordering, sizes and identifiers are bounded and validated before they influence a security decision.
8. **Revocation:** A blocked peer, or a revoked key, stops being trusted on every path, including caches and relayed copies, within the documented time.
9. **Proportion:** One peer cannot make the server do work or send requests out of proportion to its own share of the system.

## Recon additions

Add a heading "Federation model" to `domain-notes.md`:

1. **Peer protocol surfaces.** Every inbound server-to-server endpoint, message type and transaction type, with file:line. Mark which require peer authentication.
2. **Peer identity.** How the server learns who a peer is: TLS client certificate, signed requests, dialback, DNS, well-known files, discovery records, shared secrets. Where the claimed name is compared with the verified name.
3. **Key discovery.** Where peer keys come from (the peer itself, a notary or third party, DNS, a ledger), how long they are cached, how expiry and rotation work, and what happens on a cache miss.
4. **Authority table.** For each object type a peer can send: which peer has authority over it (origin server, owner's server, any member's server), which signature proves it, and which fields are signed.
5. **Replicated state.** Which state is shared across operators, how conflicts are resolved, which algorithm versions exist, and which security decisions depend on the resolved state.
6. **Local policy.** Allow lists, deny lists, rate limits per peer, trust levels for notaries or relays.
7. **Outbound peer requests.** Every place the server contacts a peer or a peer-supplied URL, and which input chooses the destination.

## Lead searches

| Search | A hit may mean | False-hit notes |
|---|---|---|
| Server-to-server route or handler registration, compared with the list of handlers that call the peer-authentication function | A peer endpoint without peer authentication (FD-01) | Some endpoints are public by design (key discovery). Check what they return. |
| `origin\|sender\|server_?name\|actor\|issuer\|domain\|host` read from a message body, compared with the authenticated peer identity | Claimed origin not bound to verified peer (FD-01, FD-04) | Binding may happen in a shared decoder. Read it. |
| `verify\|check_?sig\|validate_?signature` whose return value is not checked, or is checked after the data is used | Signature not enforced (FD-03) | Hand primitive misuse to crypto. |
| Fields read from peer objects that are **not** in the signed part (`unsigned`, `meta`, envelope headers, transport metadata) | Trust in unsigned data (FD-03) | Unsigned fields used only for display may be hardening. |
| `fetch_?key\|get_?key\|key_?server\|notary\|well-known\|discover` | Key discovery path (FD-02) | |
| Cache of keys or peer data: `cache\|ttl\|expire` near key or peer code | Stale trust after rotation or revocation (FD-02, FD-09) | |
| `split\|@\|:` used to extract a domain or server name from an identifier | Namespace authority checks; parser differences (FD-04) | Check every parser of the same identifier format. |
| `timestamp\|_ts\b\|created\|depth\|sequence\|clock` from peer data used in ordering, expiry or authorization | Peer-controlled metadata (FD-07) | |
| `resolve\|merge\|conflict\|fork\|reconcile\|consensus` | Replicated-state logic (FD-06) | Separate trusted-cluster consensus (concurrency). |
| `fetch_?missing\|get_?ancestors\|predecessors\|walk\|recurs` on peer-provided references | Peer-driven amplification (FD-10) | |
| `version\|capabilit\|feature\|supported_?versions` in peer handshakes or object headers | Downgrade (FD-11) | |
| Deny-list or allow-list checks for peers | Revocation coverage (FD-09) | Compare with every inbound path. |

## Attack classes

### FD-01 Peer identity and discovery

- **What fails:** the server accepts a message as coming from peer P, but P's identity was not verified, or the verified identity is not the identity used later.
- **Where to look:** inbound authentication of server-to-server requests; comparison of the claimed server name with the TLS certificate, request signature or dialback result; discovery of the peer's address (DNS records, well-known files, delegation); redirects during discovery; connection reuse across peers.
- **Questions:**
  - Is every peer endpoint authenticated, or only some message types?
  - Is the name in the message compared with the authenticated name? Exactly, after the same normalisation?
  - Can discovery delegate peer P's identity to a host that P does not control? Does the server verify the delegation?
  - Does a pooled connection authenticated for peer P accept messages that claim to come from peer Q?
- **Sad-path inputs:** a message claiming origin Q over a connection authenticated as P; mixed case, trailing dots, ports, IDN and punycode forms of the server name; a discovery record that points to another domain; a certificate valid for a wildcard or a parent domain.
- **Evidence for confirmed:** the authentication point, the place where the claimed identity is used, and the path where they differ. E1 is often enough.
- **Not a finding:** a public endpoint that returns only public data; identity differences that the specification allows and the code binds correctly.
- **CWE:** CWE-290 (authentication bypass by spoofing); CWE-287 (class-level, improper authentication) if no more specific entry fits.

### FD-02 Key discovery and key trust

- **What fails:** the server accepts a key for peer P that P does not control, or keeps trusting a key after it expires or is replaced.
- **Where to look:** fetching keys from the peer itself and from third parties (notaries, ledgers, directories); verification of key responses (are they self-signed, signed by a notary, both?); key ID handling; expiry fields; cache lifetime; behaviour when the key server is down.
- **Questions:**
  - Is a key response itself authenticated? By whom?
  - If a notary or third party supplies P's key, which notaries are trusted, and can a peer act as a notary for other peers?
  - Is the key ID bound to the key? Can two keys share an ID?
  - Is the validity period checked against the time the signed object was created, the current time, or neither? Is that choice consistent across paths?
  - On cache miss or key-server failure, does verification fail closed?
- **Sad-path inputs:** a key response for P served by Q; an expired key; a key valid in the future; a key with a reused ID; an unreachable key server; a notary response that disagrees with the peer's own response.
- **Evidence for confirmed:** the path where a key not controlled by P is accepted for P, or an expired key is accepted outside the documented rule.
- **Not a finding:** accepting historical keys for historical objects when the specification requires it and the time check is correct.
- **CWE:** CWE-347 (improper verification of cryptographic signature); CWE-324 (use of a key past its expiration date).

### FD-03 Signature coverage and unsigned data

- **What fails:** the server verifies a signature, then trusts a field that the signature does not cover, or trusts data before verification.
- **Where to look:** objects with signed and unsigned parts; envelopes and transport headers; fields added by relays; redaction or stripping rules applied before verification; objects with several signatures where only one is checked; processing that starts before verification finishes (streaming, partial parsing).
- **Questions:**
  - List every field the server uses for a security decision. Is each one inside the signed content?
  - Does the server verify, then re-parse or re-read the object from a different buffer?
  - When an object needs signatures from several parties, does the server check all of them?
  - Does redaction remove or keep the fields that the signature covers? Is the redaction algorithm the same as the signer's?
- **Sad-path inputs:** a valid signed object with an extra unsigned field that changes the sender, room, group, permissions or timestamp; an object with a valid signature from the wrong party; a duplicated key in the object (first in the signed form, second in the parsed form).
- **Evidence for confirmed:** the verified content, the unsigned field, and the decision that uses it. Duplicate-key and canonicalisation differences are parser differentials and need E3.
- **Not a finding:** unsigned fields that the server uses only for display and never for a decision (record as hardening if users can be misled).
- **CWE:** CWE-347; CWE-345 (class-level, insufficient verification of data authenticity) when no signature exists at all.

### FD-04 Namespace authority

- **What fails:** a peer creates or changes objects that belong to another peer's namespace, for example asserting actions by users of another server.
- **Where to look:** checks that compare the domain part of user, object or group identifiers with the sending peer; identifier parsers; objects that reference users of several servers; join, invite, follow and membership flows that involve two servers.
- **Questions:**
  - For each object type, which peer may create it? Does the code enforce that rule on every inbound path?
  - Do all components parse identifiers the same way (separator, case, escaping, ports, IPv6 literals)?
  - Can a peer claim a user ID on another server by using an identifier that two parsers split differently?
- **Sad-path inputs:** identifiers with two separators; uppercase domains; trailing dots; port numbers; IPv6 literals; Unicode in the domain part; empty localparts.
- **Evidence for confirmed:** the inbound path, the missing or wrong namespace check, and the accepted foreign object. Parser differences need E3.
- **Not a finding:** documented cases where a peer may act for another (for example signed invitations relayed by design, with verification of the original signature).
- **CWE:** CWE-290; CWE-863 (class-level) for wrong authority decisions.

### FD-05 Relayed and third-party data

- **What fails:** the server trusts data about peer B because peer A relayed it, without verifying B's own proof.
- **Where to look:** fetching missing objects from any available peer; gossip; forwarding; caches of remote objects; "fetch from the peer that told us about it" logic; batch responses that contain objects from many origins.
- **Questions:**
  - When peer A returns an object that originates on peer B, is B's signature checked?
  - Is the relayed object checked against the same rules as a direct one (authority, size, version)?
  - Can peer A substitute an older valid object for a newer one (replay)?
- **Sad-path inputs:** a correctly signed but stale object; an object whose origin is B but that arrives only through A; a response that mixes valid objects with one forged object.
- **Evidence for confirmed:** the relay path and the missing verification.
- **Not a finding:** relayed data that is verified end to end.
- **CWE:** CWE-345 (class-level); CWE-294 (authentication bypass by capture-replay) for stale substitution.

### FD-06 Replicated state and conflict resolution

- **What fails:** a hostile peer makes the server compute a security-relevant state (membership, permissions, ownership, bans) that the rules do not allow, or that differs from what other compliant peers compute.
- **Where to look:** algorithms that merge histories or forks; state computed from an object graph; tie-breaking rules; handling of objects that reference unknown or rejected predecessors; algorithm version selection per shared object; persistence of intermediate state; differences between the specification and the implementation.
- **Questions:**
  - Which inputs can a peer control: predecessors, timestamps, depth, ordering keys, which objects it sends and which it withholds?
  - Is each authorization rule applied to each object at the right point in history (the state before the object), and again for the current state where the specification requires it?
  - What happens to objects that fail authorization: are they dropped, stored as rejected, or still used as references?
  - Does a fork created with old but valid credentials (for example an admin before demotion) override later state?
  - Is the algorithm deterministic? Does it depend on iteration order of hash maps, floating point, or local clock?
- **Sad-path inputs:** a fork that branches before a permission change; objects that reference rejected objects; equal timestamps and equal ordering keys; very deep or very wide histories; objects that arrive out of order.
- **Evidence for confirmed:** a deterministic test that feeds a crafted history to the resolution code and shows the forbidden resulting state. **E3 is required.** Reasoning alone about these algorithms is not reliable.
- **Not a finding:** a divergence that the specification documents and that cannot change any security decision.
- **CWE:** CWE-863 for the wrong authorization result; CWE-841 (improper enforcement of behavioural workflow) when ordering rules are skipped.

### FD-07 Peer-supplied metadata

- **What fails:** a security decision depends on metadata that the peer controls and the server does not bound.
- **Where to look:** timestamps used for expiry, ordering, rate windows or key validity; depth, sequence and counter fields; sizes and counts declared by the peer; display names and labels that users rely on; identifiers that are assumed unique.
- **Questions:**
  - Which decisions use a peer timestamp? Can the peer move an object into the past (before a ban) or the future (after a key expiry)?
  - Are declared sizes and counts checked against the real content?
  - Can a peer reuse an identifier that another peer already used?
- **Sad-path inputs:** timestamps far in the past and future, zero, negative, maximum; identifiers that collide with existing ones; display names that impersonate other users or servers.
- **Evidence for confirmed:** the metadata field, the decision, and the forbidden result.
- **Not a finding:** metadata used only for sorting a display, where the user is told it is peer-supplied.
- **CWE:** CWE-345 (class-level); CWE-20 (class-level, improper input validation) only if nothing more specific fits.

### FD-08 Split views and equivocation

- **What fails:** a peer sends different, valid-looking versions of the same object or history to different servers, and the system does not detect it, so servers act on contradictory states.
- **Where to look:** places where the protocol relies on peers being honest about what they sent elsewhere; absence of hash chains or cross-checks; objects identified by a name rather than by a content hash.
- **Questions:**
  - Can two different objects have the same identifier?
  - Does any mechanism (content hashes, transparency logs, cross-peer checks) reveal equivocation?
  - What security decision changes if two servers see different versions?
- **Sad-path inputs:** two objects with the same ID and different content sent to two local test instances.
- **Evidence for confirmed:** a local test with two server instances (or two state stores) that accept contradictory objects, and the security decision that differs. E3 required.
- **Not a finding:** equivocation that the protocol accepts as a known limit and that changes no local security decision.
- **CWE:** name the weakness in words (equivocation), or CWE-345 (class-level).

### FD-09 Revocation and de-federation

- **What fails:** a blocked peer, a removed member server or a revoked key continues to be trusted through a path that the block does not cover.
- **Where to look:** deny lists and allow lists; per-object server access lists; key revocation; cached keys and cached peer objects; relayed objects from blocked peers; outbound traffic to blocked peers.
- **Questions:**
  - Is the block applied to every inbound endpoint, to relayed data, and to outbound sends?
  - Is the peer name normalised the same way in the block list and in the checks?
  - Do cached keys and objects from a blocked or revoked source stay valid?
- **Sad-path inputs:** a blocked peer using a name variant; objects from a blocked peer relayed by an allowed peer; a key revoked after it was cached.
- **Evidence for confirmed:** the block or revocation, the path that ignores it, and the accepted data or action.
- **Not a finding:** a documented propagation delay within its bound.
- **CWE:** CWE-299 (improper check for certificate revocation) for certificate-based trust; otherwise CWE-863.

### FD-10 Peer-driven amplification

- **What fails:** a single peer makes the server do disproportionate work, or makes the server send many requests to other servers.
- **Where to look:** recursive fetching of missing predecessors or referenced objects; fan-out of one inbound message to many peers; retries to unreachable peers chosen by a hostile peer; verification of many signatures per object; large histories requested at once; key fetches triggered by unknown key IDs.
- **Questions:**
  - Is there a limit on recursion depth, total objects and total bytes per inbound request?
  - Can one inbound message cause outbound requests to an attacker-chosen list of servers?
  - Is the work done before the peer is authenticated, or before the object's signature is checked?
- **Sad-path inputs:** a reference chain longer than any limit; many unknown key IDs; references to many non-existent peers; a single message addressed to a very large audience.
- **Evidence for confirmed:** a bounded local test showing the ratio of work (or outbound requests) to input size, and the missing limit. Do not generate load against any real peer. E3 for claims about shared availability; E1 for a missing limit on a clearly unbounded loop.
- **Not a finding:** fan-out that the protocol requires and that is bounded per peer.
- **CWE:** CWE-770 (allocation of resources without limits or throttling); CWE-406 (class-level; insufficient control of network message volume, network amplification).

### FD-11 Version and capability negotiation

- **What fails:** a peer selects an older protocol or object version with weaker checks, and the server accepts it in a context where the stronger rules must apply.
- **Where to look:** version lists in handshakes; per-object version fields that select algorithms; default versions when the field is absent; fallbacks after errors; feature flags announced by peers.
- **Questions:**
  - Can a peer choose the version, or is it fixed by the object's creator?
  - Are old versions still accepted for new objects?
  - Does an unknown version fail closed?
- **Sad-path inputs:** missing version; unknown version; the oldest supported version for a new object; a version change in the middle of a session.
- **Evidence for confirmed:** the negotiation path, the weaker rule set, and the security decision it changes.
- **Not a finding:** support for old versions that the specification requires, with the same checks.
- **CWE:** CWE-757 (selection of less-secure algorithm during negotiation).

## Variant search

1. **Every inbound peer endpoint.** Build a table: endpoint × peer authentication × origin binding × signature check × namespace check × block-list check. Every empty cell is a lead.
2. **Every identifier parser.** Find every function that splits or normalises the same identifier format. Compare them on the sad-path inputs from FD-04.
3. **Every trusted field.** For each object type, list fields used in decisions and mark signed or unsigned.
4. **Every relay path.** List every way an object can arrive without coming from its origin.
5. **Implementation differences.** If other implementations of the same protocol exist, the specification and their public issue trackers show where implementations have diverged before. Use them as leads only, and only if web access is allowed.

## Chain primitives

This domain often **gives**:
- the ability to act as, or for, users of another server (impersonation);
- control over shared state that other servers trust (membership, permissions, bans);
- outbound requests from the server to attacker-chosen hosts (SSRF seed for outbound-network);
- injection of content that other users or servers render (seed for injection and web-client);
- disproportionate load on the server or on third parties.

This domain often **needs**:
- control of one peer (a cheap assumption: anyone can run a server in an open federation);
- a canonicalisation or parser difference (from crypto-protocols or input-parsing);
- a stale cached key or object (from data-lifecycle or caching code).

## Verification notes

- **Threat assumption.** In an open federation, assume the attacker controls at least one peer and its keys. The question is what that peer can do beyond its own namespace.
- **E1 is usually enough** for FD-01, FD-03 (missing field coverage), FD-04 (missing check), FD-09 and FD-11, when the verification code and the decision are both in the repository.
- **E3 is required** for FD-06 and FD-08, and for any parser or canonicalisation difference (FD-03 duplicate keys, FD-04 identifier parsing). Build a unit test that feeds crafted objects or histories to the local code. Never send test objects to a real peer.
- **E3 or needs-validation** for FD-10 availability claims.
- **Specification first.** Before you report, read the relevant part of the protocol specification if it is in the repository or available. If the code follows the specification and the specification is weak, report it as a design finding and say so.
- **Severity examples:**
  - critical – any peer can impersonate users of other servers, or make the server accept forged signed state that other servers then trust;
  - high – a peer changes the authorization state of shared objects outside its authority (for example removes another server's administrators); a peer reads private objects of other servers through relay or fetch paths;
  - medium – equivocation that needs a persistent hostile peer and affects one shared object; a revoked key accepted for a bounded window beyond the documented one;
  - low – spoofing of display metadata with limited effect;
  - informational – a missing limit that only a large federation of hostile peers could use.

## Fix patterns

- **Bind identity once.** Authenticate the peer at the transport or request-signature layer, then derive the origin from that identity. Ignore or reject origin fields that disagree.
- **Verify, then parse the verified bytes.** Use the exact bytes that were verified for every later read. Reject duplicate keys and non-canonical input before verification.
- **Sign what you trust.** Move every trusted field into the signed content. Treat unsigned fields as untrusted display data.
- **One identifier parser.** Use one function to parse and normalise identifiers everywhere, with tests for every sad-path input.
- **Namespace rule in one place.** Check origin authority in the shared inbound pipeline, not in each handler.
- **Fail closed on keys.** Reject when keys cannot be fetched or verified. Bound cache lifetimes. Honour revocation in caches.
- **Bound peer work.** Limit recursion depth, object counts, bytes and outbound fan-out per inbound request and per peer.
- **Pin versions per object.** Let the object's creator fix the version, and reject unknown versions.
- **Looks right but is not:** checking that a signature is valid without checking whose key it is; checking the sender of the transaction but not of each object inside it; trusting a notary without limiting which notaries; comparing server names without normalisation; applying block lists only to direct connections.

## Regression tests

- For each inbound peer endpoint: a test that sends a correctly signed message from peer P that claims origin Q, and asserts rejection.
- A test per trusted field: change the field outside the signed content and assert rejection or no effect.
- Identifier parser tests with every sad-path input from FD-04, run against every parser.
- Replicated-state tests with crafted histories: forks before permission changes, references to rejected objects, equal ordering keys. Assert the expected resolved state.
- Key tests: expired key, future key, wrong-peer key, reused key ID, unreachable key server. Assert rejection.
- Block-list tests on direct, relayed and outbound paths, with name variants.
- Amplification tests: assert the limit on depth, objects, bytes and outbound requests per inbound message.
