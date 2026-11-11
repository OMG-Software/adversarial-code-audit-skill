# Domain: Resource exhaustion

## Scope

- **Load when:** untrusted input controls the size, count, depth, rate or cost of work. Signs: regular expressions applied to input; decompression, archive, image or media handling; recursive or nested formats; user-controlled filters, sorts or queries; listeners that accept connections or datagrams; worker pools and queues; retry loops; calls to paid services (model APIs, SMS, e-mail, cloud functions, storage egress).
- **Covers:** algorithmic complexity; regular-expression backtracking; decompression and expansion bombs; unbounded buffers, collections and recursion; connection, thread and descriptor exhaustion; work done before authentication; quota scope; queue and worker starvation; spend on paid resources; reflection and amplification (UDP and fan-out); retry storms.
- **Hand off to:**
  - `domain-input-parsing.md` – format meaning, parser differentials, archive path escape. This file owns size, depth and expansion limits.
  - `domain-abuse.md` – spam, scraping, account farming and the choice of rate-limit key as an anti-abuse control. This file owns cost that grows faster than the input, or has no bound.
  - `domain-outbound-network.md` – SSRF and URL fetching. This file owns the timeout and size limit on each fetched response.
  - `domain-ai-llm.md` – agent loops and model-specific cost controls. This file owns spend on any other paid API.
  - `domain-memory-safety.md` – integer overflow in size arithmetic that corrupts memory.
  - `domain-messaging.md` – delivery semantics and dead-letter stores. This file owns the resource cost of the queue.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Work:** The CPU time for <operation> is at most <bound> in the input size, and a fixed cap applies to each input dimension (length, count, depth, nesting).
2. **Memory:** The memory held for one <request | connection | principal> is below <cap>. The code checks the cap before it allocates.
3. **Expansion:** Decoding or decompressing <input> yields at most <output cap> bytes and at most <ratio> times the input size. The code enforces both while it decodes.
4. **Depth:** Nesting depth and recursion depth for <parser | resolver | walker> are at most <N>. A deeper input gets an error, not a crash.
5. **Pre-authentication:** A peer that has not authenticated can cause at most <bounded CPU, memory and state> before authentication completes.
6. **Handles:** Connections, threads, descriptors and pool slots are limited per principal and in total. The code releases each slot on every exit path, including errors and timeouts.
7. **Timeout:** Every blocking read, write, lock wait, outbound call and job has a timeout.
8. **Quota scope:** A quota applies to the principal or resource that bears the cost. The attacker cannot avoid it by changing a field that the quota key uses.
9. **Fairness:** One principal cannot delay the work of another principal beyond its fair share of a shared worker pool or queue.
10. **Amplification:** Until the source is verified, a response is not larger than the request. Fan-out per request is bounded.
11. **Spend:** The paid calls that one principal can trigger stay under <budget> per <period>.
12. **Retry:** Retries are bounded, use back-off with jitter, and do not multiply across layers.

## Recon additions

Add these to `domain-notes.md` under a heading "Resource budget". Keep it short; hunters copy it.

1. **Budget table.** One row for each entry surface. Columns: input dimension the attacker controls | resource used | limit (value, file:line, or "none") | pre-authentication? | scope of the limit (request, connection, principal, tenant, global) | shared pool.
2. **Pools and queues.** List each worker pool, thread pool, connection pool and queue. Give the size, the bound, the timeout and the fairness rule.
3. **Expanding formats.** List each place that decompresses, decodes, resolves references or renders input to a larger form (archives, images, XML, YAML aliases, protocol compression, template includes).
4. **Listeners.** List each TCP, UDP, WebSocket or other listener. Note what the code does before authentication and what it sends back to an unverified source.
5. **Paid calls.** List each call that costs money or a quota: model APIs, SMS, e-mail, cloud functions, storage egress. Note which principal can trigger it and which budget limits it.
6. **Limit source.** Mark each limit as code, configuration, or external (proxy, platform). External limits are assumptions. List each retry or reconnect loop with its back-off rule.

## Lead searches

| Search | A hit may mean | False-hit notes |
|---|---|---|
| Nested quantifiers and ambiguous alternation in patterns: `\([^)]*[+*][^)]*\)[+*{]`, `(\.\*\|\.\+).*(\.\*\|\.\+)`, `\(a\|a\)` shapes | Backtracking blow-up (RX-02) | Linear-time engines are immune. Find the engine first. |
| Regular expression built from input: `compile\|Regex\(\|RegExp\(\|re\.\w+\(` with a request-derived argument | Attacker-chosen pattern (RX-02) | A fixed pattern on input is a different lead. |
| `gunzip\|inflate\|decompress\|unzip\|untar\|extract\|ZipFile\|BZ2\|zstd\|lzma\|Image\.open\|decode` with no size or ratio argument | Expansion bomb (RX-03) | A cap may sit in a wrapper or reader. Read it. |
| `read_all\|readAll\|ReadAll\|readToEnd\|\.read\(\)\|slurp\|getBytes\|to_vec\|collect` on a request or socket | Unbounded buffer (RX-04) | A body limit may apply earlier in the stack. |
| Length or count field read from input, then used in `alloc\|malloc\|new \|make\(\|with_capacity\|reserve\|resize\|Array\(` | Allocation by attacker size (RX-04) | Check for a cap between read and use. |
| `accept\|listen\|ThreadPool\|Executor\|spawn\|go func` with no limit, semaphore or timeout nearby | Connection or thread exhaustion (RX-05) | The framework may set defaults. Check the pinned version. |
| Password hashing, signature verification, key exchange or database look-up before the authentication result | Pre-authentication work (RX-06) | Cheap look-ups are fine. Cost it. |
| `rate_?limit\|throttle\|quota\|bucket\|limiter` and the key they use | Limit scope (RX-07) | Read the key. A key from a header or body is a lead. |
| `queue\|channel\|mailbox\|backlog\|buffer` created without a bound (`unbounded\|Infinity\|MaxInt\|0` as capacity) | Unbounded queue (RX-08) | A bounded queue that blocks the producer can still starve others. |
| `recvfrom\|sendto\|UDP\|datagram\|broadcast\|multicast\|discovery` | Amplification (RX-10) | Check whether the reply is larger than the request. |
| `retry\|backoff\|reconnect\|attempts\|redeliver\|requeue` and loops with `sleep(0)` or none | Retry storm (RX-11) | Read the delay formula. |

## Attack classes

### RX-01 Algorithmic complexity

- **What fails:** the cost of an operation grows faster than the input size, and the attacker picks the input that triggers the worst case. A small request then uses a large amount of CPU.
- **Where to look:** hash tables keyed by attacker strings; sorting and de-duplication by nested loops; string building by repeated concatenation; list scans inside loops; graph, dependency or conflict resolution over attacker-supplied links; diff and merge; search with wildcard or fuzzy matching; queries that join on user filters (including N+1 patterns); pagination by large offset; export builders.
- **Questions:**
  - What is the cost in terms of the input size n, and of each dimension (count, length, depth)?
  - Does the attacker control the worst-case shape (collisions, long chains, many duplicates, deep links)?
  - Does a cap on n exist? Is the cap low enough for the cost?
- **Sad-path inputs:** maximum count of items; items that collide in the hash function; one very long item; a graph that is a single chain or a dense cluster; a filter that matches every row; an offset near the maximum; many equal sort keys.
- **Evidence for confirmed:** the line with the superlinear step, the input shape that triggers it, the cap (or its absence), and a measured growth ratio from a bounded local test. E3 is normally required (see verification notes).
- **Not a finding:** a superlinear step on a trusted or tiny input; a cost bounded by a small cap; slowness that affects only the attacker.
- **CWE:** CWE-407 (class-level; inefficient algorithmic complexity); CWE-834 (class-level; excessive iteration) when a loop bound comes from input; CWE-1284 when a quantity from input is not checked.

### RX-02 Regular-expression complexity (ReDoS)

- **What fails:** a pattern takes exponential or high-polynomial time on some inputs, because the engine backtracks.
- **Where to look:** validators for e-mail, URL, host name, version and markup; log and header parsers; patterns with nested quantifiers `(a+)+`, overlapping alternations `(a|a)*`, or adjacent quantified groups that match the same characters; patterns built from input; user-defined rules and filters; routing rules.
- **Questions:**
  - Which engine runs the pattern? A backtracking engine is vulnerable. A linear-time engine (automaton-based) is not.
  - Does the pattern have an ambiguous part that can match the same text in more than one way?
  - Does input length have a cap before the match?
- **Sad-path inputs:** a long run of the repeated character followed by one character that makes the match fail; maximum-length subject; many near-matches; Unicode characters that change the match length.
- **Evidence for confirmed:** the pattern, the engine and its version, the length cap, and a bounded timing test that shows growth when the subject doubles in length. Stop the test early. Do not run an input that takes more than a few seconds.
- **Not a finding:** a pattern that is ambiguous but runs on a linear-time engine; a pattern whose subject is capped at a small length; a pattern on trusted configuration only.
- **CWE:** CWE-1333 (inefficient regular expression complexity).

### RX-03 Decompression and expansion bombs

- **What fails:** a small input expands to a very large output in memory, on disk or in CPU time. The code does not limit output size or ratio while it expands.
- **Where to look:** gzip, zip, tar and zstd readers; image decoders (pixel dimensions, frame counts); document formats; XML entity expansion; YAML alias expansion; protocol-level compression; template includes; nested archives; recursive thumbnailing or transcoding.
- **Questions:**
  - Does the code limit the decompressed size as it reads, or after it has read everything?
  - Is there a ratio limit, a nesting limit and a total entry count limit?
- **Sad-path inputs:** a small archive with a very large declared size; high-ratio data (long runs of one byte); an archive that contains itself or many tiny entries; an image header with huge dimensions and a short body; an XML document with nested entity definitions; a YAML document with anchors that double at each level.
- **Evidence for confirmed:** the reader call without a cap, the input shape (small, safe, local), and the measured output size or memory growth in a bounded test with a hard limit set by the test harness.
- **Not a finding:** a reader that enforces a cap before it allocates; a bomb that only the operator can upload; a tool that the user runs on their own files.
- **CWE:** CWE-409 (improper handling of highly compressed data); CWE-776 (XML entity expansion) for DTD cases; CWE-789 when an allocation uses a size from input.

### RX-04 Unbounded buffers, collections and recursion

- **What fails:** memory or stack use grows with an input dimension that the code does not cap. The result is memory exhaustion, an out-of-memory kill, or a stack-overflow crash.
- **Where to look:** request bodies, multipart parts, headers; length-prefixed fields; per-connection read buffers; maps and caches without eviction; per-session state that nothing removes; subscription lists; recursive descent over nested JSON, XML or expressions; serialisers on cyclic data.
- **Questions:**
  - Who enforces the maximum size of each of these?
  - Does the code check a declared length before it allocates, and does it still check when the body uses chunked or streaming transfer?
  - What is the recursion depth for the deepest accepted input?
- **Sad-path inputs:** the declared length at its maximum and at maximum + 1; a body that exceeds its declared length; thousands of small headers; deeply nested arrays (a depth of tens of thousands); many distinct keys for a cache; a field repeated many times.
- **Evidence for confirmed:** the allocation or growth site, the missing cap on the path from the entry, and a bounded test that shows the growth with an input of known small size. A process crash from stack depth shows the defect directly at E3.
- **Not a finding:** growth that a proxy, framework default or pinned library limit stops (name it with file:line); growth limited to the attacker's own session and freed at its end.
- **CWE:** CWE-770 (allocation of resources without limits or throttling); CWE-674 (class-level; uncontrolled recursion); CWE-789; CWE-772 for state that nothing releases.

### RX-05 Connection, descriptor and slot exhaustion

- **What fails:** an attacker holds connections, threads, descriptors, database connections or pool slots, so that other principals cannot get one.
- **Where to look:** accept loops; thread-per-connection servers; streaming subscriptions; keep-alive settings; read and write timeouts; database, HTTP-client and worker pools; error paths that skip the release; child processes, temporary files and sockets opened per request.
- **Questions:**
  - Is there a limit on connections per source, per principal and in total?
  - Does every read have a timeout, including the first byte and the body?
  - Does every error path, including timeouts and cancellation, release the slot?
- **Sad-path inputs:** a connection that sends nothing; a client that sends one byte at a time; a half-open connection; many idle subscriptions; a client that never reads the response; an error injected after a slot is taken.
- **Evidence for confirmed:** the missing limit or timeout, the slot that is not released, and a bounded local test with a small pool (for example a pool of 4) that shows a second principal blocked by the first. A shared impact must be shown, not only a held connection.
- **Not a finding:** a limit set by the platform that the repository documents and pins; exhaustion that only blocks the attacker's own connections.
- **CWE:** CWE-770; CWE-774 (file descriptors or handles without limits); CWE-772 (missing release of resource).

### RX-06 Pre-authentication work

- **What fails:** a peer that has not proved its identity makes the service spend CPU, memory or state before the first check.
- **Where to look:** handshakes; key agreement and signature checks on unauthenticated messages; password hashing run before a rate limit; state allocated per half-open session; parsing of large bodies before the token check.
- **Questions:**
  - What is the first check on the path, and what does the code do before it?
  - Does the code allocate state before the peer proves a return address or a token?
- **Sad-path inputs:** many handshake starts that never finish; messages with invalid signatures; login attempts for unknown accounts; large bodies with an invalid token; many distinct source addresses.
- **Evidence for confirmed:** the order of operations from entry to the first check, the cost of the work before it (measured on a small local loop), and the absence of a cap or cookie.
- **Not a finding:** work that is cheap and constant; a cost the code already caps per source and in total.
- **CWE:** CWE-405 (class-level; asymmetric resource consumption) and CWE-770; use the child that matches the root cause.

### RX-07 Quota and limit scope

- **What fails:** a limit exists, but it counts the wrong thing, uses a key the attacker controls, or applies on only one path.
- **Where to look:** rate limiters and quotas; keys built from IP address, header, body field or session; limits per request when the request holds many items (batch, aliases, bulk import); a limit on one endpoint while a sibling does the same work; limits checked after the work; counters that reset on restart.
- **Questions:**
  - What does the key contain? Can the attacker change it per request?
  - Do all paths to the same work (v1 and v2, internal, batch, WebSocket) share the limit?
- **Sad-path inputs:** one request with the maximum number of items; the same work through a sibling path; a changed key value (header, case, encoding); a request that fails after the work but before the count.
- **Evidence for confirmed:** the limiter configuration, the key or counting error, the path that skips it, and a test that shows the limit does not apply.
- **Not a finding:** a limit set low enough for the cost on every path; a missing limit on a path that only trusted principals reach. Account farming and scraping belong to `domain-abuse.md`.
- **CWE:** CWE-799 (class-level; improper control of interaction frequency); CWE-770.

### RX-08 Queue and worker starvation

- **What fails:** one principal's work fills a shared queue or worker pool, so other principals wait without a bound.
- **Where to look:** shared job queues; one event loop for all tenants; synchronous calls inside an asynchronous handler; jobs without a time limit; a queue with no bound or per-tenant share; priority fields the attacker sets; jobs that create more jobs.
- **Questions:**
  - Is the queue bounded? What happens when it is full (drop, block, grow)?
  - Does a fairness rule exist (per-tenant queue, weighted share)?
  - Can one job run forever or for a very long time? What stops it?
- **Sad-path inputs:** many large jobs from one principal; one job that never ends; a job that creates more jobs.
- **Evidence for confirmed:** the shared resource, the missing bound or fairness rule, and a bounded test that shows a second principal's job delayed by the first (small pool, short jobs). The delay must affect another principal.
- **Not a finding:** a queue that is bounded with per-tenant fairness; delay that only the submitting principal sees.
- **CWE:** CWE-770; CWE-400 (class-level; use a more specific entry when one fits).

### RX-09 Spend on paid resources

- **What fails:** a low-trust principal makes the service spend money or a vendor quota that the principal does not pay for.
- **Where to look:** handlers that call model, SMS, e-mail, push, map or cloud-function APIs; media processing on paid platforms; storage egress; free tiers that reach paid calls; unauthenticated endpoints that send messages to addresses the caller supplies.
- **Questions:**
  - Which principal can trigger the paid call, and how often?
  - Is there a budget per principal, per tenant and in total? What happens when it ends?
  - Can the caller choose the recipient or the size (the message count, the output length)?
- **Sad-path inputs:** a request with the maximum recipients; repeated requests below the rate limit but above the budget; a size parameter at its maximum; a loop that calls the paid API on each failure.
- **Evidence for confirmed:** the handler, the paid call, the absence of a budget or cap, and the number of paid calls one request can cause. Do not call the real service. Use a stub and count calls.
- **Not a finding:** spend the principal pays for and controls; a cost the platform caps with a documented hard budget that the repository shows.
- **CWE:** CWE-770; CWE-799 for missing frequency control.

### RX-10 Amplification and reflection

- **What fails:** a small request causes a large response or a large number of messages, and the response goes to a victim address or to many recipients.
- **Where to look:** connectionless services (discovery, query, status, name look-up); replies sent before the source proves its address; fan-out of one message to many recipients, rooms or subscribers; notification and webhook fan-out; recursive resolution that makes many outbound requests per inbound request.
- **Questions:**
  - What is the ratio of response bytes to request bytes before the source is verified?
  - Can the attacker forge the source address (datagram transport)?
  - Is the fan-out per request bounded, and by what?
- **Sad-path inputs:** the smallest valid request that gets the largest reply; a request that names a large list; a source address that is not the sender; a message sent to the largest group.
- **Evidence for confirmed:** the reply path, the measured byte ratio on loopback with a local client, and the absence of a source check or size cap. Do not send forged packets to any real address.
- **Not a finding:** a reply that is not larger than the request; a service reachable only on a private link that the repository restricts.
- **CWE:** CWE-406 (insufficient control of network message volume); CWE-405 (class-level).

### RX-11 Retry storms and feedback loops

- **What fails:** failure causes retries that make the failure worse, or one failure multiplies across layers.
- **Where to look:** retry loops without back-off or jitter; retries at several layers (client, proxy, service, queue); reconnect loops; cache expiry that makes all clients refresh at once; redelivery of failed messages without a limit.
- **Questions:**
  - What is the delay formula? Does it grow? Does it have jitter and a cap?
  - Can an attacker cause the first failure on purpose?
- **Sad-path inputs:** a dependency that returns an error for every call; a restart of all clients at once; a poison input that always fails.
- **Evidence for confirmed:** the retry code, the missing bound or back-off, and a fake-clock test that counts attempts. The attacker must be able to start the failure.
- **Not a finding:** retries bounded with back-off, where the attacker cannot start the failure.
- **CWE:** CWE-400 (class-level); CWE-834 for loops without a bound.

## Variant search

When you find one resource-exhaustion failure:
1. **Same sink.** List every caller of the unbounded reader, decoder, regex or allocator.
2. **Same dimension.** For each input dimension (length, count, depth, ratio), list every place that reads it and whether a cap applies.
3. **Same pool.** List every code path that takes a slot from the same pool, and whether each releases it on error.
4. **Same key.** If a limiter key is wrong, list every limiter that builds its key the same way.
5. **Same engine.** If one pattern is ambiguous, list all patterns with the same shape.

## Chain primitives

This domain often **gives**:
- a crash or restart of a process, which resets in-memory security state (rate-limit counters, caches, one-time values);
- delay of a peer or worker, which widens a race window or a time-out;
- filled disk or log space, which stops audit logging.

This domain often **needs**:
- an entry that a low-trust principal can reach (from authn or the API surface);
- knowledge of a limit or a pool size (from configuration or error messages);
- a way to start a failure for retry storms (from any domain).

## Verification notes

- **Shared impact.** An availability claim must show that another principal, or the service as a whole, loses service. Self-impact is not a finding. Record the measured effect on a second principal.
- **Do not overstate.** "Slow" is not denial of service. Report measured degradation. A crash of a shared process by a low-trust actor is a stronger claim than a delay.
- **E1 is usually enough** for RX-04, RX-05, RX-07, RX-09 and RX-11 when the missing cap, timeout, key or budget is plain in source, and no external layer decides. Examples: a collection that grows per request with no removal; a slot taken and not released on an error path; a limiter key that is a client header; a paid call with no budget; an unbounded retry loop the attacker can start. The waiver must name every layer checked (framework defaults, proxy limits in the repository, body-size settings).
- **E3 is required** for RX-01, RX-02 and RX-03. The cost depends on the library or engine, which E1 cannot read. Use a bounded local test: run at size n, 2n and 4n with small n; check that time or memory grows faster than linear; stop at a hard limit. A result that grows linearly is rejected.
- **E3 is required** for RX-08 and RX-06 claims about relative cost. Show the shared pool and the delay with a small pool and short jobs.
- **E3 is required** for RX-10. Measure the response and request sizes on loopback. The ratio must be above one before source verification.
- **Bounded tests only.** Use small inputs, a resource limit set by the harness (time limit, memory limit, process limit) and a local process. Never run load against a live or shared system. If a claim needs load to prove, mark it `needs-validation` with a reproduction plan.
- **Severity examples:**
  - critical – an unauthenticated request of small size crashes or hangs the only instance of a service that many tenants share, and it repeats at will (only with E3 evidence);
  - high – a low-trust actor repeatedly crashes a shared service, or blocks every other principal's work; unbounded spend through an unauthenticated endpoint;
  - medium – a delay of other principals that needs sustained effort; a small amplification ratio above one; unbounded growth that an authenticated user triggers and a restart clears;
  - low – a cost that only slows the attacker's own tenant, or needs a large effort for a small effect;
  - informational – a missing cap that a pinned layer in the repository already covers (record as hardening).

## Fix patterns

- **Cap before work.** Check size, count and depth before allocating or parsing. Reject over-limit input with an error.
- **Stream with limits.** Decode and decompress as a stream, with a cap on total output, a ratio limit, a nesting limit and an entry-count limit. Stop at the first limit.
- **Linear-time matching.** Use an automaton-based regular-expression engine for untrusted subjects. Or rewrite the pattern to remove ambiguity, and cap the subject length.
- **Bounded structures.** Give every map, cache and queue a size bound and an eviction or rejection rule.
- **Timeouts and release.** Set connect, read, write, idle and total timeouts, and a deadline on each job. Release slots in scope guards or `finally` blocks.
- **Cost-based limits.** Count items, bytes and seconds, not only requests. Key limits on the principal that pays. Check before the expensive step.
- **Cheap first.** Verify identity or a return address (cookie, token) before expensive work. Keep unverified replies no larger than the request.
- **Budgets.** Give each paid call a budget per principal and in total, with a hard stop.
- **Retry discipline.** Use exponential back-off with jitter, a cap, a retry budget, and one layer that owns retries.
- **Looks right but is not:** checking `Content-Length` only (chunked bodies skip it); checking size after reading the whole body; a ratio check after full decompression; limiting compressed size only; a limit on request count when one request holds many items; a limit per source address only; a timeout on connect but not on read; a regex timeout that does not stop the matching thread; catching an out-of-memory error and continuing; a client-side limit.

## Regression tests

- **Boundary tests:** input at the limit passes. Input at the limit + 1 fails with an error. Test size, count and depth.
- **Growth test:** for each risky function, run at n and 2n, and assert that the ratio of cost stays under a fixed bound. Keep n small.
- **Slot release test:** inject an error at each step after a slot is taken, and assert that the pool returns to full.
- **Fairness test:** two principals share a small pool. The first submits many jobs. Assert that the second job starts within a bound.
- **Amplification test:** for each unauthenticated reply, assert that response size ≤ request size until the source is verified.
- **Retry test:** use a fake clock and a failing dependency. Assert that attempts follow the back-off formula and stop.
