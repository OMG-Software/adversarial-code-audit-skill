# Domain: Concurrency

## Scope

- **Load when:** more than one thread, task, request, process or node can touch the same state, and that state has security meaning. Signs: locks, atomics, thread pools, async handlers with `await`, worker queues, transactions, version columns, distributed locks, leases, leader election, global mutable objects, thread-local storage, shared caches, object pools, one-time values (tokens, codes, invites, nonces).
- **Covers:** check-then-act on security state; double use of one-time values; lost updates and data races on logic state; store isolation; state shared between principals; cancellation and partial completion; lock misuse; reentrancy; consensus and leader-election errors inside one trusted cluster; rules for deterministic reproduction.
- **Hand off to:**
  - `domain-authz.md` – races that change an authorization decision (AZ-09). Use this file for the mechanism and the reproduction rules.
  - `domain-financial.md` – double spend, balance races and order races. Financial owns the money invariant.
  - `domain-memory-safety.md` – a race that corrupts memory. This file covers logic races only.
  - `domain-kernel.md` – kernel locking, double fetch and reference-count races.
  - `domain-filesystem-process.md` – file TOCTOU, symlink races and signal handlers.
  - `domain-messaging.md` – duplicate delivery, ordering and replay between producers and consumers.
  - `domain-federation.md` – peers with independent operators. This file covers one trusted cluster only.
  - `domain-data-lifecycle.md` – tenant data in cached copies, indexes and backups.
  - `domain-resource-exhaustion.md` – starvation by volume. This file covers the lock design error.
  - `domain-business-logic.md` – workflow rules that are not about timing.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Atomic decision:** The check of <security state> and the action that relies on it happen as one atomic step with respect to every concurrent writer.
2. **Single use:** <one-time value> is accepted at most once, for any number of parallel requests, across all processes and nodes.
3. **No lost update:** Every concurrent update to <security-relevant state> is applied or rejected. None is overwritten without notice.
4. **Visibility:** A change to <security flag or grant> reaches every reader within <documented window>.
5. **Separation:** State created for <principal A> is never readable by <principal B> through a shared object, cache, pool, or thread-local or task-local storage.
6. **Cancellation:** When <operation> is cancelled, times out or fails midway, the state still satisfies the invariants, and every lock and resource is released.
7. **Liveness:** No principal can hold <lock, lease or slot> long enough to block others. Lock order prevents deadlock.
8. **Single leader:** At most one node acts as <leader or owner> of <resource> at a time. A stale leader cannot write.

## Recon additions

Add these to `domain-notes.md` under a heading "Concurrency model". Keep it short.

1. **Runtime model.** Threads, event loop, processes, tasks, actors. Where a context switch can happen (each `await`, blocking call and callback). How many instances run. An in-process lock does not protect two instances.
2. **Shared state table.** Columns: state | where | writers | readers | guard | security meaning. Include globals, singletons, caches, pools and counters.
3. **Check-then-act table.** Columns: check location | act location | guard between them (lock, transaction, constraint, atomic operation, none) | gap.
4. **One-time values.** Every token, code, invite, nonce, coupon and idempotency key: where it is stored, how it is marked used, whether the mark is atomic.
5. **Store isolation.** Database engine, isolation level, transaction boundaries, unique constraints, row locks, version columns, distributed locks, fencing.
6. **Cluster coordination.** Leader election, leases, quorum size, clock source, membership changes, epochs. Say whether one operator runs all nodes.
7. **Context carriers.** Thread-local and task-local storage, singletons, pools, memoised functions.
8. **Test hooks.** Existing race detectors, stress tests, injectable clocks.

## Lead searches

Adapt the patterns to the language. The language file adds primitives and framework names.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| Concept: a read of state, then a write of the same state in a later statement, with no lock, transaction or conditional write between them | Check-then-act (CC-01) | A single-threaded run-to-completion handler has no gap. Check for `await` or I/O between the two steps. |
| `(used\|consumed\|redeemed\|claimed\|revoked\|expired\|spent)` read in one statement and set in another | One-time value used twice (CC-02) | A conditional update that checks the affected-row count is safe. |
| `exists\|find_or_create\|get_or_create\|upsert`, or a query followed by an insert on the same key | Missing atomicity or unique constraint (CC-01, CC-04) | A unique index may close the gap. Read the schema. |
| `(global\|static\|singleton\|shared\|class_var)` mutable map, list, counter, buffer or flag | Unsynchronised shared state (CC-03, CC-05) | Read-only after start-up is safe. Check how the object is published. |
| `thread_?local\|ThreadLocal\|task_?local\|AsyncLocal\|ContextVar`; `(cache\|memo\|lru\|ttl)` with a key built without a principal or tenant | State that survives between requests, or a cross-principal leak (CC-05) | Check where state is reset, including the error path. The cached value may be public. |
| `(atomic\|volatile\|compare_?and_?(swap\|set)\|memory_?order\|relaxed)` | Weak ordering or non-atomic compound operations (CC-03) | A relaxed counter used only for metrics is not a lead. |
| Lazy initialisation: `if (x == null\|None\|nil)` then assignment, with the lock only inside | Double-checked locking (CC-03) | A correct lazy-init primitive is safe. |
| `(lock\|mutex\|synchronized\|semaphore\|flock\|advisory)`; `try_?lock\|lock_?timeout` | Lock inventory; fail-open on lock failure (CC-07) | Compare to the shared state table. Read what happens when the lock is not acquired. |
| Lock key built from request data; lock held across I/O, callback or `await`; `(emit\|notify\|callback\|listener\|hook)` inside a state update | Attacker-held lock (CC-07); reentrancy (CC-08) | |
| `(cancel\|abort\|timeout\|deadline\|context\.Done\|finally\|defer\|drop\|using)` near multi-step state changes | Partial completion (CC-06) | Check that cleanup also runs on cancel. |
| `(spawn\|go func\|Thread\(\|create_task\|submit\|detach\|fire_?and_?forget)` inside request handlers | Work that outlives the request or its principal (CC-06) | |
| `(leader\|lease\|quorum\|election\|heartbeat\|fencing\|epoch\|term\|raft\|paxos\|etcd\|zookeeper\|consul\|redlock)` | Cluster coordination (CC-09) | A library used with default settings still needs the Recon check. |

## Attack classes

### CC-01 Check-then-act on security state

- **What fails:** code reads a security state, decides, and acts later. Another request, thread or process changes the state between the two steps. The action uses the old decision.
- **Where to look:** membership or permission check, then action; "if not exists, create" for names, emails and keys; quota check, then deduct; status check, then transition (`pending` to `paid`); check in a handler, action in a queued job; any `await`, I/O or callback between check and act.
- **Questions:**
  - Is there one atomic step: a conditional write, a lock over both steps, a unique constraint, or a transaction at an isolation level that blocks the anomaly?
  - Do all writers use the same lock on the same object?
  - On an event loop, is there a suspension point between check and act? One thread is not atomic across `await`.
  - Does the isolation level allow write skew (two transactions check one rule and write different rows)?
- **Sad-path inputs:** N identical requests in parallel (2, 10, 100); two conflicting requests (revoke and use); a request that stalls between check and act; the same action through two entry paths.
- **Evidence for confirmed:** the check, the act, the missing atomicity, and a forced schedule that gives the wrong outcome (E3).
- **Not a finding:** both steps run in one serialisable transaction or one conditional write; only the acting principal can change the state, so there is no victim; a run-to-completion handler with no suspension point.
- **CWE:** CWE-367 (time-of-check time-of-use race condition, base); CWE-362 (class-level) when the root cause is missing synchronisation and not a check-act gap.

### CC-02 One-time value used more than once

- **What fails:** a value that must work once is accepted several times when requests run in parallel or on different nodes.
- **Where to look:** reset and verification tokens; one-time passcodes and recovery codes; invite codes; coupons; refresh-token rotation; anti-replay nonce stores; idempotency keys; download-once links; "claim" and "vote once" actions; counters with a limit (attempt limits, quotas).
- **Questions:**
  - Does the code mark the value used by one atomic conditional operation (conditional update with an affected-row check, delete-and-return, set-if-absent, compare-and-swap)?
  - Does the mark come before the effect? If the mark comes after, two requests can both pass the check.
  - Is the store shared by all instances? An in-memory set is not.
  - Do two parallel refreshes with one rotation token both succeed? Is reuse detected?
  - Does the nonce store evict entries? Then a replay after eviction passes.
  - Does a failure path unmark the value after a side effect already happened?
- **Sad-path inputs:** 2 to 100 parallel redemptions of one value; redemption on two nodes; a retry after a timeout; redemption at the expiry boundary; a restart that clears an in-memory store.
- **Evidence for confirmed:** a parallel run, with a barrier at the check, where more than one request has the effect (E3). Count the effects, not the status codes.
- **Not a finding:** the second success returns the same result with no extra value (true idempotency); a unique constraint rejects the second effect.
- **CWE:** CWE-362 (class-level). The specific weakness is a single-use action that the code does not enforce. No narrower entry was checked.

### CC-03 Data races and lost updates on in-process state

- **What fails:** threads read and write shared logic state without correct synchronisation. Counters and limits are wrong. A revocation flag is not seen. A half-built object is read. The check and the use see different values.
- **Where to look:** global counters (rate limits, quotas); maps and sets changed by several threads; flags such as `revoked` and `initialised`; double-checked locking; compound operations on "thread-safe" containers (`contains` then `put`); weak memory ordering; objects published before they are fully built.
- **Questions:**
  - Which lock or atomic protects each shared variable? Does every access use it, including reads?
  - Is each compound operation atomic as a whole?
  - Does a security decision read state outside the lock?
  - Does the code read a value twice and assume both reads match?
- **Sad-path inputs:** parallel increments; parallel add and remove; a read during a write; many threads at start-up.
- **Evidence for confirmed:** a thread-sanitizer or race-detector report on the logic state, plus a stress test where the final value or the security effect is wrong (E3). For a security claim, show the exceeded limit or the stale flag.
- **Not a finding:** a race on a metric; state confined to one thread; an immutable object published safely; a lock the hunter did not read.
- **CWE:** CWE-362 (class-level); CWE-567 (unsynchronized access to shared data in a multithreaded context); CWE-820 (missing synchronization); CWE-609 (double-checked locking).

### CC-04 Store isolation: transactions, constraints and distributed locks

- **What fails:** several processes work on the same record in a database, cache, object store or file. A missing transaction, a weak isolation level, a missing constraint or a weak lock lets them interleave.
- **Where to look:** read-then-write in an ORM; autocommit per statement; read-committed isolation with the rule checked in application code; write skew ("at least one admin remains", "total stays below the limit"); version columns the code does not check; distributed locks whose lease expires during the work; locks without a fencing token; cache-aside fills that write a stale value after an invalidation; decisions read from a lagging replica.
- **Questions:**
  - Which constraint or conditional write protects the invariant when two transactions run together?
  - Is the whole read-decide-write sequence in one transaction, with a retry?
  - If a lease expires while the holder still works, does the store reject the late write (fencing token)?
  - After an invalidation, can a slow reader write the old value back to the cache?
- **Sad-path inputs:** two concurrent transactions on one row set; lease expiry during a pause; replica lag; failover during a transaction.
- **Evidence for confirmed:** a run on the same engine and isolation level as production, with a barrier between read and write, that shows the broken invariant (E3). A different engine does not prove the claim. If the isolation level is set outside the repository, the finding is `needs-validation`.
- **Not a finding:** serialisable isolation with retry; a unique constraint or conditional update that blocks the second write.
- **CWE:** CWE-362 (class-level); CWE-367 when the gap is between a check and a use.

### CC-05 State shared between principals

- **What fails:** data of one principal becomes visible to another through a shared mutable object.
- **Where to look:** globals and singletons that hold request data; thread-local storage not cleared on pooled threads; context storage that follows the thread and not the task; cache keys without principal or tenant; pooled connections that keep session settings (role, tenant); reused buffers and object pools; parsers or formatters shared across requests; memoised functions whose output depends on the principal.
- **Questions:**
  - Is the principal or tenant part of every cache key whose value depends on it?
  - Is per-request state reset at the start and the end, including the error path?
  - Does the pool reset session state before it hands out an object?
  - Does context follow the task across `await` points and thread switches?
- **Sad-path inputs:** two principals that alternate on one worker; an error in the first request; a cancelled request.
- **Evidence for confirmed:** principal B receives data of principal A in a test. A leak without timing can be E1 with a waiver, when the cache key or shared object plainly lacks the principal and no other layer separates the data. A leak that needs interleaving needs E3.
- **Not a finding:** the cached value is public by design; a wrapper adds the principal to the key.
- **CWE:** CWE-488 (exposure of data element to wrong session); CWE-567 or CWE-362 when unsynchronised sharing is the root cause.

### CC-06 Cancellation, timeout and partial completion

- **What fails:** an operation stops midway (disconnect, cancellation, timeout, exception, process kill) and leaves state that breaks an invariant. Examples: a grant without its audit record; a debit without the credit; a lock never released; a half-created resource that others can reach; a raised privilege never dropped.
- **Where to look:** async handlers with several `await` points; cleanup in `finally`, `defer`, destructors or `using` blocks; cancellation tokens that code ignores or catches; gateway timeouts while the work continues; multi-step provisioning; privilege raise and drop blocks; detached background tasks; retry wrappers around non-idempotent calls.
- **Questions:**
  - If the operation stops between step k and step k+1, what is the state? Who repairs it?
  - Does cleanup run on cancel as well as on error? Can cleanup itself be cancelled?
  - Does a timed-out operation keep running and apply its result later?
  - Is the retried operation idempotent?
  - Can the attacker choose the cancellation point (disconnect at a chosen moment)?
- **Sad-path inputs:** a disconnect after each `await`; a timeout at each step; a process kill between commit and acknowledgement; an exception inside cleanup.
- **Evidence for confirmed:** fault injection at the named step, and a state dump that shows the broken invariant (E3). E1 is enough only for a plain error path with no cleanup and no runtime cancellation semantics.
- **Not a finding:** the partial state is harmless, or a reconciler repairs it before use; the attacker harms only its own data.
- **CWE:** CWE-459 (incomplete cleanup); CWE-460 (improper cleanup on thrown exception).

### CC-07 Lock misuse: ordering, scope and attacker-held locks

- **What fails:** locks deadlock, are missing on some path, or can be held by an attacker. A failed `try_lock` counts as success. A lock name comes from user input, or one lock serves all tenants.
- **Where to look:** nested locks taken in different orders; locks held across I/O, callbacks or `await`; named locks, advisory-lock keys and lock files built from request data; `try_lock` with a fallback that proceeds; missing unlock on an error path; read-to-write lock upgrades; priority inversion in firmware (see `domain-embedded.md`).
- **Questions:**
  - Is there one documented lock order, and do all paths follow it?
  - What does the code do when it cannot get the lock?
  - Can a low-trust principal choose the lock key, or hold the lock for long (slow client, long query)?
  - Does one tenant's use of a shared lock block another tenant?
- **Sad-path inputs:** two locks taken in opposite orders; a client that stops reading while the server holds a lock; a lock key that collides across tenants.
- **Evidence for confirmed:** for deadlock, a deterministic schedule or a lock-order tool report (E3). For an attacker-chosen lock key, the source path can be E1, because it is a logic fault with no timing. A denial-of-service claim must show that a shared service blocks.
- **Not a finding:** lock-order inversion between paths that cannot run together; a short, bounded hold time; a deadlock only the operator can trigger.
- **CWE:** CWE-833 (deadlock); CWE-412 (unrestricted externally accessible lock); CWE-413 (improper resource locking); CWE-667 (improper locking, class-level).

### CC-08 Reentrancy and callback interleaving

- **What fails:** code runs again (through a callback, event handler, observer, nested event loop or hook) while an earlier call is midway through an update. The second call sees a broken invariant.
- **Where to look:** callbacks and hooks called while a structure is only partly updated; event emitters; plugin hooks; recursive lock acquisition; message loops that process events inside a handler; callbacks that change the collection under iteration; functions with static buffers used in concurrent code.
- **Questions:**
  - Which calls leave the module while state is inconsistent? Can the callee call back in?
  - Does the code re-validate its state after the callback?
  - Can a callback change authentication or permission state during a check?
- **Sad-path inputs:** a callback that calls the same API; a callback that removes the object being processed; a hook that throws.
- **Evidence for confirmed:** a test callback that re-enters, and the broken invariant it shows (E3). For logic state, E1 can be enough when code fixes the call order and no scheduler is involved. For memory corruption, use `domain-memory-safety.md`.
- **Not a finding:** the callback is operator code only.
- **CWE:** CWE-663 (use of a non-reentrant function in a concurrent context); CWE-1265 (unintended reentrant invocation of non-reentrant code via nested calls).

### CC-09 Consensus and leader-election errors in a trusted cluster

- **What fails:** nodes of one trusted cluster disagree on who may act (leader, lock owner, primary), or commit conflicting state. Two nodes lead at once (split brain). A stale leader keeps writing. A revocation reaches nodes at different times. A node decides from a stale replica.
- **Where to look:** custom election code; leases that rely on clocks; storage that does not check an epoch or fencing token; a quorum smaller than a strict majority; reads from any replica for security decisions; snapshot restore that brings back revoked state; followers that accept writes; term or epoch values taken from the client.
- **Questions:**
  - What makes a leader legitimate? Does the resource reject writes from an older epoch?
  - Does lease expiry allow for clock skew, pauses and clock jumps?
  - Is the quorum a strict majority of the configured membership?
  - Does a node that rejoins or restores from a snapshot undo a revocation?
- **Sad-path inputs:** a partition between leader and followers; a leader paused past its lease; a clock jump; two nodes with one ID; a restore from an old snapshot.
- **Evidence for confirmed:** a harness with a controlled clock and controlled message loss that shows two leaders accepting writes, or the undone revocation (E3). A formal model of the protocol supports the claim, but it is not E3 for the code.
- **Not a finding:** a documented availability-over-consistency choice that touches no security state; a standard library used as designed; an attacker that must be an operator or sit inside the cluster.
- **CWE:** no checked entry fits. Name the weakness in words (split brain, missing fencing). Use CWE-362 (class-level) only as a last resort.

## Variant search

When you find one concurrency failure:
1. **Same state.** List every reader and writer of the state. Compare their guards. Every unguarded or differently guarded access is a variant lead.
2. **Same gap.** Build a table of every check-then-act of the same shape (for example every "check quota, then deduct"). Mark which ones have an atomic step.
3. **Same kind of value.** List every one-time value kind. Check each for an atomic mark (CC-02).
4. **Same lock.** List every path to the state that skips the lock used elsewhere.
5. **Same runtime.** If an `await` between check and act causes the gap, list every handler with that shape.
6. **Same history.** If an earlier fix added a lock or constraint at one site, check the sibling sites and the other instances.

## Chain primitives

This domain often **gives**:
- repeated use of a one-time value (extra credit, repeated invites);
- a bypassed limit or quota (attempt limits that other defences rely on);
- action with a revoked or stale grant;
- another principal's cached data (identifiers, tokens, internal URLs);
- in a cluster, writes accepted by a stale leader.

This domain often **needs**:
- the ability to send parallel requests to one target;
- the identifier of the target value (from enumeration or disclosure);
- a valid session of some principal (from authn);
- for CC-09, a network position inside the cluster (an external assumption).

## Verification notes

- **E3 is required** for `confirmed` on every race claim: CC-01, CC-02, CC-03, CC-04, CC-08 and the deadlock and cluster parts of CC-07 and CC-09. Without T2, these claims are `needs-validation` with a reproduction plan.
- **E1 can be enough** (with a waiver that names every layer checked) for: CC-05 leaks without timing; CC-07 attacker-chosen lock names; CC-06 missing cleanup on a plain error path; CC-08 on logic state with a fixed call order.
- **Deterministic reproduction rules.**
  - A race that you saw once is not E3. When the schedule is forced, the test must give the wrong result on every run. After the fix, it must give the right result on every run.
  - Force the schedule at the gap with a barrier or latch that holds all actors between check and act. Add the barrier or a delay only in a copy of the code in scratch.
  - Use a fake clock for leases and timeouts.
  - Add a control run with the fix, or with a lock around check and act. It must give the right result.
  - Count effects, not status codes. Two "ok" responses prove nothing until the state shows two effects.
  - Tools, where the language supports them: a thread sanitizer (`-fsanitize=thread`), the Go race detector (`go test -race`), `loom` for Rust, `jcstress` for Java, `rr record --chaos` on Linux, and Valgrind `helgrind`. A tool report on logic state supports the claim. The forced-schedule test proves it.
  - For clusters, use a deterministic simulation on loopback inside the sandbox, with injected partitions and a fake clock. Never test a live cluster.
- **Unit test first, then reachability.** A network race has a narrow window. A unit test with a barrier proves the missing atomicity. Then show that a real request path reaches the same gap, and state the window width. A narrow window lowers likelihood. It does not remove the finding.
- **Reachability checks.** Confirm that the runtime is concurrent: one thread with no suspension point has no race. Confirm that the isolation level and lock settings you tested are the defaults.
- **False-positive checks.** Thread confinement; immutable state; a serial executor per entity; a database constraint; an idempotent effect; a window that only harms the attacker.
- **Severity examples:**
  - critical – a race lets an unauthenticated actor reuse a single-use recovery token and take over arbitrary accounts; a stale leader accepts writes that other nodes trust as signed state;
  - high – a parallel request passes a single-use or limit check many times with a real effect on other users (CC-02); one user reads another user's cached data (CC-05); a revoked admin keeps acting on a stale decision;
  - medium – a bypass of a low-value quota; a revocation gap with a narrow window; a lock held by a low-trust client that blocks one feature;
  - low – inconsistent state with no security effect; a deadlock that a user causes only on its own resources;
  - informational – a race that needs a privileged position, or only serves as a chain link.

## Fix patterns

- **Make check and act one atomic step.** Use a conditional write (`UPDATE … WHERE state = 'x'`, then check the affected-row count), compare-and-swap, a unique constraint, a row lock, or a serialisable transaction that retries the whole decision.
- **Consume one-time values first.** Mark the value used by an atomic operation (delete-and-return, set-if-absent) before the effect. Use a store that all instances share. Keep entries until the value expires.
- **Confine state.** Give each entity one serial executor, or pass messages.
- **Scope locks.** One lock protects each variable for all readers and writers. Hold it briefly, not across I/O, callbacks or `await`. Fix one lock order. Build lock keys on the server.
- **Fence leaders and leases.** Use a monotonic epoch that the resource checks, a strict majority quorum, and a safety margin on expiry.
- **Clean up on every exit.** Use structured concurrency, `finally`, `defer` or RAII. Make operations idempotent.
- **Key caches by principal.** Put the principal and tenant in every key whose value depends on them. Reset per-request state in a `finally` block.
- **Re-check at the last point.** Check the version or state again just before the effect.
- **Looks right but is not:** an in-process mutex when several instances run; a lock around the check only; a sleep or retry that makes the window "small"; checking twice; a time-limited lock with no fencing; read-committed isolation with the rule in application code; catching a duplicate-key error and still applying the effect; setting the "used" flag after the effect; a plain boolean as a thread signal; a thread-safe container with a separate `contains` and `put`; per-instance rate-limit memory behind a load balancer.

## Regression tests

- For each fixed finding, a **barrier test**: N parallel actors held at the gap, then released. Assert that exactly one succeeds. Assert the final state, not only the status codes.
- A control run without the fix, to show that the test can fail.
- For one-time values, a test that redeems one value from two instances.
- For cancellation, a **fault-injection test** that cancels at each suspension point and asserts the invariant.
- For caches and pools, a test where two principals alternate on one worker, with an error in the first request.
- A race detector or thread sanitizer in the continuous-integration run, with failures as errors.
- A lock-order check in tests.
- For clusters, a simulation with a fake clock that pauses the leader past its lease and asserts that its late write is rejected.
