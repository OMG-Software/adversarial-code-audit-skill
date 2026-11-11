# Domain: Sandboxes and untrusted code execution

## Scope

- **Load when:** the product runs code, scripts, expressions or templates that a lower-trust principal wrote, and relies on a boundary to contain them. Signs: plugin, mod or extension runtimes; embedded interpreters (Lua, JavaScript, Python, WASM and others); expression and rule languages; user-authored templates; formula engines; "run user code" features; code execution tools for AI agents; serverless or edge isolates; OS-level sandboxes that the product configures (seccomp, namespaces, containers, AppContainer, platform sandbox profiles).
- **Covers:** the host API surface exposed to guest code, language-level escapes through reflection and object graphs, deny-list sandboxes, resource limits, data and calls that cross the boundary, isolation between guests, OS-level sandbox configuration owned by the product, guest lifecycle (load, update, unload), the permission model, and consistency between interpreter and JIT tiers.
- **Hand off to:**
  - `domain-injection.md` – attacker input that reaches an evaluator **by accident** (concatenated into a template or expression). Sandbox owns evaluators that run user-authored code **by design**.
  - `domain-memory-safety.md` – native memory defects in the interpreter, JIT or host functions. Sandbox owns the logical boundary; memory-safety owns the corruption.
  - `domain-supply-chain.md` – how plugins and mods are distributed, signed and updated.
  - `domain-ai-llm.md` – how a model decides to run code. Sandbox owns where that code runs.
  - `domain-client-trust.md` – trust in client-side mods. Sandbox owns server-side and host-side execution.
  - `domain-filesystem-process.md` and `domain-cloud-deploy.md` – general process and container hardening that is not the product's own sandbox.
  - `domain-resource-exhaustion.md` – general limits. Sandbox keeps limits on guest execution (SB-04).

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Capability:** Guest code can reach only the host functions and objects in <allow-list>, and through them only the resources the guest's owner may use.
2. **No reflection escape:** No object reachable by guest code gives a path to host internals (classes, constructors, module loaders, global scope, native functions) outside the allow-list.
3. **Limits:** Guest execution stops within <CPU, memory, time, output, recursion> limits, and a guest that hits a limit cannot leave the host in a bad state.
4. **Boundary data:** Every value that crosses from guest to host is validated by the host as untrusted input, every time it is read.
5. **Isolation:** One guest cannot read or change another guest's state, or the host's state, except through documented interfaces.
6. **Lifecycle:** A guest's rights at run time equal the rights its owner approved, and nothing the guest registered remains active after it is unloaded.
7. **Configuration:** The OS-level sandbox that the product sets up applies the documented restrictions on every platform and in every launch path.

## Recon additions

Add a heading "Sandbox model" to `domain-notes.md`:

1. **Guests.** Each kind of untrusted code: who writes it, how it gets in (upload, marketplace, config, chat, model output), and who is affected when it runs (only its author, other users, the operator).
2. **Runtimes.** The interpreter, engine or isolate, its version, and the sandbox mode used (for example a restricted environment, a separate process, a WASM runtime, an OS sandbox).
3. **Host surface.** Every function, object, module and global the host exposes to guests, with file:line. Mark each as pure (no side effects), scoped (side effects limited to the guest's own data), or powerful (filesystem, network, process, database, other users).
4. **Limits.** CPU or instruction limits, wall-clock limits, memory limits, recursion limits, output limits, and where each is enforced.
5. **Isolation unit.** One runtime per guest, per user, per tenant, or shared.
6. **Permission model.** How permissions are declared, approved and enforced; defaults; how updates change permissions.

## Lead searches

| Search | A hit may mean | False-hit notes |
|---|---|---|
| Interpreter and engine creation: `new.*(Lua\|State\|Isolate\|Context\|Engine\|Interpreter\|Runtime\|Instance\|Sandbox)`, `luaL_newstate`, `vm\.`, `exec(`, `eval(`, `compile(`, `Function(`, `ScriptEngine`, WASM instantiate calls | Guest execution point | Confirm the code is user-authored by design (else injection). |
| Host registration: `register\|expose\|bind\|setglobal\|set_global\|global\[\|define_function\|export_function\|addFunction\|import_object\|linker\.define` | Host surface (SB-01) | List every registration. |
| Standard-library loading in interpreters: `openlibs\|luaL_openlibs\|require\|import\|loadlib\|package\.\|os\.\|io\.\|debug\.\|ffi` | Powerful modules given to guests (SB-01) | Some hosts remove them after loading. Read the whole setup. |
| Deny lists: `blacklist\|denylist\|blocked\|forbidden\|disallow\|__\w+__\|constructor\|prototype\|getClass\|forName` in filtering code | Deny-list sandbox (SB-03) | |
| Limits: `timeout\|deadline\|instruction\|step\|fuel\|gas\|memory_?limit\|max_?depth\|interrupt\|set_?hook\|terminate` | Limit enforcement (SB-04) | Check where and how often limits are checked. |
| Host functions that take pointers, offsets or lengths from guest memory | Boundary data (SB-05) | WASM and FFI hosts. |
| Shared caches, module registries, global tables across guests | Isolation (SB-06) | |
| `seccomp\|prctl\|unshare\|setns\|chroot\|pivot_root\|landlock\|sandbox_init\|AppContainer\|capabilit` | OS-level sandbox set-up (SB-07) | |
| Plugin manifest parsing, permission prompts, update handlers, unload hooks | Lifecycle and permissions (SB-08, SB-09) | |

## Attack classes

### SB-01 Powerful host surface

- **What fails:** the host gives guest code a function or object that reaches resources outside the guest's scope.
- **Where to look:** every registered host function and global; objects passed into the guest (request objects, database handles, loggers, configuration, file handles); standard-library modules left loaded; helper functions with broad parameters ("run query", "read file", "http get").
- **Questions:**
  - For each host function: which resources can it touch? Are its parameters bound to the guest's scope (its own files, its own tenant, its own data)?
  - Does any exposed object have methods or properties that reach more than the function intended (a "user" object whose session can be modified, a logger that writes files, a config object with secrets)?
  - Are dangerous modules (process, filesystem, networking, native loading, debug facilities) removed before the first guest code runs, on every code path that creates a runtime?
- **Sad-path inputs:** paths outside the guest's directory; IDs of other tenants; URLs to internal addresses; calls to host functions before set-up finishes.
- **Evidence for confirmed:** the registration, the reachable resource, and a guest script (benign marker action, for example reading a dummy file outside the guest scope) that shows access. E1 is enough when the host function clearly has no scope check; E3 when it depends on runtime behaviour.
- **Not a finding:** a powerful function available only to guests whose owner already has that power (for example an operator's own server scripts).
- **CWE:** CWE-250 (execution with unnecessary privileges); CWE-749 (exposed dangerous method or function).

### SB-02 Escape through reflection and object graphs

- **What fails:** guest code walks from an allowed object to host internals through language reflection, metadata or shared prototypes.
- **Where to look:** expression and template evaluators with object access; embedded scripting with host object binding; restricted modes of general-purpose languages; metatables, prototypes, class objects, constructors, module objects, stack frames, exception objects and error messages reachable from guest code.
- **Questions:**
  - From each object exposed to the guest, which other objects are reachable through attributes, prototypes, metatables, class references, constructors or exceptions?
  - Does the runtime's "restricted" or "sandboxed" mode claim to be a security boundary in its own documentation? Some do not (for example Node.js documents `node:vm` as not a security mechanism).
  - Do host objects shared with the guest share a prototype or metatable with host code, so that a guest change affects the host?
- **Sad-path inputs:** attribute access on exposed objects to reach class, constructor or module references; changes to shared prototypes or metatables; exceptions raised by the host and caught by the guest.
- **Evidence for confirmed:** a guest expression or script, in a local test, that reaches a host object outside the allow-list and performs a benign marker action. E3 is required: reflection paths depend on runtime behaviour.
- **Not a finding:** a reachable object that has no capability beyond the allow-list.
- **CWE:** CWE-94 (code injection) when the escape leads to host code execution; CWE-470 (unsafe reflection) when the guest selects classes or methods; CWE-1321 for prototype pollution of shared objects.

### SB-03 Deny-list sandboxes

- **What fails:** the sandbox blocks known-dangerous names or patterns instead of granting known-safe capabilities, and an equivalent path is not blocked.
- **Where to look:** source filters that scan guest code for keywords; attribute-name filters; AST filters; lists of forbidden modules or functions; string-based checks before evaluation.
- **Questions:**
  - Does the filter work on the text, the tokens, the syntax tree or the runtime access? Text filters miss encodings, concatenation and aliasing.
  - Does the list cover every alias, every equivalent function and every way to obtain a reference (indexing, string-to-name conversion, `getattr`-like functions)?
  - Does the evaluator expand or decode the code after the filter runs?
- **Sad-path inputs:** names built from concatenated strings; alternative syntax for the same access; Unicode identifiers where the language allows them; comments and whitespace inside tokens.
- **Evidence for confirmed:** the filter, the equivalent path it misses, and a local test with a benign marker action. E3.
- **Not a finding:** a deny list used as defence in depth behind a capability-based boundary that already blocks the path (hardening note).
- **CWE:** CWE-184 (incomplete list of disallowed inputs).

### SB-04 Missing or weak execution limits

- **What fails:** guest code consumes CPU, memory, time, recursion depth, output or host calls without a limit, and affects other guests or the host.
- **Where to look:** instruction counters and hooks; wall-clock timers; memory allocators given to the runtime; recursion limits; output buffers; limits on host calls (a guest that calls an expensive host function in a loop); behaviour after a limit is hit (is state rolled back, are locks released?).
- **Questions:**
  - Is each limit enforced inside long-running host functions and native calls, or only between guest instructions?
  - Can a guest block in a host call (I/O, a lock, a sleep) where the CPU limit does not count?
  - When the limit triggers, does the host clean up: release locks, close handles, reset shared state?
  - Is the limit per guest, or shared, so that one guest uses another's budget?
- **Sad-path inputs:** tight loops; deep recursion; large string or array growth; regular expressions with heavy backtracking inside the guest; repeated expensive host calls; a guest that catches the limit error and continues.
- **Evidence for confirmed:** a bounded local test showing the missing or bypassed limit and its effect on a second guest or on the host (for example a stuck worker). E3 for availability claims. Never run unbounded tests against shared systems.
- **Not a finding:** a guest that only slows its own execution, within the documented quota.
- **CWE:** CWE-770 (allocation of resources without limits or throttling); CWE-674 (class-level; uncontrolled recursion).

### SB-05 Data and calls across the boundary

- **What fails:** the host trusts values, memory or calls that come from the guest.
- **Where to look:** host functions that receive pointers, offsets and lengths into guest memory (WASM, FFI); host functions that read the same guest memory twice; values converted between guest and host types; callbacks from host into guest during a host operation (re-entrancy); objects shared by reference between guest and host.
- **Questions:**
  - Does each host function validate offsets and lengths against the guest's memory size, with overflow-safe arithmetic?
  - Does the host copy guest data once, then validate the copy? Or can the guest change memory between check and use?
  - Can a guest callback run while the host holds a lock or is half-way through an update?
  - Does a type conversion lose information (integer width, NaN, very large numbers, strings with embedded nulls)?
- **Sad-path inputs:** offset + length overflow; lengths past the memory end; memory changed by another guest thread during a host call; callbacks that call back into the host; values at type limits.
- **Evidence for confirmed:** the host function, the missing validation, and a local test with a sanitizer or a marker effect. E3 (these are memory, race or type claims).
- **Not a finding:** a runtime that bounds-checks every guest memory access by design, when the host uses only the runtime's checked accessors.
- **CWE:** CWE-367 for check-then-use on shared memory; CWE-1285 (improper validation of specified index, position, or offset in input); hand native corruption to memory-safety.

### SB-06 Isolation between guests

- **What fails:** one guest reads or changes another guest's data or behaviour.
- **Where to look:** runtimes shared across users, tenants or plugins; module caches; global tables; shared prototypes; persistent state between runs; caches keyed without the guest identity; temporary directories shared between guests.
- **Questions:**
  - Is a runtime instance reused for different owners? Is state reset between uses, completely?
  - Can a guest change a shared global, prototype or module that another guest uses?
  - Are files, caches and storage keyed by guest identity?
- **Sad-path inputs:** two guests from different owners run in sequence or in parallel; a guest that changes shared globals and a second guest that reads them.
- **Evidence for confirmed:** a local test with two guests showing the cross-guest read or change. E3.
- **Not a finding:** sharing between guests of the same owner, by design.
- **CWE:** CWE-653 (class-level; improper isolation or compartmentalization).

### SB-07 OS-level sandbox configuration

- **What fails:** the OS sandbox that the product sets up for guests is weaker than documented, or is not applied on some paths or platforms.
- **Where to look:** seccomp filters and their default action; namespace and mount set-up; capability dropping; file descriptors inherited by the sandboxed process; environment passed in; container options set by the product; platform sandbox profiles; Windows job objects and AppContainer settings; fallbacks when a sandbox feature is unavailable.
- **Questions:**
  - Is the filter an allow list with a deny default? Which risky calls does it allow?
  - Which host paths are mounted, and are they read-only?
  - Which descriptors and sockets does the child inherit?
  - What happens when the kernel or platform does not support the sandbox feature: does the product refuse to run guests, or run them unsandboxed?
- **Sad-path inputs:** platforms or kernels without the feature; launch paths other than the main one (debug mode, tests, CLI); guest processes that spawn children.
- **Evidence for confirmed:** the configuration, the missing restriction or fallback, and a guest action that shows it. E1 is enough for a fallback that runs unsandboxed when a feature is missing; E3 for claims about what a filter permits.
- **Not a finding:** a restriction missing in a documented developer-only mode that the production build cannot enable.
- **CWE:** CWE-250; CWE-636 (class-level) for unsandboxed fallback.

### SB-08 Guest lifecycle

- **What fails:** a guest keeps rights or effects outside its approved lifetime, or gains rights during an update.
- **Where to look:** load and initialisation order; timers, event handlers, hooks and callbacks that guests register; unload and hot-reload; update flows; disable and uninstall.
- **Questions:**
  - Does guest code run before its permissions are applied?
  - Are all registrations removed on unload? Can a callback run after unload (use-after-unload)?
  - Does an update change permissions without new approval?
  - Does disabling a plugin stop all of its background work?
- **Sad-path inputs:** a guest that registers many hooks then is unloaded; an update with a wider permission manifest; hot reload during an active callback.
- **Evidence for confirmed:** the lifecycle path and the effect after unload or after update. E3 when timing matters.
- **Not a finding:** documented behaviour that keeps data, not code, after unload.
- **CWE:** CWE-672 (class-level; operation on a resource after expiration or release) for use-after-unload; CWE-269 (class-level) for silent permission growth.

### SB-09 Permission model

- **What fails:** guests get permissions they did not declare, or that the owner did not approve, or approval can be bypassed.
- **Where to look:** manifest parsing; default permissions; permission checks inside host functions; permission prompts; capability tokens passed to guests; permissions inherited by child guests or spawned tasks.
- **Questions:**
  - Is each host function's permission checked at call time, against the calling guest's identity?
  - Can a guest obtain another guest's capability token or handle?
  - Are default permissions minimal?
  - Is the manifest the guest declares the same one the owner approved?
- **Sad-path inputs:** a manifest with unknown permission names; a call to a host function without the permission; a guest that passes its handle to another guest.
- **Evidence for confirmed:** the missing check and the call that succeeds without the permission. E1 is often enough.
- **Not a finding:** broad permissions that the owner explicitly approved.
- **CWE:** CWE-862 (class-level) for missing checks; CWE-863 (class-level) for wrong checks.

### SB-10 Interpreter and JIT consistency

- **What fails:** for audits of runtimes themselves: an optimised tier removes or changes a check that the interpreter performs, or the validator and the executor disagree.
- **Where to look:** bytecode or module validators; optimisation passes that remove bounds or type checks; tier-up and tier-down; assumptions cached by the JIT and invalidated on change.
- **Questions:**
  - Does the validator check the same properties that the executor relies on?
  - Is every removed check justified by a proof that holds after later changes to the object?
  - Do interpreter and JIT produce the same result for the same input?
- **Sad-path inputs:** inputs at type and range limits; objects whose shape changes after optimisation; differential tests between tiers.
- **Evidence for confirmed:** a differential test or a sanitizer report showing the inconsistency and its effect. E3. Hand native corruption to memory-safety.
- **Not a finding:** a performance difference with the same semantics.
- **CWE:** CWE-733 (compiler optimization removal or modification of security-critical code); CWE-436 (class-level; interpretation conflict). Use memory-safety CWEs for resulting corruption.

## Variant search

1. **Host surface table.** List every host function and object × resource reached × scope check × permission check. Every empty cell is a lead.
2. **Every runtime creation path.** Find every place a runtime or isolate is created (main, tests, CLI, debug, worker pools, hot reload). Check that each applies the same set-up and limits.
3. **Every exposed object type.** For each, walk the reachable object graph to its limit.
4. **Every boundary function.** For WASM and FFI hosts, list every function that reads guest memory and check validation and copy-once.
5. **Runtime documentation.** Read the runtime's own security notes. A mode that the runtime says is not a security boundary must not be used as one.

## Chain primitives

This domain often **gives**:
- code execution in the host process or with host privileges;
- access to other guests' data, or to host secrets and configuration;
- a stuck or crashed worker shared by many users;
- persistent code that runs after the user thinks it is removed.

This domain often **needs**:
- the ability to submit guest code (often any user, mod author or model output);
- a reachable powerful host function (from SB-01) or a reflection path (SB-02);
- a native defect in the runtime (memory-safety).

## Verification notes

- **Who writes the guest code?** Establish who can submit it. If only the operator can, most escapes are not boundary failures.
- **E1 is usually enough** for SB-01 (an unscoped powerful host function), SB-07 (an unsandboxed fallback), and SB-09 (a missing permission check).
- **E3 is required** for SB-02, SB-03, SB-05, SB-06 and SB-10, and for SB-04 availability claims. Use a local test runtime with benign marker actions (create a file in scratch, return a host value that the guest must not see). Never run guest escape tests on a shared host.
- **Runtime version.** Behaviour of reflection and restricted modes changes between versions. Record the version in the repository's lockfile or build. If the version is not fixed in the repository, the finding may be needs-validation.
- **Severity examples:**
  - critical – any user who can submit guest code runs code in the host process on a shared server;
  - high – a guest reads other users' data or host secrets; a guest escapes an OS sandbox to the service account;
  - medium – a guest stalls a shared worker pool until restart; a plugin keeps running after uninstall;
  - low – a guest learns host version or path information;
  - informational – a deny-list gap behind a capability boundary that holds.

## Fix patterns

- **Capabilities, not deny lists.** Start the runtime with nothing, then add only the functions the guest needs. Never load the full standard library and remove parts.
- **Scope host functions.** Bind each host function to the guest's identity and resources when the runtime is created, not by parameters the guest supplies.
- **Separate processes for strong isolation.** Use a process or VM boundary with an OS sandbox when guests are hostile. Use in-process restricted modes only when the runtime documents them as a security boundary.
- **One runtime per trust domain.** Do not reuse runtimes across owners. Reset completely, or create new.
- **Copy, then validate.** Copy guest data into host memory once, then validate the copy.
- **Enforce limits at the right layer.** Instruction or fuel counters, plus wall-clock limits that also cover host calls; clean up locks and state when a limit triggers.
- **Fail closed on sandbox set-up.** If a sandbox feature is unavailable, refuse to run guests.
- **Track registrations.** Record every hook and timer a guest registers, and remove all of them on unload.
- **Looks right but is not:** removing dangerous globals after the runtime is created (references may already exist); filtering source text for keywords; trusting a runtime mode its authors say is not a security boundary; setting a timeout only between guest instructions; reusing one interpreter "for performance".

## Regression tests

- For each host function: a guest test that calls it with out-of-scope arguments and asserts rejection.
- An object-graph test: from each exposed object, attempt known reflection paths and assert no host internals are reached.
- Limit tests: loops, recursion, memory growth, output growth and blocking host calls, each asserting termination and clean-up.
- Two-guest isolation tests: guest A changes shared state, guest B asserts it sees no change.
- Boundary tests for WASM or FFI hosts: offsets and lengths at and past the limits, with sanitizers on.
- Lifecycle tests: unload, then trigger every registered hook and assert none runs; update with a wider manifest and assert re-approval is required.
- Sandbox set-up tests on each supported platform, including the "feature unavailable" path.
