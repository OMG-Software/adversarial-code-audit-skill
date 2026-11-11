# Domain: Memory safety

## Scope

- **Load when:** the code has no automatic memory-safety guarantee and handles untrusted bytes, or crosses a boundary where the guarantee ends. Signs: C or C++ sources; `unsafe` blocks in Rust, Go, C# or Swift; native extensions for Python, Node or Java (JNI); FFI wrappers; custom allocators, pools and arenas; native codecs, parsers and protocol stacks; embedded interpreters; SIMD code and inline assembly.
- **Covers:** bounds errors; integer overflow, truncation and sign errors that feed sizes and indexes; use after free, double free and dangling references; type confusion; uninitialised memory; FFI and unsafe-block contracts; allocator and container misuse; undefined behaviour that optimisers use; format-string misuse; sanitizer and fuzzing guidance.
- **Hand off to:**
  - `domain-input-parsing.md` – format logic, parser differentials and deserialisation rules. This file covers the memory effect of a parser defect.
  - `domain-kernel.md` – user-copy, double fetch and object lifetime inside kernels and drivers.
  - `domain-embedded.md` – memory protection units, boot code and firmware image parsers.
  - `domain-concurrency.md` – logic races. This file keeps races that corrupt memory.
  - `domain-sandbox.md` – logic faults in interpreters, JIT and WASM hosts. Native defects in them belong here.
  - `domain-resource-exhaustion.md` – a huge allocation that only exhausts memory. Use this file when the allocation size also causes corruption.
  - `domain-crypto.md` – key lifecycle and wiping of secrets. This file covers the compiler removing the wipe (MEM-08).
  - `lang-*.md` – API lists, compiler flags and sanitizer options per language.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Bounds:** Every read and write through <buffer, index or pointer> in <function> stays inside the object, for every value of the attacker-controlled <length, count, offset or index>.
2. **Arithmetic:** Every size, count, offset or index that comes from <untrusted source> is computed without overflow, wrap, truncation or sign change before it is used for <allocation, copy or bounds check>.
3. **Lifetime:** No pointer, reference, iterator or view is used after its object is freed, moved, reallocated, reset or out of scope.
4. **Ownership:** Each allocation has one owner. The matching release routine frees it exactly once, on every path including errors.
5. **Type:** The code reads an object only as the type it holds. The code checks the tag, size or version field that selects the type before the cast.
6. **Initialisation:** No uninitialised byte is read, copied to an output, sent, or used in a decision.
7. **Boundary contract:** Across <FFI or unsafe boundary>, both sides agree on ownership, length, nullability, alignment, lifetime and threading. Safe callers cannot drive a safe wrapper into undefined behaviour.
8. **Defined behaviour:** No path reaches undefined behaviour that the compiler may use to remove a check or a wipe.

## Recon additions

Add these to `domain-notes.md` under a heading "Native surface". Keep it short.

1. **Native inventory.** Files and languages with unsafe code, with the author (own or vendored) and the count of `unsafe` blocks or raw-pointer functions. Note which modules are safe code that calls into unsafe code.
2. **Untrusted entries.** Table: entry (network protocol, file format, IPC message, plugin interface) | parser function | who controls the bytes | length caps before the parser.
3. **Length fields.** Table: field | width | signed or unsigned | source | what it sizes (allocation, copy, loop, index).
4. **Allocation sites** whose size depends on input, and the allocator in use (system, pool, arena, slab, custom).
5. **FFI table.** Boundary | direction | ownership rule | callbacks | exceptions or panics across the boundary | thread rules.
6. **Existing assurance.** Fuzz targets, corpora, sanitizer builds in continuous integration, static-analysis results, crash history from `git log` (phase 2.3).
7. **Hardening flags** in the build files (stack protector, fortified libc functions, control-flow integrity, hardened standard-library modes, automatic variable initialisation). These change likelihood. They do not remove a defect.

## Lead searches

The language file adds the exact API names. Adapt the patterns.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `strcpy\|strcat\|sprintf\|vsprintf\|gets\|stpcpy\|wcscpy` | Unbounded copy (MEM-01) | A constant source with a known size is safe. |
| `memcpy\|memmove\|memset\|bcopy\|copy_nonoverlapping\|copy_within\|arraycopy` with a length not tied to the destination size | Bounds error (MEM-01) | Check where the length was validated and against which size. |
| `strncpy\|strncat\|snprintf\|strlcpy\|strlcat` | Off-by-one, missing terminator, truncated result used as complete (MEM-01) | |
| Allocation call with arithmetic in the size: `(malloc\|calloc\|realloc\|alloca\|new\s*\[\|reserve\|resize\|with_capacity).*[*+<]` | Overflow before allocation (MEM-02, MEM-07) | A checked-multiply helper is safe. |
| Reads of wire values: `ntohl\|ntohs\|be32toh\|le32toh\|from_(be\|le)_bytes\|read_u(16\|32\|64)\|get_u(16\|32)` followed by use as a size or index | Attacker-controlled length (MEM-01, MEM-02) | |
| Narrowing casts of sizes: `\(u?int(8\|16\|32)_t\)\|\(int\)\|\(short\)\|static_cast<int>\|as (u8\|u16\|u32\|i32)` | Truncation or sign error (MEM-02) | |
| `free\|delete\|release\|drop\|munmap\|dispose` followed by later use, or `goto (cleanup\|err\|fail)` | Use after free, double free on an error path (MEM-03) | |
| Pointer, view or iterator kept from a container, then the container grows or is destroyed: `\.data\(\)\|c_str\(\)\|as_ptr\(\)\|string_view\|span` | Dangling reference (MEM-03, MEM-07) | |
| `reinterpret_cast\|bit_cast\|transmute\|union\b\|container_of\|offsetof\|#pragma pack\|packed` and casts of byte buffers to struct pointers | Type confusion, alignment, layout assumption (MEM-04) | |
| Struct built partly, then written, sent or copied out: `write\|send\|copy_to\|serialize` of a whole struct | Uninitialised bytes and padding (MEM-05) | A zeroing call or `= {0}` before use is safe. |
| `unsafe\b\|UnsafePointer\|Unsafe\.\|Marshal\.\|from_raw\|into_raw\|extern "C"\|JNIEXPORT\|DllImport\|ctypes\|cgo\|dlopen` | FFI or unsafe boundary (MEM-06) | List each one in the FFI table. |
| `printf\|fprintf\|syslog\|snprintf\|wprintf` with a non-literal format argument | Format-string misuse (MEM-09) | |
| `assert\(\|DCHECK\|debug_assert\|NDEBUG` guarding a bounds or null condition | Check present only in debug builds (MEM-01) | |
| `memset\|bzero\|SecureZero\|explicit_bzero` before `free` or at function end | Wipe removed by the optimiser (MEM-08) | |

## Attack classes

### MEM-01 Out-of-bounds read and write

- **What fails:** the code reads or writes outside the object it meant to use. Causes include a missing length check, a check against the wrong size, an off-by-one, a missing string terminator, or a length that the input changes after the check.
- **Where to look:** copy and format routines; parsers that read length-prefixed fields; loops over counts from input; index use after a weak check; string handling that assumes a terminator; fixed-size buffers; decoders that write to an output buffer; two-pass code where pass one counts and pass two writes.
- **Questions:**
  - What is the size of the destination, and where does the code enforce that size? Is the same value used in the check and in the copy?
  - Does the check compare the right quantity: remaining bytes against needed bytes, not total against offset plus length?
  - Does a field read twice give the same value both times?
  - Is the terminator counted in the buffer size?
  - Does the check exist in release builds, or only in assertions?
- **Sad-path inputs:** length 0, 1, maximum minus one, maximum, maximum plus one; a length larger than the data left; a count of zero with non-zero data; an offset at the exact end; a string with no terminator; a negative value in a signed field.
- **Evidence for confirmed:** an address-sanitizer report (or an equivalent) on the named function with the crafted input, giving access type, size and location (E3).
- **Not a finding:** a cap in a caller or framing layer that makes the length safe; a size fixed at compile time; code that only a test uses.
- **CWE:** CWE-787 (out-of-bounds write); CWE-125 (out-of-bounds read); CWE-120 (buffer copy without checking size of input); CWE-193 (off-by-one error); CWE-170 (improper null termination); CWE-129 (improper validation of array index); CWE-805 (buffer access with incorrect length value). Choose the child that fits the root cause.

### MEM-02 Integer overflow, truncation and sign errors

- **What fails:** arithmetic on an attacker-controlled number wraps, truncates or changes sign. The result is a small allocation with a large copy, a bypassed bounds check, or a negative index.
- **Where to look:** size computations (`count * item_size`, `header + length`); checks written as `offset + length <= size`; conversion between widths (64-bit length stored in 32 bits); signed lengths passed to functions that take unsigned sizes; mixed signed and unsigned comparisons; loops with narrow counters.
- **Questions:**
  - Can any operand reach the type limit? What is the type of each operand and of the result?
  - Does the overflow check itself overflow? Compare `length <= size - offset`, after checking `offset <= size`.
  - Where does a value change width or signedness on its way from input to sink?
  - Does the language trap, wrap or give undefined behaviour on overflow in this build?
- **Sad-path inputs:** values near 2^7, 2^8, 2^15, 2^16, 2^31, 2^32 and 2^63; minus one; the maximum value of the type; two factors whose product wraps; a length of 0xFFFFFFFF on a 32-bit size type.
- **Evidence for confirmed:** a run with the overflowing input that shows a wrong computed size or value, and the resulting out-of-bounds report (E3). An integer sanitizer report (`-fsanitize=integer` or `undefined`) on the named line supports the claim. Unsigned wrap is defined behaviour in C and C++, so show the downstream effect.
- **Not a finding:** a checked-arithmetic helper on the path; an operand bounded by a cap before the computation; a wrap with no security use.
- **CWE:** CWE-190 (integer overflow or wraparound); CWE-191 (integer underflow); CWE-195 (signed to unsigned conversion error); CWE-196 (unsigned to signed conversion error); CWE-197 (numeric truncation error); CWE-131 (incorrect calculation of buffer size); CWE-680 (integer overflow to buffer overflow, a chain).

### MEM-03 Use after free, double free and dangling references

- **What fails:** the code uses memory after release, releases it twice, or keeps a pointer, reference, iterator or view to something that no longer exists.
- **Where to look:** error paths that free and then continue; shared ownership with manual counts; callbacks and timers that fire after their owner is gone; containers that reallocate while pointers into them live; views of temporaries; the address of a local returned; objects destroyed during iteration; close-then-use of handles.
- **Questions:**
  - Who owns the object, and at which line does it die? Which pointers outlive that line?
  - Does each error path free the same set as the success path, and no more?
  - Can a callback run after the owner is destroyed?
  - Does the code copy a pointer before an operation that can move or free the object?
- **Sad-path inputs:** an error half-way through a multi-step operation; a message that closes a connection while a reply is queued; a duplicate close; allocation failure at each step.
- **Evidence for confirmed:** an address-sanitizer report with the access stack, the free stack and the allocation stack (E3). Stop at the report. Do not examine what an attacker could place in the freed memory.
- **Not a finding:** the pointer is cleared or reference-counted on every path; the object lives for the whole process; the freed memory is not read or written afterwards.
- **CWE:** CWE-416 (use after free); CWE-415 (double free); CWE-825 (expired pointer dereference); CWE-562 (return of stack variable address); CWE-1341 (multiple releases of same resource or handle).

### MEM-04 Type confusion and invalid casts

- **What fails:** the code treats an object as a type it is not. A field, tag or length selects the type, and the code does not check it or trusts a value that an attacker controls.
- **Where to look:** tagged unions where code reads a member before it checks the tag; down-casts without a checked cast; `void *` user-data slots; casts of byte buffers to structs; scripting-engine and serialisation code that builds objects from type names; shared memory with a header that selects the layout.
- **Questions:**
  - Which field selects the type? Who controls it? Is it checked before every cast?
  - Can a second thread or a later message change the type while the first view is in use?
- **Sad-path inputs:** each tag value including unknown and out-of-range ones; a tag that changes between two reads; an object of a sibling type with a smaller size; a null `void *` user-data slot.
- **Evidence for confirmed:** a sanitizer report of an invalid cast (for example `-fsanitize=vptr`) or of an out-of-bounds access caused by it, or a wrong value read from the other member (E3).
- **Not a finding:** a checked cast on every path; a variant type that enforces the tag in the access function.
- **CWE:** CWE-843 (access of resource using incompatible type, "type confusion").

### MEM-05 Uninitialised memory and padding disclosure

- **What fails:** the code reads memory that it never set. The result is a wrong decision, or a disclosure when the bytes go to an output.
- **Where to look:** structs copied to a socket or file as a whole (padding and unset fields); buffers from an allocator that does not zero; stack arrays sent after a partial fill; fields set on one branch only; pooled buffers that keep old content; output length larger than the filled length.
- **Questions:**
  - Does every byte of the output come from a defined value?
  - Does the code serialise field by field, or dump the struct?
  - Does each branch set every field that a later reader uses?
  - Does a reused buffer carry data of another principal?
- **Sad-path inputs:** the shortest valid input (fewest fields set); each early-return branch; a reply shorter than its buffer; a pooled buffer reused after a large request.
- **Evidence for confirmed:** a memory sanitizer report (`-fsanitize=memory`, Clang, with all code instrumented), a Valgrind `memcheck` report on a use of uninitialised value, or a captured output with bytes that differ between runs (E3). For disclosure, show the output bytes in the test and stop.
- **Not a finding:** the memory is zeroed by the allocator or by a flag in this build; the bytes are never output or used.
- **CWE:** CWE-457 (use of uninitialized variable); CWE-908 (use of uninitialized resource); CWE-824 (access of uninitialized pointer); CWE-226 (sensitive information in resource not removed before reuse).

### MEM-06 FFI and unsafe-block contract violations

- **What fails:** the two sides of a boundary disagree on a rule, or a safe wrapper exposes an operation that is only safe under a hidden condition.
- **Where to look:** ownership and free routines across the boundary (allocate in one runtime, free in another); lengths passed with pointers; null promises; buffers that the native side keeps after the call returns; callbacks on another thread; exceptions or panics that unwind through native frames; layout and alignment of shared structs; string encodings; `unsafe` blocks whose safety comment states a condition that safe callers can break; hand-written thread-safety markers.
- **Questions:**
  - What does each side assume about ownership, lifetime, length, null and thread? Where is that written?
  - Can safe code in the caller break the assumption (a public safe function that holds the unsafe precondition)?
  - Does the native side keep a pointer to managed memory that the runtime can move or free?
  - What happens when a callback throws, or when the runtime unloads the library?
- **Sad-path inputs:** null; zero length; a length larger than the real buffer; a handle used after close; a managed object collected during a native call; a string with an embedded terminator.
- **Evidence for confirmed:** a sanitizer report from a harness that calls the boundary through its public safe interface (E3). For Rust, a report from the interpreter-based checker for unsafe code (`cargo miri test`) on a safe-only caller shows the unsoundness.
- **Not a finding:** the precondition is enforced in the wrapper; the function is private and all callers meet the precondition.
- **CWE:** CWE-628 (function call with incorrectly specified arguments); CWE-822 (untrusted pointer dereference); CWE-762 (mismatched memory management routines); CWE-476 (NULL pointer dereference).

### MEM-07 Allocator and container misuse

- **What fails:** allocation size, allocation failure, reallocation, pooling or container growth breaks a memory rule.
- **Where to look:** allocation sizes from input; unchecked allocation results; `realloc` patterns that keep stale pointers; arenas and pools that reset while pointers live; containers where code writes to capacity but not size, or keeps a pointer across growth; mismatched allocate and release families (`new[]` with `delete`); release of an interior pointer.
- **Questions:**
  - Is the allocation size checked against a cap, and is the product of count and size checked for overflow?
  - What happens when the allocation fails? Does the code check the result?
  - Does any pointer or iterator survive an operation that can reallocate?
  - Does a pool or arena reset only when no live pointer remains?
- **Sad-path inputs:** a count that makes the size zero or huge; allocation failure at each call (use a failing-allocator hook); two growths in a row; a request to free a pointer not at the start of its block.
- **Evidence for confirmed:** a sanitizer report, or a failure-injection run that dereferences a null result or uses a stale pointer (E3).
- **Not a finding:** a size cap in an earlier layer; an allocator that aborts on failure by design; a pool whose reset is tied to request end with no cross-request pointers.
- **CWE:** CWE-789 (memory allocation with excessive size value); CWE-762 (mismatched memory management routines); CWE-761 (free of pointer not at start of buffer); CWE-401 (missing release of memory after effective lifetime); CWE-252 (unchecked return value); CWE-476 (NULL pointer dereference).

### MEM-08 Undefined behaviour that optimisers exploit

- **What fails:** the code relies on behaviour that the language leaves undefined or unspecified. The compiler may then remove a check, a wipe or a branch, so the safe-looking source does not match the machine code.
- **Where to look:** signed overflow in checks; a null check placed after a dereference; shifts by too large an amount; reads through a pointer of an incompatible type (aliasing rules); overlapping copies with a function that forbids overlap; `memset` of a secret just before release; reliance on evaluation order; a race on a plain variable.
- **Questions:**
  - Does a security check depend on behaviour the language does not define?
  - Is a wipe of a secret followed by no read, so the optimiser can drop it?
  - Does the code pass different compilers or optimisation levels with the same result?
- **Sad-path inputs:** values at the type limit; shift counts of 0, the type width and above; overlapping source and destination; null passed to a function that dereferences before its check.
- **Evidence for confirmed:** an undefined-behaviour sanitizer report (`-fsanitize=undefined`), or a disassembly or test at the release optimisation level that shows the check or wipe is gone (E3). A source-only argument is not enough.
- **Not a finding:** the behaviour is defined by the compiler flags in this build (for example wrapping signed arithmetic); the removed code has no security role.
- **CWE:** CWE-758 (reliance on undefined, unspecified or implementation-defined behavior, class-level); CWE-1335 (incorrect bitwise shift of integer); CWE-476 (NULL pointer dereference). For a removed wipe, name the weakness in words: the compiler removes code that clears a buffer.

### MEM-09 Format-string and variadic misuse

- **What fails:** attacker data reaches the format argument of a printf-style function, or the arguments do not match the format. The function reads or writes memory it should not.
- **Where to look:** logging wrappers that pass a message as the format; error reporters; wrappers that forward a variable argument list; custom printf-style functions without format-checking attributes; translation files that hold formats.
- **Questions:**
  - Is the format a literal, or can input reach it?
  - Does every wrapper mark its format parameter so the compiler checks calls?
- **Sad-path inputs:** a message that contains conversion specifiers; more specifiers than arguments; a very long width.
- **Evidence for confirmed:** a run where a harmless specifier in the input changes the output (leaks a stack value) or a sanitizer report. Stop at that proof.
- **Not a finding:** the format is a literal; the input is escaped or passed only as an argument.
- **CWE:** CWE-134 (use of externally-controlled format string).

## Variant search

When you find one memory-safety defect:
1. **Same function family.** List every caller of the routine and every sibling that copies, parses or frees in the same way.
2. **Same field.** For a bad length field, list every use of that field. Check each use for the same missing check.
3. **Same pattern.** Search the lead patterns for the same shape (the same arithmetic form, the same cleanup label, the same cast).
4. **Same format.** Other decoders for the same message or file type, other language bindings, and vendored copies of the same library.
5. **Same error path.** Other functions that use the same cleanup idiom (`goto`, defer, scope guard).
6. **Same fix.** If an earlier fix patched one site, check the sibling sites. Run the fuzzer on the other entry points.

## Chain primitives

This domain often **gives**:
- an out-of-bounds read: a disclosure of other memory (secrets, keys, other users' data, layout information);
- an out-of-bounds write or use after free: corruption of nearby state (reported only as the minimum proven effect);
- a repeatable crash: denial of service of a shared process;
- a wrong size or wrong value: input to later checks in other domains.

This domain often **needs**:
- a path that delivers attacker bytes to the native entry (from the network, a file, IPC);
- a precondition from another domain, such as an authenticated session that reaches the parser;
- a leak of layout information, where the report claims more than a crash. Do not chain past the proven effect.

## Verification notes

- **E3 is required** for `confirmed` on every attack class. This domain has no E1 waiver: a memory-safety claim depends on compiler output and memory layout. Without T2, the finding is `needs-validation` with a reproduction plan: build command, sanitizer flags, harness, input.
- **Reproduction.** Work on a copy in scratch, at the isolation level in `plan.md`.
  - Call the vulnerable function from a small harness with the crafted input. Do not run the whole service.
  - Build with `-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all`. Set `ASAN_OPTIONS=detect_stack_use_after_return=1:abort_on_error=1`.
  - Use `-fsanitize=memory` (Clang) for uninitialised reads. All linked code must be instrumented, or the result is unreliable. Use Valgrind `memcheck` when a rebuild is not possible.
  - For Rust unsafe code, use `cargo miri test`. For Go code that uses `unsafe`, use `go test -race` and `-gcflags=all=-d=checkptr`. For JNI, use `-Xcheck:jni`.
  - A fuzz target (libFuzzer, AFL++ or honggfuzz) can find an input. Give it a time limit, a memory limit and a corpus from the repository. Minimise the crash input, then rerun it under the sanitizer. Fuzzing is target-code execution: follow `execution.md`.
  - Static analysers (the Clang static analyzer, `cppcheck`, CodeQL) support a claim at E2. They do not replace the run.
- **Minimum effect.** The sanitizer report proves the defect: access type, size, location and stacks. Stop there. Do not read what the memory holds, do not shape what lands in freed memory, and do not claim code execution. A crash is not code execution. A report is not proof of exploitability. Severity follows the supported effect and conditions; do not infer critical impact from a remote out-of-bounds write or use after free alone.
- **Reachability.** Show that the real entry passes attacker bytes to the function, and that callers do not cap the length first. Show that the harness input is valid at the real entry. Confirm the code is compiled in the default build.
- **False-positive checks.** A cap or framing check in an earlier layer; a build that wraps or traps on overflow by design; instrumentation mismatch (partly instrumented containers or custom allocators can give false reports); test-only code; a debug-only assertion where release is safe.
- **Hardening is not a verdict.** Stack protectors, address randomisation and similar flags change likelihood. A defect with these flags on stays a defect.
- **Severity examples:**
  - critical – only when the evidence shows a critical impact from phase-verify.md section 6.5. A sanitizer report of an out-of-bounds write or use after free does not show this by itself;
  - high – an unauthenticated remote out-of-bounds write or use after free in a network-facing parser of a daemon; an out-of-bounds read that returns other users' data to a remote low-trust client; a repeatable remote crash of a shared service by a low-trust actor; memory corruption reachable by an authenticated user;
  - medium – a read of a few bytes with a narrow precondition; a crash that needs a malicious local file opened by the victim;
  - low – an uninitialised read of non-sensitive padding; a null dereference in a single-user tool;
  - informational – undefined behaviour with no observed effect on supported compilers.

## Fix patterns

- **Make the length check the first step.** Compare `length <= remaining` before any use. Keep offsets and lengths in the widest size type, and check conversions.
- **Use checked arithmetic** for every size computation (compiler overflow built-ins, checked-math helpers in the language).
- **Use bounds-carrying types.** Pass spans or slices, not pointer and length pairs. Enable checked container access in the build where it is available.
- **One owner per allocation.** Use scope-bound ownership (RAII, unique ownership, arenas with a stated lifetime). Avoid raw pointers that outlive the owner.
- **Initialise at declaration.** Zero structs before use. Serialise field by field.
- **Check tags before casts.** Use variant types or checked casts.
- **Shrink the unsafe surface.** Put each unsafe operation in a small function with a written precondition, and validate at the boundary.
- **Fail the build on banned functions** with lint rules. Keep sanitizer builds and fuzz targets in continuous integration.
- **Looks right but is not:** `strncpy` without a terminator; `offset + length <= size` with no wrap check; a cap larger than the buffer; `assert` as the only bounds check; a pointer set to null after free while an alias remains; stack protectors or address randomisation as the fix; widening a value after it has overflowed; `sizeof` of a pointer used as a buffer size; a wipe the optimiser can remove; a signal handler that catches the crash; a check on one copy of the length while the code uses another.

## Regression tests

- A **fuzz target** for each parser entry, with every crash input saved in the seed corpus.
- A **sanitizer build** of the unit tests in continuous integration, with failures as errors.
- **Boundary-length tests** for each fixed site: 0, 1, limit minus one, limit, limit plus one, 2^31, 2^32 minus one, and a length larger than the data.
- **Failure-injection tests** that fail the Nth allocation and check that the code returns an error without leaks, double frees or null use.
- **Lifetime tests** for each error path: trigger the error and run under the sanitizer.
- For unsafe Rust, a test run under `cargo miri test` that calls the safe interface with hostile arguments.
- A test that proves a secret wipe survives optimisation (build at release level and inspect the output buffer or use a volatile-safe wipe routine).
