# Language: C

## Scope
- Covers: C89 to C23, compiled with GCC, Clang or MSVC; POSIX and Linux user space; Windows C code; firmware C; C code inside C++ projects (read `lang-cpp.md` too). Library code, daemons, command-line tools, plugins and shared objects.
- Common frameworks: libc and POSIX; OpenSSL; libcurl; zlib; libxml2; SQLite; libevent; libuv; libmicrohttpd; nginx and Apache modules; FastCGI; D-Bus (libdbus, GDBus); glib.
- Domain link: `domain-memory-safety.md` owns the attack logic for memory defects. This file lists the C-specific sinks and traps.

## Entry points

Attacker data enters at the places below. Mark each as an entry in `threat-model.md`.

- **Process start.** `int main(int argc, char **argv)`, `getopt`, `getopt_long`, `getenv`, `environ`, `stdin`, config files read at start-up.
- **Sockets and files.** `recv`, `recvfrom`, `recvmsg`, `read`, `readv`, `pread`, `fread`, `fgets`, `getline`, `fscanf`, `mmap` of a file, `accept`, `accept4`, `epoll_wait`, `poll`, `select`.
- **Event frameworks.**
  - libevent: `evconnlistener_new`, `bufferevent_setcb` (read callback), `evhttp_set_gencb`, `evhttp_set_cb`.
  - libuv: `uv_read_start` (read callback), `uv_listen`, `uv_udp_recv_start`.
  - libmicrohttpd: `MHD_start_daemon` with an access handler callback.
  - Mongoose and CivetWeb: `mg_http_listen`, event handler `ev_handler`, `mg_set_request_handler`.
- **Server modules.** nginx: `ngx_http_*_handler`, `ngx_http_request_t` fields, `ngx_command_t` tables. Apache: `ap_hook_handler`, `ap_hook_*` registrations. FastCGI: `FCGX_Accept_r`. CGI: `QUERY_STRING`, `CONTENT_LENGTH` and other environment variables.
- **Callbacks that carry network data.** libcurl: `CURLOPT_WRITEFUNCTION`, `CURLOPT_HEADERFUNCTION`. OpenSSL: `SSL_read`, `BIO_read`, verify callbacks. Parser libraries: SAX-style handlers in libxml2 and expat.
- **Local IPC.** D-Bus method handlers, Unix socket servers, `SO_PEERCRED` use, shared memory (`shm_open`, `mmap`), signals (`signal`, `sigaction`), `ioctl` and netlink handlers in kernel code.
- **Exported functions.** Every non-`static` function in a library header or a symbol map. Callers pass lengths and pointers that the library must check.
- **Plugin loading.** `dlopen`, `dlsym`, module tables.
- **Embedded.** Interrupt handlers, UART, SPI and USB receive buffers, DMA completion callbacks.

Search the registration forms, then follow the callback to the first use of the data length.

## Sinks by domain

| Domain | Dangerous API or pattern | Safer alternative | Notes |
|---|---|---|---|
| memory-safety | `gets` (removed in C11), `strcpy`, `strcat`, `sprintf`, `vsprintf`, `scanf("%s")`, `memcpy`/`memmove`/`read` with an attacker length, `alloca`, variable-length arrays sized from input | `snprintf`, `memcpy` after an explicit size check, `fgets`, fixed-width scanf fields, heap buffers with checked sizes | `strncpy` does not always add a NUL. `strncat` size is the space left, not the buffer size. |
| memory-safety | `malloc(n * size)`, `malloc(a + b)`, `realloc(p, n * 2)` | `calloc`, `reallocarray` (glibc 2.26 or later, BSD), `__builtin_mul_overflow` (GCC 5+, Clang), `ckd_mul` in `<stdckdint.h>` (C23) | Check overflow before the call. Check the result for `NULL`. |
| memory-safety | `snprintf` return value used as a length | Compare the return value with the buffer size before use | `snprintf` returns the length it wanted to write, not the length it wrote. |
| input-parsing | `atoi`, `atol`, `sscanf("%d")`, `strtol` without `errno` and end-pointer checks, hand-written TLV and length-prefix parsers | `strtol`/`strtoul` with full checks, a bounds-checked reader struct | `atoi` gives no error signal. Check negative values before they become `size_t`. |
| input-parsing | libxml2 with `XML_PARSE_NOENT` or `XML_PARSE_DTDLOAD`; `xmlReadMemory` without `XML_PARSE_NONET` | Do not set `NOENT` or `DTDLOAD` for untrusted XML. Set `XML_PARSE_NONET`. | `NOENT` turns on entity substitution. Handoff: external entities and expansion are in `domain-input-parsing.md`. |
| input-parsing | libarchive extraction without secure flags; own tar or zip code that joins entry names to a path | `archive_write_disk_set_options` with `ARCHIVE_EXTRACT_SECURE_NODOTDOT`, `ARCHIVE_EXTRACT_SECURE_SYMLINKS` and `ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS` | Check link entries as well as file entries. |
| injection | `system`, `popen`, `execl`/`execlp`/`execvp` with a shell string, `sh -c` built with `snprintf` | `execv` or `posix_spawn` with an argument array and an absolute path | `execlp`, `execvp` and `posix_spawnp` search `PATH`. |
| injection | `sqlite3_exec` or `mysql_query` with a string built by `sprintf` | `sqlite3_prepare_v2` with `sqlite3_bind_*`; prepared statements in other client libraries | `sqlite3_mprintf("%q")` escapes quotes only inside quotes. |
| injection | `printf(s)`, `fprintf(f, s)`, `syslog(prio, s)`, `snprintf(b, n, s)` where `s` has attacker data | `printf("%s", s)`, `syslog(prio, "%s", s)` | A format string gives read and write primitives. Compiler `-Wformat-security` finds many. |
| filesystem-process | `access` then `open`; `stat` then `open`; `open` without `O_NOFOLLOW`, `O_EXCL` or `O_CLOEXEC` | `open` then `fstat`; `openat` with a directory descriptor; `O_CLOEXEC` on every descriptor | Handoff: TOCTOU logic is in `domain-filesystem-process.md`. |
| filesystem-process | `mktemp`, `tmpnam`, `tempnam`, `tmpfile` in shared directories, `fopen("/tmp/name")` | `mkstemp`, `mkdtemp`, `O_TMPFILE` (Linux) | A predictable name in a shared directory is a link-attack lead. |
| filesystem-process | `chmod(path)` and `chown(path)` after creation; `umask` set late or never; `realpath` result compared by prefix | `fchmod`/`fchown` on the descriptor; create with the final mode; compare path components | A prefix test `strncmp(p, base, n)` accepts `/base-evil`. |
| filesystem-process | `setuid`, `setgid`, `setreuid` without return check; wrong order | Drop groups first (`setgroups`, `initgroups`), then the group ID, then the user ID. Check every return value. Use `setresuid`/`setresgid` on Linux. | A failed drop must stop the program. `getenv` in setuid code: use `secure_getenv` (glibc 2.17). |
| filesystem-process | `chroot` without `chdir("/")` after it; `LD_PRELOAD`, `PATH`, `IFS` inherited by child | `chdir("/")` straight after `chroot`; clean environment for children | `chroot` is not a sandbox for root processes. |
| crypto | `rand`, `random`, `srand(time(NULL))`, `drand48` for keys, tokens, nonces | `getrandom` (Linux), `arc4random_buf` (BSD, macOS, glibc 2.36 or later), `RAND_bytes` (check the return value), `BCryptGenRandom` (Windows) | `RAND_bytes` can fail. A failure that is ignored leaves a zero or stale buffer. |
| crypto | `memcmp`, `strcmp`, `strncmp` on MACs, hashes, tokens | `CRYPTO_memcmp` (OpenSSL), `sodium_memcmp` (libsodium) | Early exit leaks the match length through timing. |
| crypto | OpenSSL `EVP_CIPHER` ECB or CBC without a MAC; fixed or counter IV from a reset counter; `EVP_DecryptFinal_ex` result ignored | AEAD modes (`EVP_aes_256_gcm`, ChaCha20-Poly1305) with a unique nonce; check every `EVP_*` return value | Check `EVP_VerifyFinal`, `EVP_DigestVerify` results with `== 1`, not `!= 0`. |
| crypto | `memset(key, 0, n)` before `free` | `explicit_bzero` (glibc 2.25, BSD), `OPENSSL_cleanse`, `sodium_memzero`, `SecureZeroMemory` (Windows) | The compiler may remove a `memset` on a dead buffer. |
| outbound-network | `SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, ...)`; verify callback that returns 1; no host check | `SSL_VERIFY_PEER`; `SSL_set1_host` or `X509_check_host`; `SSL_get_verify_result` | OpenSSL does not check the host name unless the code asks. |
| outbound-network | libcurl `CURLOPT_SSL_VERIFYPEER` set to 0; `CURLOPT_SSL_VERIFYHOST` set to 0; `CURLOPT_FOLLOWLOCATION` with no `CURLOPT_PROTOCOLS_STR` (curl 7.85.0) or `CURLOPT_REDIR_PROTOCOLS_STR` limit | Leave verification on; limit protocols and redirects; set `CURLOPT_TIMEOUT` and `CURLOPT_MAXFILESIZE_LARGE` | `CURLOPT_URL` from input is an SSRF lead. Handoff: `domain-outbound-network.md`. |
| outbound-network | `gethostbyname` (not thread-safe), `inet_ntoa`, address checks on a string host name before `connect` | `getaddrinfo`, check the resolved address that `connect` uses | A check on a name and a connect to a second lookup allows DNS rebinding. |
| authn | `strcmp(input, stored_password)`; `crypt` result compared with `strcmp`; PAM `pam_authenticate` without `pam_acct_mgmt` | Password hash function from `domain-crypto.md`; constant-time compare; both PAM calls | PAM accounts that are expired or locked pass `pam_authenticate`. |
| concurrency | Shared globals without a lock; `strtok`, `localtime`, `gmtime`, `getpwnam`, `strerror`, `rand` in threads | `strtok_r`, `localtime_r`, `getpwnam_r`, `strerror_r` | See the Concurrency section. |
| resource-exhaustion | Allocation sized from a length field; `inflate` loop with no output limit; unbounded `realloc` growth; recursion on nested input | Cap every length; cap the output of `inflate`; cap depth | A cap that applies after allocation is too late. |
| logging-privacy | `syslog`, `fprintf(stderr, ...)` with passwords, tokens or keys; CR/LF from input in log lines | Log IDs, not secrets; encode control characters | Core dumps hold keys. See Build and runtime settings. |
| secrets-config | Keys as string literals or `static const` arrays; `getenv("DEBUG")` toggles; config parsed with `sscanf` | Load keys from a protected store; compile debug paths out of release | Handoff: `domain-secrets-config.md`. |
| sandbox | `seccomp` filter with a default of allow; `dlopen` of a path from input; embedded interpreter with `os`-style host functions | Default-deny filters (libseccomp `SCMP_ACT_KILL_PROCESS`); fixed plugin paths | Check `prctl(PR_SET_NO_NEW_PRIVS)` before the filter. |
| local-ipc | D-Bus or socket handler that trusts the sender name in the payload; no `SO_PEERCRED` or PolicyKit check | Read peer credentials from the kernel (`SO_PEERCRED`); check the D-Bus sender | Handoff: `domain-local-ipc.md`. |
| kernel | `copy_from_user`, `copy_to_user`, `get_user`, `put_user`, length from user space; `ioctl` argument structs read twice | Copy once into kernel memory, then validate the copy | Double fetch is a race. Handoff: `domain-kernel.md`. |
| embedded | `memcpy` from DMA or UART buffers with a length from the peer; `volatile` used as a lock; `strcpy` in firmware | Bounds check at the driver edge | Handoff: `domain-embedded.md`. |
| supply-chain | Vendored copies of zlib, OpenSSL, libpng and others; `curl \| sh` in build scripts; `Makefile` that fetches sources | Pinned, hashed sources | Compare the vendored version with the upstream fix history. |

## Language traps

- **Signed overflow is undefined behaviour.** The compiler may remove checks that depend on it.
  - Wrong: `if (a + b < a) return -1;` (for `int a, b`)
  - Right: `if ((b > 0 && a > INT_MAX - b) || (b < 0 && a < INT_MIN - b)) return -1;`, then add. Or use `__builtin_add_overflow(a, b, &r)` or C23 `ckd_add` and handle overflow.
- **Unsigned arithmetic wraps without warning.** A wrapped value passes a size check.
  - Wrong: `if (off + len <= total) memcpy(dst, src + off, len);`
  - Right: `if (len <= total && off <= total - len) memcpy(dst, src + off, len);`
- **Signed to unsigned conversion.** A negative `int` becomes a very large `size_t`.
  - Wrong: `int n = read_len(); if (n > MAX) return; memcpy(d, s, n);` (a negative `n` passes)
  - Right: `if (n < 0 || n > MAX) return;`
- **Truncation.** `uint16_t n = (uint16_t)len;` drops high bits. Check the range before every narrowing cast. A length stored in `int` can differ from `size_t`.
- **`char` signedness.** `char` is often signed. `table[c]` and `isalpha(c)` need `(unsigned char)c`. A negative index reads before the table.
- **Embedded NUL bytes.** C string functions stop at the first NUL. A name check can see `"safe.txt"` while the buffer holds `"safe.txt\0../../x"`. Keep the length from the input and compare lengths.
- **Missing terminator.** `strncpy(dst, src, sizeof dst)` does not terminate when `src` is long. Set `dst[sizeof dst - 1] = 0`, or use `snprintf`.
- **`sizeof` on a pointer.** A function parameter `char buf[64]` is a pointer. `sizeof buf` gives 8, not 64.
- **Off-by-one on the terminator.** `char b[16]; memcpy(b, s, 16); b[16] = 0;` writes one byte past the end.
- **Use after free and double free.** Set the pointer to `NULL` after `free` only as a hint. Other copies of the pointer stay dangling. Check error paths with `goto cleanup` for double free.
- **`realloc` failure.** `p = realloc(p, n);` leaks and loses `p` on failure. Use a temporary.
- **Uninitialised memory.** Stack structs copied to a peer or file leak padding bytes. Zero the struct with `memset` before filling it, then copy fields.
- **Null check after use.** The compiler may delete `if (p == NULL)` that follows `*p`. Look at the order.
- **Shifts and division.** `1 << 31` on `int`, shift counts of 32 or more on 32-bit types, `INT_MIN / -1`, `abs(INT_MIN)` and division by zero are undefined behaviour.
- **Strict aliasing.** Casting a `char *` to a `struct *` or `uint32_t *` and reading it can be undefined behaviour and unaligned access. Use `memcpy` to read wire data.
- **Format strings.** See the injection row. `%n` writes memory.
- **Return values ignored.** `read`, `write`, `snprintf`, `setuid`, `fchmod`, `fclose` and `RAND_bytes` can fail. A short `read` or `write` is normal on sockets.
- **Macros.** `#define MAX(a,b) ((a)>(b)?(a):(b))` evaluates arguments twice. A call that reads input runs twice.
- **`assert`.** `assert(len < MAX)` vanishes when `NDEBUG` is set. A security check must not live in `assert`.

## Deserialisation and reflection

C has no built-in object deserialisation. The risk comes from raw structures and dynamic loading.

- **Struct reads from the wire.** `fread(&hdr, sizeof hdr, 1, f)` or `memcpy(&hdr, buf, sizeof hdr)` copies padding, native byte order and pointer fields. Look for pointer or function-pointer members that come from the file. Look for lengths used without a range check.
- **Offsets as pointers.** File formats that store offsets (ELF-like, font, image, database pages) need a range check on every offset and every `offset + size`. Parser differential risk: two parsers read the same bytes differently.
- **TLV and ASN.1 parsers.** Check that the inner length fits the outer length. Check recursion depth. Check that a length field of 0 or a maximum value works.
- **Parser libraries.** Protobuf-C, nanopb, cJSON, jansson and msgpack-c check lengths in different ways. Read how the project calls them.
- **Dynamic loading.** `dlopen(path)`, `dlsym(handle, name)` with a path or name from input, config or a writable directory runs attacker code. Check `RTLD_*` flags, the search path (`LD_LIBRARY_PATH`, `RPATH`, `RUNPATH`) and the owner of the directory. On Windows, check `LoadLibrary` without a full path (DLL search order).
- **Function tables.** Command dispatch by name or index into an array of function pointers needs a bounds check on the index.

## Concurrency

- **Primitives.** POSIX threads (`pthread_mutex_*`, `pthread_cond_*`, `pthread_rwlock_*`), C11 `<threads.h>` (`mtx_*`) and `<stdatomic.h>`, Windows critical sections, signals, `fork`.
- **`volatile` is not synchronisation.** It does not give atomicity or ordering between threads. Use `_Atomic` or a lock.
- **Check-then-act on files and state.** A lock around the check and a second lock around the act is a race. Handoff: `domain-concurrency.md`.
- **Lock errors.** A missing `pthread_mutex_unlock` on an error path causes a deadlock. A double unlock is undefined. Look at every `return` and `goto` between lock and unlock.
- **Non-reentrant functions.** `strtok`, `localtime`, `gmtime`, `asctime`, `getpwnam`, `getenv` (with `setenv`), `strerror`, `rand`, `inet_ntoa`, `gethostbyname` use shared static state. Use the `_r` versions or per-thread buffers.
- **Signal handlers.** A handler may use only async-signal-safe functions and `volatile sig_atomic_t` variables. `malloc`, `free`, `printf`, `syslog` and locks in a handler can corrupt the heap or deadlock. A handler that does a cleanup `free` can race with the main code.
- **`fork` in threaded programs.** The child holds only the calling thread. Locks held by other threads stay locked. Between `fork` and `exec`, use only async-signal-safe functions.
- **Shared buffers.** A buffer that one thread frees while another thread reads is a use-after-free. Look for reference counts without atomic operations.

## Build and runtime settings

Check the real build lines in the `Makefile`, `CMakeLists.txt`, `meson.build` or `configure` output. The flags below are safe-by-default choices. Their absence is a hardening note, not a finding.

- **Warnings.** `-Wall -Wextra -Wformat=2 -Wformat-security -Wconversion -Wsign-conversion -Wshadow -Wvla`. Also `-Werror=implicit-function-declaration` (an undeclared function gets an implicit `int` return type in old C).
- **Fortify.** `-D_FORTIFY_SOURCE=2` with `-O1` or higher. `-D_FORTIFY_SOURCE=3` needs GCC 12 or later (or recent Clang) and glibc 2.33 or later. Fortify cannot see through all pointers.
- **Stack.** `-fstack-protector-strong`, `-fstack-clash-protection` (GCC 8+, Clang 11+), `-Wl,-z,noexecstack`.
- **Control flow.** `-fcf-protection=full` (x86; GCC 8+), `-mbranch-protection=standard` (AArch64; GCC 9+).
- **Position independence.** `-fPIE -pie` for programs, `-fPIC` for libraries. `-Wl,-z,relro,-z,now` for full RELRO.
- **GCC 14 and later.** `-fhardened` turns on a set of the flags above.
- **Initialisation.** `-ftrivial-auto-var-init=zero` (GCC 12 and later) zeroes automatic variables. It hides leaks. It does not remove the bug.
- **Optimiser behaviour.** `-fwrapv` makes signed overflow wrap. `-fno-strict-aliasing` and `-fno-delete-null-pointer-checks` remove two classes of surprise. A project that needs these flags has latent undefined behaviour.
- **Check a built binary (offline).** `readelf -lW bin` shows `GNU_STACK` and `GNU_RELRO`. `readelf -d bin` shows `BIND_NOW`. `readelf -h bin` shows `DYN` for PIE.
- **Runtime.** Core dumps (`ulimit -c`, `/proc/sys/kernel/core_pattern`) can hold keys. glibc ignores `LD_*` variables in setuid programs (secure-execution mode), but custom code that reads `getenv` is not protected. `MALLOC_PERTURB_` helps tests find uninitialised use.
- **Insecure defaults to find.** Sockets that bind `INADDR_ANY`; files created with mode `0666` and a loose `umask`; verify-off TLS flags kept for "testing"; debug macros (`DEBUG`, `-DTEST`) in release targets.

## Tools

Run only tools that are already installed. Do not fetch rules. This list agrees with `phase-leads.md` section 2.1.

- **Compiler warnings and analyser (no execution of target code).**
  `gcc -fsyntax-only -Wall -Wextra -Wformat=2 -Wconversion -Wsign-conversion -Wshadow -fanalyzer file.c` (`-fanalyzer` needs GCC 10 or later). Use the flags from `compile_commands.json`.
- **clang-tidy.** `clang-tidy -p build --checks='-*,bugprone-*,cert-*,clang-analyzer-*' file.c`. The `-p` directory holds `compile_commands.json`.
- **cppcheck.** `cppcheck --enable=warning,portability --inconclusive --project=build/compile_commands.json`.
- **scan-build.** `scan-build -o "$SCRATCH/out" make`. This runs the build. Build scripts are target code: follow `execution.md` first.
- **Sanitisers (run target code).** `-fsanitize=address,undefined -g -O1` for tests. `-fsanitize=thread` for races (not together with AddressSanitizer). `-fsanitize=memory` for uninitialised reads (Clang only; needs instrumented libraries). Clang also has `-fsanitize=unsigned-integer-overflow` and `-fsanitize=implicit-conversion`. Set `ASAN_OPTIONS=abort_on_error=1:detect_leaks=1`.
- **Valgrind.** `valgrind --error-exitcode=1 ./test` when the sanitisers are not available.
- **Fuzzers.** libFuzzer: `clang -g -O1 -fsanitize=fuzzer,address,undefined harness.c parser.c -o fuzz`, then `./fuzz corpus_dir -runs=100000 -max_len=4096`. AFL++: `afl-clang-fast` to build and `afl-fuzz -i in -o out -- ./target @@` to run. AFL++ may need system settings that need admin rights.
- **Multi-language.** `semgrep --metrics=off --config <local rule dir>`; never `--config auto`.

## Lead searches

| regex | meaning | false-hit notes |
|---|---|---|
| `\b(gets\|strcpy\|strcat\|sprintf\|vsprintf\|stpcpy)\s*\(` | Unbounded copy (memory-safety) | Safe if the source is a literal or the size is proven. Check the destination size. |
| `\b(strncpy\|strncat\|memcpy\|memmove\|bcopy)\s*\([^;]*(len\|size\|n\b\|count)` | Copy with a computed length | Find where the length comes from and where it is checked. |
| `\b(malloc\|calloc\|realloc\|alloca)\s*\([^)]*[*+]` | Size arithmetic in allocation | `calloc(n, size)` is safe against overflow. A product in `malloc` is not. |
| `\b(printf\|fprintf\|syslog\|snprintf\|vsnprintf\|dprintf)\s*\([^"]*\b[a-z_]+\s*\)` | Format string not a literal | Wrappers with `__attribute__((format))` are checked by the compiler. |
| `\b(system\|popen\|execl\|execlp\|execvp\|execve\|posix_spawnp?)\s*\(` | Process creation | Check whether the command, arguments or `PATH` come from input. |
| `\b(mktemp\|tmpnam\|tempnam\|tmpfile)\s*\(` | Weak temp file creation | `mkstemp` and `mkdtemp` are the safe forms. |
| `\b(access\|stat\|lstat)\s*\([^;]*;[\s\S]{0,200}\b(open\|fopen\|unlink\|rename)\s*\(` | Check then use on a path | Not a bug if the path is private to the process. |
| `\b(setuid\|setgid\|seteuid\|setreuid\|setresuid\|setgroups\|initgroups\|chroot)\s*\(` | Privilege change | Check order and return values. |
| `\b(rand\|srand\|random\|drand48)\s*\(` | Weak RNG | A false hit when the value has no security role. |
| `\b(memcmp\|strcmp\|strncmp\|bcmp)\s*\([^;]*(mac\|hmac\|tag\|token\|hash\|digest\|sig\|password\|secret)` | Non-constant-time compare | A false hit when both sides are public. |
| `SSL_VERIFY_NONE\|VERIFYPEER\s*,\s*0\|VERIFYHOST\s*,\s*0` | TLS verification off or weak | Test code and unit-test servers are false hits only if the build excludes them. |
| `\b(dlopen\|LoadLibrary[AW]?\|dlsym)\s*\(` | Dynamic loading | Check the path source and directory owner. |
| `\b(signal\|sigaction)\s*\(` | Signal handler | Read the handler for unsafe calls. |
| `\bassert\s*\(` | Check removed by `NDEBUG` | A false hit when the assert guards only a developer invariant. |
| `NOLINT\|#pragma GCC diagnostic ignored\|__attribute__\s*\(\(unused` | Silenced tool | Read the line. A suppressed warning is a strong lead. |
| `\(\s*(u?int(8\|16)_t\|short\|unsigned short\|char)\s*\)` | Narrowing cast | Check that the value is range-checked before the cast. |

## Verification notes

- **Evidence level.** Every memory-safety claim needs E3 for `confirmed`. Without T2 the verdict is `needs-validation` with a reproduction plan. E1 is enough for plain logic defects, such as a TLS verify flag set to off in the default build, or a fixed-size `strcpy` of a long constant.
- **Smallest harness.** Compile the one function with its direct dependencies. Write a `main` that reads a file into a buffer and calls the function. Build with `-fsanitize=address,undefined -g -O1`. Run it with an input that has the length the attack needs. The sanitiser report (type, stack, offset) is the E3 evidence. Use a fixed-size buffer in the harness that matches the real one.
- **Fuzz shape.** Export `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`, call the parser, and return 0. Add seeds from the test directory. Crash files are the evidence.
- **Race shape.** Build with `-fsanitize=thread`. Start two threads that run the two conflicting calls in a loop. A ThreadSanitizer report is evidence of a data race. It does not prove a security effect: show the effect with a second check.
- **Integer defects.** Run the arithmetic in a tiny program with fixed inputs. Show the wrapped value and the allocation or copy size that follows.
- **False positives.**
  - A length checked by the caller, a protocol limit, or a fixed-size input upstream.
  - A sanitiser report in code compiled only for tests.
  - `strcpy` where the source is a compile-time constant that fits.
  - A hardening flag missing in a project that is not exposed to attackers.
- **Reachability.** Show that the entry (see Entry points) reaches the function in the default build. Check `#ifdef` guards and `configure` options.
- **Blind spots.** AddressSanitizer does not find overflow inside one struct. A clean run is not proof of safety.
