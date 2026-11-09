# Language: C++

## Scope

- **Covers:** C++11 to C++26, with GCC, Clang and MSVC, on libstdc++, libc++ and the Microsoft STL. Use `lang-c.md` as well for C APIs called from C++.
- **Common frameworks:** Boost.Asio and Boost.Beast, standalone Asio, gRPC C++, Qt (network, core), POCO, cpp-httplib, Crow, Drogon, Seastar; OpenSSL, BoringSSL and libsodium; protobuf, FlatBuffers, Cap'n Proto, nlohmann::json, RapidJSON, simdjson; game engines with C++ gameplay code (for example Unreal Engine).

C++26 features in this file (erroneous behaviour, library hardening, contracts) depend on compiler and library support. Check the toolchain version in the repository before you rely on them.

## Entry points

| Source of input | Search patterns |
|---|---|
| Program start, CLI | `int main\(`, `wmain\(`, `getopt`, `boost::program_options`, `CLI::App`, `cxxopts`, `argv\[` |
| Environment and config | `getenv`, `secure_getenv`, `_wgetenv`, `QSettings`, `QProcessEnvironment`, config loaders |
| Sockets (Asio, Beast) | `async_accept`, `async_read`, `async_read_some`, `async_read_until`, `http::read`, `http::async_read`, `websocket::stream.*async_read` |
| HTTP frameworks | cpp-httplib `\.(Get\|Post\|Put\|Delete\|Patch)\(`; Crow `CROW_ROUTE\(`; Drogon `ADD_METHOD_TO\|METHOD_ADD\|PATH_ADD`; POCO `handleRequest\(` |
| gRPC services | `::grpc::Status \w+\(::grpc::ServerContext\*`, `grpc::ServerBuilder`, `RegisterService` |
| Qt | `QTcpServer`, `newConnection`, `readyRead`, `QLocalServer`, `QDBus`, slots connected to network or IPC signals |
| Raw I/O | `recv\(`, `recvfrom\(`, `read\(`, `ReadFile\(`, `std::ifstream`, `fread\(` |
| Exported APIs | `extern "C"`, `__declspec\(dllexport\)`, `__attribute__\(\(visibility\("default"\)\)\)`, public headers of a library |
| Game server RPCs | engine RPC markers, for example Unreal `UFUNCTION\(Server` and its `_Validate` functions |

For libraries, every public function that takes caller data is an entry point. The caller is the lower-trust principal only if the library documents that it handles untrusted data.

## Sinks by domain

| Domain | Dangerous API or pattern | Safer alternative | Notes |
|---|---|---|---|
| memory-safety | `memcpy`, `strcpy`, `sprintf`, `strcat` and other C string functions | `std::string`, `std::span` with checked sizes, `snprintf` with result checks | See `lang-c.md`. |
| memory-safety | `operator[]` on `vector`, `array`, `string`, `span` with untrusted index | `.at()`, explicit bounds check, hardened library mode | `std::span::at` exists from C++26. |
| memory-safety | `std::string_view`, `std::span`, iterators, `c_str()`, `data()` that outlive their owner | Own the data (`std::string`, `std::vector`) where lifetime is unclear | See language traps. |
| memory-safety | `reinterpret_cast`, C-style casts, `static_cast` downcasts, unions for type punning | `std::bit_cast` (C++20), `memcpy` into a value, `dynamic_cast` with a check | |
| memory-safety | raw `new` and `delete`, `get()` from smart pointers stored elsewhere | `std::unique_ptr`, `std::shared_ptr`, clear ownership | |
| injection | `std::system`, `system`, `popen`, `QProcess::startCommand`, shell strings in `boost::process` | `execve`-family or `QProcess::start(program, arguments)` with an argument list | Argument lists still need option-injection checks (`--` separator). |
| injection | SQL built with string concatenation for `sqlite3_exec`, `pqxx::work::exec`, `mysql_query` | `sqlite3_prepare_v2` with `sqlite3_bind_*`; `pqxx` parameterised execution; prepared statements | |
| injection | `printf`-family with a non-literal format; `fmt::runtime(user)`, `std::vformat(user, ...)` | Literal format strings; pass data as arguments | `fmt` and `std::format` throw on bad formats rather than corrupt memory, but a user format can still read arguments. |
| input-parsing | libxml2 options `XML_PARSE_NOENT`, `XML_PARSE_DTDLOAD`; Xerces with external entities enabled | Disable entity substitution and DTD loading for untrusted XML | |
| input-parsing | JSON libraries: duplicate keys, large numbers, deep nesting | Check the library's documented behaviour; reject duplicates where a signature or check covers the object | Behaviour differs between libraries. |
| input-parsing | `std::filesystem::path` built from input; `lexically_normal` used as a security check | Resolve with `weakly_canonical` or `canonical`, then check the prefix; better, open relative to a directory handle | `lexically_normal` does not resolve symbolic links. |
| filesystem-process | `tmpnam`, `std::tmpnam`, predictable temp names | `mkstemp`, `mkdtemp`; on Windows `GetTempFileName` with care | |
| filesystem-process | `std::filesystem::exists` or `status` then open (TOCTOU); `remove_all` on paths an attacker can change | Open with `O_NOFOLLOW`, `openat` relative to a trusted directory descriptor | Check the library version's symlink behaviour for recursive operations. |
| crypto | `rand`, `std::rand`, `std::mt19937`, `std::default_random_engine` for tokens, keys, nonces | OS CSPRNG: `getrandom`, `BCryptGenRandom`, `RAND_bytes`, `randombytes_buf` | `std::random_device` is not required by the standard to be non-deterministic. |
| crypto | `==`, `memcmp`, `std::equal` on secrets | `CRYPTO_memcmp`, `sodium_memcmp` | |
| crypto | OpenSSL return values ignored (`EVP_*`, `X509_verify_cert`, `SSL_get_verify_result`) | Check every return value; fail closed | |
| outbound-network | `SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, ...)`; `ssl::context::set_verify_mode(ssl::verify_none)`; no host-name check | `SSL_VERIFY_PEER` plus `SSL_set1_host` or `X509_VERIFY_PARAM_set1_host`; Asio `ssl::host_name_verification` (older versions: `rfc2818_verification`) | |
| outbound-network | libcurl `CURLOPT_SSL_VERIFYPEER` or `CURLOPT_SSL_VERIFYHOST` set to 0; `CURLOPT_FOLLOWLOCATION` without protocol limits | Keep verification on; set `CURLOPT_PROTOCOLS_STR` and `CURLOPT_REDIR_PROTOCOLS_STR` | |
| resource-exhaustion | `std::regex` on untrusted input | A linear-time engine (RE2) or strict input length limits | Some `std::regex` implementations recurse per character and can overflow the stack. |
| resource-exhaustion | `reserve`, `resize`, `new T[n]` with `n` from input; recursive parsers without depth limits; `async_read_until` without a maximum size | Cap sizes before allocation; Beast `parser::body_limit` and `header_limit`; depth counters | |
| concurrency | shared objects behind `std::shared_ptr` used from several threads; Asio handlers that capture `this` | Synchronise the object, not only the pointer; capture `shared_from_this()` | `shared_ptr` reference counting is thread-safe; the pointee is not. |
| logging-privacy | `spdlog`, `fmt`, streams that log tokens, keys, request bodies | Redact at the logging call | |
| secrets-config | secrets in `constexpr` or string literals; `#ifdef DEBUG` or `#ifndef NDEBUG` branches that skip checks | Load secrets at run time; never compile security checks out | `assert` is removed when `NDEBUG` is defined. |
| client-trust | server RPC handlers that apply client values without validation (for example an empty Unreal `_Validate` function that returns `true`) | Validate and recompute on the server | |
| sandbox | embedded Lua, V8, wasmtime and similar hosts | See `domain-sandbox.md` and `lang-lua.md` | |

## Language traps

1. **Dangling views.** A `string_view` or `span` to a temporary dies at the end of the full expression.
   - Wrong: `std::string_view name = user.get_name();` when `get_name()` returns `std::string` by value.
   - Right: `std::string name = user.get_name();`
2. **Range-for over a temporary's member.** `for (auto& x : make_obj().items())` dangles before C++23. C++23 extends the lifetime of temporaries in the range initialiser. Check the language standard the project builds with.
3. **Iterator and reference invalidation.** `push_back`, `insert`, `erase`, `rehash` invalidate iterators, pointers or references, depending on the container.
   - Wrong: storing `&vec[0]` and then appending.
   - Right: store indices, or reserve and never grow while references exist.
4. **Coroutine and async lifetimes.** A coroutine that takes a parameter by reference can resume after the caller's object has died. An Asio handler that captures `this` or a local by reference can run after its owner is destroyed.
   - Wrong: `task<void> handle(const std::string& body)` called with a temporary.
   - Right: take parameters by value in coroutines; capture `shared_from_this()` in handlers.
5. **Signed overflow and undefined behaviour removing checks.** Signed overflow is undefined, so the compiler may delete an overflow check written after the overflow.
   - Wrong: `if (offset + len < offset) return error;` with signed values.
   - Right: `if (len > size - offset) return error;` with unsigned values and `offset <= size` checked first; or `__builtin_add_overflow`, `std::add_sat` (C++26), or checked arithmetic helpers.
6. **Signed and unsigned comparisons.** `int` compared with `size_t` converts the `int` to unsigned. A negative length becomes huge. Use `std::cmp_less` and related functions (C++20) or check signs first.
7. **`std::map::operator[]` inserts.** Reading `roles[user]` for an unknown user inserts a default value. If the default role or permission value is not the least privileged, this is an authorization defect (`domain-authz.md`).
   - Right: `find()` or `contains()` (C++20), then handle "not found" explicitly.
8. **Use after move.** Most moved-from standard types are "valid but unspecified". `std::unique_ptr` is null after a move, so later use dereferences null.
9. **Unchecked `optional` and `expected`.** `*opt` and `opt->` on an empty `std::optional` are undefined; the same holds for `*exp` on a `std::expected` (C++23) that holds an error. Error paths that forget the check become memory errors.
10. **Exceptions and partial state.** An exception between two updates of security state (for example after removing a role but before writing the audit record) leaves the object half-updated. An exception from a `noexcept` function or a destructor calls `std::terminate`, which is a denial of service if input can trigger it.
11. **Type punning and aliasing.** `reinterpret_cast<Header*>(buf)` breaks strict aliasing and alignment rules. Use `std::bit_cast` or `memcpy`; C++23 adds `std::start_lifetime_as` for some cases.
12. **Uninitialised variables.** Before C++26, reading an uninitialised automatic variable is undefined. C++26 makes it "erroneous behaviour" with an implementation-defined value unless the variable has `[[indeterminate]]`. Do not rely on either: it can still leak data or break logic.
13. **`assert` as a security check.** `assert` disappears when `NDEBUG` is defined, which most release builds do. C++26 contracts can also be ignored, depending on the evaluation semantic chosen at build time. Security checks must be ordinary code.
14. **Null to `std::string`.** Constructing `std::string` from a null `const char*` is undefined; C++23 deletes the `nullptr_t` constructor, but a null pointer variable still compiles.

## Deserialisation and reflection

- **Boost.Serialization and cereal** are not designed for untrusted input. Treat use on network or file input from other principals as a lead for `domain-input-parsing.md` and `domain-memory-safety.md`.
- **FlatBuffers:** accessing a buffer before running `flatbuffers::Verifier` on it is unsafe for untrusted data.
- **protobuf:** parsing is memory-safe by design, but check recursion limits, total size limits, unknown-field handling and `Any` type resolution.
- **Cap'n Proto:** check traversal and nesting limits in reader options.
- **Downcasts:** `static_cast<Derived*>(base)` on a type tag from input is type confusion if the tag is wrong. Use `dynamic_cast` with a null check, or validate the tag against the real object.
- **Plugins:** `dlopen`, `LoadLibrary`, `QPluginLoader` and `QLibrary` with paths from config or input: see `domain-filesystem-process.md` (search order) and `domain-supply-chain.md`.
- **C++26 static reflection** works at compile time. It does not add a run-time attack surface by itself.

## Concurrency

- **Data races are undefined behaviour,** not only wrong values. A race on a `std::string` or container can corrupt memory.
- `std::shared_ptr` copies are thread-safe; reads and writes of the same `shared_ptr` object are not, unless you use `std::atomic<std::shared_ptr<T>>` (C++20).
- `memory_order_relaxed` used to publish data that another thread then reads without synchronisation is a race.
- Function-local statics are initialised thread-safely (C++11); namespace-scope statics across translation units have unspecified initialisation order.
- Asio: handlers on one `strand` do not run concurrently; handlers on different strands or on a multi-threaded `io_context` without a strand can.
- `std::thread::detach` and fire-and-forget tasks can outlive the objects they use.
- Lock order: hold the same locks in the same order on every path; never call user callbacks while holding a lock.

## Build and runtime settings

Check the build files (CMake, Meson, Bazel, MSBuild, Makefiles) for these. Missing hardening is a hardening note, not a finding, unless it decides whether a confirmed defect is exploitable.

- **Library hardening:** `-D_GLIBCXX_ASSERTIONS` (libstdc++); `-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST` or `_EXTENSIVE` (libc++ 18 and later); recent Microsoft STL versions have a hardening option (check the toolset documentation). C++26 standardises a hardened library mode.
- **Compiler hardening:** `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3` (needs optimisation; level 3 needs glibc 2.34 or later with GCC 12 or later, or a recent Clang), `-fstack-clash-protection`, `-fcf-protection` (x86), `-ftrivial-auto-var-init=zero`, `-fPIE -pie`, `-Wl,-z,relro,-z,now`.
- **MSVC:** `/GS`, `/sdl`, `/guard:cf`, `/DYNAMICBASE`, `/HIGHENTROPYVA`, `/analyze`.
- **Warnings worth enabling for leads:** `-Wall -Wextra -Wconversion -Wsign-conversion -Wshadow -Wformat=2 -Werror=format-security`, Clang `-Wdangling` and `-Wdangling-gsl`, GCC 13+ `-Wdangling-reference`.
- **Semantics changes:** `-fwrapv` and `-fno-strict-overflow` define signed overflow; `-fno-exceptions` changes error paths (failures may abort instead of throwing); `-fno-rtti` disables `dynamic_cast` checks.
- **Release versus debug:** confirm which configuration ships. Checks inside `#ifndef NDEBUG` do not exist in release builds.

## Tools

Use the project's compile database if one exists. Generating it with `cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON` runs the project's CMake code (and can fetch dependencies through `FetchContent`), so it is target execution: follow `execution.md`.

- `clang-tidy -p build --checks='bugprone-*,cert-*,clang-analyzer-*,cppcoreguidelines-*,performance-*' <files>`
- `cppcheck --project=build/compile_commands.json --enable=warning,portability --inline-suppr`
- `scan-build cmake --build build` (Clang static analyser; runs the build, so T2)
- `semgrep --metrics=off --config <local rules>` with local C++ rules only
- CodeQL C++ queries, only if a database can be built offline
- Sanitizers (T2 only): `-fsanitize=address,undefined` with `-fno-sanitize-recover=all`; `-fsanitize=thread` for races; `-fsanitize=memory` (Clang, Linux) for uninitialised reads, which needs all code instrumented
- Fuzzing (T2 only): libFuzzer (`-fsanitize=fuzzer,address`), AFL++, honggfuzz with existing harnesses and corpora
- `valgrind --tool=memcheck` when sanitizers are not available

## Lead searches

| Regex | Meaning | False-hit notes |
|---|---|---|
| `\b(memcpy\|memmove\|strcpy\|strcat\|sprintf\|vsprintf\|gets)\s*\(` | C buffer operations | Check sizes against both buffers. |
| `string_view\s+\w+\s*=\s*[^;]*\(` | View initialised from a call result | Safe if the function returns a view of long-lived data. |
| `\[\s*\w+\s*\]` near `size\|len\|count\|index\|offset` from input | Unchecked indexing | Many are safe. Trace the index source. |
| `reinterpret_cast<\|static_cast<\w+\s*\*>` | Type punning and downcasts | |
| `\b(system\|popen\|_popen\|ShellExecute\w*\|CreateProcess\w*)\s*\(` | Process execution | Argument arrays are safer than shell strings. |
| `\b(rand\|srand\|mt19937\|default_random_engine\|minstd_rand)\b` | Non-cryptographic RNG | Fine for non-security uses. |
| `VERIFY_NONE\|verify_none\|SSL_VERIFYPEER,\s*0\|SSL_VERIFYHOST,\s*0` | TLS verification off | Check if test-only. |
| `\[this\]\|\[&\]` in callbacks passed to `async_\|post\|dispatch\|then\|std::thread` | Lifetime of captured objects | |
| `co_await\|co_return` in functions with `const \w+&` parameters | Coroutine reference parameters | |
| `assert\s*\(` on input, auth or bounds | Checks removed in release | |
| `\w+\s*\[\s*\w+\s*\]` on `std::map\|unordered_map` of roles, permissions, limits | Insert-on-read defaults | |
| `catch\s*\(\s*\.\.\.\s*\)` | Swallowed errors, possible fail-open | |
| `NOLINT\|cppcheck-suppress\|#pragma\s+(GCC\|clang)\s+diagnostic\s+ignored\|#pragma\s+warning\s*\(\s*disable` | Suppressed warnings (strong leads) | |
| `std::regex` | ReDoS or stack exhaustion | |
| `#if\s+0\|#ifdef\s+(DEBUG\|_DEBUG)\|#ifndef\s+NDEBUG` near auth or checks | Build-dependent security | |

## Verification notes

- **E3 is required** for memory-safety, lifetime, undefined-behaviour and race claims (SKILL.md section 6). Without T2, report them as needs-validation with a harness plan.
- **Smallest harness:** a GoogleTest, Catch2 or doctest case that calls the vulnerable function with the minimal input, or a libFuzzer entry point:
  ```cpp
  extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
      parse_frame(std::span<const uint8_t>(data, size));
      return 0;
  }
  ```
  Build with `-fsanitize=address,undefined -fno-sanitize-recover=all -g -O1`. Record the sanitizer report and the exact input.
- **Races:** use TSan with a test that forces the interleaving (barriers or latches). A single TSan run that passes proves nothing.
- **Authorization and logic defects in C++** follow the domain rules (often E1 is enough).
- **False positives:**
  - `operator[]` with an index proven in range on every path;
  - `string_view` to string literals or to data with static or owning-object lifetime that outlives the view;
  - "use after move" on types that document a defined moved-from state, when the code resets the object before use;
  - `rand` used for non-security purposes (jitter, sampling).
- **Hardened builds:** if the shipped build enables library hardening or `_FORTIFY_SOURCE`, a bounds defect may become a controlled abort. Report the defect and state the effect seen in the configured build (abort, which is availability impact, or corruption).
