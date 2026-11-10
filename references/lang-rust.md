# Language: Rust

## Scope
- Covers: Rust 2018, 2021 and 2024 editions (the 2024 edition needs Rust 1.85 or later); `std`, `no_std` and embedded targets; `unsafe` code and FFI; WebAssembly targets.
- Common frameworks: tokio; axum, actix-web, Rocket, warp, hyper and tower; tonic (gRPC); serde; clap; sqlx and diesel; reqwest; rustls and the RustCrypto crates; ring; askama, tera and maud templates; wasmtime.
- Domain link: `domain-memory-safety.md` owns `unsafe` and FFI attack logic. Safe Rust removes most memory errors. The remaining risk is in `unsafe`, logic, panics, arithmetic and the crates the project uses.

## Entry points

- **Process start.** `fn main`, `#[tokio::main]`, `std::env::args`, `std::env::var`, `clap` types with `#[derive(Parser)]`, `std::io::stdin`.
- **axum.** `Router::new().route("/path", get(handler))`, `.nest(`, `.merge(`, extractors in handler arguments: `Json<T>`, `Path<T>`, `Query<T>`, `Form<T>`, `Multipart`, `HeaderMap`.
- **actix-web.** `App::new().route(`, `web::resource(`, `web::scope(`, `#[get("/")]`, `#[post("/")]`, `.configure(`, extractors `web::Json`, `web::Path`, `web::Query`, `web::Payload`.
- **Rocket.** `#[get("/")]`, `#[post("/", data = "<x>")]`, `routes![...]`, request guards (types that implement `FromRequest`).
- **warp.** `warp::path(`, `.and(warp::body::json())`, `warp::header`.
- **hyper and tower.** `service_fn`, `impl Service<Request<...>>`, `hyper::server::conn`.
- **tonic.** `#[tonic::async_trait]` with `impl <Service> for`, `Server::builder().add_service(`, interceptors.
- **Consumers.** `rdkafka` consumers, `lapin` `basic_consume`, `async-nats` `subscribe`, `redis` pub/sub, `aws_lambda_events` with `lambda_runtime::run`.
- **Exports.** `pub extern "C" fn` with `#[no_mangle]` (`#[unsafe(no_mangle)]` in edition 2024), `#[wasm_bindgen]`, `#[pyfunction]` (PyO3), `#[napi]`, `#[proc_macro]`.
- **Build time.** `build.rs` and procedural macros run code at build time. They are entries for `supply-chain`.

For each route, list the extractors. The extractors decide what the attacker controls. Then check the layers that apply to the route (see Language traps, the layer-order trap).

## Sinks by domain

| Domain | Dangerous API or pattern | Safer alternative | Notes |
|---|---|---|---|
| memory-safety | `unsafe` blocks; `get_unchecked`, `get_unchecked_mut`, `slice::from_raw_parts`, `from_raw_parts_mut`, `transmute`, `MaybeUninit::assume_init`, `Vec::set_len`, `str::from_utf8_unchecked`, `ptr::read`, `ptr::write`, `Box::from_raw`, `static mut`, `unsafe impl Send` or `Sync` | Safe indexing, `get`, `chunks`, `bytemuck` with `Pod` checks, `zerocopy` | Read the safety comment. Check that every caller meets the stated invariant. |
| memory-safety | `extern "C"` declarations and callbacks; `CString::from_raw`; pointers passed to C | `CStr::from_ptr` after a check; copy data in | Wrong signatures in `extern` blocks are undefined behaviour. A panic unwinding out of `extern "C"` aborts since Rust 1.81. |
| injection | `Command::new("sh").arg("-c").arg(user)`; `Command::new(user)` | `Command::new("/usr/bin/tool").arg(user)` with separate arguments | `Command::new` searches `PATH` for a bare name. On Windows before Rust 1.77.2, arguments to `.bat` and `.cmd` files were not escaped correctly. |
| injection | `sqlx::query(&format!(...))`; diesel `sql_query(format!(...))`; string-built `ORDER BY` | `sqlx::query("... $1").bind(x)`; `query!` macros; diesel query builder | Column and table names cannot be bound. Use an allow-list. |
| injection | askama `\|safe`; tera `\| safe`; maud `PreEscaped`; leptos `inner_html`; yew `Html::from_html_unchecked` | Default escaping | askama and tera escape HTML by default for `.html` templates. Check templates with other extensions. |
| input-parsing | `serde` into structs without `#[serde(deny_unknown_fields)]`; `#[serde(untagged)]`; `#[serde(flatten)]`; `String::from_utf8_lossy` on identifiers; `&s[a..b]` byte slices | Typed DTOs; `deny_unknown_fields`; `str::get(a..b)` | Slicing a `str` off a character boundary panics. Duplicate JSON keys: structs reject them, maps keep the last. |
| input-parsing | `tar::Archive::unpack`; `zip::ZipArchive::extract`; manual `Path::join(entry_name)` | `ZipFile::enclosed_name()`; check each component | `Path::join` with an absolute second argument replaces the base path. |
| filesystem-process | `Path::join(user)`, `PathBuf::push(user)`; `starts_with` on unresolved paths; `fs::metadata` then `fs::open`; `File::create` with default mode | `canonicalize` then check; `cap-std` for directory-scoped access; `OpenOptions` with `create_new(true)`; `std::os::unix::fs::OpenOptionsExt::mode` | `Path::starts_with` compares components, not text. It does not resolve `..` or links. |
| filesystem-process | `std::env::temp_dir()` with a fixed file name | `tempfile::NamedTempFile`, `tempfile::tempdir` | A fixed name in a shared directory is a link-attack lead. |
| crypto | `rand::rngs::SmallRng`; `fastrand`; time-seeded generators | `rand::rngs::OsRng`, `getrandom`, `rand::rngs::StdRng` seeded from the OS | `thread_rng()` (rand 0.8, `rng()` in 0.9) is a CSPRNG, but check the crate version. |
| crypto | `==` on MACs, tags and tokens; AES-GCM with a counter or a repeated nonce; `md5`, `sha1` for integrity | `subtle::ConstantTimeEq`; `hmac` `verify_slice`; fresh random nonces or `ring::aead` sequences | Check that `verify` results are not discarded. A `Result` that is dropped with `let _ =` hides failure. |
| outbound-network | `reqwest::ClientBuilder::danger_accept_invalid_certs(true)`; `danger_accept_invalid_hostnames(true)`; rustls `dangerous()` with a custom verifier that accepts all; `native_tls` `danger_accept_invalid_certs` | Default verification | `dangerous_configuration` was the feature name in older rustls. |
| outbound-network | `reqwest::get(user_url)`; default redirect policy (follows up to 10); proxy from the environment | `redirect::Policy::none()`; `.no_proxy()`; resolve and check addresses; set `.timeout()` | `reqwest` has no overall timeout by default. |
| authn / authz | Middleware order; `Router::layer` after `route`; Rocket route without the guard argument; actix scope without `.wrap(` | `route_layer`; put the check in an extractor that every handler must name | See the layer-order trap. |
| api | `Json<DbModel>` bound straight into an update; `#[serde(flatten)]` with a server-owned struct | A DTO with fixed fields; `#[serde(skip_deserializing)]` on server-owned fields | Mass assignment. Handoff: `domain-api.md`, `domain-authz.md`. |
| web-client / http-protocol | `CorsLayer::permissive()` and `very_permissive()` (tower-http); `actix_cors::Cors::permissive()`; cookies built without `secure`, `http_only` and `same_site` | Explicit origin lists and cookie attributes | Defaults depend on the crate. Read the builder. |
| resource-exhaustion | `Vec::with_capacity(n)` and `vec![0; n]` with `n` from input; `read_to_end`, `read_to_string` on a stream; `mpsc::unbounded_channel`; recursive descent without depth limit; `Regex::new(user)` | `Read::take(limit)`; bounded channels; depth counters; body-limit layers (`axum::extract::DefaultBodyLimit`, tower-http `RequestBodyLimitLayer`) | The `regex` crate runs in linear time. `fancy-regex` can backtrack. Stack overflow aborts the process. |
| logging-privacy | `#[derive(Debug)]` on types with secrets; `tracing::instrument` without `skip`; `{:?}` of requests | `secrecy::SecretString`; `#[instrument(skip(...))]`; manual `Debug` | `#[instrument]` records all arguments by default. |
| secrets-config | `env::var` with a fallback to a literal key; `cfg!(debug_assertions)` toggles; `dotenvy` in release | Fail when the variable is missing | A default value that disables a check is a lead. |
| concurrency | See the Concurrency section | | |
| sandbox | wasmtime `Engine` without `Config::consume_fuel` or `epoch_interruption`; host functions that give file or network access | Fuel or epoch limits; narrow host imports (WASI preopened directories only) | Handoff: `domain-sandbox.md`. |
| supply-chain | Git dependencies; `[patch]` and `[replace]`; `build.rs` that downloads; `*` version requirements | `Cargo.lock` committed; `cargo build --locked` | Proc macros run arbitrary code in the build. |
| embedded / kernel | `#![no_std]` code with `unsafe` register access; `core::ptr::read_volatile` on peer data | Typed register wrappers | Handoff: `domain-embedded.md`, `domain-kernel.md`. |
| business-logic / financial | Plain `+`, `-`, `*` on money and counts; `as` casts; `f64` for money | `checked_add`, `checked_mul`, `saturating_*`; `TryFrom`; `rust_decimal` | See the arithmetic trap. |
| messaging | Consumer that trusts a sender field inside the payload | Identity from the transport | Handoff: `domain-messaging.md`. |

## Language traps

- **Arithmetic wraps in release builds.** With default profiles, `+` panics on overflow in debug builds and wraps in release builds.
  - Wrong: `let total = qty * unit_price;` on `u32`
  - Right: `let total = qty.checked_mul(unit_price).ok_or(Error::Overflow)?;`
- **`as` casts truncate and saturate without error.** `u64 as u32` drops bits. `-1i32 as usize` is a huge value. `f64 as u8` saturates. Use `u32::try_from(x)?`.
- **`debug_assert!` is removed in release builds.** A security check in `debug_assert!` is absent in production. `assert!` stays.
- **`unwrap`, `expect`, indexing and slicing panic.** `v[i]`, `&s[a..b]`, `x / 0`, `RefCell::borrow_mut` twice and `Duration` subtraction below zero panic. A panic on attacker input is a denial-of-service lead. Its impact depends on the panic setting (see Build and runtime settings).
- **Panic as fail-open.** A `catch_unwind` or a task wrapper that logs a panic and continues may skip a security step. Check what state remains.
- **Dropped `Result`.** `let _ = check(x);` ignores a failed check. The `#[must_use]` warning does not fire for `let _ =`.
  - Wrong: `let _ = verify(sig, msg);`
  - Right: `verify(sig, msg)?;`
- **Layer order in axum.** `Router::layer` wraps only the routes added before the call. Routes added after it are not covered.
  - Wrong: `Router::new().route("/a", h).layer(auth).route("/admin", admin)`
  - Right: add `.layer(auth)` after all routes, or use `route_layer` per group, and test each route.
- **`Path::join` with an absolute path** replaces the base: `Path::new("/srv").join("/etc/passwd")` is `/etc/passwd`. Reject absolute input and `..` components.
- **`Instant` and `SystemTime`.** `SystemTime` can go backwards. `duration_since` returns `Err`. Code that unwraps it panics, or treats the error as zero.
- **String bytes versus characters.** `len()` counts bytes. `to_lowercase` follows Unicode rules and can change length. Use `eq_ignore_ascii_case` for ASCII identifiers. Normalise with the `unicode-normalization` crate before comparison when identities must match.
- **`mem::forget` and `ManuallyDrop`** skip destructors. Locks, guards and zeroise-on-drop wrappers may not run.
- **Interior unsafety.** A safe function that wraps `unsafe` can break its contract through public fields, `Drop` order or a panic in the middle. Read panic paths inside `unsafe` code (leaks and double drops).
- **Edition 2024.** `unsafe_op_in_unsafe_fn` warns by default. `static mut` references are denied by default (`static_mut_refs`). `extern` blocks need `unsafe extern`.

## Deserialisation and reflection

- **serde is data only.** Standard serde formats do not run code. Risks are type confusion, size and logic: `#[serde(untagged)]` tries variants in order; `#[serde(flatten)]` merges fields and can accept extra keys; unknown fields are ignored by default; numbers can exceed expected ranges.
- **Size limits.** `bincode` needs a limit on lengths (bincode 1.x: `DefaultOptions::new().with_limit(n)`). A length prefix of `u64::MAX` in a `Vec` field asks for a huge allocation. `serde_json` has a recursion limit of 128 by default. The `disable_recursion_limit` feature removes it.
- **Trait objects by name.** The `typetag` crate deserialises `Box<dyn Trait>` by a type name in the input. Check that every registered type is safe for untrusted data.
- **Zero-copy formats.** `rkyv` access functions without validation (`archived_root` in 0.7, `access_unchecked` in 0.8) trust the bytes. Use the checked forms. `bytemuck` and `zerocopy` need types where every bit pattern is valid.
- **YAML and other formats.** `serde_yaml` has no tag-based code execution, but anchors can expand input (a size lead). Treat each format crate's version and status as a lead.
- **Dynamic loading.** `libloading::Library::new(path)` and `.get(name)` run native code. Check where `path` comes from.
- **Reflection.** `std::any::Any::downcast_ref` and `TypeId` are type checks, not name lookups. There is no `eval`. `include!`, `include_str!` and `env!` read at compile time.

## Concurrency

- **What the type system gives.** `Send` and `Sync` stop data races in safe code. They do not stop logic races such as check-then-act.
- **Lock across await.** A `std::sync::Mutex` guard held across `.await` can deadlock the runtime, or make the future `!Send`. A `tokio::sync::Mutex` guard held across a slow call blocks every task that needs the lock.
- **Check-then-act across await.** Code that reads a permission or a balance, awaits, then writes uses stale state. Handoff: `domain-concurrency.md`.
- **Cancellation.** Dropping a future cancels it at its last `.await`. `tokio::select!` drops the losing branches. Code that updates state in two steps can stop between them. The tokio documentation marks which methods are cancel-safe. A spawned task (`tokio::spawn`) keeps running after its caller is gone, unless the code aborts the `JoinHandle`.
- **Poisoning.** `std::sync::Mutex` is poisoned when a thread panics with the guard held. `lock().unwrap()` then panics on every later call. `parking_lot::Mutex` has no poisoning: the data may be half-updated after a panic.
- **Atomics.** `Ordering::Relaxed` on a flag that guards other data gives no ordering. `load` then `store` on an `AtomicBool` is a race. Use `compare_exchange` or `swap`.
- **Blocking in async.** Blocking calls (`std::fs`, `std::thread::sleep`, heavy hashing) in an async task stall the worker. Use `spawn_blocking`. Handoff: `domain-resource-exhaustion.md`.
- **Unbounded queues.** `unbounded_channel` grows without limit when the producer is faster.
- **Lock order.** Two locks taken in different orders deadlock.

## Build and runtime settings

- **Profile settings (`Cargo.toml`).**
  - `[profile.release] overflow-checks = true` makes release builds panic on overflow. Its absence means wrapping arithmetic.
  - `debug-assertions` decides whether `debug_assert!` runs.
  - `panic = "abort"` ends the process on any panic. `panic = "unwind"` (default) lets tasks and threads catch it. Under `abort`, one attacker input can stop the service.
  - `lto`, `strip` and `opt-level` change binaries, not security logic.
- **Source-level lints.** `#![forbid(unsafe_code)]` blocks `unsafe` in a crate. `#![deny(unsafe_op_in_unsafe_fn)]`. A workspace may allow `unsafe` in some crates only.
- **Compiler flags.** `RUSTFLAGS="-D warnings"`. `-Zsanitizer=address` (and `thread`, `memory`) needs a nightly toolchain, often with `-Zbuild-std`.
- **Network and lock files.** `cargo build --locked --offline` uses `Cargo.lock` and the local registry cache only. A missing crate then fails instead of downloading.
- **`unsafe` count.** A project with many `unsafe` blocks, or with a dependency that has them, needs a larger memory-safety share of the budget.
- **Insecure defaults.** `reqwest` follows redirects and reads proxy variables. axum sets no request timeout by default. Cookie crates do not set `Secure` or `HttpOnly` unless asked. Debug logging of request bodies is on in some templates. `cfg(debug_assertions)` code that skips authentication must not reach release.
- **Features.** Cargo features can turn on `danger`-named options or test code. List the default features of security-relevant crates.

## Tools

Run what is installed, plus tools the user approved in phase 0 (`execution.md` section 5.1). `cargo build`, `cargo check`, `cargo clippy` and `cargo test` run `build.rs` and procedural macros. These are target code: follow `execution.md` before you run them. `cargo audit` and `cargo deny check advisories` read `Cargo.lock` and run no target code: they are T1, so a missing one is `absent` or `absent-declined`, not `T2-skipped`. This list agrees with `phase-leads.md` section 2.1.

- **clippy.** `cargo clippy --offline --locked --all-targets -- -W clippy::unwrap_used -W clippy::indexing_slicing -W clippy::arithmetic_side_effects -W clippy::cast_possible_truncation -W clippy::undocumented_unsafe_blocks`. The `unwrap_used`, `indexing_slicing`, `arithmetic_side_effects` and `undocumented_unsafe_blocks` lints are in the restriction group. They are noisy. Group the results.
- **cargo-geiger.** `CARGO_NET_OFFLINE=true cargo geiger` counts `unsafe` per crate. Use it to rank crates.
- **cargo-audit.** `cargo audit --no-fetch --db <local advisory-db path>`. Without a local database, list pinned versions from `Cargo.lock` as leads.
- **cargo-deny (if present).** `cargo deny check --disable-fetch` (needs a local advisory database).
- **Miri.** `cargo +nightly miri test` finds undefined behaviour in `unsafe` code. It needs the nightly toolchain and the Miri component. The first setup downloads a sysroot. Ask first.
- **Fuzzing.** `cargo fuzz run <target>` (cargo-fuzz; nightly; libFuzzer). Target shape: `fuzz_target!(|data: &[u8]| { let _ = parse(data); });`.
- **Concurrency models.** The `loom` crate runs a test under many thread interleavings.
- **Property tests.** `proptest` or `quickcheck` for arithmetic and parser invariants.
- **Multi-language.** `semgrep --metrics=off --config <local rules>`.

## Lead searches

| regex | meaning | false-hit notes |
|---|---|---|
| `\bunsafe\b` | `unsafe` block, function or impl | Many are sound. Check the safety comment and each caller. |
| `\.(unwrap\|expect)\(` | Panic on error | Only a lead when the value depends on input. Tests and start-up code are false hits. |
| `\bas\s+(u8\|u16\|u32\|i8\|i16\|i32\|usize\|isize)\b` | Truncating or sign-changing cast | Safe if the range is proven. |
| `\bCommand::new\(` | Process creation | Check the program name, the arguments and `sh -c`. |
| `format!\(.*(SELECT\|INSERT\|UPDATE\|DELETE\|WHERE)` | SQL built by string | Constant fragments are false hits. |
| `danger_accept\|dangerous\(\)\|set_verify\|no_verify` | TLS verification weakened | Check that test code is not in the release build. |
| `\.join\(\|PathBuf::push\|Path::new\(` | Path from input | Check absolute paths and `..`. |
| `from_utf8_unchecked\|from_raw_parts\|get_unchecked\|transmute\|set_len\|assume_init` | Unchecked memory operation | See the `unsafe` row. |
| `debug_assert` | Check absent in release | A false hit if it guards only an internal invariant. |
| `let _ = .*(verify\|check\|auth\|validate\|decrypt)` | Dropped security result | Read the callee. |
| `Ordering::Relaxed` | Weak memory order | Fine for counters. A lead for flags that guard data. |
| `unbounded_channel\|unbounded\(\)` | Unbounded queue | Check the producer rate. |
| `#\[allow\(\|#!\[allow\(` | Silenced lint | A suppressed warning is a strong lead. Read why. |
| `permissive\(\)\|Any\b.*allow_origin\|allow_credentials` | Open CORS | Check whether cookies or tokens are in use. |
| `(rand::random\|SmallRng\|fastrand).*(token\|key\|nonce\|secret\|id)` | Weak RNG | Check the use of the value. |
| `typetag\|libloading\|archived_root\|access_unchecked\|disable_recursion_limit` | Risky deserialisation or loading | See the Deserialisation section. |

## Verification notes

- **Smallest harness.** A `#[test]` in the crate (or a test in `tests/`) that calls the function with the attacker input and asserts the safe result. Run `cargo test <name> --offline --locked`. For authorisation defects, build two dummy principals and assert deny.
- **Arithmetic claims.** Run the test in both profiles: `cargo test` and `cargo test --release`. Debug builds panic on overflow, release builds wrap. State which profile the product ships.
- **Panic claims.** Use `std::panic::catch_unwind` or `#[should_panic]` to show the panic. Then read the profile: with `panic = "abort"` the process stops. With `unwind`, a tokio task or an actix worker usually survives. Say which. A panic that kills one request is low impact.
- **`unsafe` claims.** Needs E3. Run the test under Miri (`cargo +nightly miri test`) or with `-Zsanitizer=address`. The Miri report is the evidence. A passing run is not proof.
- **Race claims.** Needs E3. Use `loom`, or a test that repeats the two calls in threads. State the interleaving.
- **Fuzz claims.** Keep the crashing input as a test file.
- **False positives.**
  - `unsafe` code whose invariant a safe wrapper enforces.
  - `unwrap` on a value that the code proved earlier, or on a literal.
  - Arithmetic bounded by a type or an earlier check.
  - Panics in test, example or build code.
  - A weak RNG used for a non-security purpose such as jitter.
- **What E1 can prove.** A disabled TLS verification in the default configuration; a route added after a layer in axum; a `Json<Model>` that binds server-owned fields; a dropped verification result. These need no runtime facts when the source shows the full path.
