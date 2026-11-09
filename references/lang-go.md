# Language: Go

## Scope
- Covers: Go 1.x modules, with version marks where behaviour changed (1.20, 1.21, 1.22, 1.24, 1.25); servers, command-line tools, Kubernetes-style controllers and cgo code.
- Common frameworks: `net/http` and `http.ServeMux`; gorilla/mux; chi; gin; echo; fiber; gRPC (`google.golang.org/grpc`); gorilla/websocket; `database/sql` with pgx, sqlx and GORM; cobra; `html/template` and `text/template`; golang-jwt.
- Domain link: Go is memory-safe except for `unsafe`, `cgo` and data races. Most findings are logic, input handling and resource defects.

## Entry points

- **Process start.** `func main()`, `flag.Parse`, `os.Args`, `os.Getenv`, `os.LookupEnv`, cobra `&cobra.Command{Run:` or `RunE:`, `init()` functions, `bufio.Scanner` on `os.Stdin`.
- **net/http.** `http.HandleFunc(`, `http.Handle(`, `mux.HandleFunc(`, `http.NewServeMux()`, `http.ListenAndServe(addr, nil)` (uses `DefaultServeMux`, which `net/http/pprof` and `expvar` also register on). Since Go 1.22, patterns can hold a method and wildcards (`"POST /items/{id}"`).
- **Routers.** gorilla/mux `r.HandleFunc(`, `r.PathPrefix(`; chi `r.Get(`, `r.Route(`, `r.Mount(`; gin `r.GET(`, `r.Group(`; echo `e.GET(`, `e.Group(`; fiber `app.Get(`, `app.Static(`.
- **Request data.** `r.URL.Query()`, `r.FormValue`, `r.PostFormValue`, `r.Form`, `r.Header`, `r.Body`, `r.Cookie`, `mux.Vars(r)`, `chi.URLParam`, `r.PathValue` (Go 1.22), gin `c.Param`, `c.Query`, `c.ShouldBind*`, `c.Bind*`, echo `c.Param`, `c.Bind`.
- **gRPC.** `pb.Register<Service>Server(`, `grpc.NewServer(` with `grpc.UnaryInterceptor` or `grpc.ChainUnaryInterceptor`. Stream interceptors are separate: a unary interceptor does not cover streams.
- **WebSocket.** `websocket.Upgrader{CheckOrigin: ...}` (gorilla). A `CheckOrigin` that returns `true` disables the same-origin check.
- **Network.** `net.Listen`, `Accept`, `net.ListenPacket`, `tls.Listen`.
- **Message consumers.** sarama `ConsumeClaim`, kafka-go `ReadMessage`, `nats.Subscribe`, `amqp` `Consume`, Pub/Sub `Receive`, `lambda.Start`.
- **Exports.** cgo `//export`, plugins loaded with `plugin.Open`.

For each route, find the middleware chain (`Use(`, `Group(`, `With(`, interceptors). Compare it with the route list.

## Sinks by domain

| Domain | Dangerous API or pattern | Safer alternative | Notes |
|---|---|---|---|
| injection | `db.Query(fmt.Sprintf(...))`, `db.Exec("..." + x)`; GORM `Where(fmt.Sprintf(...))`, `Raw(...)`, `Order(userInput)`; sqlx `NamedQuery` built by string | `db.Query("... $1", x)` or `?`; GORM `Where("a = ?", x)` | Column, table and sort names cannot be bound. Use an allow-list. |
| injection | `exec.Command("sh", "-c", s)`; `exec.Command(user, ...)`; `syscall.Exec` | `exec.Command("/usr/bin/tool", arg1, arg2)` | `exec.Command` searches `PATH` for a bare name. Since Go 1.19, a result from the current directory returns `ErrDot`. A user value that starts with `-` is an option for the tool. Put `--` before it when the tool supports it. |
| injection | `text/template` on HTML; `template.HTML`, `template.JS`, `template.URL`, `template.HTMLAttr` conversions of input; `template.New().Parse(userInput)` | `html/template` with plain strings | `text/template` can call exported methods of the data. Never parse a template from users. |
| injection | `w.Write([]byte(userInput))` with a content type of HTML | `html.EscapeString`; `html/template` | Go sets the type by sniffing if none is set (`http.DetectContentType`). Set it. |
| input-parsing | `json.Unmarshal` into a struct bound to a server model; `io.ReadAll(r.Body)`; `gob.NewDecoder(r.Body)` | DTO structs; `json.Decoder` with `DisallowUnknownFields`; `http.MaxBytesReader` | `encoding/json` matches field names case-insensitively. It keeps the last duplicate key. Numbers into `interface{}` become `float64` (`UseNumber` avoids this). |
| input-parsing | `archive/zip` and `archive/tar` names joined to a directory | Check each name with `filepath.IsLocal` (Go 1.20) | Since Go 1.20, `zip.NewReader` returns `zip.ErrInsecurePath` only when `GODEBUG=zipinsecurepath=0` is set. `archive/tar` has the same with `tarinsecurepath=0`. The default still reads such names. |
| input-parsing | `encoding/xml` with custom `Decoder.Strict = false`; `yaml.Unmarshal` to `interface{}` | Typed structs | `encoding/xml` does not resolve external entities. Expansion size is the risk. |
| filesystem-process | `filepath.Join(base, userPath)`; `strings.HasPrefix(p, base)`; `http.Dir`/`http.FileServer` on a directory with links; `os.Stat` then `os.Open`; `os.OpenFile(name, flags, 0666)`; `ioutil.TempFile` with fixed names | `os.Root` / `os.OpenRoot` (Go 1.24); `filepath.IsLocal`; check with `filepath.Rel`; `os.CreateTemp`, `os.MkdirTemp` | `filepath.Join("/srv", "../etc")` gives `/etc`. `filepath.Clean("/"+p)` removes leading `..`. `HasPrefix` accepts `/srv-evil`. `http.Dir` follows symbolic links. |
| filesystem-process | `os.Chmod` after create; `os.MkdirAll(p, 0777)`; `os.Setenv` in a shared process | Create with the final mode | The process `umask` still applies. |
| crypto | `math/rand` or `math/rand/v2` (Go 1.22) for tokens, nonces, IDs, keys | `crypto/rand` (`rand.Read`, `rand.Int`) | Since Go 1.20, `math/rand` is seeded randomly. It is still not secure. |
| crypto | `==`, `bytes.Equal`, `strings.EqualFold` on MACs, tokens, hashes | `subtle.ConstantTimeCompare`; `hmac.Equal` | |
| crypto | `crypto/md5`, `sha1`, `des`, `rc4`; `cipher.NewCBCDecrypter` without a MAC; reused GCM nonce; `bcrypt` input over 72 bytes | `cipher.NewGCM` with random nonces, or `cipher.NewGCMWithRandomNonce` (Go 1.24); `x/crypto/argon2`, `scrypt`, `bcrypt` | bcrypt uses only the first 72 bytes of the password. |
| crypto | golang-jwt `Parse` with a key function that does not check `token.Method`; `ParseUnverified` | `jwt.WithValidMethods([]string{"HS256"})`; check claims | Algorithm confusion. Handoff: `domain-authn.md`. |
| outbound-network | `tls.Config{InsecureSkipVerify: true}`; `VerifyPeerCertificate` that returns nil; `http.Get(userURL)`; `http.DefaultClient` (no timeout); default redirect following | Default verification; `http.Client{Timeout:..., CheckRedirect:...}`; a custom `net.Dialer` `Control` function that blocks private addresses | `InsecureSkipVerify` with a `VerifyConnection` callback may be safe. Read the callback. Proxy variables are read by `http.ProxyFromEnvironment`. |
| outbound-network | `net.Dial` after a check on a host name | Check the resolved IP in the dialer | DNS rebinding between check and dial. |
| authn / authz | A route outside the `Group` that has the middleware; `if err != nil { http.Error(...) }` without `return`; gRPC streams without a stream interceptor; gin `c.AbortWithStatus` followed by more code | Deny by default; `return` after every error write; `c.Abort()` and `return` | See the `http.Error` trap. |
| api | `c.ShouldBind(&model)` or `json.Decode(&model)` where `model` has server-owned fields | Request-only structs; `json:"-"` on server fields | Mass assignment. Handoff: `domain-api.md`. |
| web-client / http-protocol | `http.Cookie{}` without `Secure`, `HttpOnly`, `SameSite`; `r.Header.Get("X-Forwarded-For")`; gin without `SetTrustedProxies`; `http.Redirect(w, r, userURL, ...)`; CORS `AllowedOrigins: "*"` with credentials | Set every attribute; configure trusted proxies; allow-list redirects | gin trusts all proxies by default. `Request.FormValue` mixes query and body. `net/http.CrossOriginProtection` exists from Go 1.25. |
| resource-exhaustion | `http.Server{}` with no `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`; unbounded `r.Body`; `ParseMultipartForm(n)`; `gzip.NewReader` + `io.Copy`; `make([]T, n)`; goroutine per request with no limit; `time.After` in loops | Set timeouts and `MaxHeaderBytes`; `http.MaxBytesReader`; `io.LimitReader`; worker pools | `ParseMultipartForm(n)` limits memory, not total size. Excess spills to disk. `regexp` (RE2) runs in linear time, so ReDoS is rare. |
| logging-privacy | `log.Printf("%+v", req)`; `fmt.Sprintf("%v", cfg)`; logging `r.Header` or `r.URL` with tokens | Redact; log IDs | Structs with `String()` methods print secrets. |
| secrets-config | `os.Getenv("X")` default literal; `gin.DebugMode` (default unless `GIN_MODE=release`); `net/http/pprof` import; echo `e.Debug = true` | Fail on missing config; release mode | `import _ "net/http/pprof"` plus `ListenAndServe(":8080", nil)` exposes profiling. |
| data-lifecycle | `sync.Pool` buffers reused across requests without clearing; global caches keyed without tenant | Clear on `Put`; scoped keys | A pooled buffer can hold the previous request's data. |
| concurrency | Shared maps and counters; check-then-act across lock sections | `sync.Mutex`, `sync/atomic`, `errgroup` | See the Concurrency section. |
| sandbox | `plugin.Open`; embedded interpreters (Lua, JS, WASM hosts) with host functions | Narrow imports; limits | wazero and wasmtime-go have limits to set. Handoff: `domain-sandbox.md`. |
| messaging | Consumer that trusts a sender field inside the payload; no dedupe | Transport identity; idempotency | Handoff: `domain-messaging.md`. |
| memory-safety | `unsafe.Pointer`, `unsafe.Slice`, `reflect.SliceHeader`, cgo `C.GoBytes`, `C.CString` without `C.free`; `//go:linkname` | Safe code; copy with checks | Go's runtime checks bounds, so overflow needs `unsafe` or cgo. |
| supply-chain | `replace` directives; `go:generate` lines; `GOFLAGS=-mod=mod`; `GOINSECURE`; `GONOSUMDB`; `GOTOOLCHAIN` auto-switch | Vendor and verify `go.sum` | See Build and runtime settings. |
| business-logic / financial | `float64` for money; `int` arithmetic wrap; `time.Time` comparisons across zones | `big.Int`, `math/big`, decimal libraries; checked helpers | See the integer trap. |

## Language traps

- **`http.Error` does not stop the handler.** Execution continues after an error write.
  - Wrong: `if !ok { http.Error(w, "forbidden", 403) }` then the action runs.
  - Right: `if !ok { http.Error(w, "forbidden", 403); return }`
- **`err` shadowing.** `:=` in an inner block creates a new `err`. The outer `err` stays nil and the check passes.
  - Wrong: `if x { v, err := load() }` then `if err != nil` outside.
  - Right: declare `var err error` once and use `=`.
- **Ignored errors.** `_ = f.Close()`, `val, _ := strconv.Atoi(s)` and unchecked `rand.Read` hide failure. A zero value from a failed parse often means "allow" or "no limit". `crypto/rand.Read` is fatal on failure since Go 1.24, but code for older versions can ignore a short read.
- **Integer conversion.** `int` is 64 bits on most targets, but `int32(x)`, `uint32(x)` and `int(uint64)` wrap without error. `a + b` wraps. `strconv.Atoi` returns a platform `int`.
  - Wrong: `n := int32(len(buf)) + hdr`
  - Right: check `len(buf) <= math.MaxInt32-hdr` first.
- **Slices share memory.** `b := a[:2]; b = append(b, x)` can overwrite `a[2]`. Returning a sub-slice of a pooled or request buffer keeps the whole array alive and visible. Use `slices.Clone` (Go 1.21) or `copy`.
- **Typed nil in an interface.** `var p *MyErr = nil; var e error = p` gives `e != nil`. A check can pass or fail the wrong way. Return untyped `nil`.
- **Loop variable capture.** Before Go 1.22 (by the `go` line in `go.mod`), closures and goroutines in a `for` loop share one variable. All goroutines can see the last item or the wrong principal.
  - Wrong (go 1.21 or lower): `for _, u := range us { go func() { act(u) }() }`
  - Right: `u := u` inside the loop, or `go 1.22` in `go.mod`.
- **`defer` in a loop** runs at function exit, not at the end of each iteration. Locks and files stay open.
- **Maps.** Writing to a nil map panics. Concurrent map access is a fatal error that `recover` cannot catch. Iteration order is random: a security rule that depends on order is a bug.
- **Strings.** `len(s)` counts bytes. `for range s` yields runes and turns invalid bytes into U+FFFD. `strings.ToLower` and `EqualFold` apply Unicode rules. Normalise identifiers with `golang.org/x/text/unicode/norm` before comparison when two spellings must match.
- **`panic` and `recover`.** `net/http` recovers a panic in a handler, logs it and closes the connection. A panic in a goroutine that the code started ends the whole process. A `recover` that returns normally can skip an authorisation step: look at what the handler returns after recovery.
- **`context` cancellation.** `r.Context()` is cancelled when the client disconnects. Work in the middle of two writes stops half done. Without a transaction, state stays partial.
- **`path` versus `filepath`.** `path` uses `/`. `filepath` uses the OS separator. On Windows, `filepath.Join` and `Clean` treat `\` and drive names. Use `filepath.IsLocal` (Go 1.20) and, on Windows, check reserved names.
- **`url.Parse`.** `u.Host` can hold a port and user info is separate. Check `u.Hostname()`. Different parsers split odd URLs differently. Handoff: `domain-outbound-network.md`.

## Deserialisation and reflection

- **encoding/json and encoding/xml** do not run code. The risk is binding to the wrong struct, case-insensitive names, ignored unknown fields, large numbers, duplicate keys and very deep nesting.
- **encoding/gob** with `gob.Register` decodes into interface values by registered type name. Treat network gob as a resource and type-confusion lead.
- **YAML.** `gopkg.in/yaml.v2` and `v3` do not run code. Anchors and aliases can expand input.
- **Reflection.** `reflect.Value.MethodByName(name).Call(...)` with a name from input calls any exported method. `reflect.New` and `reflect.Value.Set` on fields from input are mass-assignment tools. `text/template` and many binders use reflection: a template can call exported methods on the data you pass.
- **Dynamic code.** `plugin.Open(path)` loads native code. `go:linkname` bypasses package visibility. cgo loads C libraries. `os/exec` can call `go run` on input.
- **Binders.** gin `ShouldBind`, echo `Bind`, GORM `Updates(map)` and `Updates(struct)` set whatever fields the input names. Check which fields are allowed. GORM `Updates(struct)` skips zero values, which can make "unset a flag" impossible but also hides intent.

## Concurrency

- **Primitives.** goroutines, channels, `sync.Mutex`, `sync.RWMutex`, `sync.Once`, `sync.WaitGroup`, `sync.Map`, `sync/atomic`, `errgroup`, `context`.
- **Data races.** A race on a map is a fatal error. A race on an interface, slice or string header can give torn values and memory corruption in practice. The Go memory model does not define the behaviour.
- **Check-then-act.** Handlers share global state. Two sections of one lock with a gap between them is a race. Example: `if !used[token] { ...; used[token] = true }` with separate locks. Handoff: `domain-concurrency.md`.
- **Request data in goroutines.** A goroutine that outlives the handler may read `r` or a pooled `*http.Request` after it is reused. Copy values first.
- **Leaks.** An unbuffered channel with no receiver blocks the goroutine for ever. `time.After` in a loop keeps timers alive until they fire. Both are resource-exhaustion leads.
- **RWMutex.** A write lock waits for readers. A reader that takes a nested read lock can deadlock if a writer is waiting.
- **Cancellation.** Cancelling a `context` does not stop code that ignores it. A cancelled request can leave a transaction open if `defer tx.Rollback()` is missing.
- **Shared state in middleware.** Per-request values stored in a package variable belong to all requests.
- **Detector.** `go test -race` finds only races that happen during the run.

## Build and runtime settings

- **Race detector.** `go test -race ./...`, `go run -race`, `go build -race`. It needs cgo on most platforms and slows the program by several times. It reports races that occur, not all possible races.
- **Module settings.** `go.mod` lines `go 1.xx` (sets loop variable semantics from 1.22 and other defaults) and `toolchain` (Go 1.21). The `go` command may download a newer toolchain: set `GOTOOLCHAIN=local` to stop that. `GOFLAGS=-mod=vendor` or `-mod=readonly` and `GOPROXY=off` keep builds offline. `go mod verify` checks the local module cache against `go.sum`.
- **Insecure module settings.** `GOINSECURE`, `GONOSUMDB`, `GOSUMDB=off` and `GOFLAGS=-mod=mod` weaken integrity. `replace` directives can point to local or forked code.
- **`GODEBUG`.** Compatibility settings such as `zipinsecurepath`, `tarinsecurepath` and others in `go.mod` `godebug` lines can restore older, weaker behaviour.
- **Sanitisers.** `go build -asan` and `-msan` (Go 1.18) check cgo and `unsafe` code. They need a C toolchain. `-gcflags=all=-d=checkptr` checks `unsafe.Pointer` rules (it is on with `-race`).
- **Build modes.** `-buildmode=pie`, `-trimpath`. `CGO_ENABLED=0` removes C code from the build.
- **Server defaults.** `http.Server` has no timeouts by default. `ListenAndServe(":8080")` binds all interfaces. `http.DefaultClient` has no timeout. TLS defaults: servers accept TLS 1.2 and later from Go 1.22; set `MinVersion` anyway. gin runs in debug mode unless `GIN_MODE=release`.
- **`go generate`.** It does not run during build. It is target code if someone runs it.

## Tools

Run only what is installed. `go build`, `go vet` and `go test` can compile and run cgo code and, for tests, run `init()` and test code. Treat them as target code and follow `execution.md`. `staticcheck` and `gosec` load packages the same way; without cgo they only read source. This list agrees with `phase-leads.md` section 2.1.

- **go vet.** `GOFLAGS=-mod=vendor GOPROXY=off go vet ./...` (without a vendor directory, use `GOFLAGS=-mod=mod GOPROXY=off` with a populated module cache).
- **staticcheck.** `staticcheck ./...`
- **gosec.** `gosec -no-fail -fmt=json -out gosec.json ./...`. Useful rule groups: subprocess launch, file inclusion, weak crypto, TLS settings, weak RNG, SQL string building, unhandled errors.
- **govulncheck.** Needs a vulnerability database. Offline form: `govulncheck -db file:///path/to/vulndb ./...`. Without a database, list versions from `go.sum` and `go list -m all` as leads.
- **Race detector.** `go test -race -count=1 -run <Test> ./pkg`.
- **Fuzzing.** `go test -run=^$ -fuzz=FuzzName -fuzztime=30s ./pkg` (Go 1.18). A fuzz target: `func FuzzParse(f *testing.F) { f.Add([]byte("seed")); f.Fuzz(func(t *testing.T, b []byte) { _, _ = Parse(b) }) }`.
- **Module checks.** `go mod verify`, `go list -m all`, `go list -deps ./...`.
- **Multi-language.** `semgrep --metrics=off --config <local rules>`.

## Lead searches

| regex | meaning | false-hit notes |
|---|---|---|
| `InsecureSkipVerify\s*:\s*true` | TLS verification off | Test files; or a `VerifyConnection` callback does the check. |
| `exec\.Command(Context)?\(` | Process creation | Check the program, arguments and `sh -c`. |
| `(Query\|Exec\|QueryRow\|Raw\|Where\|Order)\w*\(.*(fmt\.Sprintf\|\+\s*\w)` | SQL built by string | A constant fragment is a false hit. |
| `filepath\.Join\(.*(r\.\|req\.\|c\.\|Param\|Query\|Name)` | Path from input | Check `..`, absolute and prefix tests. |
| `strings\.HasPrefix\(.*(path\|Path\|dir\|Dir)` | Prefix test on a path | Real only if no separator check follows. |
| `math/rand` | Weak RNG | False hit if the value has no security role. |
| `http\.Error\([^)]*\)\s*$` | Error write; look at the next line for `return` | Last statement of a function is fine. |
| `, _ :?= \|_ = ` | Ignored error | Many are fine (`Close` on read). Look at security calls. |
| `template\.(HTML\|JS\|URL\|HTMLAttr\|CSS)\(` | Escape bypass | Constants are false hits. |
| `net/http/pprof\|expvar` | Debug endpoints | Check that the listener is not public. |
| `CheckOrigin\s*:\s*func.*return true` | WebSocket origin check off | A token-based, non-cookie flow can make this fine. |
| `http\.(Get\|Post\|Head\|DefaultClient)` | Client with no timeout | Check the URL source for SSRF. |
| `&http\.Server\{\|http\.ListenAndServe` | Server without timeouts | Look for `ReadHeaderTimeout`. |
| `unsafe\.\|reflect\.(SliceHeader\|StringHeader)\|go:linkname` | Memory-unsafe code | Look at the bounds logic. |
| `//\s*nolint\|#nosec\|//\s*lint:ignore` | Silenced tool | A suppressed warning is a strong lead. Read why. |
| `go func\(\)` | Goroutine start | Check captured variables (go before 1.22), lifetime and shared state. |
| `ShouldBind\|\.Bind\(\|Unmarshal\(.*&\w*(user\|account\|model)` | Binding into a model | Check for server-owned fields. |

## Verification notes

- **Smallest harness.** A `_test.go` file in the package. Use `net/http/httptest`: `rr := httptest.NewRecorder(); h.ServeHTTP(rr, httptest.NewRequest("POST", "/path", body))`, then assert the status and side effects. Run `go test -run TestName -count=1 ./pkg`. No server or network is needed. For authorisation, build two dummy principals and a resource owned by one.
- **Middleware claims.** Build the real router in the test and send a request to each route without credentials and with a lower role. This also shows registration-order and group mistakes.
- **Path claims.** Call the function with `../` input in a temporary directory (`t.TempDir()`). Assert that no file outside it is read.
- **Race claims.** Needs E3. Run the test with `-race` and two goroutines that call the conflicting paths in a loop. The race report names the lines. For a logic race with no data race, show the interleaving with a channel-based hook or a sleep in the test copy.
- **Panic claims.** Show the panic in a test. State whether `net/http` recovers it (handler goroutine) or not (own goroutine). A recovered panic is low impact.
- **Integer claims.** A test with the boundary value and the converted result.
- **`unsafe` and cgo claims.** Needs E3: `go test -asan` or `-race` (with checkptr) and the failing input.
- **False positives.**
  - `InsecureSkipVerify` with a custom verification callback, or in test code.
  - `math/rand` for jitter or load balancing.
  - SQL with only constant or allow-listed fragments.
  - `http.Error` as the last statement.
  - `HasPrefix` followed by a separator check.
  - gosec rules on test files and `Close` errors.
- **What E1 can prove.** A missing `return` after `http.Error`, a route outside the middleware group, a disabled TLS check in the default configuration, SQL built from request fields, and a binder into a model with server-owned fields. State the layers you read in the reproduction waiver.
