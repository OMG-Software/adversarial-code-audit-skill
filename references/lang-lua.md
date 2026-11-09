# Language: Lua

## Scope
- Covers: Lua 5.1 to 5.4 and LuaJIT 2.x (5.1 semantics plus FFI), as embedded in a host program. The host decides which libraries and functions a script can reach. Luau has its own sandbox model and is out of scope.
- Common hosts and frameworks: nginx with OpenResty or `lua-nginx-module`, Redis `EVAL` scripts, game engines and game servers with mod or script support, editors and tools with Lua configuration, LÖVE. Lua used as a configuration format is code execution.

## Entry points
The host defines the entry points. Read the host code first, then the scripts.

- **Host registration (C or C++):** `lua_register`, `lua_pushcfunction`, `lua_setglobal`, `luaL_newlib`, `luaL_register`, `luaL_setfuncs`, `lua_newuserdata`. Each registered function is an API that attacker-controlled scripts or script data can call.
- **Library opening:** `luaL_openlibs` opens every standard library, including `io`, `os`, `debug` and `package`. `luaL_requiref` and `luaopen_*` open selected libraries. Record which libraries each Lua state gets.
- **Script loading:** `luaL_loadfile`, `luaL_loadbuffer`, `luaL_loadbufferx`, `luaL_dostring`, `luaL_dofile`, `lua_load`, and Lua `load`, `loadstring`, `loadfile`, `dofile`, `require`.
- **Event and command callbacks in scripts.** Names depend on the host. Search for registration idioms: `(Register|Add)\w*(Event|Handler|Command|Listener|Callback)`, `hook\.Add`, `net\.Receive`, `RegisterNetEvent`, `on_[a-z_]+\s*=`, `function\s+on[A-Z_]`. Events that a client or player can trigger are untrusted input.
- **OpenResty phases:** `init_by_lua*`, `init_worker_by_lua*`, `set_by_lua*`, `rewrite_by_lua*`, `access_by_lua*`, `content_by_lua*`, `balancer_by_lua*`, `header_filter_by_lua*`, `body_filter_by_lua*`, `log_by_lua*`, `ssl_certificate_by_lua*`. Input: `ngx.req.get_uri_args`, `ngx.req.get_post_args`, `ngx.req.get_headers`, `ngx.req.get_body_data`, `ngx.req.get_body_file`, `ngx.var.*` (`arg_*`, `http_*`, `uri`, `request_uri`), `ngx.socket.tcp`.
- **Redis:** `EVAL` bodies, `KEYS` and `ARGV`.
- **Configuration code:** `dofile("config.lua")`, `require "settings"`, files in writable mod directories.

## Sinks by domain

| Domain | Dangerous API or pattern | Safer alternative | Notes |
|---|---|---|---|
| `sandbox` | `load` or `loadstring` of script text, `dofile`, `loadfile`, `require` of a name from input, `package.loadlib` | `load(s, name, "t", env)` with an allow-list `env` (5.2+). On 5.1 and LuaJIT: `loadstring` then `setfenv(f, env)`. | `mode "t"` blocks binary chunks. 5.1 `loadstring` has no `env` argument. |
| `sandbox` | `debug.*` (`getinfo`, `getupvalue`, `setupvalue`, `upvaluejoin`, `setmetatable`, `getregistry`, `sethook`), `getfenv`, `setfenv`, `rawset` on shared tables | Do not give `debug` to untrusted code | `debug` can reach any function and upvalue. |
| `sandbox` | `getmetatable("")` | Remove `getmetatable` or return a copy of `string` | The string metatable is shared by all code in the state. Changing `string` changes every script. |
| `injection` | `os.execute`, `io.popen` with concatenated text | Do not expose; fixed command with checked arguments | No argument array exists for these calls. They use the shell. |
| `injection` | SQL by concatenation with driver `query` (for example pgmoon `db:query`, lua-resty-mysql `db:query`, LuaSQL `conn:execute`) | Driver escape functions (`escape_literal`, `escape_identifier`, `ngx.quote_sql_str`) or prepared statements where the driver has them | Identifier names need an allow-list. |
| `injection` | Redis `EVAL` with script text built from input | Pass values in `KEYS` and `ARGV` | |
| `injection` | Template engines that run Lua (lua-resty-template `{* expr *}` raw output and code blocks) | Escaped output form, fixed templates | Template text is code. |
| `injection` | `string.find`, `match`, `gmatch`, `gsub` with a pattern from input | Plain find (`string.find(s, p, 1, true)`), escape `%` | Lua patterns are not regular expressions. They can be slow (see `resource-exhaustion`). |
| `input-parsing` | `cjson.decode`, `tonumber`, `string.unpack`, `string.byte` loops, host parsers fed by Lua strings | Validate types after decode | See the traps section. |
| `filesystem-process` | `io.open`, `io.lines`, `os.remove`, `os.rename`, `os.tmpname`, `io.tmpfile`, `os.getenv`, `os.exit` with input-derived paths | Host file API that resolves under a base directory | `os.tmpname` returns a name only (5.1 to 5.3 on POSIX). Race risk. |
| `outbound-network` | `ngx.socket.tcp():sslhandshake(...)` with `ssl_verify` false (the default), `resty.http` with `ssl_verify = false`, URL from input | Pass `ssl_verify = true`, set `lua_ssl_trusted_certificate` and `lua_ssl_verify_depth` | Check the version of each HTTP library for its default. |
| `crypto` | `math.random`, `math.randomseed(os.time())` for tokens or keys | `resty.random.bytes`, `resty.openssl.rand` (OpenResty), reading `/dev/urandom` in binary mode | Lua 5.4 seeds `math.random` randomly at start. It is still not a secure generator. |
| `authn` / `authz` | Truthiness checks on numbers and JSON null, `pcall(check)` as a result, trust of a client-supplied id | Compare explicitly (`== true`, `~= nil`) | See the traps section. |
| `api` / `web-client` | `ngx.say`, `ngx.print` of unescaped values, `ngx.redirect(url)` from input, `ngx.header[name] = value` from input | Escape output, allow-list redirect targets | |
| `http-protocol` | `ngx.var.http_x_forwarded_for`, `ngx.var.uri` against `ngx.var.request_uri`, header keys from `get_headers()` | Use the real-IP module with trusted proxies | `ngx.var.uri` is decoded and normalised. `request_uri` is raw. |
| `client-trust` | Script event handlers that take positions, amounts, ids or targets from the client | Server recomputes and validates | The host often passes the sender as an argument. Check that the handler uses it. |
| `memory-safety` | LuaJIT `ffi.cdef`, `ffi.C`, `ffi.cast`, `ffi.new`, `ffi.string`; C API calls with wrong stack use; `lua_tostring` on strings with `\0` | Do not expose `ffi`; use `lua_tolstring` and check length | Embedded zero bytes: Lua sees the whole string and C may see a prefix. A path check in Lua can pass while C opens another file. |
| `resource-exhaustion` | `while true do end`, `string.rep(s, n)`, nested patterns, `collectgarbage` loops, large tables from input | Instruction-count hook, custom allocator limit, size checks | Stock Lua has no CPU or memory limit. |
| `concurrency` | Module-level and global tables in OpenResty, `ngx.shared.DICT:get` then `set`, timers | `incr`, `add`, `safe_set` | See the concurrency section. |
| `secrets-config` | Secrets in `init_by_lua*`, in `config.lua`, in `package.path`-reachable files | Environment or secret store | |
| `logging-privacy` | `print`, `ngx.log` of headers, tokens or request bodies, `debug.traceback` in responses | Redact | |
| `data-lifecycle` | `ngx.shared.DICT` or module caches keyed without tenant or user | Include the principal in the key | |
| `supply-chain` | LuaRocks installs without pins, `package.path` with `./?.lua`, `package.cpath` with writable directories | Pinned rocks, fixed paths | Stock `package.path` includes `./?.lua`. |
| `abuse` | Missing `resty.limit.req`, `resty.limit.conn` or `resty.limit.count` on public phases | Limit before expensive work | |

## Language traps

- **Truthiness.** Only `nil` and `false` are false. `0` and `""` are true.
  - Wrong: `if user.level then allow() end` (level 0 passes). Right: `if user.level and user.level >= 2 then`.
- **JSON null.** `cjson.null` is a userdata, so it is true.
  - Wrong: `if body.is_admin then grant() end` (JSON `"is_admin": null` passes). Right: `if body.is_admin == true then grant() end`.
- **Array and object ambiguity.** `cjson.encode({})` gives `{}`. Tables with holes have an undefined `#`. A decode then encode round trip can change the type. Do not use `#t` for security checks on decoded data.
- **Key types.** `t[1]` and `t[1.0]` are one key. `t["1"]` is another.
  - Wrong: `perms[req.id]` where `id` is the string `"1"`. Right: `perms[tonumber(req.id)]` after a check that the result is not nil.
- **`pcall` result.** `pcall` returns whether the call ran, not what it decided.
  - Wrong: `if pcall(verify, token) then allow() end` (a `false` result from `verify` still passes). Right: `local ok, valid = pcall(verify, token); if ok and valid == true then`.
- **Globals by default.** An assignment to an unknown name creates a global. Under OpenResty, globals persist in the worker and are shared by requests. Write `local`.
- **`tonumber`.** It accepts `"0x10"`, `"1e2"` and surrounding spaces. It returns nil on failure, and `nil` in arithmetic raises an error. Check the result and the range.
- **Numeric types.** Lua 5.1 and LuaJIT use doubles only, and integers above 2^53 lose precision. Lua 5.3+ has integers that wrap silently on overflow. `math.tointeger` converts only exact values.
- **Modulo.** `-1 % 5` is 4 in Lua. The sign follows the divisor.
- **Strings.** Strings are byte strings with embedded `\0`. `string.lower` follows the C locale. The `utf8` library exists in 5.3+ only. `#s` counts bytes.
- **Duplicates and truncation in OpenResty.** `ngx.req.get_uri_args()` returns at most 100 arguments by default. A repeated name gives a table instead of a string.
  - Wrong: `local id = args.id; check(id)` (a table skips string checks). Right: `if type(args.id) ~= "string" then return ngx.exit(400) end`. `get_headers()` also limits to 100 headers and gives a table for repeated names.
- **Body in a file.** After `ngx.req.read_body()`, a large body is in a temporary file. `ngx.req.get_body_data()` returns nil. A check on the nil value can fail open.
- **Metatables.** `__index`, `__newindex`, `__call`, `__tostring`, `__eq`, `__gc` and (5.4) `__close` run code during normal operations. `__metatable` locks `getmetatable`/`setmetatable`. `rawget`, `rawset` and `rawequal` skip metamethods.

## Deserialisation and reflection

- **`load` of untrusted text.** It runs code with the rights of the `env` you give. The default `env` is the global table.
- **Binary chunks.** Lua 5.2 and later have no bytecode verifier. A crafted binary chunk can corrupt memory. `string.dump` output is not safe to load from a user. Always pass `mode "t"` on 5.2+. On 5.1 and LuaJIT, `load` and `loadstring` accept bytecode, so reject chunks that start with the byte `0x1B`.
- **Allow-list environments.** Build `env` from named safe functions. Never copy `_G`. A metatable on `env` with `__index = _G` defeats the sandbox.
- **Escape routes to review.** `getmetatable("").__index`, `getfenv` (5.1), `debug.*`, `coroutine` functions that wrap host callbacks, `xpcall` handlers, `require` and `package.loaded` (modules are shared between states and sandboxes in one state), `string.dump`, `os` and `io` handles returned by host functions, host functions that return userdata with a rich metatable.
- **Sandbox limits.** Use `lua_sethook` with `LUA_MASKCOUNT` or `debug.sethook` from the host for instruction limits, and a custom allocator in `lua_newstate` for memory. On LuaJIT, test that the hook fires in a hot loop. Do not assume it does.
- **Config as code.** A configuration file read with `dofile` or `require` runs with full host rights. Who can write it?
- **Reflection in the host.** Host functions that take a function name or a module name from a script and call it by name.
- **Redis.** Scripts run in a restricted environment, but built script text from input is still injection.

## Concurrency

- **Cooperative coroutines.** Lua has no preemption. A script that never yields blocks the host thread. Under OpenResty, a cosocket call (`ngx.socket.tcp`, `ngx.sleep`, `ngx.timer`) yields. Other requests then run in the same worker. A check before the yield and an action after it is a race.
- **Shared state in a worker.** Module tables and globals are shared by all requests of the worker. Use `ngx.ctx` for per-request data. `ngx.shared.DICT` is shared by all workers. `get` followed by `set` races. Use `incr`, `add` or `safe_add`.
- **Timers.** `ngx.timer.at` callbacks have no request context. `ngx.ctx` and `ngx.var` are not available.
- **Host threads.** A `lua_State` is not thread-safe. Two threads on one state corrupt memory. Check host locking, and one state per thread.
- **Stale references.** Game and server hosts pass entity or player handles to timers and callbacks. The entity can leave before the callback runs. Revalidate before use.
- **Finalisers.** `__gc` runs at an unspecified time and can resurrect objects. Do not use it for security cleanup. Lua 5.4 `<close>` variables run at scope exit.

## Build and runtime settings

- **Library set.** `luaL_openlibs` gives scripts `os`, `io`, `debug` and `package`. Open only needed libraries. Do not open `debug` or `ffi` for untrusted code.
- **Search paths.** Stock `package.path` includes `./?.lua`, so the current directory can supply modules. `LUA_PATH`, `LUA_CPATH`, `LUA_INIT` (and `LUA_INIT_5_x`) are read by the standalone `lua`. The `-E` option (5.3+) ignores them. `package.cpath` loads native code.
- **API checks.** Build with `LUA_USE_APICHECK` (5.2+) for tests. It turns host stack mistakes into errors.
- **LuaJIT.** `jit.off()`, `jit.opt.start(...)`, and the `ffi` module. Review any `require "ffi"`.
- **nginx / OpenResty.** `lua_code_cache off` (development only; code reloads per request), `lua_package_path`, `lua_package_cpath`, `lua_ssl_verify_depth`, `lua_ssl_trusted_certificate`, `lua_shared_dict` sizes, `client_max_body_size` (default 1 MB), `client_body_buffer_size` (body spills to a file above it), `lua_max_running_timers`, `lua_check_client_abort`.
- **cjson.** `cjson.decode_max_depth` and `cjson.encode_max_depth` (default 1000 in lua-cjson 2.1.0.x), `cjson.encode_sparse_array`. Check the pinned version.
- **Running as root.** A standalone interpreter or a host running as root gives every script that power.

## Tools

Run only tools that are installed. `phase-leads.md` section 2.1 has no Lua row. The multi-language row applies (Semgrep with local rules and `--metrics=off`). Semgrep support for Lua is limited. Lead searches carry most of the load.

| Tool | Offline-safe command | Notes |
|---|---|---|
| luacheck | `luacheck src --std max --codes --formatter plain` | Use `--std luajit`, `lua51`, `lua53` or `ngx_lua` to match the target. Codes W111, W112 and W113 report global writes, mutated globals and undefined reads. |
| `luac` | `luac -p file.lua` | Parse only. No execution. `luac -l` lists bytecode. |
| lua-language-server | `lua-language-server --check <dir>` | Type and undefined-variable diagnostics. |
| selene | `selene src` | Alternative linter. |
| busted | `busted spec/` | Unit tests. Stub `ngx` for OpenResty code. |
| `resty` CLI | `resty -e '<code>'` | Runs a LuaJIT script in the OpenResty runtime. Executes code. |
| Host sanitizers | ASan or UBSan build of the host, libFuzzer harness around `luaL_loadbufferx` | For C or C++ hosts. See `lang-c.md` or `lang-cpp.md`. |
| Semgrep | `semgrep --config ./local-rules --metrics=off src` | Never `--config auto`. |

## Lead searches

| Regex | Meaning | False-hit notes |
|---|---|---|
| `\b(load\|loadstring\|loadfile\|dofile)\s*\(` | Dynamic code loading | Loading the host's own fixed files is fine. |
| `\brequire\s*\(?\s*[^"'\s)]` | `require` with a computed name | Constant names are fine. |
| `\b(os\.(execute\|remove\|rename\|tmpname\|getenv\|exit)\|io\.(popen\|open\|lines\|tmpfile))` | Process and file API | Fixed paths in tools or tests. |
| `\bdebug\.\w+\|\bgetfenv\b\|\bsetfenv\b\|getmetatable\s*\(\s*["']{2}\s*\)` | Sandbox escape routes | `debug.traceback` for logs is low risk. |
| `package\.(path\|cpath\|loadlib\|loaded)` | Module search and native loading | |
| `luaL_openlibs\|luaopen_(io\|os\|debug\|package\|ffi)\|luaL_requiref` | Library set of a state | |
| `lua_register\|luaL_newlib\|luaL_setfuncs\|luaL_register\|lua_pushcfunction\|lua_setglobal` | Host API surface | Read each function body. |
| `lua_tostring\|luaL_checkstring\|lua_tolstring\|luaL_checklstring` | C string use of Lua strings | `lua_tolstring` with length use is fine. |
| `ffi\.(cdef\|C\|cast\|new\|string)\|require\s*\(?\s*["']ffi["']` | LuaJIT FFI | |
| `(Register\|Add)\w*(Event\|Handler\|Command\|Listener\|Callback)\|hook\.Add\|net\.Receive\|RegisterNetEvent` | Callback entry points | Host-specific. |
| `ngx\.(req\.get_(uri_args\|post_args\|headers\|body_data\|body_file)\|var\.(arg_\|http_\|uri\|request_uri))` | OpenResty input | Check types and duplicates. |
| `ngx\.(say\|print\|redirect\|exec\|header\[)` | Output and redirect sinks | |
| `sslhandshake\|ssl_verify\s*=\s*false\|lua_ssl_verify_depth` | TLS verification | |
| `ngx\.shared\.\w+:(get\|set)\|ngx\.timer\.at` | Shared state and timers | |
| `math\.random(seed)?\s*\(` | Weak randomness | Games and jitter are fine. |
| `cjson\.(null\|decode\|encode)\|json\.decode` | JSON decode | Check null and type handling. |
| `pcall\s*\(\|xpcall\s*\(` | Error swallowing | Check the use of the result. |
| `^\s*[A-Za-z_]\w*\s*=` outside functions or in functions without `local` | Possible global write | Prefer `luacheck`. |
| `lua_code_cache\s+off` | Development setting | |

## Verification notes

- **Smallest harness.** A Lua script run by the standalone `lua` in a scratch directory with a clean environment and `-E` (5.3+). Build the sandbox `env` as the host does. Load a chunk with `load` and check what it can reach. Test for absence of the reference, not for the effect. For example, assert that `load("return debug", "t", "t", env)()` returns nil. Do not call `os.execute` to prove a point.
- **Canary tests.** Give the chunk a host function that sets a flag. Assert the flag only changes for the allowed call.
- **Host functions.** Call each registered function with wrong types, negative numbers, huge numbers, empty strings, strings with `\0`, and another player's or entity's id. The harness needs the real host build or a small C test that registers the same function. Use ASan.
- **OpenResty logic.** Stub `ngx` with a table of fake functions in `busted`. For real nginx behaviour (body spill, argument limits, header normalisation), use a loopback-only server in the sandbox and send crafted local requests. This needs E3.
- **False positives.** `load` on fixed host files. `os.execute` in build or test scripts. `io.open` of a constant path. `debug.traceback` in logs. Globals in a file that the host wraps in a private environment.
- **Needs E3.** Sandbox escape claims (they depend on the Lua version or LuaJIT build and on the host's library set), bytecode loading, NUL truncation (depends on the host function), hook behaviour on LuaJIT, nginx body spill and argument limits, races across yields.
