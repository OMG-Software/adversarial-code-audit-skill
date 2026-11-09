# Language: JavaScript and TypeScript

## Scope

- Covers: JavaScript (ES2022 and later) and TypeScript on Node.js 18 to 22, with notes for Deno and Bun where behaviour differs. Also browser code, browser extensions and Electron main and renderer code.
- Common frameworks: Express, Fastify, NestJS, Koa; Next.js (App Router and Pages Router, with server actions), Remix, SvelteKit, Nuxt; React, Vue, Angular, Svelte; Mongoose, Sequelize, Prisma, Knex.
- TypeScript types vanish at run time. A type is a claim, not a control.

## Entry points

- **Express and Koa.** `app.get(`, `app.post(`, `app.all(`, `app.use(`, `router.route(`, `express.Router()`, `router.use(`. Order matters: a `use` that sets authentication affects only routes registered after it. Input: `req.params`, `req.query`, `req.body`, `req.headers`, `req.cookies`, `req.files`.
- **Fastify.** `fastify.get(`, `fastify.route({`, `fastify.register(`, `addHook('onRequest' | 'preHandler')`. Hooks apply to the plugin context where you add them. `fastify-plugin` removes that scope. A hook in one plugin does not cover routes in a sibling plugin.
- **NestJS.** `@Controller(`, `@Get(`, `@Post(`, `@Body()`, `@Param()`, `@Query()`, `@UseGuards(`, global guards through `APP_GUARD`, `@Public()` (custom opt-out decorators), `@MessagePattern(` and `@EventPattern(` for microservices, `@SubscribeMessage(` for sockets, GraphQL `@Resolver`.
- **Next.js.** `app/**/route.ts` (exports `GET`, `POST`), `pages/api/**`, `middleware.ts` (with its `matcher`), `getServerSideProps`, server components, and server actions: any exported async function in a file with `'use server'`. A server action is a public POST endpoint. Check the authorization inside each action, not only in the page that calls it.
- **Other full-stack frameworks.** Remix `loader` and `action`; SvelteKit `+server.ts`, `+page.server.ts`, `actions`, `hooks.server.ts`; Nuxt `server/api/**`.
- **WebSockets and queues.** `ws` `wss.on('connection'`, `socket.io` `io.on('connection'`, `socket.on(`; `bullmq` workers, `amqplib` consumers, `kafkajs` `eachMessage`, AWS Lambda `exports.handler`.
- **CLI and scripts.** `process.argv`, `commander`, `yargs`, `process.stdin`, `process.env`.
- **Deno and Bun.** `Deno.serve(`, `Bun.serve(`, `Hono` and `Oak` routers. Deno denies file, network, environment and subprocess access unless a flag allows it (`--allow-read`, `--allow-net`, `--allow-env`, `--allow-run`, `-A`). `-A` removes that control.
- **Browser and extensions.** `addEventListener('message'`, `window.postMessage`, `location.hash`, `location.search`, `document.referrer`, `window.name`, `chrome.runtime.onMessage`, `chrome.runtime.onMessageExternal`. Read `manifest.json`: `permissions`, `host_permissions`, `externally_connectable`, `content_scripts`, `web_accessible_resources`.
- **Electron.** `ipcMain.handle(`, `ipcMain.on(`, `contextBridge.exposeInMainWorld(`, `app.setAsDefaultProtocolClient(`, `webContents.setWindowOpenHandler(`.
- **Exported modules.** `module.exports`, `export` in a library: the public API is the entry surface.

## Sinks by domain

| Domain | Dangerous API or pattern | Safer alternative | Notes |
|---|---|---|---|
| injection | Template literals in `query(`, `knex.raw(`, `sequelize.query(`; Prisma `$queryRawUnsafe`, `$executeRawUnsafe` | Placeholders; Prisma tagged `$queryRaw` | Column and order names cannot be placeholders. |
| injection | MongoDB: `req.body` object passed to `find(`; `$where`; `$regex` from input | Check `typeof x === 'string'`; Mongoose `sanitizeFilter` | `{"password": {"$ne": null}}` is operator injection. |
| injection | `child_process.exec`, `execSync`, `spawn(..., {shell: true})` | `execFile`, `spawn` with an argument array | Add `--` before user values. Bun: `Bun.$` escapes interpolation; `Bun.spawn` takes an array. |
| injection | EJS `<%-`, Pug `!{}` and `!=`, Handlebars `{{{ }}}`, `lodash.template`, `new Function` templates | Escaped output (`<%=`, `{{ }}`) | Template text built from input is server-side template injection. |
| web-client | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `srcdoc`, React `dangerouslySetInnerHTML`, Vue `v-html`, Svelte `{@html}`, Angular `bypassSecurityTrustHtml`, `eval`, `setTimeout(string)`, `location = user`, `javascript:` URLs | `textContent`; framework binding; DOMPurify for HTML | Sources: URL, `postMessage`, storage, server data. |
| web-client | `addEventListener('message', ...)` without `event.origin` check; `postMessage(data, '*')`; `cors({origin: true})`; `res.redirect(req.query.next)` | Exact origin compare; fixed target origin | Express `res.redirect` does not validate the target. |
| web-client | `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` variables that hold secrets; props from `getServerSideProps` or server components that carry full records | Select fields before you return them | Next.js writes page props into the HTML (`__NEXT_DATA__`). Hand off storage to `secrets-config`. |
| input-parsing | `path.join(base, user)`, `fs.readFile(user)`, `createReadStream(user)`, `res.sendFile(user)`, archive libraries (`tar`, `adm-zip`, `unzipper`) | `path.resolve` then `path.relative(base, p)` must not start with `..` or be absolute | `path.resolve('/a', '/etc')` returns `/etc`. Check symlinks with `fs.realpath`. |
| input-parsing | `JSON.parse` then deep merge; `qs` or `extended` query parsing; `multer`, `busboy` file names and types; `xml2js`, `libxmljs` with entity options | Schema validation (Ajv, zod); allow-list of keys; generate file names | Express 4 uses `qs` by default (`a[b]=1` makes objects). Express 5 uses the simple parser. |
| filesystem-process | `fs.chmod`, `fs.writeFile` to shared paths, `os.tmpdir()` with a fixed name, `fs.access` then `fs.open`, `process.env` into `spawn` | `fs.mkdtemp`; open with flags `wx`; pass a clean `env` | `NODE_OPTIONS` and `PATH` change what a child runs. |
| outbound-network | `fetch`, `axios`, `got`, `undici`, `http.request`, `node-fetch` with a URL from input; `rejectUnauthorized: false`; `NODE_TLS_REJECT_UNAUTHORIZED=0` | Host allow-list; check the address after DNS; `redirect: 'manual'` | `fetch` follows redirects by default. `axios` follows up to 5 (`maxRedirects`). `fetch` has no timeout unless you add `AbortSignal.timeout()`. |
| api | `Model.create(req.body)`, `update(req.body)`, Prisma `data: req.body`, `Object.assign(doc, req.body)`, `req.body as Dto` | NestJS `ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })`; DTO with fixed fields; zod | A TypeScript `as` cast validates nothing. Fastify schemas run Ajv with `removeAdditional` and `coerceTypes` on by default. |
| authn | `jwt.decode` used as if it verified; `jwt.verify` with no `algorithms`; `===` on secrets; `express-session` `MemoryStore`; `cookie.secure` unset | `jwt.verify(t, key, {algorithms: ['RS256']})`; `crypto.timingSafeEqual` | `timingSafeEqual` throws if lengths differ. Compare hashes of equal length. |
| authz | `findById(req.params.id)` with no owner filter; middleware order; Fastify hook scope; a NestJS guard missing on one controller | Scope the query by principal; deny-by-default global guard | Read the registration order, not only the handler. |
| crypto | `Math.random()` for tokens, `crypto.createHash('md5' \| 'sha1')` for passwords, `createCipher` (removed in Node 22), ECB mode, fixed IVs | `crypto.randomBytes`, `randomUUID`, `crypto.getRandomValues`; `createCipheriv` with GCM; `scrypt` | Web Crypto in browsers: `crypto.subtle`. |
| crypto-protocols | `JSON.stringify` output signed or hashed without a fixed key order | Canonical form; sign the bytes you send | Key order follows insertion order. Integer keys sort first. |
| messaging | Webhook route behind `express.json()` that verifies a signature over `JSON.stringify(req.body)` | `express.raw()` for that route; `timingSafeEqual` | Re-serialised JSON differs from the signed bytes. |
| concurrency | `await` between a check and a write; module-level state in handlers; in-memory counters | Database transaction or atomic update | See "Concurrency". |
| memory-safety | Native addons (`node-gyp`, N-API), `Buffer.allocUnsafe`, `new Buffer(n)` | `Buffer.alloc` | `allocUnsafe` can return old memory contents. |
| resource-exhaustion | Regex with nested quantifiers on input; `zlib.gunzip` without `maxOutputLength`; `Buffer.alloc(userSize)`; `JSON.parse` on huge bodies; no `limit` on body parsers | Size limits; `maxOutputLength`; linear-time regex engines | One slow regex blocks the single event loop. `express.json()` default limit is 100 kB; Fastify `bodyLimit` default is 1 MiB. |
| secrets-config | `process.env.X \|\| 'default'`; `dotenv` files in the repository; `devtool` or `productionBrowserSourceMaps` in production | Fail at start when a secret is missing | See "Build and runtime settings". |
| logging-privacy | `console.log(req.headers)`, `morgan` with tokens in URLs, Sentry `sendDefaultPii` | `pino` `redact` option; log fixed fields | Authorization headers and cookies are the usual leak. |
| data-lifecycle | `lru-cache` and `node-cache` keys without tenant; Next.js data cache and full-route cache; ISR (`revalidate`) of per-user pages | Tenant in key; `no-store` for private data | Next.js 14 caches `fetch` by default. Next.js 15 does not. |
| supply-chain | `preinstall`, `install`, `postinstall` scripts; `latest` or git dependencies; `.npmrc` `registry=`; `npx` without a version | `npm ci --ignore-scripts`; lockfile with integrity hashes | pnpm 10 and Bun skip dependency scripts unless you allow them. npm runs them. |
| sandbox | `vm.runInNewContext`, `new Function`, `eval`, `vm2`, `worker_threads` as a boundary | Separate process or `isolated-vm` with limits | Node documents `vm` as not a security mechanism. `vm2` is discontinued after sandbox escapes. |
| ai-llm | `eval` or `new Function` on model output; tools that call `exec`; model output into `innerHTML` | Structured output with validation; no code from model text | |
| local-ipc | Electron: `nodeIntegration: true`, `contextIsolation: false`, `sandbox: false`, `webSecurity: false`, `shell.openExternal(user)`, wide `contextBridge` APIs | Defaults (`contextIsolation` true since Electron 12, `sandbox` true since 20) | Validate every `ipcMain` argument and the sender frame. |
| http-protocol | `app.set('trust proxy', true)`; `req.hostname` or `req.ip` used for decisions; missing `helmet` | Trust only named proxies | Behind a proxy, `X-Forwarded-*` headers set `req.ip` and `req.protocol`. |
| abuse | `express-rate-limit` keyed on `req.ip` with wrong `trust proxy`; in-memory limiter with several workers | Shared store; per-account limits | Each cluster worker has its own memory. |
| financial | `Number` for money; `parseFloat`; `toFixed` | Integer minor units; `BigInt`; a decimal library | Integers above 2^53 lose precision. |
| smart-contracts | `ethers` or `web3` code that signs with a key from env or source | Hand off | Treat key handling under `crypto` and `secrets-config`. |
| business-logic, federation, client-trust, embedded, kernel, cloud-deploy | Not specific to JavaScript | Use the domain file | |

## Language traps

- **Loose equality and coercion.** `==` converts types. `"0" == false`, `[] == false`, `null == undefined`, `["a"] == "a"` are all true.
  - Wrong: `if (req.query.admin == true)`.
  - Right: `if (req.query.admin === 'true')`, after you have checked `typeof`.
- **Arrays from query strings.** `?id=1&id=2` makes `req.query.id` an array. `?id[]=1` does too (Express 4). `"abc".includes(x)` and `[..].includes(x)` behave differently. A string method on an array throws, and the throw is a DoS lead.
  - Right: `if (typeof id !== 'string') return res.sendStatus(400)`.
- **Number conversion.** `Number("")` is `0`. `Number(null)` is `0`. `parseInt("12abc")` is `12`. `NaN` fails every comparison. `-0 === 0`.
  - Wrong: `if (qty < 1) reject()` (NaN passes).
  - Right: `if (!Number.isSafeInteger(qty) || qty < 1) reject()`.
- **Large integers.** `JSON.parse('{"id":9007199254740993}')` gives `9007199254740992`. Two IDs can map to the same value. Bitwise operators work on 32 bits (`x | 0`).
- **Prototype pollution.** A recursive merge, `set`, or `defaultsDeep` that walks the keys `__proto__`, `constructor` and `prototype` writes to `Object.prototype`. `JSON.parse('{"__proto__":{"x":1}}')` creates an own key, but a merge of that object pollutes. Older `lodash` 4.17.x releases had pollution in `merge`, `set` and `defaultsDeep`.
  - Wrong: `for (k in src) dst[k] = merge(dst[k], src[k])`.
  - Right: skip those three keys, use `Object.create(null)` or `Map`, and `Object.hasOwn(obj, k)` (ES2022). The `in` operator walks the prototype chain: `"constructor" in {}` is true. Node's `--disable-proto=delete` removes `__proto__`, but not the other paths.
- **Dynamic keys.** `handlers[req.body.action]()` can reach `constructor` or `toString`.
  - Right: `Object.hasOwn(handlers, action)`.
- **Regex state.** A `/g` regex keeps `lastIndex` between `.test()` calls, so a shared regex gives alternating results. `new RegExp(userInput)` is injection and ReDoS. `replace(str, repl)` replaces only the first match, and `$&` in `repl` is special.
- **UTF-16 strings.** `.length` counts code units. `slice` can split a surrogate pair. `"İ".toLowerCase()` changes the length. Validate after `normalize('NFKC')` and case folding, not before. `localeCompare` depends on locale.
- **URL checks.** `url.startsWith("https://good.com")` accepts `https://good.com.evil.test`. `"https://good.com@evil.test"` has host `evil.test`.
  - Right: `new URL(x).hostname` compared with an allow-list. Legacy `url.parse` and WHATWG `URL` can disagree.
- **Equality and timing.** `===` on strings leaks timing. Use `crypto.timingSafeEqual` on equal-length `Buffer`s.
- **TypeScript.** `any`, `as`, `// @ts-ignore`, `// @ts-expect-error` and non-null `!` switch off checks. JSON from the network has the type you wrote, not the type it has.
- **Unhandled rejections.** Since Node 15 an unhandled rejection ends the process. In Express 4, a rejected promise in an `async` handler is not caught. Express 5 forwards it to the error handler.

## Deserialisation and reflection

- **Code execution from strings.** `eval`, `new Function`, `setTimeout("code")`, `vm.runInContext`, `vm.Script`, `Function.prototype.constructor`.
- **Dynamic loading.** `require(userValue)`, `import(userValue)`, `require.resolve`, `module._load`, `child_process.fork(userPath)`. The value chooses the code that loads.
- **Unsafe unserialisers.** `node-serialize` (`unserialize` can run functions), `serialize-javascript` output passed to `eval`. `js-yaml` 3.x `load` was unsafe, so use `safeLoad`. `js-yaml` 4.x `load` is safe and has no `safeLoad`. `JSON.parse` runs no code.
- **Class revival.** `class-transformer` `plainToInstance` builds class instances from plain data and can set fields you did not intend. Nest `ValidationPipe({ transform: true })` calls it.
- **Structured clone.** `structuredClone`, `v8.deserialize` and `postMessage` copy data. They do not run code. Do not use `v8.deserialize` for untrusted data across a trust boundary without review.
- **Reflection.** `obj[userKey]`, `Reflect.get`, `Reflect.apply`, `Object.assign`, `Function.prototype.call`. See dynamic keys above.
- **Templates.** `lodash.template`, EJS `render` with options from input (options can carry `outputFunctionName`), Handlebars `compile(userString)`. Treat template text from input as code.

## Concurrency

- **Event loop.** One thread runs your JavaScript. A tight loop, a heavy regex, `JSON.parse` of a huge body or a `*Sync` call blocks every client.
- **`await` is a switch point.** Another request can run between a check and a write.
  - Wrong: `if (user.credits >= cost) { await charge(); user.credits -= cost; }`.
  - Right: one atomic statement (`UPDATE ... WHERE credits >= cost`), a transaction with a lock, or a unique key.
- **Module-level state.** Variables outside the handler are shared by all requests in the process. Request data in them leaks across users. In serverless runtimes, warm instances reuse module state between invocations.
- **Several processes.** `cluster`, PM2 and containers each hold their own memory. In-memory sessions, rate limits and locks do not span them.
- **Cancellation.** A client disconnect does not stop the handler. Use `AbortController` and `req.on('close')`. `Promise.all` rejects early but the other promises keep running. `Promise.race` leaves the losers running. Partial writes stay.
- **Unhandled rejections and listeners.** An error in a callback or event handler that no one catches can end the process (`uncaughtException`). A `process.on('uncaughtException')` handler that continues can leave state half-written.
- **Threads.** `worker_threads` with `SharedArrayBuffer` and `Atomics` can race. Message passing copies data and does not.
- **Idempotency.** Queue consumers (`bullmq`, `kafkajs`) can deliver a job twice. Check dedupe keys.

## Build and runtime settings

- **`NODE_ENV`.** Express prints stack traces to clients unless `NODE_ENV` is `production`. Many libraries switch behaviour on it.
- **Express.** `app.disable('x-powered-by')`; `trust proxy`; `express.json({limit})`; `cookie: {secure, httpOnly, sameSite}` in `express-session`; `helmet` for headers. `express-session` default `MemoryStore` is not for production.
- **Fastify.** `trustProxy` (default off), `bodyLimit`, Ajv options (`coerceTypes`, `removeAdditional`).
- **NestJS.** `app.enableCors()` with no options allows any origin. `ValidationPipe` does not strip unknown properties unless `whitelist: true`.
- **Next.js.** `NEXT_PUBLIC_` variables go to the browser. `serverActions.allowedOrigins` (under `experimental` in 13 and 14) widens the origin check for server actions. `middleware.ts` must not be the only authorization layer. Source maps in production (`productionBrowserSourceMaps`) publish source.
- **Vite and bundlers.** `VITE_` variables go to the client. `DefinePlugin` and `define` inline values into bundles. `server.host` exposes the dev server.
- **Node flags.** `--inspect=0.0.0.0` exposes a debugger. `--disable-proto=delete`. Node has an opt-in permission model (`--permission`; older releases use `--experimental-permission`). It is off by default and is not a sandbox for hostile code. `NODE_TLS_REJECT_UNAUTHORIZED=0` turns off TLS checks for the process.
- **TypeScript.** `strict: false`, `noImplicitAny: false`. `skipLibCheck` hides type errors in dependencies only.
- **Browser extensions.** The manifest `content_security_policy`. Wide `host_permissions` such as `<all_urls>`. `web_accessible_resources` with broad `matches`.
- **Electron.** See the `local-ipc` row.
- **Deno and Bun.** Deno `-A`. Bun runs `postinstall` only for `trustedDependencies` and a built-in list.

## Tools

Use only installed tools. Run from the project's own `node_modules/.bin` or use `npx --no-install`, so that nothing downloads. Do not run `npm install`.

| Tool | Command | Notes |
|---|---|---|
| `eslint` | `./node_modules/.bin/eslint SRC` | Plugins: `eslint-plugin-security`, `eslint-plugin-no-unsanitized`. The config must already be in the repository. Many false hits. |
| `tsc` | `./node_modules/.bin/tsc --noEmit` | Finds type errors. Not a security tool. |
| `semgrep` | `semgrep --config LOCAL_RULES_DIR --metrics=off --disable-version-check SRC` | Local rules only. Never `--config auto`. |
| `npm audit` | Needs the registry. | Do not run without permission. Read `package-lock.json` and list security-relevant versions as leads. |
| Test runners | `node --test FILE`, `vitest run FILE`, `jest --ci FILE` | Run target code. See `execution.md`. |
| Property and fuzz tests | `fast-check` (if present), `@jazzer.js/core` (if present) | For parsers and merge functions. |

## Lead searches

| Regex | Meaning | False-hit notes |
|---|---|---|
| `\beval\(\|new Function\(\|setTimeout\(\s*["'\x60]\|vm\.(run\|Script)` | Dynamic code | Constant strings are safe. |
| `child_process\|\b(exec\|execSync)\(\|shell:\s*true` | Process creation | `execFile` with constant arguments is safe. |
| `\.(query\|raw\|execute)\(\s*\x60[^\x60]*\$\{\|\$(query\|execute)RawUnsafe\|\$where` | SQL or query built from text | Tagged `$queryRaw` is safe. |
| `\.(find\|findOne\|update\|delete)\w*\(\s*req\.(body\|query)` | Query object from the client | Safe after a type check or `sanitizeFilter`. |
| `\.(create\|update\|insert\|assign)\w*\(\s*req\.body\|Object\.assign\([^)]*req\.body\|\.\.\.req\.body` | Mass assignment | An allow-list stops it. |
| `__proto__\|constructor\.prototype\|\b(merge\|defaultsDeep\|set\|extend\|assignDeep)\(` | Prototype pollution | Hit matters only if keys come from input. |
| `innerHTML\|outerHTML\|insertAdjacentHTML\|document\.write\|dangerouslySetInnerHTML\|v-html\|\{@html\|bypassSecurityTrust` | DOM or HTML sink | Constant HTML is safe. |
| `addEventListener\(\s*["']message\|postMessage\(` | Message handling | Look for `event.origin`. |
| `rejectUnauthorized:\s*false\|NODE_TLS_REJECT_UNAUTHORIZED` | TLS checks off | Test code only. |
| `\b(fetch\|axios\|got\|request)\(\s*(req\.\|url\|input\|user)` | Outbound request | Check allow-list, redirects, timeout. |
| `Math\.random\(` | Weak RNG | Matters near token, id, nonce or key. |
| `createHash\(["'](md5\|sha1)\|createCipher\(\|-ecb` | Weak crypto | Cache keys are fine. |
| `jwt\.(decode\|verify)\(` | Token check | Look for `algorithms` and audience. |
| `path\.join\(\|sendFile\(\|createReadStream\(\|readFile(Sync)?\(` | Path sink | Check the source of the second argument. |
| `process\.env\.\w+\s*(\|\|\|\?\?)\s*["']` | Secret default | Check that production sets the value. |
| `NEXT_PUBLIC_\|VITE_\|REACT_APP_` | Client-exposed variable | Names with SECRET, KEY, TOKEN are strong leads. |
| `["']use server["']` | Server action file | List every exported function and its authorization. |
| `nodeIntegration\|contextIsolation\|webSecurity\|openExternal` | Electron setting | Defaults are safe. |
| `@ts-ignore\|@ts-expect-error\|eslint-disable\|\bas any\b` | Silenced check | Read why. |
| `"(pre\|post)?install"\s*:` | Install script | Check what it runs. |

## Verification notes

- **Smallest test shape.** One `node:test` (or `vitest` or `jest`) case with one assertion. For HTTP, import the app object without calling `listen`, and call it with `supertest` or Fastify `inject()` (if present). Use dummy principals A and B and an in-memory or temporary database.
- **Authorization.** Create a resource for B. As A, call the route. Assert 403 or 404 and assert the data is unchanged.
- **Prototype pollution.** Call the merge function with `JSON.parse('{"__proto__":{"polluted":"yes"}}')`. Then assert `({}).polluted === undefined`. Delete `Object.prototype.polluted` in a `finally` block, in the same process.
- **NoSQL operator injection.** Pass `{ "$ne": null }` where a string is expected. Assert that the function rejects it.
- **Coercion.** Call the validator with `["a"]`, `""`, `NaN`, `"0"`, `null`, `true`. Assert that each is rejected.
- **Path checks.** Pass `"../x"` and `"/etc/hosts"`. Assert that the resolved path stays under the base.
- **Async races.** Start two calls with `Promise.all`. Put a `await new Promise(r => setImmediate(r))` in the window if needed. Assert the invariant after both finish. This is E3 and needs T2.
- **Client code.** Run DOM sinks in `jsdom` (if present). Assert that a test string stays text. Full browser behaviour (CSP, parsing differences) needs a real browser. Without one, report `needs-validation`.
- **False positives.** `innerHTML` with constants; `eval` in build scripts that read no input; `exec` of fixed strings; `Math.random` for UI; `req.body` bound after a schema with `additionalProperties: false`; framework escaping that you have read (React escapes by default); `NEXT_PUBLIC_` for values that are public by design (analytics IDs, public API URLs).
- **E3 needed for:** races; behaviour that depends on a framework version (Express 4 and 5, Next.js 14 and 15); regex ReDoS timing; browser parsing differences; Electron settings that depend on packaging.
- **E1 is often enough for:** a server action with no authorization call and a sensitive effect; a secret in a `NEXT_PUBLIC_` variable; `jwt.decode` used as verification; `rejectUnauthorized: false` on a path with attacker-chosen hosts. List every layer you read in the waiver.
