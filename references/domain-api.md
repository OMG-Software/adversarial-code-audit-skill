# Domain: API surface

## Scope

- **Load when:** the code exposes HTTP, GraphQL, RPC or WebSocket endpoints to clients. Signs: route tables, controllers, resolvers, OpenAPI or schema files, RPC procedure definitions, public API keys, framework server actions or server functions, versioned URL prefixes, SDKs generated from a schema.
- **Covers:** endpoint inventory against documentation; undocumented, debug and legacy endpoints; server actions and RPC-style endpoints that are public; request binding (mass assignment); response shaping (over-fetching); GraphQL query shape (depth, batching, aliases, introspection); per-endpoint limits; error and debug leakage; versioning; content-type and method confusion; pagination, filter and sort abuse; idempotency keys.
- **Hand off to:**
  - `domain-authz.md` – the decision logic: roles, ownership, tenants, field rules. The API domain finds endpoints that lack a decision. Authz owns whether the decision is correct. Use both files for a missing check.
  - `domain-authn.md` – how the caller is identified (sessions, tokens, API keys, OAuth).
  - `domain-web-client.md` – server data serialised into pages, hydration leaks, secrets in client bundles, CORS, CSRF on browser-called endpoints.
  - `domain-secrets-config.md` – storage of secrets that end up in client bundles.
  - `domain-injection.md` – a filter, sort or query argument that reaches a query engine as code.
  - `domain-input-parsing.md` – parser and deserialiser defects behind the endpoint.
  - `domain-abuse.md` – whether a limit holds against many identities and at scale.
  - `domain-resource-exhaustion.md` – CPU, memory and parser cost of one request.
  - `domain-messaging.md` – webhooks that the service receives.
  - `domain-outbound-network.md` – endpoints that make the server fetch a URL.
  - `domain-http-protocol.md` – Host and forwarded headers, proxy behaviour.
  - `domain-financial.md` – money rules behind an idempotency key.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Inventory:** Every endpoint that the running server exposes is documented, intended, and behind the authentication and authorization layer unless the design marks it public.
2. **Binding:** A request can set only the fields that <endpoint> documents for <principal>. The server owns every other field.
3. **Response:** A response to <principal> contains only fields that <principal> may read. An error response contains no internals (stack, query, path, secret, other users' data).
4. **Shape:** No single request makes the server do work larger than the documented bound for depth, batch size, alias count, page size and nesting.
5. **Limit:** Every endpoint that checks a secret, sends a message, spends money or runs a costly job has a server-side limit with a stated key and size.
6. **Version:** Every version, alias, mount point and legacy path of <endpoint> enforces the same controls as the current one.
7. **Type:** An endpoint accepts only the methods and content types that it documents. The validator and the handler read each value in the same way.
8. **Replay:** A retry with the same idempotency key from the same principal and with the same body has one effect. No other principal or body can reuse the key.

## Recon additions

Add these to `threat-model.md` under a heading "API surface".

1. **Endpoint inventory.** One row per endpoint: method, path or procedure name, handler, auth layer, documented (yes or no), version, caller type (browser, mobile, partner, internal). Build it from route registration in code, not from the documentation. Then add the documented endpoints. The difference in each direction is a lead.
2. **Registration styles.** List every way the code registers an endpoint: route tables, annotations, file-system routing, plugins, server actions, RPC procedures, GraphQL fields, WebSocket message types. A style that the inventory missed is a lead.
3. **Schema and binding.** For each write endpoint: the input type (DTO, model, raw map) and the bind method. For each read endpoint: the output type and the serialiser.
4. **GraphQL facts.** Limits on depth, cost, aliases and batch size. Introspection setting per environment. Persisted queries. Whether subscriptions exist.
5. **Limits table.** Per endpoint: rate limit (key, size, store), body size, page size, timeout. Mark "none".
6. **Error handling.** Global error handler, debug flags, difference between development and production mode, error format.
7. **Exposure.** Which endpoints a public client can reach, and which only a gateway or internal network can reach. Mark each network assumption as external.

## Lead searches

Adapt the patterns to the language. The language file adds framework registration patterns.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| Route registrations compared with the documented endpoint list | API-01: an undocumented or forgotten endpoint | Documentation may lag the code. Judge the endpoint by its effect. |
| `(/v[0-9]+/\|/api/(old\|legacy\|internal\|admin\|debug\|test\|beta\|private))` | API-07, API-01: a legacy, internal or debug path | A redirect to the current version is safe. Compare the checks. |
| `use server\|"use server"\|createServerFn\|server_?action\|server\$\|publicProcedure\|rpc\.\|@RpcMethod\|@Remote` | API-02: a server function that the client can call | Check for an auth call inside the function body. A check in the page component does not protect the function. |
| `(swagger\|openapi\|api-docs\|graphiql\|playground\|redoc\|actuator\|/metrics\|/debug\|/health\|/status)` | API-01, API-06: a documentation, console or diagnostic endpoint | Public health checks that return only "ok" are normal. |
| `req(uest)?\.(body\|params)\b.*(update\|create\|merge\|assign\|save)`, `\*\*(kwargs\|body\|data)`, `Object\.assign`, spread of request body, `fields *= *['"]__all__`, `permit!`, `$guarded *= *\[\]`, `exclude *=` | API-03: mass assignment | An allow-list stops it. A deny-list or `exclude` does not. |
| `toJSON\|to_dict\|model_to_dict\|serialize\|marshal` of a whole model, `select \*`, `fields *= *['"]__all__` | API-03: over-fetching | Check the model for private fields. |
| `introspection\|depth_?limit\|query_?cost\|complexity\|max_?aliases\|batch` near GraphQL setup | API-04: a limit that is off or missing | A persisted-query allow-list replaces these limits. |
| `rate_?limit\|throttle\|limiter\|slowapi\|express-rate-limit` compared with the endpoint list | API-05: an endpoint without a limit | The gateway may limit. Mark that as external. |
| `debug *= *(true\|1)\|DEBUG\|stack_?trace\|e\.(message\|stack)\|traceback\|err(or)?\.(toString\|message)` in response code | API-06: internals in responses | Development-only branches. Check the production default. |
| `Content-Type\|content_type\|multipart\|urlencoded\|bodyParser\|json\(\)\|method_?override\|_method\|X-HTTP-Method-Override` | API-08: type or method confusion | A strict parser with one accepted type is safe. |
| `limit\|offset\|page_?size\|per_?page\|cursor\|order_?by\|sort\|filter` taken from the request | API-09: unbounded or unvalidated list controls | Check the maximum and the allowed field list. |
| `idempot\|Idempotency-Key\|request_?id\|dedup` | API-10: scope of the key | Check the key store: does it include the principal and the body hash? |

## Attack classes

### API-01 Endpoint inventory gaps

- **What fails:** the server exposes an endpoint that nobody listed, so no control was designed for it. Examples are admin, debug, test, export, internal-callback and forgotten feature endpoints.
- **Where to look:** routes registered by plugins, modules, conventions or file-system routing; endpoints that exist only in the generated client or in the mobile app; documentation, console and diagnostic endpoints; endpoints behind a feature flag that the default build enables; catch-all routes; WebSocket message types without a matching REST route.
- **Questions:**
  - Which registered endpoints are not in the documentation or in the client code?
  - Which of them reach a state change or a data read?
  - Does the same authentication and authorization layer cover each one? Check how the layer matches paths.
  - Does the production build include test and debug routes?
- **Sad-path inputs:** a request to each undocumented path with no credentials, with a low-privilege credential, and with a wrong method.
- **Evidence for confirmed:** the registration, the missing control on the path to the effect, and the effect. E1 is normally enough when the route is registered in the default build.
- **Not a finding:** a public endpoint that exposes nothing protected; a route compiled out of the default build; an endpoint that only the operator can reach by design.
- **CWE:** CWE-306 (missing authentication for critical function); CWE-912 (class-level; hidden functionality). Use the specific entry from `domain-authn.md` or `domain-authz.md`.

### API-02 Server actions and RPC-style endpoints that are public

- **What fails:** a function that the framework turns into a public network endpoint runs without its own check. The developer thinks the function is "internal" because only the UI calls it.
- **Where to look:** functions marked as server actions or server functions (for example a `"use server"` module); RPC procedures with a public or base procedure type; form actions; remote-call decorators; GraphQL resolvers added through code generation; actions that take an object ID as an argument.
- **Questions:**
  - Does the function itself check the caller and the permission? The page or layout check does not count, because a client can call the function without the page.
  - Does each argument have a server-side schema check? The client type is not a check.
  - Does an exported helper function in a server-action module become a public endpoint by mistake?
  - Does the function trust a user ID, role or price in its arguments?
- **Sad-path inputs:** a direct call without the page flow; an argument with another user's ID; extra properties; a call as a lower role; a call with no session.
- **Evidence for confirmed:** the function registration, the absence of a check inside and before it on the path from the framework entry, and the effect of a call. E1 is normally enough. Read the framework version's documented behaviour first.
- **Not a finding:** a function with a check in a wrapper that the framework always applies; a function that only returns public data.
- **CWE:** CWE-749 (exposed dangerous method or function); CWE-306 (missing authentication for critical function). Use the authz entry that fits the root cause.

### API-03 Mass assignment and over-fetching

- **What fails:** on write, a generic binder copies client fields into server-owned fields. On read, the serialiser returns fields that the caller must not see. `domain-authz.md` (AZ-04) covers the field rule. This class covers the binding and serialising code.
- **Where to look:** create, update and `PATCH` handlers that pass the whole body to a model; serializers with "all fields"; nested writes; import and bulk endpoints; GraphQL input types that mirror database models; responses that return the saved model; admin and public handlers that share one serialiser.
- **Questions:**
  - Is there an allow-list, a DTO with fixed fields, or a deny-list? A deny-list misses new fields.
  - Which server-owned fields exist (role, owner, tenant, status, price, flags, internal notes, hashes, tokens, timestamps)?
  - Does the binder accept nested objects, dotted keys or array indexes that reach related models?
  - Do list endpoints return fewer fields than detail endpoints, or more?
  - Do error and validation responses echo the full submitted or stored object?
- **Sad-path inputs:** extra fields with server-owned names; the same name in other case or nesting; `null` for a field that controls a check; a foreign key to an object the caller does not own; an array where a scalar is expected.
- **Evidence for confirmed:** the binding or serialising line, the sensitive field it reaches, and the changed or leaked value. E1 is normally enough.
- **Not a finding:** a field bound but overwritten before save; a field with no security meaning; a field that the caller owns.
- **CWE:** CWE-915 for mass assignment. CWE-213 (exposure due to incompatible policies) when the response policy differs from the data policy. For other over-exposure, name the weakness in words.

### API-04 GraphQL query shape

- **What fails:** the schema lets one request do unbounded work, bypass per-request limits, or reveal hidden schema.
- **Where to look:** server setup (depth, cost, alias and batch limits); array batching of operations in one HTTP request; many aliases of one field in one query; deeply nested relations; introspection and field suggestions in production; subscriptions; mutations that are also reachable as queries; resolvers that skip the field-level check that the parent resolver has.
- **Questions:**
  - Are depth, cost, alias count and batch size limited, or is a persisted-query allow-list used?
  - Does a per-endpoint rate limit count one HTTP request, while one request holds many operations? Then a secret-checking mutation (login, code check) escapes its limit.
  - Does each resolver check authorization, or only the root fields?
  - Does introspection or field suggestion reveal admin-only types? Does that matter without an access gap?
- **Sad-path inputs:** a query nested to the limit plus one; a query with many aliases of one cheap field; a batch array with the maximum plus one operation; a type or field name that only an admin should know.
- **Evidence for confirmed:** the missing limit or the resolver without a check, and a bounded test (small numbers, local instance) that shows the limit does not hold. E1 is enough for a missing limit setting in the server config. E3 is needed for a claim of measured cost.
- **Not a finding:** introspection enabled when the schema is public by design; a limit enforced by a gateway that the repository shows.
- **CWE:** CWE-770 for missing limits. CWE-799 (class-level) for a per-request counter that does not count batched work. Name introspection leaks in words.

### API-05 Missing or inconsistent per-endpoint limits

- **What fails:** an endpoint that checks a secret, sends a message, spends money or runs a costly job has no server-side limit, or has a limit that a sibling path does not share.
- **Where to look:** login, code check, password reset, invite, message send, export, search, upload and report endpoints; limits applied in middleware to some routers only; limits applied to the UI path and not to the API path; limits keyed on a value the client controls; limiter code that fails open when its store is down.
- **Questions:**
  - Which endpoints have no limit? Which have a limit in the gateway only? Mark the gateway as external.
  - Do two routes reach the same effect, with only one limited?
  - What is the key (IP, account, token, tenant)? What does the endpoint cost?
  - What does the limiter do on store error or timeout?
- **Sad-path inputs:** requests just above the documented limit on each route; the same effect through the alternate route; a limiter store that returns an error.
- **Evidence for confirmed:** the unlimited route, and the cost or secret check it exposes. Name the limit that should exist. E1 is enough for "no limiter on this route" when the repository holds the full middleware chain. Scope of a limit across many identities belongs to `domain-abuse.md`.
- **Not a finding:** a cheap read endpoint with no secret and no cost; a limit enforced in a layer that the repository shows.
- **CWE:** CWE-799 for missing control of interaction frequency. CWE-770 for missing resource limits.

### API-06 Error and debug leakage

- **What fails:** responses reveal internals that help an attacker: stack traces, query text, file paths, framework and version strings, configuration, internal hostnames, or other users' data.
- **Where to look:** global error handlers; `catch` blocks that return the exception text; validation errors that echo input and stored values; debug flags and development middleware; database error pass-through; 404 and 500 pages; verbose health endpoints; GraphQL errors with `extensions`.
- **Questions:**
  - What does the response contain when a handler throws, when the database fails and when validation fails?
  - Does production mode switch debug off by default, or does an operator have to do it?
  - Does the error text contain a secret, a token or personal data?
- **Sad-path inputs:** a malformed body; a wrong type; a missing required field; an oversized value; an ID that does not exist.
- **Evidence for confirmed:** the line that builds the response and the sensitive item it holds. A leaked secret or personal data is a finding. A version string is a hardening note.
- **Not a finding:** a generic error message; development-only output behind a flag that is off by default in production.
- **CWE:** CWE-209 (error message containing sensitive information).

### API-07 Version and sibling divergence

- **What fails:** a newer endpoint enforces a control, and an older version, alias or mounted copy of the same function does not.
- **Where to look:** `v1` against `v2`; deprecated endpoints that still run; routes mounted under two prefixes; mobile-only and partner-only copies; handlers duplicated by copy and paste; internal endpoints that call the same service function without the check; batch and single variants.
- **Questions:**
  - Which versions or aliases reach the same effect? Build a table: effect × path × controls.
  - Does an older version bind more fields, skip a limit, or use an older auth scheme?
- **Sad-path inputs:** the same request on each version and alias; fields that only the old schema accepts.
- **Evidence for confirmed:** both paths, the control present on one and absent on the other, and the effect. E1 is normally enough.
- **Not a finding:** an old version that is read-only and exposes public data; an old route that redirects.
- **CWE:** CWE-420 (unprotected alternate channel); CWE-288 (authentication bypass using an alternate path or channel).

### API-08 Content-type and method confusion

- **What fails:** the endpoint accepts a method or a body type that the validator, the CSRF layer or the authorization layer does not expect. The checks cover one form of the request. The handler reads another.
- **Where to look:** handlers that accept JSON, form and multipart bodies at once; frameworks that merge query, body and path parameters into one map; method-override parameters or headers; `GET` handlers that change state; `HEAD` and `OPTIONS` reaching handlers; duplicate parameter names; JSON with duplicate keys; `text/plain` bodies parsed as JSON; GraphQL over `GET`.
- **Questions:**
  - Which content types does the parser accept? Does each get the same validation?
  - Which source wins when query, body and path carry the same name?
  - Does a middleware check (CSRF, auth, schema) run for every method and type?
  - Does a method override reach a more privileged handler?
- **Sad-path inputs:** the same body as JSON, form and multipart; a duplicate parameter with two values; an unexpected method; a `GET` with a body; a wrong `Content-Type` with a valid body.
- **Evidence for confirmed:** the two interpretations of one request, the check that sees only one, and the effect. E1 is enough when both parsers are in the repository. E3 is needed when a framework or proxy parser outside the repository decides.
- **Not a finding:** a parser that rejects every type but one; a merge order that the framework documents and the handler handles.
- **CWE:** CWE-351 (insufficient type distinction); CWE-436 (class-level; interpretation conflict).

### API-09 Pagination, filter and sort abuse

- **What fails:** list controls let a caller read more than allowed, or run work larger than intended. Examples are an unbounded page size, a filter on a hidden field, a sort that leaks a secret by order, and a cursor that the client can edit.
- **Where to look:** `limit`, `offset`, `page`, `cursor`, `sort`, `order`, `filter`, `where`, `search` and `fields` parameters; query-string filter languages; cursors that encode IDs or SQL fragments; export endpoints that ignore the page size.
- **Questions:**
  - What are the maximum page size and the maximum offset?
  - Can a filter or sort reference a field the caller cannot read? A filter on `password_hash` or `secret` is an oracle even when the field is not returned.
  - Is the cursor signed, or can the client change the position or the owner scope inside it?
  - Does the filter syntax reach a query engine as code? If it does, hand off to injection.
- **Sad-path inputs:** a page size at the maximum plus one; a negative or huge offset; a sort on a hidden field; a filter operator that the endpoint does not list; an edited cursor.
- **Evidence for confirmed:** the parameter, the missing bound or field allow-list, and the data revealed or the work caused. E1 is normally enough for field oracles. A cost claim needs E3.
- **Not a finding:** a large page size on public data with a total cap; a sort field that is public.
- **CWE:** CWE-770 for missing bounds. Name a hidden-field oracle in words.

### API-10 Idempotency keys and replay

- **What fails:** an idempotency or request-ID mechanism gives wrong results. A retry runs the effect twice, or one caller replays or reads another caller's stored response.
- **Where to look:** `Idempotency-Key` handling; request-ID deduplication tables; retry middleware; stored responses keyed on the client key alone; keys that expire before the retry window; endpoints that create resources, send messages or start jobs.
- **Questions:**
  - Is the key scoped to the principal and the endpoint? A global key store lets one tenant read the stored response of another.
  - Is the request body hashed? Can the same key with a different body return the first response or run the second action?
  - What happens on a crash between the key claim and the effect?
  - Does the dedup check and the insert run as one atomic step? If not, hand off the race to concurrency.
- **Sad-path inputs:** the same key from two principals; the same key with a different body; a key reused after expiry; a concurrent pair with the same key.
- **Evidence for confirmed:** the key store and its scope, and a stored response returned to the wrong principal, or a second effect for one key. Cross-principal reuse is E1. Races need E3.
- **Not a finding:** a client that reuses its own key as designed.
- **CWE:** CWE-837 (improper enforcement of a single, unique action); CWE-294 (authentication bypass by capture-replay).

## Variant search

When you find one API failure:
1. **Same registration style.** List every endpoint registered the same way (same router, plugin or action module) and check each for the same gap.
2. **Same binder or serialiser.** List every handler that uses the same DTO, model binder or serialiser.
3. **Same effect.** List every path to the same effect: versions, aliases, batch, GraphQL, RPC, WebSocket, mobile and partner copies.
4. **Same limit pattern.** List every route with the same limiter setup. Check the exceptions.
5. **Same error path.** List every handler that uses the same error helper.
6. **Same history.** If an earlier fix added a check to one endpoint, check that it reached every sibling.

## Chain primitives

This domain often **gives**:
- an unauthenticated or low-privilege call to an internal or admin function;
- write access to server-owned fields (role, owner, tenant, URL), which later checks trust;
- schema and internal names from error and introspection output;
- many guesses per request (batching, aliases), which weakens limits on secret checks;
- a replayed or shared response from a wrong idempotency scope.

This domain often **needs**:
- a session or key of any user (from authn) for authenticated routes;
- an object identifier (from enumeration or disclosure) for object-level attacks;
- the decision logic of authz to turn a missing check into a concrete impact.

## Verification notes

- **E1 is usually enough** for API-01, API-02, API-03, API-05 (no limiter on a route), API-06, API-07 and API-09 (field oracle), when registration, the full middleware chain and the sink are in the repository. The waiver names every layer checked: middleware, wrappers, base classes, framework defaults, schema validation.
- **E3 is needed** for API-04 cost claims, for API-08 when a proxy or framework parser outside the repository decides, and for API-10 races. Without T2, mark these `needs-validation` with a bounded reproduction plan.
- **Reachability:** confirm the route is registered in the default build. Confirm the caller can reach it without an internal network. If a gateway outside the repository might block it, the finding is `needs-validation`.
- **Framework defaults:** check the pinned framework version. Some frameworks bind only declared fields or disable introspection in production. Do not assume either way.
- **E3 test shape:** on a local instance with dummy data, call the endpoint as the lower principal with the minimal request. Record the status and body. For limits, send the limit plus one request and record that the last one succeeds.
- **Severity examples:**
  - critical – an unauthenticated server action or RPC method changes or reads data of all accounts or gives control of the server;
  - high – mass assignment that makes a user an admin or moves a record to another tenant; an unauthenticated debug endpoint that returns secrets or user data; a legacy version that skips authorization;
  - medium – batching or aliasing that lets one request defeat a limit on a secret check; a response that leaks another user's low-sensitivity fields; a filter oracle on a hidden field;
  - low – stack traces or internal paths in errors; introspection of a schema that has no access gap;
  - informational – version banners; an undocumented endpoint with no effect.

## Fix patterns

- **One inventory.** Generate the route table from code and compare it with the documentation in CI. Fail on an undocumented route.
- **Deny by default.** Put every route, server action and RPC procedure behind an auth layer that denies unless a rule allows. A new route fails closed.
- **Check inside the function.** In a server action or RPC procedure, authenticate and authorize inside the function. Validate every argument with a server-side schema.
- **Bind to DTOs.** Use fixed input types and fixed output types per role. Never bind the request to a model that has server-owned fields.
- **GraphQL limits.** Set depth, cost, alias and batch limits. Count operations, not HTTP requests, in rate limits. Use persisted queries for first-party clients. Switch off introspection and field suggestions in production if the schema is not public.
- **Central error handler.** Return a generic error with a correlation ID. Log details on the server.
- **One parser per endpoint.** Accept a fixed list of methods and content types. Reject the rest. Reject duplicate keys.
- **Bounded lists.** Set a maximum page size. Allow-list sort and filter fields. Sign cursors.
- **Scoped idempotency.** Key the store on principal, endpoint and key. Store a hash of the body. Make the claim atomic.
- **Looks right but is not:** hiding the route from the documentation; checking auth in the page and not in the action; a client-side type or schema as validation; a deny-list of fields; a rate limit on the HTTP request when one request holds many operations; switching off introspection while field suggestions still reveal names; a limit in the UI only.

## Regression tests

- A **route-inventory test** that lists all registered routes and fails when a route is not in the documented set.
- A **matrix test** per endpoint: no credentials, wrong role, right role. Assert the status. Generate it from the route table.
- For each mass-assignment fix, a test that sends every server-owned field and asserts that none changes.
- For serialisers, a test that checks the response field set for each role against a fixed list.
- For GraphQL, tests at the limit and at limit plus one for depth, aliases and batch size.
- For limits, a test that sends the limit plus one on each route and each alias route, and asserts rejection.
- For errors, a test that triggers a throw and asserts a generic body.
- For idempotency, tests for the same key from two principals, the same key with a different body, and a crash between claim and effect.
