# Domain: Obvious Checks

## Scope

- **Load when:** always. Every audit loads this file.
- **Covers:** the literal, cheap checks that each team assumes another team did: hard-coded secrets; committed credential files; default and backdoor credentials; debug modes in production; unauthenticated management surfaces; dynamic evaluation of input; cross-origin and cookie settings (leads); error disclosure; security TODOs and disabled checks; unpinned build inputs (leads).
- **Rule:** an obvious item is a lead until it has a traced impact. A secret in a file is not a finding. A secret that gives an attacker access to a named resource is a candidate. Trace every hit. Do not skip a hit because it looks simple.
- **Hand off to:**
  - `domain-secrets-config.md` – config precedence, feature flags, secret storage and rotation. This file finds the literal hit. That file owns the design.
  - `domain-web-client.md` – CORS, cookie scope, CSP and framing in depth. This file only lists the literal misconfigurations.
  - `domain-injection.md` – injection sinks other than direct evaluation of input.
  - `domain-authn.md` – how credentials are checked.
  - `domain-supply-chain.md` – dependency confusion, lockfile integrity, CI and release authority.
  - `domain-logging-privacy.md` – secrets and personal data in logs and telemetry.
  - `domain-outbound-network.md` – outbound TLS verification (this file only finds the switch).
  - `domain-cloud-deploy.md` – public storage, open ports and IAM in infrastructure code.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Secrets:** No file in the source tree, history, build artefact, image, package or client bundle contains a live secret that gives <attacker> access to <resource>.
2. **Defaults:** A build and configuration that follows the installation documentation has no default, test or backdoor credential, and no account that the operator did not create.
3. **Modes:** A production build has no debug, developer, test or bypass mode that an untrusted <principal> can switch on.
4. **Management surfaces:** Every admin, metrics, debug, health and management surface requires authentication, or exposes nothing protected, and listens only on the interface the documentation names.
5. **Evaluation:** No data from <untrusted source> reaches an expression evaluator, a code loader or a dynamic call target.
6. **Disclosure:** A response to an untrusted <principal> contains no stack trace, secret, internal path, query text or configuration value.
7. **Origin:** A browser or app origin that the operator does not trust cannot use a victim's credentials on <endpoint>.
8. **Controls:** Every security check in the code runs. No flag, comment-out, early return or stub turns it off in a production build.
9. **Build inputs:** Every build, install and update input is pinned to content that a maintainer reviewed.

## Recon additions

Add these to `threat-model.md` under a heading "Literal surface". Keep each item short.

1. **Listeners.** Every port, socket and default bind address, and the setting that changes it.
2. **Build profiles.** Every build mode and environment switch (debug, dev, test, production). State which one ships.
3. **Secret-bearing files.** Every committed file that holds config, key material, credentials, state or dumps, including files in history.
4. **Seed accounts.** Every account, token or key that code, migrations, fixtures or installers create.
5. **Management routes.** Admin, metrics, debug, health, profiling and diagnostic routes, with the authentication each needs.
6. **Disabled controls.** Every switch that turns off verification, authentication, encryption or validation, and its default.

## Lead searches

Adapt the patterns to the language. Run them on tracked files, on history if a tool exists, and on files that `.gitignore` hides but exist on disk.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `(password\|passwd\|secret\|api_?key\|token\|credential\|private_?key)\s*[:=]\s*["'][^"']{6,}` | Hard-coded secret (OB-01) | Placeholders (`changeme`, `example`, `xxx`, `<your-key>`), test fixtures, and values read from the environment are not secrets. Do not copy the value. |
| `-----BEGIN [A-Z ]*PRIVATE KEY-----`, and long base64 or hex literals near `key\|secret\|sign\|hmac` | Embedded key material (OB-01) | Public keys and test vectors are not secrets. |
| File names: `.env*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `id_rsa*`, `credentials*`, `*.tfstate`, `*.kubeconfig`, `*.sqlite`, `*.dump`, `*.bak` | Committed credential or state file (OB-02) | `.env.example` with empty values is normal. |
| `(admin\|root\|test\|demo\|guest\|default)` near `password\|passwd\|credential\|login` in seeds, migrations, fixtures, installers | Default or seed credential (OB-03) | A seed that forces a change on first login holds. Check that it forces it. |
| `(debug\|dev(elopment)?_?mode\|test_?mode\|insecure\|backdoor\|bypass\|god_?mode\|NO_?AUTH\|skip_?auth\|allow_?all)` in conditions, flags, env reads and build files | Debug or bypass mode (OB-04) | Check the default value and who can set it. |
| Route registrations matching `/(admin\|debug\|metrics\|health\|status\|actuator\|pprof\|swagger\|openapi\|graphql\|console\|trace\|env\|config)` | Management surface (OB-05) | The authentication can sit in middleware or in the proxy. |
| Bind to `0\.0\.0\.0`, `::`, `INADDR_ANY`, `listen(` without a host | Surface on all interfaces (OB-05) | Containers need this. Check the published port. |
| `eval\|exec\|Function\(\|compile\(\|loadstring\|vm\.run\|ScriptEngine\|Runtime\.eval\|dlopen\|require\(.*\+\|import_module\|__import__\|Class\.forName\|reflect` near request, message, file or config data | Dynamic evaluation of input (OB-06) | A constant argument is safe. Trace the argument. |
| `Access-Control-Allow-Origin`, `allow_?origins`, `cors(`, `credentials: ?true`, `withCredentials`, `Set-Cookie`, `cookie` options (`secure`, `httponly`, `samesite`) | Origin and cookie leads (OB-07) | Read `domain-web-client.md` before you judge. |
| `traceback\|stack_?trace\|printStackTrace\|e\.(message\|toString)\|err\.(stack\|message)\|debug.*true` in response writers, error handlers and templates | Error disclosure (OB-08) | A log line is not a response. Trace to the client. |
| `TODO\|FIXME\|HACK\|XXX\|temporary\|for now` near `auth\|check\|verify\|valid\|perm\|sign\|encrypt\|escape` | Known gap (OB-09) | |
| `verify\s*[:=]\s*false`, `skip_?verify`, `insecure_?skip`, `NODE_TLS_REJECT_UNAUTHORIZED`, `CERT_NONE`, `check_?hostname\s*=\s*False`, `return true;` as the only statement in a check | Disabled control (OB-09) | Test files only: not a lead. |
| Dependency specs with `latest`, `*`, `>=`, branch names, `git+`, unpinned image tags, `curl .* \| .*sh`, missing lockfile | Unpinned input (OB-10) | A lockfile may pin an unpinned spec. Read it. |

## Attack classes

### OB-01 Hard-coded secret or key

- **What fails:** a secret or key sits in source, history, a build artefact or a shipped binary. Anyone who gets the artefact gets the access.
- **Where to look:** source; configuration defaults; test code that ships; scripts and CI files; container image layers; mobile, desktop and firmware packages; client bundles; documentation; git history.
- **Questions:**
  - What does the secret unlock: a service, a signing identity, a decryption key, a database?
  - Who holds the artefact: the public, customers, or only the team?
  - Is the value a placeholder? Is it the same in every installation?
- **Sad-path inputs:** a secret used as a fixed signing, encryption or comparison value; the same key in every install; a key only in old commits.
- **Evidence for confirmed:** file and line of the secret (never the value), the line that uses it, the resource it unlocks, and the attacker who holds the artefact. E1 is enough when the code itself uses the secret in an authentication, signature or decryption step. A credential for a third-party service is `needs-validation`, because liveness is outside the repository. Never test it against a live system.
- **Not a finding:** placeholders; test keys that no production path accepts; public keys; secrets that the operator generates at install time; a secret in a private repository that the attacker cannot read, when the artefact does not ship it.
- **CWE:** CWE-798 (use of hard-coded credentials); CWE-321 (use of hard-coded cryptographic key).

### OB-02 Committed credential, key or state file

- **What fails:** a file with credentials, keys, state or data is in the repository, an image or a package.
- **Where to look:** `.env` files; key stores; cloud and cluster credential files; infrastructure state files; database dumps; backups; shell history files; archived releases; build caches.
- **Questions:**
  - Does the file contain real values or only placeholders?
  - Does the file ship in a release, an image or a package? Check ignore files of the packager as well as of version control.
- **Sad-path inputs:** a file that version control ignores but a packaging step copies; a file removed from the tip but present in history.
- **Evidence for confirmed:** the path, proof that it holds real material (by type, not value), the artefact that ships it, and the access it gives.
- **Not a finding:** example files with empty values; fixtures with generated throwaway data.
- **CWE:** CWE-538 (sensitive information in an externally accessible file or directory).

### OB-03 Default, test and backdoor credentials

- **What fails:** an account, token or key exists that the operator did not create and cannot easily remove.
- **Where to look:** seed data and migrations; installers and first-run code; fixtures loaded outside tests; string literals in login code; vendor support accounts; device defaults; magic strings.
- **Questions:**
  - Does the build create the account on a fresh install?
  - Does any login path accept a literal, a hash of a literal or a special header?
- **Sad-path inputs:** the documented default; an empty password; a username with a different case; a login that succeeds when the user store is empty.
- **Evidence for confirmed:** the creation or comparison line, the default build path to it, and the account privilege. E1 is enough for a literal compared in code.
- **Not a finding:** a seed account that exists only in test configuration; a default that the installer forces the operator to replace before first start.
- **CWE:** CWE-1392 (use of default credentials); CWE-798 (use of hard-coded credentials).

### OB-04 Debug, developer and bypass modes in production

- **What fails:** a mode that weakens security is on by default, or a low-trust principal can turn it on.
- **Where to look:** build flags and environment switches; framework debug settings; interactive consoles; test hooks; "skip authentication" flags; header, query or cookie switches; unlock commands in firmware and game servers.
- **Questions:**
  - What is the default? What does the documented production setup set?
  - Who controls the switch: the operator, the environment, or the request?
  - What does the mode expose: code execution, data, bypassed checks?
- **Sad-path inputs:** the switch absent; the switch set by a request header or field; a staging value in a production file.
- **Evidence for confirmed:** the switch, its default in the shipped configuration or its reachability by the attacker, and the exposed capability.
- **Not a finding:** a mode that only the operator can set, with a safe default.
- **CWE:** CWE-489 (active debug code); CWE-1188 (initialisation of a resource with an insecure default).

### OB-05 Unauthenticated management surface

- **What fails:** an admin, metrics, debug, health or management interface answers without authentication, or on an interface the operator did not intend.
- **Where to look:** route tables; framework management endpoints; profiling ports; admin consoles; database and cache ports on all interfaces; broker management UIs; RPC reflection endpoints; daemon and game-server control sockets; exported debug components in apps.
- **Questions:**
  - Which authentication applies to this exact path, after normalisation?
  - What does the surface return? A liveness `OK` is harmless. A heap dump, environment, user list or control action is not.
  - What is the bind address by default? Does the documented deployment publish the port?
- **Sad-path inputs:** no credentials; the path with a trailing slash, different case or an extra segment; the same endpoint on a second port.
- **Evidence for confirmed:** the registration, the missing check on the full path, the default bind address, and the sensitive data or action returned. E1 is enough when the code shows no check and no outside layer is in scope.
- **Not a finding:** a liveness probe that returns a constant; a surface on loopback only in the documented deployment.
- **CWE:** CWE-306 (missing authentication for a critical function).

### OB-06 Dynamic evaluation of input

- **What fails:** input becomes code, an expression, a class name, a module name or a library path.
- **Where to look:** evaluator calls; reflection and dynamic imports; plugin loaders that take a name from data; template engines given a template string; rule fields that hold expressions.
- **Questions:**
  - Which part of the argument can the attacker influence: all, a fragment, only a choice from a fixed list?
  - Is there an allow-list of values? Is it checked before use, on the same string that is used?
  - Who can write the source of the data: an anonymous client, a user, an admin, the operator?
- **Sad-path inputs:** a value outside the allow-list; a value that differs in case or encoding from an allowed one; a path or name with separators.
- **Evidence for confirmed:** the entry, the path to the evaluator, the absence of an effective allow-list, and the attacker's privilege. Show the effect with a harmless marker value (for example a computed number), never a payload. Language-specific sinks are in the `lang-*.md` files.
- **Not a finding:** a constant argument; data that only the operator writes, when the operator already has that power.
- **CWE:** CWE-95 (eval injection); CWE-470 (unsafe reflection).

### OB-07 Cross-origin and cookie settings (lead class)

- **What fails:** a permissive cross-origin policy or weak cookie setting lets another origin use or read a victim's session.
- **Where to look:** CORS middleware and headers; reflected `Origin` values; `null` origin allowed; wildcard with credentials; session and token cookie options; cross-origin settings for sockets and embedded webviews.
- **Questions:**
  - Does the response allow credentials together with an origin the attacker controls?
  - Is the origin matched exactly, or by suffix, prefix or regular expression?
  - Does the cookie carry a session or token? Which of `Secure`, `HttpOnly` and `SameSite` are missing, and what attack does the gap enable here?
- **Sad-path inputs:** an origin that ends with the trusted name; a `null` origin; a sibling subdomain; an `http` origin.
- **Evidence for confirmed:** the policy line, an attacker origin that it accepts, a credentialed endpoint that returns protected data or accepts a state change, and the browser rule that makes it work. Use `domain-web-client.md` for the full judgement.
- **Not a finding:** a missing cookie flag on a cookie with no security meaning; wildcard origin on a public, credential-less endpoint. A missing flag alone is a hardening note.
- **CWE:** CWE-942 (permissive cross-domain policy with untrusted domains); CWE-1275 (sensitive cookie with improper SameSite attribute).

### OB-08 Error and stack-trace disclosure

- **What fails:** a response, page or client log shows internals to an untrusted principal.
- **Where to look:** global error handlers; framework debug pages; API error bodies; GraphQL and RPC error extensions; validation errors that echo queries; crash dialogs in apps; server kick messages.
- **Questions:**
  - Does the text reach the client, or only the log?
  - What does it contain: paths, query text, secrets, user data, tokens?
- **Sad-path inputs:** a malformed body; a wrong type; a failing dependency; an unhandled exception.
- **Evidence for confirmed:** the handler, the input that reaches it, and the specific sensitive item in the response. A version string alone is a hardening note.
- **Not a finding:** a generic message with a correlation ID; detail that only an authenticated admin sees.
- **CWE:** CWE-209 (error message containing sensitive information).

### OB-09 Security TODOs and disabled controls

- **What fails:** a control exists in name only. It is stubbed, commented out, switched off or bypassed with an early return.
- **Where to look:** comments with `TODO` or `FIXME` near security code; check functions that return a constant; disabled tests of security behaviour; verification switches set to off; `#if 0` blocks; suppressed analyser warnings on security calls.
- **Questions:**
  - Does the control run in the production build?
  - What does the code rely on instead? Is another layer present (then it is a hardening note)?
  - Which attacker action does the missing control allow?
- **Sad-path inputs:** the input the control exists to reject.
- **Evidence for confirmed:** the stub or switch, the path from an entry to the protected action, and the input that the control should reject but does not.
- **Not a finding:** a TODO about style; a switch used only in tests.
- **CWE:** use the CWE of the disabled control, for example CWE-295 (improper certificate validation) for a verification switch, or CWE-306 (missing authentication for critical function) for a stubbed login check.

### OB-10 Unpinned and mutable build inputs (lead class)

- **What fails:** the build or install takes code from a source the maintainers do not control or review at that moment.
- **Where to look:** dependency manifests; missing lockfiles; image tags such as `latest`; installer scripts that fetch and run code; CI actions referenced by tag or branch.
- **Questions:**
  - Does the lockfile pin an exact version and a hash?
  - Does a build with secrets fetch mutable input?
- **Sad-path inputs:** a new release of an unpinned dependency; a moved tag.
- **Evidence for confirmed:** the mutable input, the build step that executes or ships it, and the secret or trust it reaches. Most hits are hardening notes. Hand the rest to `domain-supply-chain.md`.
- **Not a finding:** a range in a manifest that a committed lockfile pins.
- **CWE:** CWE-494 (download of code without integrity check); CWE-829 (inclusion of functionality from an untrusted control sphere).

## Variant search

When you find one obvious defect:
1. **Same literal.** Search the whole tree, history and artefacts for the same value, file name or flag.
2. **Same pattern.** Search for the same call or switch in other modules, scripts and tests that ship.
3. **Same copy.** Search images, packages and documentation for copies of the file or secret.
4. **Same surface.** List every route, port or socket of the same kind.

## Chain primitives

This domain often **gives**:
- credentials, keys and tokens that unlock other components;
- a way to read configuration and internal state;
- a session or bypass (default account, debug switch);
- code execution paths (evaluation, loaders).

This domain often **needs** nothing for first access. A chain step that uses a leaked secret needs the matching domain (authn, crypto, cloud-deploy).

## Verification notes

- **E1 is usually enough** for OB-01 (when the code uses the secret in a local decision), OB-03, OB-04, OB-05, OB-06 and OB-09, when the registration, the path and the sink are in the repository.
- **E3 is not normally needed.** E3 is required when a claim depends on runtime behaviour outside the repository, such as a framework default, a proxy rule or a deployment setting. Then use `needs-validation` with a local reproduction plan.
- **Third-party credentials** (OB-01, OB-02): never test them. Mark `needs-validation` and state "liveness unknown; owner should rotate".
- **Reachability:** confirm the file, route or flag exists in the shipped build and default configuration.
- **Impact trace:** name the victim resource. Without one, "a secret exists" is a hardening note.
- **Severity examples:**
  - critical – an unauthenticated management surface or default account gives control of the server or all accounts; a shipped signing key lets anyone forge trusted artefacts;
  - high – a hard-coded key authenticates or decrypts all installs; a client-settable debug switch bypasses authentication;
  - medium – an error that leaks a secret or query text; a cross-origin policy that exposes one authenticated endpoint;
  - low – version and path disclosure;
  - informational – an unpinned input with a lockfile that mitigates it.

## Fix patterns

- **Secrets:** remove the secret, rotate it, and read it from a secret store at run time. Rewriting history alone does not make a leaked secret safe.
- **Defaults:** create no default accounts. Fail to start when the operator has not set a credential.
- **Modes:** compile debug features out of production builds. Never let a request switch a mode.
- **Surfaces:** put authentication on a deny-by-default layer. Bind management to loopback or a private interface.
- **Evaluation:** replace evaluation with a lookup in a fixed table of allowed values.
- **Errors:** return a generic message and a correlation ID. Log the detail on the server.
- **Origins:** match origins exactly against an allow-list. Never reflect the request origin with credentials.
- **Build inputs:** pin versions and hashes, and pin CI actions to commit IDs.
- **Looks right but is not:** deleting the file in a later commit; base64 or XOR "obfuscation" of a key; hiding the route from the documentation; a blocklist of dangerous strings before evaluation.

## Regression tests

- A secret scanner in CI that fails the build on a new hit, with a reviewed allow-list of placeholders.
- A test that builds the production configuration and asserts that no debug flag is on and no default account exists.
- A route-table test: every route, called without credentials, is refused unless it is on a reviewed public list.
- A test that triggers an unhandled error and asserts that the body contains no stack frame, path or secret.
- A test that sends an attacker origin to each credentialed endpoint and asserts that it is refused.
- A test that feeds a non-allow-listed value to each evaluator or loader and asserts rejection.
