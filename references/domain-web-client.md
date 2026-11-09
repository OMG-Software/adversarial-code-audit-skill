# Domain: Web client and browser boundary

## Scope

- **Load when:** a browser, webview or browser extension runs or enforces something. Signs: HTML templates, front-end frameworks, JavaScript bundles, cookies, CORS settings, security headers, service workers, uploads served back to users, `postMessage`, extension manifests, server-side rendering with data passed to the client.
- **Covers:** DOM XSS; CSRF; CORS with credentials; framing; CSP and other security headers; cookie attributes, scope and token storage; open redirects; user-content origins; third-party scripts and SRI; `postMessage` and WebSocket origin checks; service workers; browser extensions; server data serialised into pages, hydration leaks, and secrets in client bundles.
- **Hand off to:**
  - `domain-injection.md` – server-rendered XSS (stored and reflected) and every other injection. The dividing line: if the server builds the dangerous HTML, injection owns it. If client code builds it in the DOM, this file owns it.
  - `domain-http-protocol.md` – response-header injection, caching, Host and forwarded headers, proxy and CDN configuration that sets headers.
  - `domain-api.md` – authorization of the endpoint behind a server action, and API response shaping.
  - `domain-authz.md` – the permission decision behind a browser request.
  - `domain-authn.md` – session creation, expiry and token verification. This file owns only how the browser stores and sends them.
  - `domain-secrets-config.md` – storage and rotation of secrets. This file owns a secret that the build puts in a client bundle.
  - `domain-local-ipc.md` – native webviews, deep links and exported components outside the browser.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Script:** Only script that the application trusts runs in the origin of <app>. No untrusted string reaches an HTML, script, URL or style sink in the DOM.
2. **Request origin:** A state-changing request on <app> is accepted only if the user's own page sent it with the user's intent, whatever the method, content type or ambient credentials.
3. **Cross-origin read:** Only origins that the design lists can read credentialed responses of <app>.
4. **Framing:** Only listed origins can frame sensitive pages of <app>.
5. **Credentials in the browser:** A session credential reaches only the origins that need it. Page script cannot read it, unless the design requires that.
6. **Navigation:** A redirect or navigation target that comes from input goes only to a listed destination.
7. **Content origin:** User-supplied files and markup run in an origin that holds no session and no application authority.
8. **Third-party code:** Every script, style, frame and message source that <app> trusts is listed, pinned or integrity-checked, and has no more authority than needed.
9. **Messages:** A handler of cross-window, cross-context or extension messages checks the sender's origin and identity, and the shape of the data.
10. **Client exposure:** Nothing is sent to the browser that the viewer must not see: server-only data, secrets, other tenants' records, internal URLs.

## Recon additions

Add these to `threat-model.md` under a heading "Browser boundary".

1. **Origins.** List every origin the product serves or uses: app, API, static, upload, user-content, admin, marketing, extension pages.
2. **Credential map.** For each credential (cookie, bearer token, API key): where it is stored, attributes, which origins send it, how JavaScript reaches it.
3. **Header table.** For each response class (HTML, API, upload, static): CSP, frame control, content-type options, CORS, cache control, cookies. Name the file that sets each one. Mark settings made outside the repository as external.
4. **Sink inventory.** Client-side sinks by type (HTML, script, URL, navigation, message) with the framework escape hatch for each.
5. **State-changing routes.** Every route that changes state, with method, content types and the CSRF control.
6. **Third-party and bundle inventory.** Script and frame sources; integrity attributes; variables that reach the bundle; source maps in production.
7. **Message surfaces.** `postMessage` listeners and senders, WebSocket endpoints, service workers, extension manifests.

## Lead searches

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `innerHTML\|outerHTML\|insertAdjacentHTML\|document\.write\|dangerouslySetInnerHTML\|v-html\|\[innerHTML\]\|bypassSecurityTrust\|\{@html\|\|safe\b\|html_safe\|Markup\(` | WC-01: HTML sink | Constant strings and sanitised input are safe. Read the sanitiser and its configuration. |
| `eval\(\|new Function\|setTimeout\(\s*['"]\|setInterval\(\s*['"]\|\.src *=\|location(\.href)? *=\|window\.open\|\.href *=` with a non-constant argument | WC-01, WC-06: script or URL sink | Check the scheme allow-list on URLs. |
| `location\.(hash\|search\|href)\|document\.(referrer\|cookie\|URL)\|window\.name\|URLSearchParams\|localStorage\|postMessage` as a source | WC-01: attacker-controlled source | Follow the value to a sink. |
| State-changing routes compared with CSRF middleware and token checks | WC-02: unprotected mutation | A custom-header requirement or origin check can replace a token. |
| `Access-Control-Allow-Origin\|cors\(\|CORS_\|allow_?origins\|allowCredentials\|Allow-Credentials` | WC-03: CORS policy | A wildcard without credentials on public data is normal. |
| `X-Frame-Options\|frame-ancestors\|frame-src\|allowfullscreen\|<iframe` | WC-04: framing policy | Check sensitive pages, not only the home page. |
| `Content-Security-Policy\|unsafe-inline\|unsafe-eval\|nonce-\|strict-dynamic\|script-src` | WC-04: weak or absent CSP | A weak CSP is hardening unless a script-injection path exists. |
| `Set-Cookie\|set_cookie\|cookie\(\|res\.cookie\|HttpOnly\|SameSite\|Secure\|Domain=\|__Host-\|__Secure-\|localStorage\.setItem\|sessionStorage` | WC-05: cookie attributes and token storage | Missing flags are leads only. Show the path that uses the gap. |
| `redirect\(\|Location:\|returnUrl\|return_to\|next=\|redirect_uri\|continue=\|callback=\|window\.location` with an input value | WC-06: open redirect | Relative-only targets and allow-lists are safe. Test the parser. |
| `multer\|upload\|send_file\|sendFile\|Content-Disposition\|X-Content-Type-Options\|\.svg\|text/html` near user files | WC-07: user content on the app origin | A separate cookieless origin is the fix. |
| `<script src=\|<link .*href=\|integrity=\|crossorigin\|cdn\.\|googletagmanager\|analytics\|unpkg\|jsdelivr` | WC-08: third-party code | First-party static hosts are fine. |
| `addEventListener\(['"]message\|onmessage\|postMessage\(.*['"]\*['"]\|event\.origin\|ws://\|new WebSocket\|EventSource` | WC-09: message handlers | A listener that checks `event.origin` against an exact list is safe. |
| `serviceWorker\|navigator\.serviceWorker\|caches\.\(open\|match\)\|workbox\|self\.addEventListener\(['"]fetch` | WC-10: service-worker scope and cache | |
| `manifest\.json\|content_scripts\|host_permissions\|externally_connectable\|web_accessible_resources\|runtime\.onMessage\|chrome\.\(runtime\|tabs\|storage\)\|browser\.\(runtime\|tabs\)` | WC-11: extension surface | |
| `NEXT_PUBLIC_\|VITE_\|REACT_APP_\|PUBLIC_\|NUXT_PUBLIC_\|__NEXT_DATA__\|window\.__\w+__\|getServerSideProps\|loader\(\|\.sourcemap\|devtool` | WC-12: client exposure | Public prefixes are meant to be public. Check that no secret uses them. |

## Attack classes

### WC-01 DOM-based XSS

- **What fails:** client code writes an attacker-controlled string into a sink that interprets it as markup, script or a script-bearing URL.
- **Where to look:** HTML sinks and framework escape hatches; URL sinks (`href`, `src`, `action`, `location`); script sinks (`eval`, `Function`, string timers); Markdown or rich-text renderers; client-side routers that read the hash or query; values from `postMessage`, `localStorage`, `window.name` and server JSON that includes user content; sanitiser configuration.
- **Questions:**
  - What is the source, and who controls it? A URL fragment, a stored value and a message are all attacker input.
  - Does a sanitiser sit between them? Does it fit the sink context? Does a later step change the string after sanitising?
  - Does a URL sink restrict the scheme to an allow-list, case-insensitively and after whitespace stripping?
- **Sad-path inputs:** a minimal benign text marker in each source; mixed-case schemes; entity-encoded and double-encoded values.
- **Evidence for confirmed:** source, flow, sink and the sanitiser step that fails, with file:line. E1 is enough for a direct flow with no sanitiser. A claim that a sanitiser or framework escape fails needs E3 or a pinned-version analysis of the sanitiser.
- **Not a finding:** a sink that receives only constants or numbers; the user injecting into their own view with no path to another user; a framework auto-escape on the path.
- **CWE:** CWE-79. For server-built HTML, hand off to injection.

### WC-02 Cross-site request forgery

- **What fails:** a state-changing route accepts a request that another site caused, because the browser attaches credentials by itself.
- **Where to look:** every route that changes state, including `GET` routes that change state, JSON endpoints that also accept form types, login, password and email change, API-key creation and delete actions; method-override parameters; CSRF middleware exemption lists; server actions and form actions; token checks against a cookie value that the attacker can set.
- **Questions:**
  - Which control protects this route: a token bound to the session, `SameSite`, a custom header that a cross-site form cannot send, or an `Origin` check?
  - Does the control run for all methods and content types that the handler accepts?
  - If the control is `SameSite=Lax` alone, is there a state change on `GET`, or a sibling subdomain the attacker can use? `SameSite` is same-site, not same-origin.
- **Sad-path inputs:** the request without the token; with a token from another session; with an empty token; with a `text/plain` or form content type; with the method overridden; with a missing or `null` `Origin`.
- **Evidence for confirmed:** the route, the absent or bypassable control, and the state change for a victim whose browser sends ambient credentials. E1 is enough when no layer in the repository protects the route. Bearer-token APIs that no browser attaches automatically are not affected.
- **Not a finding:** a route that uses a header-only token that a browser does not add by itself; a harmless state change (for example a UI preference); a route that needs a secret the attacker cannot know.
- **CWE:** CWE-352.

### WC-03 CORS with credentials

- **What fails:** the server tells browsers that another origin may read credentialed responses.
- **Where to look:** code that reflects the request `Origin` into `Access-Control-Allow-Origin`; allow-lists built with regular expressions, suffix matches or `startsWith`; acceptance of the `null` origin; `Access-Control-Allow-Credentials: true` with a broad origin; CORS set in the application and again in the proxy; localhost origins in the list.
- **Questions:**
  - How is the allowed origin chosen? Is the comparison exact, on scheme, host and port?
  - Does the response vary by origin (`Vary: Origin`)? If not, a cache can serve one origin's header to another (hand off to http-protocol).
  - Which responses carry secrets, tokens or personal data that a listed origin can read?
- **Sad-path inputs:** an origin that ends with the allowed domain (`allowed.example.evil.test`); an origin with the allowed domain as a prefix; `null`; a different scheme or port of an allowed host.
- **Evidence for confirmed:** the matching code, an origin that passes it and should not, and the credentialed data that this origin can read. E1 is enough when the matcher is in the repository.
- **Not a finding:** a wildcard origin without credentials on public data; a reflected origin on an endpoint with no ambient credentials and no private data.
- **CWE:** CWE-942 (permissive cross-domain policy), CWE-346 (origin validation error, class-level) when the matcher is wrong.

### WC-04 Framing, CSP and security headers

- **What fails:** a sensitive page can be framed by another origin, or the policy that should limit script injection is missing or allows what the attacker needs.
- **Where to look:** frame control (`X-Frame-Options`, CSP `frame-ancestors`) on pages with one-click sensitive actions (confirm, approve, delete, pay, grant); routes that skip the global header middleware; `script-src` with `unsafe-inline`, `unsafe-eval`, wildcard hosts, or hosts that serve user content or JSONP; nonces that repeat between responses; `base-uri` and `object-src` unset; `Content-Security-Policy-Report-Only` as the only policy; `X-Content-Type-Options`, `Referrer-Policy` and `Strict-Transport-Security` settings.
- **Questions:**
  - Which pages carry a sensitive one-click action? Does each send frame control on every route alias and error response?
  - Does the policy block inline script and untrusted hosts? Is a nonce unique per response? Does an allowed host serve attacker-controlled script?
- **Sad-path inputs:** the sensitive page through every route alias; an error response; a redirect response; a response from the static handler.
- **Evidence for confirmed:** a header gap is a finding only with a working path: a one-click action that a frame can reach, or a script-injection point (WC-01) that the policy allows, or sensitive data leaked through the referrer. Otherwise it is a hardening note. Headers set outside the repository are external assumptions.
- **Not a finding:** a missing header with no attack path; a page with no state change and no secret; a report-only policy used during roll-out.
- **CWE:** CWE-1021 for framing. For script gaps, name the weakness in words ("missing defence-in-depth header") and use CWE-79 for the injection itself.

### WC-05 Cookie attributes, scope and token storage

- **What fails:** the browser stores or sends a credential in a way that exposes it or lets another site use it.
- **Where to look:** session cookies without `HttpOnly`, `Secure` or a suitable `SameSite`; `Domain` attribute that widens scope to all subdomains; missing `__Host-` prefix; tokens in `localStorage`, `sessionStorage` or URLs; tokens in query strings that reach logs and `Referer`; cookies set by sibling subdomains.
- **Questions:**
  - Does any script on the origin need to read the credential? If a WC-01 path exists, can the script steal it?
  - Can a sibling subdomain (user content, a marketing site, a takeover-prone host) set or read the cookie?
- **Sad-path inputs:** the cookie set on the login response, the refresh response, and the logout response; the same name set with a different `Domain` or `Path`.
- **Evidence for confirmed:** a flag gap alone is a lead. Confirmed needs a path that uses it: a script-injection point that reads a token that `HttpOnly` would hide, a sibling subdomain that sets the cookie, or a token in a URL that reaches a third party. E1 is normally enough.
- **Not a finding:** a non-sensitive preference cookie; a `localStorage` token in an app with no script-injection path and no third-party script (record as hardening).
- **CWE:** CWE-1004 (no `HttpOnly`), CWE-614 (no `Secure`), CWE-1275 (improper `SameSite`), CWE-922 (insecure storage, class-level) for token storage.

### WC-06 Open redirects and navigation sinks

- **What fails:** the app sends the user to a destination that input chooses, so a trusted domain lends credibility to an attacker's link. The redirect also becomes a link in OAuth and token-leak chains.
- **Where to look:** post-login and post-logout redirects; `returnUrl`, `next`, `continue`, `redirect_uri`; URL shorteners and link trackers; client-side `location` assignments; redirect helpers that join a base and a path; validators that use `startsWith`, `contains` or a regular expression.
- **Questions:**
  - Is the target a relative path only, or an allow-listed origin? Is the check done on the parsed URL?
  - Does the validator treat `//host`, `/\host`, `https:host`, `user@host`, encoded slashes, tabs and newlines the same way as the browser?
- **Sad-path inputs:** a protocol-relative URL; a backslash form; a URL with credentials before the host; a host that has the allowed domain as a prefix or suffix; an encoded variant.
- **Evidence for confirmed:** the validator, a value that passes it and leaves the allowed set, and the use. Differences between the validator parser and the browser parser need E3, or a pinned-parser analysis.
- **Not a finding:** a redirect to a fixed set of destinations.
- **CWE:** CWE-601.

### WC-07 User-content origins

- **What fails:** files or markup uploaded by users are served from the application origin, so active content in them runs with the application's authority.
- **Where to look:** upload handlers and file-serving routes; `Content-Type` taken from the upload; HTML, SVG, XML and PDF served inline; missing `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`; user pages and sites hosted on a path or subdomain of the main domain.
- **Questions:**
  - Which origin serves user files? Does it share cookies or storage with the app origin?
  - Which content types can run script when opened (HTML, SVG, XML, some document types)? Does the server force a safe type or download?
- **Sad-path inputs:** a benign HTML or SVG file with a visible marker; a wrong extension with a script-capable body; a filename with quotes or line breaks (hand off to http-protocol for header injection).
- **Evidence for confirmed:** the serving route, the response headers for a script-capable file, and the origin that holds authority. E1 is enough when the headers come from code in the repository. Headers added by a CDN are external.
- **Not a finding:** files served from a separate, cookieless origin with no application authority; images served with a fixed image type and `nosniff`.
- **CWE:** name the weakness in words: "active user content served from the application origin". The effect is CWE-79.

### WC-08 Third-party scripts and integrity

- **What fails:** a script, style or frame from another party runs with the page's authority, and nothing pins or isolates it.
- **Where to look:** tags that load from CDNs and tag managers; analytics, chat, A/B testing and payment widgets; dependencies loaded at run time from a package CDN; missing `integrity` on pinned files; widgets on pages that handle credentials or payments; `target="_blank"` links without `rel="noopener"`.
- **Questions:**
  - Which third-party code runs on which pages? Does it run on login and payment pages?
  - Is the URL pinned to a version and checked by SRI? SRI can pin content at a mutable URL such as `latest`, but an upstream content change then fails the integrity check. Prefer an immutable versioned URL plus SRI where supported.
- **Sad-path inputs:** none to send. List the sources in the templates of each page class.
- **Evidence for confirmed:** a finding needs a concrete path: for example a mutable third-party script on a page that shows tokens, or a script source whose domain the project does not control. A missing `integrity` attribute alone is a hardening note. E1.
- **Not a finding:** a first-party script; a third-party script on a page with no sensitive data.
- **CWE:** CWE-830 (inclusion of web functionality from an untrusted source), CWE-353 (missing support for integrity check), CWE-1022 (link to untrusted target with `window.opener` access).

### WC-09 Message origin checks

- **What fails:** a handler trusts a message from another window, frame, worker, WebSocket client or extension context without checking who sent it.
- **Where to look:** `message` event listeners; `postMessage` calls with `"*"` as the target origin; checks on `event.origin` that use `includes`, `endsWith` or a regular expression; handlers that act on `event.data` (navigation, storage, token handling, DOM writes); WebSocket servers that rely on cookies and skip an `Origin` check; OAuth popup and payment-frame flows.
- **Questions:**
  - Does the listener compare `event.origin` to an exact allowed value, and also check `event.source` when needed?
  - Does a cookie-authenticated WebSocket handshake check `Origin`?
- **Sad-path inputs:** a message from an unexpected origin; a message with a missing or wrong-typed field; a handshake with a foreign `Origin`.
- **Evidence for confirmed:** the handler, the missing or weak check, and the action or leak. E1 for direct flows. A parser difference in origin matching needs E3.
- **Not a finding:** a handler that ignores messages that do not match an exact origin.
- **CWE:** CWE-940 (improper verification of source of a communication channel), CWE-1385 (missing origin validation in WebSockets), CWE-346 (class-level) for weak matching.

### WC-10 Service workers and cached authenticated responses

- **What fails:** a service worker or client cache keeps or serves data across a boundary: between users on one device, between logged-in and logged-out states, or from a path the attacker controls.
- **Where to look:** worker registration scope and the `Service-Worker-Allowed` header; fetch handlers with a cache-first strategy for API or HTML responses; caches not cleared at logout or user switch; offline storage (IndexedDB, Cache Storage) of private data.
- **Questions:**
  - Which paths can the worker intercept? Can a user-content path on the same origin register a worker?
  - Does the worker cache authenticated responses? Is the cache keyed by user? Is it cleared at logout?
- **Sad-path inputs:** logout then reopen the page offline; switch user on one browser profile; a registration attempt from a user-content path.
- **Evidence for confirmed:** the scope and cache code, and the state in which another user or state reads cached data. This often needs E3 for browser behaviour. Without T2, mark `needs-validation` with a plan.
- **Not a finding:** a cache of public static assets.
- **CWE:** CWE-525 (use of web browser cache containing sensitive information); CWE-524 (use of cache containing sensitive information).

### WC-11 Browser extensions

- **What fails:** an extension gives a web page, or another extension, power that the page must not have. Or it holds more permission than it needs.
- **Where to look:** `manifest.json` permissions and `host_permissions`; `content_scripts` match patterns; `externally_connectable`; `web_accessible_resources`; `runtime.onMessage` and `onMessageExternal` handlers; content scripts that forward page messages to the background context; use of `eval`, `innerHTML` or remote code in extension pages; storage of tokens.
- **Questions:**
  - Can a web page reach a privileged message handler? Which origins may send?
  - Does the handler check the sender (`sender.id`, `sender.url`, `sender.tab`) and validate the message shape?
- **Sad-path inputs:** a message from a page outside the allow-list; an unexpected action name.
- **Evidence for confirmed:** the handler, the missing sender check, and the privileged action (a cross-origin fetch with the extension's permissions, a storage read, a tab action). E1 is normally enough.
- **Not a finding:** a broad permission that the documented feature needs; a handler that only returns public data.
- **CWE:** CWE-940 for unchecked senders; name over-broad permission in words.

### WC-12 Client exposure: serialised data, hydration and bundles

- **What fails:** the server sends data to the browser that the viewer must not see, or the build puts a secret in code that everyone downloads.
- **Where to look:** server data passed to client components as props; page-data blobs in HTML (`__NEXT_DATA__`-style state, loader data, inlined JSON); whole records returned to components that show two fields; environment variables with a public prefix; constants and API keys in bundles; source maps in production; admin-only code shipped to all users.
- **Questions:**
  - What does the serialised data contain that the page does not display?
  - Does any variable with a public prefix hold a secret (private API key, signing key, database URL)?
- **Sad-path inputs:** view the page source and the initial data blob as a low-privilege user; list the bundle's string constants.
- **Evidence for confirmed:** the line that passes the data or secret to the client, and the sensitive value in the output. Record the secret type only, never its value. E1 is normally enough.
- **Not a finding:** a publishable key that is public by design (for example a map or analytics key with domain limits); admin route names with no access gap.
- **CWE:** CWE-201 (insertion of sensitive information into sent data); CWE-540 (inclusion of sensitive information in source code). Hand off secret storage to secrets-config.

## Variant search

When you find one browser-boundary failure:
1. **Same sink.** List every use of the same sink function, component or helper. Check each source.
2. **Same source.** List every sink that reads the same source (fragment, query, stored field, message).
5. **Same serialiser.** List every page that uses the same loader or props helper.

## Chain primitives

This domain often **gives**:
- script execution in the origin, which gives the session's authority, reads of page data and actions as the user;
- a request as the victim (CSRF), a cross-origin read (CORS), or a redirect target for token theft;
- secrets and internal URLs from bundles and page data.

This domain often **needs**:
- a stored or reflected string from injection, or an upload path;
- a victim who opens a link or a page.

## Verification notes

- **E1 is usually enough** for WC-02, WC-03 (matcher in the repository), WC-06 (simple allow-list gaps), WC-07, WC-09 (direct flow), WC-11 and WC-12, and for WC-01 when source, flow and sink are in the repository with no sanitiser.
- **E3 is needed** when the claim depends on browser behaviour (WC-01 sanitiser bypass, WC-06 parser differences, WC-10), on a sanitiser or URL parser that the repository does not contain, or on origin-matching differences. Without T2, mark `needs-validation` with a plan.
- **Headers set outside the repository** (CDN, proxy, hosting platform) make WC-04 and WC-05 `needs-validation`, unless the repository sets them itself.
- **E3 test shape:** with a local instance and dummy accounts, load a page that sends the minimal cross-origin request or message with a benign marker. Record the observed status, headers or DOM change. Do not send traffic to deployed systems.
- **Severity examples:**
  - critical – script execution in the origin of an admin or all-user session with no user interaction beyond a page view, and a path to account takeover of any user;
  - high – DOM XSS reachable from a link; CSRF on password, email or key change; CORS that lets any origin read credentialed data; a server secret in a public bundle;
  - medium – CSRF on a limited action; open redirect in an OAuth flow that leaks a code; clickjacking on a one-click destructive action; user content on the app origin with limited authority;
  - low – open redirect with no token flow; missing `HttpOnly` with no script-injection path;
  - informational – missing headers without a path; report-only CSP.

## Fix patterns

- **Safe sinks.** Use text sinks and framework templating. Where HTML is needed, sanitise with a maintained library, as the last step before the sink. Use Trusted Types where supported.
- **CSRF.** Use a per-session token or a double-submit scheme bound to the session, on every state-changing route. Add `SameSite` and an `Origin` check as extra layers. Never change state on `GET`.
- **CORS.** Compare the origin to an exact list. Send `Vary: Origin`. Never use credentials with a wildcard or a reflected origin.
- **Framing.** Set `frame-ancestors` on every HTML response, with `X-Frame-Options` for old browsers.
- **CSP.** Use a nonce-based or hash-based `script-src` with `strict-dynamic`, `object-src 'none'` and `base-uri 'none'`. Roll out with report-only, then enforce.
- **Cookies.** Use `HttpOnly`, `Secure`, `SameSite` and the `__Host-` prefix for session cookies. Keep session tokens out of web storage and URLs.
- **Redirects.** Accept relative paths or IDs that map to a server-side list. Parse the URL and compare the origin exactly.
- **User content.** Serve it from a separate registrable domain with no cookies. Force download or a safe type. Send `nosniff`.
- **Third parties.** Pin versions, add SRI, and keep them off login and payment pages.
- **Messages.** Check `event.origin` against an exact list and the shape of the data. Always give `postMessage` an exact target origin. Check `Origin` on WebSocket handshakes.
- **Client exposure.** Send view models with only the needed fields. Keep secrets out of public-prefixed variables. Disable public source maps.
- **Looks right but is not:** an `includes` or regular-expression origin check; sanitising and then decoding; an input filter instead of output encoding for the sink; a CSRF token that any session accepts; relying on `SameSite=Lax` where sibling subdomains are untrusted; hiding admin links in the UI.

## Regression tests

- For each fixed sink, a test with the minimal benign marker in each source, asserting that the marker stays text.
- For CSRF, a test per state-changing route that sends the request without a token, with another session's token and with an alternate content type, and asserts rejection.
- For CORS, tests for an allowed origin, a disallowed origin, a suffix-match lookalike and `null`.
- A header test per response class that asserts the full set of security headers.
- For redirects, a table test with relative, protocol-relative, backslash, credential-prefixed and encoded targets.
- For uploads, a test that a script-capable file is served as a download or from the isolated origin.
