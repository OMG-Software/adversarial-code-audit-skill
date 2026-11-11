# Domain: HTTP protocol and intermediaries

## Scope

- **Load when:** the repository contains or configures anything that parses, forwards, caches or terminates HTTP. Signs: web server and proxy configuration (nginx, Apache `httpd.conf` and `.htaccess`, HAProxy, Envoy, Caddy, IIS `web.config`), CDN and edge rules (cache rules, VCL, edge functions, worker routing), ingress and load-balancer manifests, a hand-written HTTP parser, a reverse proxy in application code, code that reads `Host` or `X-Forwarded-*` headers, cache middleware.
- **Covers:** request smuggling; cache poisoning by unkeyed input; cache deception; `Host` and `X-Forwarded-*` trust; response-header injection; path normalisation differences between proxy and application; web server, proxy and CDN configuration as audit targets; TLS termination assumptions.
- **Hand off to:**
  - `domain-web-client.md` – what the browser does with headers (CSP, CORS, cookie attributes, framing). This file owns where the header is set and whether caches and proxies keep it.
  - `domain-cloud-deploy.md` – infrastructure-as-code for ingress, load balancers and network exposure. Use both files for ingress manifests.
  - `domain-authz.md` – the authorization rule that a path-matching difference bypasses (AZ-11). This file owns the proxy-side cause.
  - `domain-authn.md` – a trusted identity header and the session. This file owns whether the header can come from a client.
  - `domain-abuse.md` – rate-limit scope. This file owns the client-IP source that the limiter reads.
  - `domain-resource-exhaustion.md` – slow-request, body-size and connection limits.
  - `domain-outbound-network.md` – a proxy that fetches attacker-chosen URLs (SSRF).
  - `domain-injection.md` – CRLF in email headers and logs.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Framing:** Every component on the path from client to <backend> splits the byte stream into the same requests, with the same message boundaries.
2. **Cache key:** Everything in a request that changes the response is part of the cache key, or the response is not cacheable.
3. **Cache scope:** A response that depends on the user, a cookie or an authorization header is never stored in a shared cache.
4. **Origin identity:** The scheme, host and client address that the application uses come from a source that a client cannot set. Only a listed proxy sets forwarded headers.
5. **Header integrity:** No request value reaches a response header, status line or redirect target without removal of line breaks and control characters.
6. **Path meaning:** The proxy, the web server and the application give every path the same meaning. An access rule applies to the path that the application serves.
7. **Exposure:** The web server serves only intended files and routes. It lists no directories, serves no VCS, backup or configuration files, and exposes no status page to the public.
8. **Transport:** The scheme that the application believes (HTTPS or HTTP) is the scheme the client used. A plain-text hop runs only on a trusted network.

## Recon additions

Add these to `domain-notes.md` under a heading "HTTP path".

1. **Request path diagram.** The hops from client to application: CDN, load balancer, proxy, web server, application. Name the software and version of each hop that the repository shows. Mark the other hops as external.
2. **Configuration inventory.** Every file that configures a hop: nginx `*.conf`, Apache vhosts and `.htaccess`, CDN rule exports, VCL, ingress annotations, Dockerfiles that copy these files. Note the environment each file serves.
3. **Trust table.** For each hop: which headers it adds, removes or passes (`Host`, `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `Forwarded`, `X-Real-IP`, identity and client-certificate headers). Which application code reads each one.
4. **Cache table.** For each cache layer: what it stores, the cache key, the TTL, and the rule that decides cacheability (path, extension, status, `Cache-Control`, `Vary`, cookies).
5. **Normalisation table.** For each hop: how it treats `//`, `..`, `%2f`, `%2e`, `;` parameters, trailing slash, case, backslash and null byte before it matches a rule or forwards.
6. **Protocol versions.** HTTP/1.1, HTTP/2 and HTTP/3 on each side of each hop. Mark every downgrade or protocol translation.
7. **Application parsers.** Any HTTP parsing in application code: hand-written servers, WebSocket upgrade code, raw socket handlers.

## Lead searches

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `Transfer-Encoding\|Content-Length\|chunked\|TE:\|Upgrade:\|Connection:` in proxy or parser code and configuration | HP-01: framing logic | Reading these headers in a client library is not a lead. |
| `proxy_pass\|proxy_http_version\|ProxyPass\|ProxyPassReverse\|mod_proxy\|upstream\|backend\|server_name\|RewriteRule.*\[P` | HP-01, HP-06: proxy hops | Check the HTTP version used to the backend and the path rewriting. |
| `proxy_cache\|proxy_cache_key\|proxy_no_cache\|proxy_cache_bypass\|fastcgi_cache\|mod_cache\|CacheEnable\|vcl_hash\|vcl_recv\|cache-?key\|cache_?everything\|Edge TTL\|s-maxage\|Surrogate-` | HP-02, HP-03: cache rules | Static-asset caching is normal. Check what else the rule matches. |
| `Cache-Control\|Vary\|Expires\|Pragma\|no-store\|private\|public` set in code | HP-02, HP-03: cacheability decisions | Check authenticated routes and error pages. |
| `X-Forwarded-For\|X-Forwarded-Host\|X-Forwarded-Proto\|X-Real-IP\|Forwarded\b\|X-Original-URL\|X-Rewrite-URL\|X-Forwarded-Server\|trust_?proxy\|TRUSTED_PROXIES\|set_real_ip_from\|real_ip_header\|RemoteIPHeader\|ProxyFix` | HP-04: header trust | Check who can set the header. Many frameworks have a trusted-proxy setting that defaults to off or to all. |
| `req\.hostname\|request\.host\|get_host\|HTTP_HOST\|\$host\|\$http_host\|Host:\|ALLOWED_HOSTS\|server_name _` with use in URLs, mail links or routing | HP-04: Host used for links or routing | A fixed configured base URL is safe. |
| `setHeader\|set_header\|add_header\|header\(\|Header set\|Header always\|res\.set\|response\.headers\|writeHead\|Location\|Content-Disposition` with a request value | HP-05: header injection | Modern runtimes often reject CR and LF. Check the pinned version. |
| `location *[~=^]\|location *\/\|alias \|try_files\|rewrite \|merge_slashes\|<Location\|<Directory\|<Files\|<FilesMatch\|RewriteCond\|AllowEncodedSlashes\|deny all\|allow all\|Require ` | HP-06, HP-07: path rules | Compare the rule with what the application serves. |
| `autoindex\|Options.*Indexes\|stub_status\|server-status\|server-info\|mod_status\|server_tokens\|ServerTokens\|TraceEnable\|AllowOverride\|\.git\|\.env\|\.htpasswd\|\.bak\|\.sql\|\.swp` | HP-07: exposure | A deny rule near the hit is the fix, not the finding. |
| `ssl_protocols\|ssl_ciphers\|ssl_verify_client\|SSLProtocol\|SSLVerifyClient\|ssl_client_cert\|X-SSL-\|X-Client-Cert\|X-Forwarded-Proto\|Strict-Transport\|return 301 https\|proxy_ssl_verify` | HP-08: TLS termination | |
| `listen 80\|<VirtualHost \*:80\|http://` in upstream URLs | HP-08: plain-text hop | Loopback or a private socket is normal. |

## Attack classes

### HP-01 Request smuggling

- **What fails:** two components disagree on where a request ends. An attacker hides a second request inside the first, or desynchronises the connection so that the next user's request is read as part of the attacker's.
- **Where to look:** proxy configuration that forwards `Transfer-Encoding` and `Content-Length` together; downgrade from HTTP/2 to HTTP/1.1 at the proxy or load balancer; backend connection reuse (keep-alive, pooling); proxies that pass obsolete or malformed `Transfer-Encoding` values; hand-written HTTP parsers; settings such as `proxy_http_version` and `proxy_request_buffering`.
- **Questions:**
  - Does each hop reject a request that has both `Content-Length` and `Transfer-Encoding`, duplicate `Content-Length`, or an invalid chunk size?
  - Does the proxy re-serialise the request with one framing, or pass the client's framing through?
  - For HTTP/2 to HTTP/1.1 translation: does the proxy reject header values with CR, LF or NUL, and `content-length` that disagrees with the frames?
  - Does application code parse requests itself? Does it follow RFC 9112 message framing?
- **Sad-path inputs:** a request with both framing headers; a duplicate `Content-Length` with different values; a malformed `Transfer-Encoding` value; a chunk size with extra characters; a body shorter or longer than the length; an HTTP/2 header that contains a line break. Use a local pair of the proxy and backend with dummy data.
- **Evidence for confirmed:** both parsers' behaviour for the same bytes, and a desynchronised or split request observed. This is a parser-differential claim: it needs E3 (SKILL.md section 6). If the proxy or CDN is outside the repository, the claim stays `needs-validation` with a reproduction plan and the exact version question.
- **Not a finding:** a permissive setting on a hop that sits behind a strict hop that the repository shows.
- **CWE:** CWE-444 (inconsistent interpretation of HTTP requests, "request smuggling").

### HP-02 Cache poisoning by unkeyed input

- **What fails:** a cache keys a response on some request parts, but the response also depends on others. An attacker sends a request that changes the response through an unkeyed part. The cache then serves that response to other users.
- **Where to look:** headers that the application reads but the cache key leaves out (`X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Scheme`, `X-Original-URL`, `Accept-Language`, `User-Agent`, custom headers); cookies that change content; query parameters that the cache ignores but the application reflects (tracking parameters, `utm_*`, callback names); `Vary` headers that the CDN ignores or rewrites; cached redirects and error pages; absolute URLs built from `Host` in cacheable pages.
- **Questions:**
  - Which request inputs change the response? Make a list by reading the handler and the template.
  - Which of these are in the cache key? Read `proxy_cache_key`, the CDN cache policy or `vcl_hash`.
  - Does the application send `Vary` for the inputs it reads? Does the cache honour it?
  - Does the cache store error responses and redirects, and for how long?
- **Sad-path inputs:** an unkeyed header with a harmless unique marker value, then a second plain request to the same URL from a clean client, and a check for the marker; a query parameter that the cache removes from the key.
- **Evidence for confirmed:** the list of response-changing inputs, the key without them, and the stored poisoned response served to a clean request. Cache keys are parser and configuration differentials: E3, or `needs-validation` when the cache is a managed CDN outside the repository.
- **Not a finding:** a reflected unkeyed input in a response that is never cached (`no-store`, `private`); an input that changes only a non-security header; a cache keyed on the full input.
- **CWE:** name the weakness in words: "cache stores a response that depends on an input outside the cache key". CWE-348 (use of less trusted source) applies when the input is a forwarded header the application trusts.

### HP-03 Cache deception

- **What fails:** a cache stores a private response, because the cache rule sees a static-looking request and the application sees a dynamic one. A second user then reads the first user's page.
- **Where to look:** cache rules by file extension or by path prefix; CDN "cache everything" or extension lists; applications that serve the same handler for `/account` and `/account/anything.css`; path-parameter styles (`/account;x.css`, `/account%2f..%2fstyle.css`); catch-all routes; missing `Cache-Control: private` or `no-store` on authenticated pages; CDN settings that override origin cache headers.
- **Questions:**
  - Which authenticated responses can a cache rule match? Compare each rule with each dynamic route.
  - Does the application return the account page for an unknown suffix, or a 404?
  - Does the CDN respect `Cache-Control` from the origin, or override it by rule?
  - Do authenticated responses carry `private` or `no-store`?
- **Sad-path inputs:** an authenticated dummy-account request for a dynamic path with a static suffix or a path parameter, then an unauthenticated request to the same URL, and a check for the dummy account's marker data.
- **Evidence for confirmed:** the cache rule, the dynamic route that matches it, the missing private-cache directive, and the second client's view of the first client's page. Needs E3, or `needs-validation` when the cache is outside the repository.
- **Not a finding:** a rule that matches only a static directory; a response with `no-store` that the cache honours, shown in its configuration.
- **CWE:** CWE-524 (use of cache containing sensitive information); CWE-436 (class-level; interpretation conflict).

### HP-04 Host and forwarded-header trust

- **What fails:** the application uses a value from the `Host` or `X-Forwarded-*` headers as a trusted fact, and a client can set it. Examples are the client IP, the scheme, the host in an email link, and the identity in a header from the proxy.
- **Where to look:** password-reset, invite and verification links built from `Host` or `X-Forwarded-Host`; redirect and canonical-URL builders; virtual-host routing by `Host`; rate limiters, allow-lists and audit logs that read `X-Forwarded-For` or `X-Real-IP`; `trust_proxy` set to `true` or to all hops; headers like `X-Forwarded-User` or `X-SSL-Client-Cert` that carry identity; a proxy that appends to a client-supplied header instead of replacing it; applications reachable directly, around the proxy.
- **Questions:**
  - Which hop sets each forwarded header? Does it overwrite the client's value or append?
  - Which entry of `X-Forwarded-For` does the application take? With N trusted proxies, the correct entry is the Nth from the right.
  - Is there a list of allowed hosts? Does an unknown `Host` reach a default virtual host with sensitive content?
  - Can a client reach the application without the proxy (open port, second ingress)?
  - Does any security decision use the header value (admin from internal IP, rate-limit key, identity)?
- **Sad-path inputs:** a request with a foreign `Host`; the same with `X-Forwarded-Host`; a client-supplied `X-Forwarded-For` with a loopback or internal address; identity headers sent directly to the application port.
- **Evidence for confirmed:** the code that reads the header, the hop that does not remove the client's copy, and the security effect (poisoned link, bypassed limit, spoofed identity). E1 is enough when the application reads the header unconditionally and the repository shows no proxy that removes it. If a proxy outside the repository decides, the finding is `needs-validation`. Name that proxy rule as the missing fact.
- **Not a finding:** a header that the application reads only for logging text with no security use; a framework setting that the repository sets to a verified single proxy.
- **CWE:** CWE-348 (use of less trusted source).

### HP-05 Response-header injection and splitting

- **What fails:** a request value that contains CR or LF enters a response header, a status line or a redirect target. The attacker adds headers, sets cookies, or splits the response.
- **Where to look:** `Location` built from input; `Set-Cookie` with input in name, value or path; `Content-Disposition` filenames; custom headers that echo input; redirects from a path or query; HTTP/2 to HTTP/1.1 translation (HP-01); configuration directives that copy request variables into headers (`add_header`, `proxy_set_header`, `Header set` with `%{...}e`, `RequestHeader`).
- **Questions:**
  - Does the response writer reject or encode CR, LF and NUL, in the pinned runtime version?
  - Does the nginx or Apache variable that holds the value decode `%0d%0a`? In nginx, `$uri` is decoded and `$request_uri` is not. A decoded value in `return 302 https://host$uri;` or in `add_header` can carry line breaks in old or unusual setups.
  - Is the filename sanitised for quotes, line breaks and path separators? Does it follow `filename*` encoding rules?
- **Sad-path inputs:** a value with an encoded CR LF and a harmless marker header name; a filename with a quote and a line break. Use a local instance.
- **Evidence for confirmed:** the line that writes the value, the missing neutralisation, the runtime behaviour for a line break, and a marker header in the response. Runtime behaviour is E3. E1 is enough only when the code writes raw bytes to the socket with no check.
- **Not a finding:** a modern runtime that rejects the value (confirm the pinned version's source or tests).
- **CWE:** CWE-113 (improper neutralisation of CRLF sequences in HTTP headers, "response splitting"). Use CWE-79 only for the resulting script injection.

### HP-06 Path normalisation differences

- **What fails:** the proxy or web server matches an access or routing rule on one form of the path, and the application serves another. The rule is skipped.
- **Where to look:** proxy rules that restrict `/admin`, `/internal`, `/metrics` or `/actuator` while the application matches differently; case, trailing slash, duplicate slashes, `..` and `.` segments, `%2f`, `%2e`, `%5c`, `;` path parameters, null bytes, double encoding; nginx `location` match order (exact, prefix, regular expression); `alias` in a `location` without matching trailing slashes ("off-by-slash" file read); `proxy_pass` with or without a URI part (changes decoding and rewriting); `merge_slashes off`; Apache `<Location>` against `<Directory>` and `<Files>`; `AllowEncodedSlashes`; `RewriteRule` flags such as `[NE]`; `X-Original-URL` and `X-Rewrite-URL` override headers; CDN rules that match a raw path.
- **Questions:**
  - Which hop decodes and normalises the path first? Which rule runs before and which after?
  - For each blocked path, does a variant reach the same handler?
  - Does an `alias` target path end with a slash when its `location` does?
  - Does the application honour a header that overrides the path?
- **Sad-path inputs:** each protected path in these forms: different case; trailing slash; `//`; `/./`; a `;x` segment; encoded slash and dot; double encoding. Test on a local pair of proxy and application.
- **Evidence for confirmed:** the two interpretations of one request, the rule that the proxy applies, the handler that the application serves, and the protected response. This is a parser differential: E3, or `needs-validation` when the proxy or CDN is outside the repository. For a clear `alias` or `location` mistake inside a configuration file in the repository, E1 with a waiver that names the matching rules is acceptable.
- **Not a finding:** a normalisation difference where the application enforces the same rule itself (shown by file:line); a path that returns a public page.
- **CWE:** CWE-647 (use of non-canonical URL paths for authorization decisions); CWE-41 (improper resolution of path equivalence).

### HP-07 Web server and proxy exposure

- **What fails:** the server configuration exposes files, routes or diagnostics that the design does not intend, or removes a protection that the application relies on.
- **Where to look:** directory listing (`autoindex on`, `Options +Indexes`); document roots that contain `.git`, `.svn`, `.env`, backup, dump and editor files; status and info pages (`stub_status`, `mod_status`, `server-info`) open to the public; `AllowOverride All` in upload directories; upload directories that run scripts; `TRACE` enabled; version banners (`server_tokens`, `ServerTokens`); catch-all default virtual host that serves an internal site; `add_header` inheritance (nginx drops outer `add_header` directives when an inner block defines any); Apache `.htaccess` that is lost when `AllowOverride None` is set; proxy rules that forward to an internal address chosen by a request value (`proxy_pass $variable`, open proxy); `limit_except` or `<Limit>` that guards only some methods.
- **Questions:**
  - What is in the document root? What does the deployment image copy into it?
  - Which locations are exposed to the public and which are intended?
  - Do the security headers survive in every `location` and on error responses?
  - Can a request value pick the upstream? Does the proxy allow only configured upstreams?
  - Is the configuration in the repository the one that production uses? Mark the answer.
- **Sad-path inputs:** a request for each sensitive path pattern on a local container; a request for a directory without an index; a `TRACE` request; a method not listed in `limit_except`.
- **Evidence for confirmed:** the directive, the file or route it exposes, and its sensitivity. Record secret types only, not values. E1 is usually enough when the shipped configuration and the files in the document root are both in the repository. A configuration that only an operator copy overrides is `needs-validation`.
- **Not a finding:** an example configuration marked and excluded from the image; an exposed path that holds only public files.
- **CWE:** CWE-548 (exposure of information through directory listing); CWE-530 (exposure of backup file to an unauthorized control sphere).

### HP-08 TLS termination and scheme assumptions

- **What fails:** the proxy ends TLS, and the application or the next hop assumes a security property that no longer holds. Examples are a plain-text hop on an untrusted network, a scheme header that a client can set, a client-certificate header that a client can send, and a redirect or HSTS gap that lets a downgrade through.
- **Where to look:** upstream URLs with `http://` across hosts; `proxy_ssl_verify off`; `X-Forwarded-Proto` trusted for secure-cookie, redirect and HSTS decisions; client-certificate identity forwarded in headers (`X-SSL-Client-*`) without removal of client copies; `ssl_verify_client optional` with no check in the application; weak `ssl_protocols` and `ssl_ciphers` or `SSLProtocol` settings; HTTP to HTTPS redirect rules and `Strict-Transport-Security` settings.
- **Questions:**
  - Which hops carry traffic in plain text? Do they run on loopback, a private socket or an untrusted network?
  - Does the backend verify the proxy's certificate when it re-encrypts?
  - Who can set `X-Forwarded-Proto` or the client-certificate header? Does the proxy overwrite it?
- **Sad-path inputs:** a plain-HTTP request to each public port; a client-supplied scheme or certificate header; a request that skips the optional client certificate.
- **Evidence for confirmed:** the configuration or code, and the property that fails. Network claims about untrusted hops are external assumptions: `needs-validation`. A client-settable identity header with no overwrite in the repository is E1.
- **Not a finding:** plain text on loopback; a TLS version setting that matches the documented client base; a missing HSTS header on a service that has no browser users.
- **CWE:** name the weakness in words (cleartext transmission, missing certificate verification, trust in a client-set header). CWE-348 for the client-set header.

## Variant search

When you find one HTTP-layer failure:
1. **Same hop.** List every rule, `location`, `RewriteRule`, cache rule or edge function in the same configuration that uses the same pattern.
2. **Same header.** List every place that reads the same forwarded header, or sets a response header from a request value.
3. **Same route family.** If one protected path has a bypass, test every protected path under the same proxy rule.
4. **Same environment.** Compare staging, production and container configurations. A fix may reach one file only.
5. **Same parser.** If a hand-written parser has one framing defect, review all of its length, chunk and header paths.
6. **Same history.** If an earlier fix changed one configuration file, check its copies.

## Chain primitives

This domain often **gives**:
- access to a path that the proxy was meant to block (admin, metrics, internal);
- a spoofed client IP, scheme, host or identity, which weakens limits, logs, links and authentication that trust them;
- poisoned or deceptive cache entries, which serve one user's data or an attacker's content to others;
- the requests of other users (smuggling).

This domain often **needs**:
- a reachable proxy or CDN path, and knowledge of the hop software (from recon);
- an application feature that reflects an input or serves private data on a cacheable path;
- a victim request, for cache and smuggling impact.

## Verification notes

- **E1 is usually enough** for HP-04 (unconditional read of a client-set header, no overwrite shown), HP-07 and HP-08 (configuration in the repository, shipped to production), and for a plain `alias` or `location` mistake in HP-06.
- **E3 is required** for HP-01, HP-02, HP-03 and for HP-06 claims that depend on how two parsers treat the same bytes (SKILL.md section 6). Without T2, or when the proxy or CDN is outside the repository, set `needs-validation`. State the one missing fact (for example "CDN cache key includes the query string") and a safe check.
- **Reachability:** confirm the configuration file is used by the default deployment (Dockerfile, chart, CI deploy step). A sample file that no deployment path loads is not reachable.
- **External hops:** if a managed CDN, cloud load balancer or platform router sits in front, mark its behaviour as an external assumption. Do not guess its normalisation or caching.
- **Header trust:** if the repository shows a proxy that overwrites the header and the application has no direct access, reject the finding with file:line.
- **E3 test shape:** run the proxy and the application locally with dummy data. Send the minimal request. Record both components' logs and the response. For a cache test, add a unique cache buster and use two clean clients.
- **Severity examples:**
  - critical – smuggling or path bypass that lets an unauthenticated client reach an admin function or read other users' requests and sessions; a cache rule that serves any user's account page to others;
  - high – a client-settable header that gives admin identity or bypasses authentication; cache poisoning that serves attacker script to all visitors; a repository or secret file exposed by the web server;
  - medium – a spoofed client IP that defeats a limit on a secret check; a poisoned link in a password-reset email (needs victim action); header injection that sets a cookie;
  - low – directory listing of non-sensitive files; a status page with limited data;
  - informational – version banners; missing headers with no path.

## Fix patterns

- **One framing per hop.** Run current proxy and server versions. Reject requests with both `Content-Length` and `Transfer-Encoding`, duplicates and malformed values. Use HTTP/2 end to end, or a proxy that re-serialises the request. Do not reuse backend connections after an error.
- **Complete cache keys.** Key on every input the response uses, or strip the input before the application sees it. Send `Vary` for the rest. Mark private and per-user responses `private` or `no-store`. Make the CDN honour origin cache headers for dynamic routes.
- **Cache by route, not by suffix.** Cache only a known static directory. Make the application return 404 for unknown path suffixes.
- **Fixed origin identity.** Configure the public base URL. Use an allowed-hosts list. Take client IP and scheme only from a listed proxy, and have that proxy overwrite the headers. Close direct access to the application.
- **Header writes.** Reject or strip CR, LF and NUL in every header value, in one helper. Encode filenames with the standard rules.
- **One path meaning.** Normalise the path once at the first hop, then forward the normalised path. Apply access rules in the application as well. Use exact `location` matches for sensitive paths, and check `alias` slashes.
- **Locked-down server.** Turn off directory listing, status pages and `TRACE`. Deny dotfiles and backup extensions. Build the document root from an allow-list. Set `add_header ... always` in every block that needs it, or use one include.
- **Transport.** Re-encrypt to the backend and verify the certificate. Overwrite scheme and client-certificate headers at the proxy.
- **Looks right but is not:** a deny rule written for the exact path only; a WAF rule in front of a smuggling-prone hop; trusting `X-Forwarded-For` because "the proxy adds it" (it appends); validating the `Host` header after using it; cache `Vary: *` that the CDN ignores; a regular-expression check on the decoded path when the proxy matches the raw path; hiding the version banner only.

## Regression tests

- A **framing test** against the proxy and backend pair: requests with both framing headers, duplicate lengths and bad chunks all get a 400 and a closed connection.
- A **cache-key test**: for each input the application reads, a request with a changed input and a clean follow-up that shows no change.
- A **private-response test**: every authenticated route returns `private` or `no-store`, and a static-suffix request to a dynamic route returns 404 or an uncached response.
- A **forwarded-header test**: client-supplied `X-Forwarded-*`, `Host` and identity headers do not change the client IP, scheme, link host or identity.
- A **header-write test**: a value with CR and LF is rejected or encoded in every header writer.
- A **path-variant test** per protected path: case, slash, encoding and parameter variants all get the same denial.
- A **configuration lint** in CI: no directory listing, no status page, no dotfile access.
