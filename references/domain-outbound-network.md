# Domain: Outbound Network

## Scope

- **Load when:** the code makes network requests to a destination that a lower-trust party can choose or influence, or uses a client whose trust settings matter. Signs: HTTP clients, URL fetchers, webhook senders, link previews, image proxies, URL imports, feed readers, discovery fetches in sign-in flows, headless renderers, proxy and relay features, TURN servers, outbound TLS clients.
- **Covers:** server-side request forgery (direct, through redirects, DNS rebinding and URL parser differences); access to metadata and internal services; outbound TLS verification; proxy settings from the environment; webhook senders; link previews and URL imports; fetches in sign-in flows; relay abuse (TURN and similar); response timeouts and size limits (owned by resource-exhaustion).
- **Hand off to:**
  - `domain-authn.md` – the sign-in protocol logic (token validation, redirect URI rules, state and nonce). This file owns the fetch of an attacker-influenced URL inside that flow.
  - `domain-messaging.md` – webhooks that the product receives, brokers and queues.
  - `domain-injection.md` – input that changes the structure of a request line, a header or a body (INJ-07).
  - `domain-web-client.md` – open redirects that the browser follows, and CORS.
  - `domain-resource-exhaustion.md` – response size, timeout, connection and fan-out limits, and UDP amplification. Report a missing limit there.
  - `domain-ai-llm.md` – agent tools that fetch URLs for a model. Use this file for the fetch.
  - `domain-logging-privacy.md` – data sent to third parties (telemetry, trackers) and IP leaks by real-time media.
  - `domain-cloud-deploy.md` – network policy and metadata settings in infrastructure code.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Allowed destinations:** The server sends a request on behalf of <principal> only to destinations in <allowed set>. The set excludes loopback, private, link-local, metadata and other internal addresses, unless the feature needs them by design.
2. **Same address:** The address that the code checks is the address that the code connects to. The code resolves a name once and connects to the checked address.
3. **Every hop:** Each redirect target passes the same checks as the first URL, or the client does not follow redirects.
4. **Same URL meaning:** The component that validates a URL and the component that fetches it read the same scheme, host, port and path.
5. **Verified peer:** Every outbound TLS connection verifies the certificate chain and the host name against the intended peer. No code path turns this off or falls back to plain text.
6. **No ambient trust:** Proxy settings, credentials, cookies and authorization headers come from the code's own configuration. They do not come from request data. A credential goes only to the host it belongs to.
7. **Bounded fetch:** A fetch has a timeout, a maximum response size and a maximum redirect count. It reads only the content types the feature needs.
8. **Relays stay public:** A relay or proxy feature forwards only to destinations the operator allows, and only for authenticated, rate-limited principals.

## Recon additions

Add a heading "Outbound requests" to `threat-model.md`.

| Feature | Client and library (version) | Destination source (config / user / third party / stored) | Allow-list or block-list? | Redirects followed? | Resolution and connect (one step or two) | TLS settings | Proxy source | Credentials sent | Response returned to caller? | Limits (time, size) |
|---|---|---|---|---|---|---|---|---|---|---|

Then add these notes:
1. **Fetch features.** List every feature that fetches a URL: webhooks, previews, avatars, imports, feeds, OAuth metadata, screenshots, conversion, plugin install, health checks.
2. **Network position.** Record what the server can reach that a client cannot: loopback services, private subnets, metadata endpoints, admin ports. State which come from deployment files in the repository and which are assumed.
4. **Defaults.** Record the library defaults for redirects, supported schemes, certificate checks, proxy variables and timeouts. Read the pinned version.

## Lead searches

Adapt the patterns to the language. The language file adds the HTTP clients and their options.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| HTTP client calls (`get\|post\|fetch\|request\|urlopen\|HttpClient\|curl_\|http\.Get\|Net::HTTP\|WebClient\|reqwest`) whose URL argument traces to a request field, stored field or third-party data | URL from a lower-trust source (ON-01) | A constant URL, or a host from operator configuration, is not a lead. |
| `webhook\|callback_?url\|notify_?url\|redirect_?uri\|avatar_?url\|image_?url\|feed_?url\|import_?url\|preview\|unfurl\|oembed\|proxy\|screenshot\|render` | Fetch feature (ON-01, ON-07, ON-08) | |
| `127\.0\.0\.1\|localhost\|169\.254\|10\.\|192\.168\|172\.(1[6-9]\|2\d\|3[01])\|::1\|fc00\|fd00\|0\.0\.0\.0\|is_?private\|is_?loopback\|is_?link_?local\|ipaddress\|block_?list\|deny_?list` | Address filter (ON-01, ON-03, ON-04) | A filter is a control only if it covers all forms and runs on the connect address. |
| `follow_?redirects\|allow_?redirects\|max_?redirects\|redirect\s*[=:]\s*(true\|follow)\|CURLOPT_FOLLOWLOCATION\|FollowRedirects` | Redirect handling (ON-02) | Check the library default if the code sets nothing. |
| `getaddrinfo\|gethostbyname\|resolve\|lookup\|dns\|InetAddress\.getByName\|socket\.connect` before a separate client call | Resolve then connect in two steps (ON-03) | One step with a pinned address is safe. |
| `urlparse\|urlsplit\|new URL\|URI\(\|Uri\.\|parse_url\|\.host\b\|\.hostname\|netloc\|startswith\(['"]http\|endswith\(` on a URL | Host check by string or by one parser (ON-04) | A check that uses the same parsed object for the fetch is better. |
| `verify\s*[=:]\s*(false\|False\|0)\|insecure\|skip_?verify\|InsecureSkipVerify\|rejectUnauthorized\|VERIFYPEER\|VERIFYHOST\|ServerCertificateValidationCallback\|trust_?all\|check_?hostname\s*=\s*False\|CERT_NONE\|NODE_TLS_REJECT_UNAUTHORIZED\|ssl_?context.*unverified` | TLS verification off (ON-05) | Test-only code is not a finding if it cannot ship. Check the build. |
| `HTTP_PROXY\|HTTPS_PROXY\|ALL_PROXY\|NO_PROXY\|http_proxy\|ProxyHandler\|trust_?env\|proxies\s*=\|\.netrc\|getproxies` | Proxy or credential source from the environment (ON-06) | In a CGI-style handler, a request header can become an environment variable. |
| `Authorization\|Cookie\|api_?key\|token\|Bearer\|auth=` set on a shared client or forwarded across redirects | Credential sent to the wrong host (ON-06) | |
| `jwks_?uri\|well-known\|openid-configuration\|issuer\|metadata_?url\|sso_?url\|idp_?url\|entity_?id` fetched | Sign-in fetch of a controlled URL (ON-09) | |
| `turn\|stun\|relay\|tunnel\|socks\|CONNECT\|port_?forward\|proxy_?pass\|forward_?to\|reverse_?proxy` | Relay or forwarder (ON-10) | |

## Attack classes

### ON-01 Direct SSRF

- **What fails:** a user (or a third party) chooses a URL or host that the server fetches. The server reaches destinations that the user cannot reach: loopback services, private networks, cloud metadata, admin ports, or other tenants' services. The result or the side effect returns to the user, or changes state.
- **Where to look:** webhooks, link previews, avatar and image URLs, URL imports, feed subscriptions, "test connection" buttons, renderers that load remote resources, package installers, and API parameters named url, uri, host, endpoint, callback, domain or source.
- **Questions:**
  - Which part of the URL does the user control: the whole URL, the host, the path, or only a query value?
  - Does the code allow only `http` and `https`? Which other schemes does the client library support (file, ftp, gopher, dict, and similar)?
  - Is there an allow-list of hosts, or a block-list of addresses? A block-list must cover loopback, private, link-local (including the metadata address), carrier-grade NAT, unspecified, multicast and reserved ranges, in IPv4 and IPv6, and the IPv4-mapped IPv6 form.
  - What does the user get back: the body, a status code, headers, a screenshot, timing, or only an error? Blind SSRF still reaches internal services that act on a request.
- **Sad-path inputs:** a loopback address; a private-range address; the link-local metadata address; a name that resolves to loopback; an alternate numeric form of an address; an IPv4-mapped IPv6 form; a scheme other than `http` and `https`. Test only against a loopback listener or a documentation range (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) in a sandbox. Never test a real metadata service or live host.
- **Evidence for confirmed:** the line where input becomes the destination, every check on the path, the gap, and a loopback listener in a sandbox that records the request. E1 is enough when no host check exists on any path and the client behaviour is documented. A block-list claim depends on resolution and client behaviour: use E3.
- **Not a finding:** the host is fixed in operator configuration; the feature is meant to reach internal hosts and only trusted administrators use it; an allow-list applies on the connect address.
- **CWE:** CWE-918.

### ON-02 SSRF through redirects

- **What fails:** the first URL passes the check. The server then follows a redirect to an internal address, or to a scheme or host the check would refuse.
- **Where to look:** HTTP clients with redirect following on (often the default); validators that check only the first URL; link previews and importers that fetch the final page; webhook senders that follow redirects; code that follows redirects by hand in a loop.
- **Questions:**
  - Does the client follow redirects? Is that set in code or by the library default (pinned version)?
  - If yes, does the code validate each hop with the full set of checks, including scheme, host and resolved address?
- **Sad-path inputs:** a redirect from a public documentation-range host to a loopback address (use a local test server that issues the redirect); a redirect to a different scheme; a long redirect chain; a redirect with a relative or malformed target.
- **Evidence for confirmed:** the redirect setting, the check on the first URL only, and a local test where the redirect hits a loopback listener. E1 is enough when the code sets follow explicitly and no per-hop check exists. For a library default, read the pinned version or use E3.
- **Not a finding:** redirects are off; every hop is validated and connects to the checked address.
- **CWE:** CWE-918.

### ON-03 DNS rebinding and resolution gaps

- **What fails:** the code resolves a name to check it, then resolves it again to connect. An attacker's DNS server answers with a public address first and an internal address second. The check passes on one answer. The connection goes to the other.
- **Where to look:** validators that resolve a host and test the address, followed by a client call with the original URL; caches and short time-to-live values; clients that re-resolve on retry or on redirect; proxies that resolve names themselves; long-lived connections and connection pools.
- **Questions:**
  - Does the code connect to the address that it checked, or does the client resolve the name again?
  - If an egress proxy resolves names, which component checks the final address?
- **Sad-path inputs:** a test resolver (in a sandbox) that returns different answers on the first and second query for one name; a name with both public and internal answers.
- **Evidence for confirmed:** the two resolution points at file:line and a sandbox test with a controlled resolver that shows the connection reaching the loopback listener. This is a race and a resolution-differential claim: E3 is required.
- **Not a finding:** the code connects to the checked IP and sets the host header and TLS name separately; an egress filter enforces the address at the network layer in the repository.
- **CWE:** CWE-918; CWE-367 for the check-then-use gap.

### ON-04 URL parser differentials

- **What fails:** the validator and the HTTP client read the same URL string differently. The validator sees an allowed host. The client connects to another.
- **Where to look:** host checks built with string tests (`startswith`, `endswith`, regular expressions); two URL parsers in one flow; checks on the raw string before decoding; URL rewriting between check and fetch; user-info (`name@host`), backslashes, fragments, ports, trailing dots and internationalised names.
- **Questions:**
  - Does the check use a real parser, and is the parsed object the one that the fetch uses?
  - Does the allow-list compare exact hosts, or suffixes? A suffix test accepts `allowed.example.evil.test`.
- **Sad-path inputs:** user-info before an `@` that looks like an allowed host; a backslash where a slash is expected; a fragment that holds an allowed name; a trailing-dot host; a suffix-lookalike host under the reserved `.test` or `.invalid` names.
- **Evidence for confirmed:** both readers at file:line, one URL and the two hosts they read, and the allowed fetch of a loopback listener in a sandbox. A parser-differential claim needs E3.
- **Not a finding:** one parsed object serves both the check and the fetch; the allow-list matches exact hosts.
- **CWE:** CWE-918; CWE-436 (class-level) for the differential.

### ON-05 Outbound TLS verification

- **What fails:** the client turns off or weakens certificate or host name checks, accepts any certificate, falls back to plain text, or trusts a wrong set of authorities. A network attacker then reads or changes traffic that carries tokens, data or updates.
- **Where to look:** clients with verification flags; custom trust managers and verification callbacks; checks disabled "for development" that ship; STARTTLS and opportunistic TLS in mail and directory clients; update checkers, telemetry and plugin downloads; webhooks with a "skip verification" option; pinning code; scripts that call download tools with an insecure flag.
- **Questions:**
  - Is verification off in any build that ships? Does an environment variable or a configuration value turn it off?
  - Does the client fall back to plain HTTP or an older protocol version when TLS fails?
  - Does a user-visible "allow insecure" option exist, and what is its default and scope? (A customer-chosen option on their own endpoint is design authority, with a hardening note.)
- **Sad-path inputs:** a server in a sandbox with a self-signed certificate; a certificate for another host name; an expired certificate; a server that refuses TLS; a STARTTLS server that does not offer the extension.
- **Evidence for confirmed:** the disabled or weak check at file:line, the data on the connection, and a reachable path in a shipped build. E1 is enough for an explicit "verification off" in shipped code. A sandbox server with a wrong certificate gives E3.
- **Not a finding:** test-only code that does not ship; a loopback connection between co-located processes in the same trust domain; an option the connection owner selects for their own endpoint.
- **CWE:** CWE-295; CWE-297 for missing host name checks; CWE-319 for plain-text fallback.

### ON-06 Proxy settings, ambient credentials and header forwarding

- **What fails:** the client takes its proxy, credentials or headers from a source that a lower-trust party controls, or sends a credential to a host that must not get it.
- **Where to look:** clients that read proxy variables from the environment; CGI-style handlers where a request header becomes `HTTP_PROXY`; `.netrc` and credential helper files; shared clients with default authorization headers or cookie jars; code that forwards the caller's cookies to a fetched URL; credentials kept across redirects.
- **Questions:**
  - Which proxy variables does the client read? Can any request data set them?
  - Does one client object carry a credential and also serve user-chosen destinations?
  - Does the code copy request headers (cookies, authorization, internal identity headers) into the outbound request?
- **Sad-path inputs:** a request with a header that maps to a proxy variable (CGI-style test); a redirect to a second host from a first host that required credentials; an outbound request to a loopback listener that logs received headers.
- **Evidence for confirmed:** the source of the proxy or credential, the attacker's control of it, and a listener that receives the credential or the redirected traffic. Library behaviour on redirect and credentials needs the pinned version or E3.
- **Not a finding:** the proxy comes from operator configuration; the credential belongs to the destination and is only sent there.
- **CWE:** CWE-15 (external control of system or configuration setting); CWE-441 (class-level; confused deputy).

### ON-07 Webhook senders and callbacks

- **What fails:** a feature lets a user register a URL that the server calls on events. The destination, the body or the headers then serve as an attack path on internal services, or the delivery leaks data to the wrong party.
- **Where to look:** webhook registration and test endpoints; event deliveries and retries; "notify URL" fields in payment, upload and job APIs; callback URLs stored with a job; deliveries that carry secrets or user data.
- **Questions:**
  - Is the URL checked at registration only, or at every delivery? DNS can change between the two (ON-03).
  - Does a delivery follow redirects? Does it return the response body or status to the registrant? (A response channel turns blind SSRF into data theft.)
  - Does the delivery carry a secret in the URL or a header that goes to the registrant's host? Is it the registrant's own secret, or one shared with another tenant?
- **Sad-path inputs:** a registered URL that points to a loopback listener; a URL that resolves to a private address only after registration; a destination that redirects.
- **Evidence for confirmed:** the registration and delivery code, the missing check at delivery, and a loopback listener that receives the delivery. Apply ON-01 to ON-04 evidence rules for the check claims.
- **Not a finding:** only administrators can register webhooks, and the feature is documented to reach internal hosts; the delivery body is fixed and carries no secret.
- **CWE:** CWE-918.

### ON-08 Link previews, URL imports and content fetchers

- **What fails:** the server fetches and processes content from a URL on a user's behalf. The fetch reaches internal hosts. Or the processing of the fetched content (HTML, images, documents, feeds, SVG, XML) loads further resources, runs a renderer or leaks content.
- **Where to look:** previews and unfurl services; image proxies and thumbnailers; import from URL; feed readers; headless browsers; PDF and screenshot generators; markdown and email renderers that fetch remote images; model and dataset downloaders.
- **Questions:**
  - Does the fetcher apply ON-01 to ON-04 checks to the page URL and to every sub-resource that the renderer loads (images, scripts, frames, stylesheets, redirects, meta refresh)?
  - Does the response show the user content from the internal target (preview text, image data, error text, screenshot)?
- **Sad-path inputs:** a page on a local test server that references a loopback sub-resource; an image URL that redirects to a loopback listener; a meta refresh to an internal address.
- **Evidence for confirmed:** the fetcher code, the sub-resource path without a check, and a listener or marker that shows the internal request or content. Renderer behaviour is often external: use E3 or `needs-validation`.
- **Not a finding:** the renderer is isolated from internal networks by a policy in the repository; the preview shows no content from the target.
- **CWE:** CWE-918.

### ON-09 Server fetches in sign-in and federation flows

- **What fails:** a sign-in or trust flow makes the server fetch a URL that an external party supplies: a discovery document, a key set, a metadata file or a callback. The fetch reaches internal hosts, or it trusts content from a host the attacker controls.
- **Where to look:** OpenID Connect discovery and key-set fetches; SAML metadata fetches; OAuth client registration with logo and key-set URLs; token introspection endpoints taken from request data; update and license servers named in editable configuration; key fetches from a URL named in a signed message.
- **Questions:**
  - Does the URL come from configuration that only an operator sets, or from data that another party supplies (a token header, a registration request, a message)?
  - Is the issuer or key URL checked against a configured allow-list before the fetch?
- **Sad-path inputs:** a token whose header names a key-set URL on a loopback listener; a registration request with logo and key-set URLs that point to loopback; an issuer that differs from the configured one.
- **Evidence for confirmed:** the line where an external value becomes the fetch URL, the missing allow-list, and the loopback listener that receives the request. Mark protocol-level consequences for authn or federation.
- **Not a finding:** the URL comes from operator configuration only; the fetched URL must equal a configured value.
- **CWE:** CWE-918. Name any trust-of-fetched-key weakness in words and hand it to authn.

### ON-10 Relays, proxies and forwarders

- **What fails:** a feature forwards traffic for a client. The client uses it to reach destinations that it must not reach, or the feature relays traffic for anyone who asks.
- **Where to look:** TURN and STUN servers; SOCKS, CONNECT and HTTP proxy features; tunnelling and port forwarding; media relays; reverse proxies with a destination taken from a request value; "fetch through server" features in games and remote tools.
- **Questions:**
  - Can a client choose the relay's peer or destination? Does the relay refuse loopback, private, link-local and metadata addresses and the relay's own interfaces?
  - Does a relay require authentication, and are credentials short-lived and bound to a user and a realm? Are long-term credentials shared widely?
- **Sad-path inputs:** a relay request for a loopback peer address; a request for a private-range peer; a request with no credentials or expired credentials; a request on a port outside the allowed range.
- **Evidence for confirmed:** the relay code that accepts the destination, the missing address filter or the missing authentication, and a sandbox test that reaches a loopback listener through the relay. Network-position facts about the deployment are external.
- **Not a finding:** a public relay by design for authenticated users, with address filtering in place; a relay that only forwards to a fixed operator-chosen host.
- **CWE:** CWE-918 for destination control; CWE-1327 only when the issue is binding a service to all interfaces.

## Variant search

When you find one outbound-network failure:
1. **Same client.** List every use of the same HTTP client, wrapper or session object. Compare options.
2. **Same fetcher.** List every feature that calls the same fetch helper or URL validator.
3. **Same parameter.** Search for other fields and parameters that carry URLs (url, uri, link, image, icon, logo, avatar, source, endpoint, host).
4. **Same validator.** If the host check is wrong, list every use of that validator.

## Chain primitives

This domain often **gives**:
- reads of internal services and metadata endpoints, which return credentials and tokens (to cloud-deploy, secrets-config and authn);
- requests to internal services that act on one request (admin ports, caches, queues);
- credential theft from a client with ambient credentials (ON-06);
- traffic interception when TLS verification is off (ON-05).

This domain often **needs**:
- an account or an unauthenticated route that accepts a URL (from api);
- knowledge of internal addresses or services (from recon, logs or disclosure);

## Verification notes

- **E1 is usually enough** for: a fetch of a user-supplied URL with no host or address check on any path, when client behaviour is documented (ON-01, ON-07); an explicit "verification off" in shipped code (ON-05); a credential sent to a user-chosen host (ON-06); a relay with no address filter in code (ON-10). The waiver must name the HTTP client, its version and the documented behaviour.
- **E3 is required** for: DNS rebinding claims (ON-03, resolution race); URL parser-differential claims (ON-04); block-list completeness claims that depend on address-notation handling by the resolver or client (ON-01); redirect claims that depend on a library default that you did not read (ON-02); renderer and sub-resource behaviour (ON-08).
- **Reachability:** confirm the feature is on in the default configuration and that the named principal can reach it. A feature for administrators only is design authority.
- **Network position:** a finding needs a reachable internal target. A target that exists only in the deployment makes the finding `needs-validation`. Name the target to check.
- **E3 test shape:** in a sandbox, start a loopback listener that logs requests. Send the input. The expected result is a refusal and no request at the listener. Never send traffic to a real metadata service or host.
- **Severity examples:**
  - critical – an unauthenticated user reads credentials from a metadata or internal service through a full-response SSRF; TLS verification off on a code or update download channel;
  - high – an authenticated user reaches internal services with a response channel (ON-01); credentials sent to an attacker host (ON-06); traffic interception of tokens through disabled verification (ON-05);
  - medium – blind SSRF with a state-changing request to a reachable internal service; a relay to private addresses with a limited reach;
  - low – port-scan style information from timing or error differences; a rebinding window that needs an unusual resolver;
  - informational – an unused fetch path, or verification off in non-shipping test code.

## Fix patterns

- **Prefer an allow-list.** Fetch only from hosts that the feature needs. If users must choose hosts, add a block-list, then an egress policy.
- **Validate the address you connect to.** Resolve the name once. Check every returned address against the block-list (all special ranges, IPv4 and IPv6, mapped forms). Connect to that address. Keep the original host for the host header and the TLS name.
- **Control redirects.** Turn off automatic redirects, or follow them by hand and run the full check on each hop. Cap the hop count. Block scheme changes. Drop credentials on a host change.
- **One parser.** Parse the URL once with a standards-compliant parser. Use that object for the check and for the fetch.
- **Isolate the fetcher.** Run user-driven fetches in a client with no credentials, no shared cookie jar and no ambient proxy. Better, add an egress policy that blocks internal ranges and metadata addresses. Use the metadata service's session-token mode where the platform offers it.
- **Keep TLS verification on.** Use the system trust store or a pinned set from configuration. Verify the host name. Fail closed on error. Never fall back to plain text. Make "skip verification" unavailable in production builds.
- **Set the proxy in code.** Read proxy settings from operator configuration. Do not trust environment variables in handlers that process request data.
- **Limit the fetch and the answer.** Set timeouts, a size cap, a redirect cap and a content-type allow-list. Return only the data the feature needs, with one generic error for all failures. Allow only `http` and `https` on standard ports.
- **Looks right but is not:** a block-list of the strings `localhost` and `127.0.0.1`; checking the name but not the resolved address; resolving, checking, then letting the client resolve again; a regular expression or `startswith` on the URL string; validating at registration but not at delivery; checking the first URL but following redirects; hiding the response while the request still reaches the target.

## Regression tests

- **Address table:** for each fetch feature, a table of destinations (loopback, private, link-local, metadata address, mapped IPv6, alternate numeric forms, names that resolve to these). Assert refusal and no request at a local listener.
- **Redirect test:** a local server that redirects to a loopback listener, to another scheme and in a long chain. Assert refusal and bounded hops.
- **Rebinding test:** a test resolver that changes its answer on the second query. Assert that the connection goes only to the checked address.
- **URL differential set:** user-info, backslash, fragment, trailing-dot and suffix-lookalike URLs. Assert that the check and the client agree on the host or that the URL is rejected.
- **TLS test:** a local server with a wrong host name, an expired certificate and a self-signed certificate. Assert that the connection fails. Assert that there is no plain-text fallback.
- **Credential test:** a client with a credential and a redirect to a second host. Assert that the second host receives no credential.
- **Relay test:** peer requests for loopback and private addresses. Assert refusal. Assert that unauthenticated requests fail.
