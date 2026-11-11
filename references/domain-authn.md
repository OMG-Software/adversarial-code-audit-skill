# Domain: Authentication

## Scope

- **Load when:** the code decides who a principal is. Signs: login handlers, password checks, sessions, cookies that carry identity, bearer tokens, JWT or similar libraries, OAuth, OIDC or SAML code, OTP or MFA code, WebAuthn, password reset, API keys, client certificates, device or service credentials, pre-shared secrets, signed requests that name a sender.
- **Covers:** credential checks; session and token life cycle; token verification and claim binding; OAuth, OIDC and SAML as client and as server; identity-provider and SCIM server side; MFA, passkeys and step-up; account recovery, email and phone change; account linking; API keys; mTLS, device and service identity; guess limits and enumeration.
- **Hand off to:**
  - `domain-authz.md` – what a known principal may do. Authn ends when the principal is established.
  - `domain-crypto.md` – password hashing, token randomness, constant-time comparison and signature API misuse. Authn owns the decision logic around them: which token, which claims, which key source.
  - `domain-web-client.md` – cookie attributes, CSRF on non-login routes, open redirects, token storage in the browser.
  - `domain-http-protocol.md` – `Host` and forwarded-header trust. A reset link built from the `Host` header is found there.
  - `domain-abuse.md` – account farming and enumeration at scale. Authn owns the per-account guess limit.
  - `domain-injection.md`, `domain-input-parsing.md` – injection in a login query; XML parser flaws in SAML.
  - `domain-secrets-config.md` – default accounts, hard-coded credentials and debug login switches.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Credential:** The system accepts a principal only after it verifies a credential that belongs to that principal, on every entry path to <surface>.
2. **Binding:** A session, token or key names exactly one principal. No request field changes which one.
3. **Verification:** The verifier accepts a token only after it checks signature or lookup, algorithm, issuer, audience, token type, expiry and revocation state. It takes the algorithm and key source from server configuration, not from the token.
4. **One-time:** A one-time value (reset token, OTP, authorization code, challenge, invite) works once, for one purpose and one principal, inside its lifetime.
5. **Lifetime:** Logout, password change, reset, account disable and loss of a factor end the affected sessions and tokens within <documented time>, on every path, including open connections.
6. **Equal strength:** No enrolment, recovery, change or fallback path gives access that the primary login would refuse.
7. **Identity link:** An external identity maps to a local principal only through a stable identifier that the identity provider verified. A mutable or unverified attribute (such as an email address) does not link accounts.
8. **Guess limit:** Guesses against one credential, one account and one source are limited. A request field cannot change the limit key.
9. **Failure:** When a check cannot finish (error, timeout, missing key, unknown token type, missing configuration), the result is no authentication.
10. **Uniform response:** Login, reset and registration responses do not tell a caller whether an account exists, unless the design accepts it.

## Recon additions

Add these to `domain-notes.md` under a heading "Authentication model". Keep it short; hunters copy it.

1. **Principal types.** Users, admins, services, devices, peers, anonymous. For each: credential type and storage.
2. **Entry points.** Every place that creates an authenticated context: login, token endpoint, SSO callback, API-key header, client certificate, WebSocket upgrade, CLI flag, pre-shared secret, signed message.
3. **Token and session inventory.** Table: name | issuer | format | verifier (file:line) | key source | lifetime | storage | revocation | fields bound.
4. **Credential life-cycle matrix.** Table: action (enrol, change, reset, recover, link, delete) | proof required | notification sent | sessions ended.
5. **Factors and fallbacks.** Each factor, and each way to skip or replace it (remember-device, recovery code, support override, legacy client).
6. **External identity.** Each trusted issuer, its audience, key source, key refresh rule, and the claim used as the local identifier.
7. **Guess-limit map.** Each endpoint that checks a secret, its limit key, limit store, and behaviour when the store fails.
8. **Upstream identity.** Any identity that arrives in a header or environment variable, and who may set it.

## Lead searches

Adapt the patterns to the language. The language file adds library names.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `(decode\|parse\|unverified\|insecure).*(jwt\|token\|claims)`; `verify_?signature.*false`; `ignore_?(exp\|expiration)`; `alg(orithm)?s?\b.*(none\|\[)` | Claims used without verification, or algorithm chosen by the token (AN-04) | Unverified decode is normal when it only reads a key ID before verification. Follow the result. |
| `(aud\|iss\|azp\|typ\|nonce\|exp\|nbf)` in verification code, against the claims the code checks | Missing claim checks (AN-04, AN-05) | Some libraries check these by default. Read the call options. |
| `session.*(create\|new\|regenerate\|rotate\|renew)`; login handlers that do not call them | Fixation (AN-02) | The framework can rotate on login. Check its configuration. |
| `(expire\|max_?age\|ttl\|lifetime\|idle\|timeout)` and `(logout\|sign_?out\|revoke\|invalidate\|deny_?list)` near `session\|token\|cookie\|refresh` | Missing lifetime or revocation (AN-03) | Deleting a client cookie is not revocation. |
| `(redirect_?uri\|return_?to\|callback)`, `state`, `nonce`, `code_?(verifier\|challenge)`, `pkce` | OAuth and OIDC flow checks (AN-05, AN-06) | Public and confidential clients differ. |
| `(saml\|assertion\|nameid\|audience\|recipient\|in_?response_?to\|signed_?info\|xmldsig)` | SAML validation (AN-07) | |
| `(otp\|totp\|hotp\|mfa\|2fa\|second_?factor\|recovery_?code\|step_?up\|remember_?(me\|device)\|webauthn\|passkey\|rp_?id\|sign_?count)` | MFA and passkey logic (AN-08) | |
| `(reset\|forgot\|recover\|verify_?(email\|phone)\|change_?(email\|phone\|password))` near `token\|code\|link` | Recovery and change flows (AN-09) | |
| `(email_?verified\|verified_?email)`, `find_?or_?create`, `(link\|merge\|associate).*(account\|identity\|provider)` | Account linking (AN-10) | |
| `(api_?key\|access_?key\|personal_?access\|client_?secret\|x-api-key)`; `(peer_?cert\|client_?cert\|ssl_client\|subject_?dn\|common_?name)`; `(X-Forwarded-User\|X-Remote-User\|REMOTE_USER)` | Key handling and identity mapping (AN-11) | A header is safe only if a trusted proxy strips client copies. |
| `(rate\|throttle\|lockout\|attempt\|failed_?login\|captcha\|backoff)` near login, reset and OTP code | Guess limits (AN-12) | |
| `(admin\|root\|test\|demo\|default\|guest\|master\|backdoor)` near `password\|passwd\|pwd\|token\|secret` | Default or hidden credential (AN-01) | Test fixtures are false hits unless they ship. |

## Attack classes

### AN-01 Credential check flaws

- **What fails:** the code accepts a credential that is wrong, empty, or not tied to the principal.
- **Where to look:** login and token handlers; comparison code; code that loads a user by name or email before the check; default, test and service accounts; clients that send a stored hash or a client-computed result; fallback to a second backend when the first fails.
- **Questions:**
  - Does the check run when the password, code or token is empty, null, missing or an array?
  - Does a loose comparison, type coercion or truncation make unequal values match?
  - If the user does not exist, does the code skip the check and still create a context?
  - Does the server accept a stored password hash as the secret, or trust a client-side "verified" flag?
  - What happens when the backend (database, directory, hash library) fails?
- **Sad-path inputs:** empty string; null; `"0"`, `"null"`, `"false"`; an array or object instead of a string; a very long password; a user name with different case, spaces or Unicode forms; a disabled or pending user; a directory bind with a name and an empty password.
- **Evidence for confirmed:** the comparison, the input that passes it, and the context that results. E1 is normally enough.
- **Not a finding:** a test account that exists only under a test build flag; a default credential that setup forces the operator to change (cite the code).
- **CWE:** CWE-287 (class-level; use a child where one fits), CWE-306, CWE-304, CWE-603, CWE-836, CWE-1392, CWE-798.

### AN-02 Session creation and fixation

- **What fails:** a session identifier survives a change of privilege, or an attacker chooses it.
- **Where to look:** login, SSO callback, MFA completion, privilege change and "switch account" handlers; code that accepts a session ID from a URL, header or body; pre-login session state that carries into the post-login session.
- **Questions:**
  - Does the code issue a new identifier at login and at every step-up?
  - Can the client supply an identifier that the server keeps?
  - Does pre-login state (return URL, flow state, MFA flags) carry over and hold trust?
- **Sad-path inputs:** a session ID set before login and used after; an identifier in a query parameter; two logins that share one session.
- **Evidence for confirmed:** the login path that keeps the old identifier, and a way for the attacker to set it. E1 is enough when the framework behaviour is in the repository. Identifier randomness belongs to `domain-crypto.md` (CR-04).
- **Not a finding:** a framework that rotates the identifier on login by default, when the code does not disable it.
- **CWE:** CWE-384.

### AN-03 Expiry, logout and revocation

- **What fails:** a session or token stays valid after it must end.
- **Where to look:** session stores; token issuers; refresh-token code; logout, password change, reset and account-disable handlers; long-lived connections; remember-me cookies; API keys with no expiry.
- **Questions:**
  - Does logout end server-side state, or only delete the client copy?
  - After password change, reset or disable, which sessions, refresh tokens, keys and remember-me tokens still work?
  - Is there an absolute lifetime as well as an idle timeout?
- **Sad-path inputs:** a token used after logout; a session used after password reset; a refresh token used twice; an access token used after account disable; a token with no `exp`.
- **Evidence for confirmed:** the revocation event, the path that still accepts the old credential, and how long it stays valid. Race-dependent claims need E3.
- **Not a finding:** a short documented token lifetime with no revocation list, inside the stated tolerance.
- **CWE:** CWE-613.

### AN-04 Token verification and claim binding

- **What fails:** the verifier accepts a forged, replayed or wrong-purpose token.
- **Where to look:** JWT, JWS, JWE, PASETO, signed cookies, opaque-token lookups, HMAC-signed query strings; custom "sign then encode" formats; code that decodes before it verifies; key lookup by `kid`, `jku`, `x5u` or an embedded key.
- **Questions:**
  - Who picks the algorithm: server configuration or the token header? Is `none`, or a symmetric algorithm for an asymmetric key, accepted?
  - Where does the verification key come from? Can the token point to a key URL, an embedded key, or a key ID that reaches a file path or query?
  - Does the verifier check issuer, audience, expiry, not-before and token type?
  - Can a token of one kind (ID, access, refresh, email-link, service) work where another kind is expected?
  - Which claim becomes the local principal? Is it unique within the issuer?
- **Sad-path inputs:** algorithm `none`; header algorithm switched to a symmetric one; missing signature; expired and future-dated tokens; wrong audience; a staging token with the same key; duplicate JSON keys; a `kid` with path characters; a token of the wrong type.
- **Evidence for confirmed:** the verification code, the missing or wrong check, and the context that results. E1 is enough for missing claim checks and algorithm choice by the token. Parser-differential claims need E3. General signature API misuse is CR-08.
- **Not a finding:** a claim that no code uses; a library that enforces the check by default in the pinned version (cite version and library code).
- **CWE:** CWE-347, CWE-345 (class-level), CWE-565, CWE-807.

### AN-05 OAuth and OIDC as a client

- **What fails:** the relying party accepts a response that the user did not start, or an identity that the provider did not assert for this client.
- **Where to look:** authorization-request builders; callback handlers; ID token validation; token exchange; "log in with" and "connect" flows; mobile and desktop apps with custom URL schemes or loopback receivers; code that supports several providers.
- **Questions:**
  - Is `state` unpredictable, bound to the browser or app that started the flow, single-use and checked? Without it, login CSRF and account attachment are possible.
  - Does the code check ID token signature, issuer, audience, expiry and `nonce`? Is the issuer the one the flow started with (mix-up between providers)?
- **Sad-path inputs:** callback with no `state`; `state` from another session; reused code; ID token for another client; ID token from provider B at the callback of provider A; missing `nonce`.
- **Evidence for confirmed:** the callback code that skips the check, and the login or link that results. E1 is normally enough.
- **Not a finding:** a confidential-client code flow where a framework layer checks `state` (cite it).
- **CWE:** CWE-352 for a missing `state` check, CWE-346 (class-level), CWE-294.

### AN-06 OAuth, OIDC and SCIM as a server

- **What fails:** the authorization server or identity provider issues a grant, token or identity to the wrong party.
- **Where to look:** redirect URI matching; authorization-code issue and exchange; refresh-token rotation; client authentication; consent and scope assignment; dynamic client registration; introspection and revocation endpoints; SCIM user and group endpoints.
- **Questions:**
  - Is the redirect URI compared as an exact string? Do prefixes or wildcards pass?
  - Is the code bound to client, redirect URI and PKCE challenge, and single-use?
  - Can a client request scopes beyond its registration?
  - Do SCIM endpoints authenticate the caller, limit it to its tenant, and block changes to admin attributes?
- **Sad-path inputs:** a redirect URI with a path suffix, extra parameter, different case or encoded characters; a replayed code; a code exchanged by another client; a scope list wider than registered; a SCIM write that sets an admin group.
- **Evidence for confirmed:** the matching or binding code and a start-and-exchange pair that gives the grant to the wrong party. E1 is enough for missing binding. A race on code redemption needs E3.
- **Not a finding:** a loopback redirect with any port for a public native client, where the design follows the native-app guidance.
- **CWE:** CWE-346, CWE-294, CWE-306.

### AN-07 SAML and signed identity assertions

- **What fails:** the service provider trusts an assertion that is forged, altered, replayed or meant for another party.
- **Where to look:** SAML response handlers; signature-validation helpers; code that finds the signed element by ID or path; metadata loading; single logout; any system that accepts a signed identity document from a provider.
- **Questions:**
  - Does the code read only the element that the signature covers? Can unsigned content sit next to a signed element?
  - Does it reject a document with no signature?
  - Does it check issuer, audience, recipient, destination, `InResponseTo`, validity window and assertion replay?
  - Does identifier extraction read the same text as the signature check?
  - Where does the trusted certificate come from? Can the document supply it?
- **Sad-path inputs:** an unsigned assertion; a signed element plus an extra unsigned assertion; a signature over a different element; an assertion for another audience; a replayed assertion; a user identifier that contains an XML comment.
- **Evidence for confirmed:** the validation code and the exact gap. Claims that depend on two XML parsers reading one document differently are parser-differential claims and need E3.
- **Not a finding:** a library that rejects the document shape in the pinned version (cite library code or test).
- **CWE:** CWE-347, CWE-345 (class-level), CWE-294.

### AN-08 MFA, passkeys and step-up

- **What fails:** a second factor can be skipped, replaced, guessed or reused.
- **Where to look:** the point after the first factor where the code sets "authenticated"; factor enrolment and removal; step-up checks; recovery codes; remember-device cookies; push and SMS flows; WebAuthn registration and assertion handlers; routes (API tokens, legacy clients, SSO) that skip MFA.
- **Questions:**
  - Does the session become fully authenticated after the first factor, with MFA enforced only by the UI or one route?
  - Can a first-factor session enrol a new factor or remove the old one without proof of the old one?
  - Is an OTP single-use, bound to the user, and limited per user and not only per source? Do recovery codes have enough entropy, single use and an attempt limit?
  - Does a step-up result bind to one action, or unlock everything?
  - For WebAuthn: is the challenge random, stored server-side, single-use and short-lived? Does the server check origin, relying-party ID, ceremony type and user verification as policy needs, and that the credential belongs to the claimed user?
- **Sad-path inputs:** a direct request to a post-MFA route with a first-factor session; the same OTP twice; an OTP for another user ID; an API path with no MFA; a reused challenge; an assertion for another origin; a credential ID of another user.
- **Evidence for confirmed:** the state flag or missing check, the route that relies on it, and the access gained. OTP reuse by race needs E3.
- **Not a finding:** a documented exemption for service tokens with their own scoped credential; a policy that accepts user presence without verification when the design states it.
- **CWE:** CWE-308, CWE-304, CWE-294, CWE-307, CWE-345 (class-level).

### AN-09 Account recovery, credential change and contact change

- **What fails:** a weaker path takes over an account that the login protects.
- **Where to look:** forgot-password and reset handlers; email and phone change; password change; verification links; support or admin override tools; security questions; invite acceptance that sets a password.
- **Questions:**
  - Is the reset token random, hashed at rest, single-use, short-lived, and bound to user and purpose?
  - Does a change need the old credential or recent re-authentication? Does an email change need confirmation from the old address?
  - Does a stale reset token or pending email change still work after the password changes?
  - After reset, does the code end all sessions, tokens and keys, and notify the owner?
  - Can the user in the request differ from the user in the token?
- **Sad-path inputs:** a token used twice; the token of A with the user ID of B; an expired token; an email change with no password; a reset while MFA is on; two reset requests in sequence (does the old token still work?).
- **Evidence for confirmed:** the weak step and the access that follows. Race-based reuse needs E3.
- **Not a finding:** email-only recovery that the design states, where no stronger channel exists.
- **CWE:** CWE-640, CWE-620, CWE-304.

### AN-10 Account linking and identity merge

- **What fails:** the system joins two identities on an attribute that the attacker controls.
- **Where to look:** first login through an external provider; "connect account" flows; email-based matching; import and migration code; code that creates a local user from claims; user name reuse after deletion.
- **Questions:**
  - Which attribute links the identity: the stable subject ID of the issuer, or an email address?
  - Does the provider assert the email is verified, and does the code check that claim?
  - Can an attacker pre-register a local account with the victim's email, so that a later external login merges into it?
  - Does "connect" require a login to the target account first?
- **Sad-path inputs:** an unverified email claim; an email with different case or a plus-address; two providers with one email; a subject ID reused across issuers; a new account with an unconfirmed address.
- **Evidence for confirmed:** the linking code, the attacker-controlled attribute, and the resulting access. E1 is normally enough.
- **Not a finding:** linking on an email that a trusted provider proves verified for a domain the operator trusts.
- **CWE:** CWE-287 (class-level), CWE-807.

### AN-11 API keys, service, device and mTLS identity

- **What fails:** a key, certificate or header identifies the wrong principal, or too many principals.
- **Where to look:** key issue, lookup and storage; service-to-service tokens; device enrolment and provisioning; client-certificate mapping; identity headers from a proxy; shared secrets between components; pre-shared tokens in CLIs and daemons.
- **Questions:**
  - Are keys stored hashed and looked up by a non-secret ID? Does a key carry owner, scope, expiry and revocation?
  - For mTLS: is the chain validated against the intended CA only? Which certificate field maps to the principal? Can another certificate from the same CA pass?
  - Does device enrolment need proof of ownership? Is the credential unique per device, or shared across a product line?
- **Sad-path inputs:** a revoked key; an expired key; a valid certificate for another tenant; a certificate with the right name in the wrong field; an identity header sent straight to the app port; one key shared by all devices.
- **Evidence for confirmed:** the lookup or mapping code and the wrong principal that results. Proxy behaviour outside the repository makes the claim `needs-validation`.
- **Not a finding:** a long-lived key that the design allows, with revocation and scope in place.
- **CWE:** CWE-290, CWE-295, CWE-522 (class-level), CWE-798, CWE-306.

### AN-12 Guess limits and enumeration

- **What fails:** an attacker can try many credentials, or learn which accounts exist, without a working limit.
- **Where to look:** login, reset, OTP, recovery-code and API-key endpoints; limit keys (IP, account, session, header); limit storage; lockout rules; differing messages, status codes and timing for known and unknown accounts.
- **Questions:**
  - Is the limit per account as well as per source? A per-source limit alone fails against distributed guessing.
  - Can the attacker change the limit key (forwarded header, case or Unicode form of the name, a second route to the same check)?
  - Does the limit fail open when its store is down?
  - Do responses differ between "no such user" and "wrong password"?
- **Sad-path inputs:** the same user name in another case; a forged forwarded address; many guesses in one body; a second route that skips the limiter.
- **Evidence for confirmed:** the limit key and the way to vary it, or no limit on a credential check. E1 is enough for a missing or bypassable limit. Timing-based enumeration needs E3, or stays `needs-validation`.
- **Not a finding:** differing responses where the product must tell users a name is taken, and the design states it.
- **CWE:** CWE-307, CWE-799 (class-level), CWE-204, CWE-208 (timing; needs E3).

## Variant search

When you find one authentication failure:
1. **Same verifier.** List every caller of the verification function. Check that each passes the same options (algorithm, audience, type).
2. **Same token family.** List every token, cookie and key the system issues. Check each for the same flaw in lifetime, binding and revocation.
3. **Same flow.** If one reset, link or enrolment flow is weak, check every flow that sets or changes a credential (invite, import, support tool, mobile, legacy).
4. **Same entry.** Check that every entry in the recon list reaches the same checks (REST, WebSocket, CLI, internal port, older API version).

## Chain primitives

This domain often **gives**:
- a session or token as another user (account takeover);
- a valid low-privilege identity, which every authorization chain needs;
- the ability to mint or refresh tokens;
- knowledge of which accounts exist;
- a way to drop a second factor.

This domain often **needs**:
- a weak token or leaked key (from `domain-crypto.md` or `domain-secrets-config.md`);
- a way to read a reset token or code (logs, injection, caches);
- a victim action such as a click (from `domain-web-client.md`);
- a race window (from `domain-concurrency.md`).

## Verification notes

- **E1 is usually enough** for AN-01, AN-02, AN-05, AN-06 (missing binding), AN-08, AN-09 (design flaws), AN-10 and AN-12 (missing or bypassable limit), when every step is in the repository and you read the framework default in the pinned version.
- **E3 is needed** for single-use failures that depend on a race (AN-03, AN-06, AN-08, AN-09), for parser-differential claims (AN-04, AN-07), and for any timing claim (AN-12 enumeration, token comparison). Without T2, they are `needs-validation` with a reproduction plan.
- **External assumptions:** identity-provider behaviour (does it send `email_verified`, does it sign the response or the assertion), proxy handling of identity headers, and mail delivery are outside the repository. If one decides the claim, the status is `needs-validation`. Name that fact.
- **Dummy data only:** use test accounts and test keys. Never test against a real identity provider. Never copy a secret value into a finding.
- **E3 test shape:** create two dummy users A and B. Start a flow as A, then finish it in a way that must fail (wrong state, reused token, ID of B). The expected result is refusal. Record the observed result.
- **Severity examples:**
  - critical – an unauthenticated client forges a session or token for any user, or logs in as admin through a bypass;
  - high – takeover of another user's account through reset, linking or MFA bypass; a token accepted for a wrong audience or type with real access; refresh tokens that survive account disable;
  - medium – a weakness that needs a victim action or a rare precondition; no guess limit on a second factor; sessions that outlive a password change;
  - low – account enumeration with no further use; a long but bounded session lifetime;
  - informational – a missing claim check that no code path can use.

## Fix patterns

- **One verification function per token family.** It fixes algorithm, key source, issuer, audience, type and clock tolerance. Callers cannot change them.
- **Bind the token to principal and purpose.** Include type, audience and subject. Reject a token of another kind.
- **Rotate on privilege change.** Issue a new session identifier at login, MFA completion and step-up. End the old one.
- **Make revocation real.** Keep server-side session state, or a short-lived access token with a revocable refresh token. End all of them at password change, reset and disable.
- **One-time values.** Store them hashed. Consume them in one atomic operation. Bind them to user and purpose. Keep the lifetime short.
- **Exact matching.** Compare redirect URIs as exact strings. Require and check `state` or PKCE. Link identities by the stable subject ID.
- **Equal-strength recovery.** A recovery path needs at least the proof that the login needs, and notifies the owner.
- **Limit by account and by source.** Fail closed when the limit store fails. Normalise the user name before it becomes a key.
- **Looks right but is not:** checking the first factor only in the UI; a client-side "verified" flag; decoding a token and trusting its claims; a new identifier with the old one still valid; a per-source limit only; a long random reset token with no expiry or single use; linking by email without a verified claim; matching redirect URIs by prefix; deleting the cookie at logout and keeping the server session.

## Regression tests

- For each token family: tests that send a wrong algorithm, wrong audience, wrong type, expired token and unsigned token, and assert refusal.
- A session test: the identifier changes at login and at MFA completion, and the old one is refused.
- A revocation test: logout, password change, reset and disable each end the sessions, refresh tokens and keys of that user.
- A one-time test: use each reset token, code and challenge twice and assert that the second use fails. Add a parallel-use test for the redemption step.
- An OAuth test: callbacks with no `state`, another session's `state`, a changed redirect URI and a replayed code.
- An MFA test: from a first-factor session, call each post-MFA and enrolment route and assert refusal.
- A guess-limit test: the limit holds when the user name changes case, when a forwarded header changes, and when many guesses arrive in one request.
