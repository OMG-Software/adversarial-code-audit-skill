# Domain: Abuse at scale

## Scope

- **Load when:** a feature lets many low-trust actors create accounts, send content, invite others, search, download or spend resources. Signs: public sign-up, invite or referral codes, messaging, comments, posts, reviews, votes, public profiles or search, directory and autocomplete endpoints, email or SMS sending, free tiers or trials, rewards and credits, report and block features, limiter code.
- **Covers:** sign-up and account-farming controls; invite and referral abuse; spam in user content and messaging; scraping and enumeration at scale; rate-limit scope and bypass (per account, per IP, per tenant); costly features without quotas; evasion of bans, blocks and sanctions; manipulation of votes, ratings and rewards.
- **A finding in this domain must name the anti-abuse control that fails.** A control is a limit, a verification step, a quota, a block list, a detection rule or a moderation action. Show the control, show why it fails or is absent, and show the result at scale. "This feature could be abused" is not a finding. It is a hardening note.
- **Hand off to:**
  - `domain-authn.md` – brute force and credential-stuffing controls on login, recovery and code checks. This file owns bulk account creation and enumeration of accounts at scale.
  - `domain-resource-exhaustion.md` – CPU, memory, disk and connection cost of one request or one parser. This file owns missing product-level quotas and per-actor spend.
  - `domain-api.md` – whether a limit exists on an endpoint, and GraphQL batching that defeats it. This file owns whether the limit holds against many identities.
  - `domain-http-protocol.md` – the source of the client IP (`X-Forwarded-For` trust). This file owns the choice of limiter key.
  - `domain-business-logic.md` – workflow and quota-rule errors that are not about adversaries at scale.
  - `domain-client-trust.md` – cheating in games and client-reported results.
  - `domain-financial.md` – payment fraud, chargebacks, double spend.
  - `domain-concurrency.md` – races on counters and quotas.
  - `domain-input-parsing.md` – Unicode normalisation and case folding of identifiers.
  - `domain-outbound-network.md` – features that fetch URLs for the user.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Identity cost:** Creating one more <account | identity> costs the actor at least <verification step | fee | delay>, and the same real actor cannot hold more than <N> identities by trivial variation of <email | username | device | IP>.
2. **Scope:** A limit on <action> uses a key that the actor cannot change or multiply for free. The limit holds across every path that performs <action>.
3. **Quota:** No actor can cause more than <amount> of <paid or shared resource> in <period>. This covers email, SMS, storage, compute, third-party API calls and model calls.
4. **Reward:** A reward, credit, trial or referral bonus is granted once per real person, and never to the actor that triggers it for itself.
5. **Reach:** A new or untrusted actor cannot send to more than <N> recipients, or post to more than <N> places, in <period>. A recipient can stop a sender.
6. **Enumeration:** No endpoint lets an actor list or test more than <N> accounts, names, emails or objects in <period> with no authorization.
7. **Sanction:** A banned, blocked or rate-limited actor cannot return by a trivial route (re-registration, a second endpoint, a changed identifier).
8. **Failure mode:** When a limiter, a verification service or a detection service fails, the feature is limited or off. It does not run unlimited.

## Recon additions

Add these to `threat-model.md` under a heading "Anti-abuse controls".

1. **Abuse scenario list.** From the product's features, list the scenarios a bad actor would run at scale: mass sign-up, spam, scraping, reward farming, cost inflation, ban evasion, vote manipulation.
2. **Control inventory.** A table with one row per scenario: control (rate limit, CAPTCHA, email or phone verification, invite gate, quota, block list, moderation queue, reputation score) | key (IP, account, device, tenant, token) | limit and window | store (memory, database, cache) | where enforced (application, gateway, third party) | behaviour on failure. A scenario with no control is a lead. A control that sits outside the repository is an external assumption.
3. **Identity inventory.** What makes an identity: email, phone, username, device ID, payment method. How each is normalised and checked for uniqueness. What the verification proves.
4. **Cost inventory.** Features that cost money or shared capacity per use: outbound email and SMS, storage, exports, search, media processing, model calls, third-party APIs. For each, the per-actor cap.
5. **Reach inventory.** Features that deliver content to other users: direct messages, mentions, invites, comments, notifications, shares. For each, the recipient controls (mute, block, opt out, approval).
6. **Public data inventory.** Endpoints that return user or object lists without login, or to any account: search, directory, autocomplete, profile, leaderboard, sitemap, feed. ID format (sequential or random) and page size limits.
7. **Alternate paths.** API, mobile, bulk, webhook and admin paths to the same action.

## Lead searches

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `register\|signup\|sign_up\|create_?account\|create_?user` handlers, then `captcha\|recaptcha\|hcaptcha\|turnstile\|verify\|confirm\|otp\|rate\|limit` near them | AB-01: sign-up without a control | The control may sit in middleware or a gateway. |
| `disposable\|temp_?mail\|blocklist\|blacklist\|\+\|normali[sz]e.*email\|lower\(\)\|strip` near email handling | AB-01: email uniqueness and alias handling | Normalising lowers risk. The risk is when it is missing or is partial. |
| `invite\|referral\|refer\|promo\|coupon\|voucher\|credit\|bonus\|trial\|reward\|affiliate\|redeem` | AB-02, AB-07: reward and invite logic | |
| `send_?(email\|sms\|message\|mail)\|twilio\|sendgrid\|ses\.send\|smtp\|notify\|push` with a recipient from input | AB-03, AB-06: sending to arbitrary recipients | A recipient fixed to the account's verified address is safe. |
| `mention\|@all\|@everyone\|broadcast\|bulk\|batch_?send\|dm\b\|direct_?message\|comment\|post\b\|publish` | AB-03: reach of one sender | |
| `block\|mute\|ignore\|report\|flag\|moderat\|ban\|suspend\|spam` | AB-03, AB-07: moderation and recipient controls | Check what the control actually blocks. |
| `search\|autocomplete\|suggest\|typeahead\|directory\|list_?users\|profile/\|/users/\|sitemap\|export\|feed` without authentication | AB-04: public data | |
| `page_?size\|per_?page\|limit\|offset\|cursor` with a large or absent maximum | AB-04: bulk read | |
| `rate_?limit\|throttle\|limiter\|bucket\|quota\|sliding_?window\|redis.*incr\|X-Forwarded-For\|remote_?addr\|client_?ip` | AB-05: limiter key and scope | Read the key and the store. |
| `except\|catch\|fail_?open\|if .*redis\|if .*limiter` near limiter calls | AB-05: limiter fails open | |
| `export\|report\|generate\|render\|thumbnail\|transcode\|ocr\|summari[sz]e\|completion\|llm\|openai\|upload` as user-triggered jobs | AB-06: costly feature without a quota | |
| `vote\|upvote\|like\|rating\|review\|karma\|reputation\|score\|leaderboard\|follow` | AB-08: manipulable counters | |
| `deleted\|banned\|suspended\|deactivated` flags compared with re-registration, login and API-key paths | AB-07: sanction evasion | |

## Attack classes

### AB-01 Sign-up and account-farming controls

- **What fails:** the control that makes a new identity costly is absent, weak or bypassable, so one actor can create many accounts. Account farming feeds spam, reward abuse, vote manipulation and ban evasion.
- **Where to look:** registration endpoints on every client (web, mobile API, OAuth sign-up, import); email and phone verification; CAPTCHA or proof-of-work checks and where the server verifies them; email uniqueness checks; invite-only gates; sign-up through a third-party identity provider; trial accounts.
- **Questions:**
  - Which control limits sign-up: verification, CAPTCHA, rate limit, fee, invite? Is the server the one that checks it?
  - Is the CAPTCHA or verification result bound to the request? Can one solved token or one verified code serve many requests?
  - Does the uniqueness check treat `a+x@mail.test`, dots in the local part, case, and Unicode variants as one address? Does the product want that?
  - Does an unverified account already have full powers (send, post, invite, use the API)?
  - Can the API or mobile route skip the control that the web route has?
- **Sad-path inputs:** two sign-ups with addresses that differ only by an alias tag or case; a sign-up without the CAPTCHA field; a verification code used for two accounts; a sign-up through the alternate route.
- **Evidence for confirmed:** the control, the path or input that skips it, and the number of identities one actor can create under the stated limit. Name the control. E1 is enough when the control is absent from a path in the repository or its key is client-controlled. E3 is needed for claims about runtime counters or third-party verification behaviour.
- **Not a finding:** a product that wants open sign-up and has no abuse scenario that matters; a control enforced by a gateway that the repository shows.
- **CWE:** name the weakness in words: "missing control against automated account creation". CWE-799 (class-level; improper control of interaction frequency) applies when a frequency limit is the failed control.

### AB-02 Invite and referral abuse

- **What fails:** the invite, referral or promotion logic lets an actor gain rewards or access it should not, or create unlimited invites.
- **Where to look:** invite code generation and redemption; referral credit rules; promo and coupon codes; trial and free-tier grants; invite chains that grant rights; codes without expiry or use count; self-referral through a second account; rewards given before the referred account does anything real.
- **Questions:**
  - Is a code single-use, bound to an invited identity and expiring? Which control enforces this?
  - Can an actor refer itself: same email alias, same device, same payment method, same IP?
  - When is the reward granted: at sign-up, at verification, or after real use? Is it removed when the referred account is banned or refunded?
  - How many invites can one account create? Can invitees create more without bound?
- **Sad-path inputs:** a code redeemed twice; a code redeemed by its creator's second account; an expired code; a code used on a path that skips the use count.
- **Evidence for confirmed:** the redemption or grant code, the missing or weak control (use count, binding, self-referral check), and a reward gained beyond the design. E1 is normally enough. Races need E3.
- **Not a finding:** a generous but documented promotion; a reward bound by a limit shown in code.
- **CWE:** name the weakness in words: "improper enforcement of a single, unique action" for reuse. CWE-799 for missing frequency control on invite creation.

### AB-03 Spam in user content and messaging

- **What fails:** a sender can deliver unwanted content to many recipients, and the controls meant to stop this (reach limits, recipient controls, content filters) are absent or bypassable.
- **Where to look:** direct messages, comments, posts, mentions, invites, notifications, email-from-the-platform features (share by email, "send to a friend"); new-account limits; recipient settings (mute, block, message requests, approval); content filters and link rules; report flows.
- **Questions:**
  - Which control limits how many recipients or places a sender reaches per period? Is it keyed on the sender, the account age or the recipient?
  - Can a recipient stop a sender? Does block, mute or opt-out apply on every delivery path (direct, mention, group, invite, API, notification)?
  - Does the content filter normalise Unicode, case, whitespace and encoding before it matches?
  - Can a sender make the platform send to arbitrary external addresses with attacker-chosen text (mail relay)?
- **Sad-path inputs:** a message to many recipients in one request; the same message through the alternate path; a message to a user who blocked the sender; a filtered word with zero-width characters or different Unicode forms.
- **Evidence for confirmed:** the delivery path, the missing or bypassable control (reach limit, block check, filter), and the volume or recipient set it allows. E1 is enough when a delivery path has no recipient-control check that a sibling path has.
- **Not a finding:** spam that the documented design allows (for example public posts, where reach is the feature).
- **CWE:** name the weakness in words after the failed control. CWE-799 when a frequency limit fails. Open relay of platform email is also a missing recipient restriction.

### AB-04 Scraping and enumeration at scale

- **What fails:** an endpoint lets an actor read or test large sets of accounts, names, emails or objects without authorization or with weak limits. Examples are a user directory, search with no result cap, sequential IDs, "does this email exist" checks, and contact discovery.
- **Where to look:** unauthenticated search, autocomplete, directory, profile and feed endpoints; sequential or guessable IDs; list endpoints with large or absent page maximums; export and sitemap endpoints; registration, reset and invite responses that differ for existing and new addresses; contact-matching features; public APIs for partners; per-object existence oracles (AZ-12 in `domain-authz.md` covers one object).
- **Questions:**
  - Which data can a no-privilege actor list in bulk? Is it sensitive in bulk, even if public one by one (email, phone, location, member lists)?
  - What are the page and result maximums? Is there a per-actor cap on pages?
  - Do sign-up, reset, invite and login responses reveal whether an identifier exists? What control limits the number of probes?
  - Are IDs sequential, so that a loop reads all of them?
- **Sad-path inputs:** a list request with a page size at the maximum plus one; two probes of a known and an unknown address, compared; a search with a one-character query.
- **Evidence for confirmed:** the endpoint, the missing cap or limit, the data class returned, and why bulk access crosses a boundary (sensitive in bulk, or the product says it is private). Name the control that should limit it. E1 is normally enough.
- **Not a finding:** public data that the product publishes on purpose; an oracle for a value the product shows publicly.
- **CWE:** name the weakness in words: "observable response discrepancy" for existence oracles and "missing limit on bulk access" for scraping. CWE-799 and CWE-770 apply to the missing limit.

### AB-05 Rate-limit scope and bypass

- **What fails:** a rate limit exists but the actor can avoid it. The limiter key, store or placement is wrong.
- **Where to look:** limiter configuration and middleware; key choice (IP only, account only, global, per tenant); client-IP derivation from forwarded headers; IPv6 addresses (a /64 range is one user); limits on one route and not its aliases or versions; keys that include a client-controlled part (case, trailing slash, query string, a header, an extra parameter); fixed-window counters; per-instance counters; limiters that fail open when the store is down.
- **Questions:**
  - What is the key? Can the actor change it for free: rotate IPs, add a header, vary the path or case, create accounts, use many tokens?
  - Does the same limit apply on every route and version that performs the action? Does a batch request count each item?
  - How does the service derive the client IP, and who can set that value (hand off to http-protocol)?
  - What does the limiter do if its store errors or times out?
  - Is the limit per instance? With N instances, the real limit is N times larger.
- **Sad-path inputs:** requests at the limit plus one on each route and alias; the same request with a changed key part (header, case, trailing slash); a limiter store that returns an error; many accounts from one source.
- **Evidence for confirmed:** the key derivation or placement defect, and the number of actions allowed per window against the intended limit. Name the failed control. E1 is enough for a client-controlled key, a missing alias route, and a fail-open branch. E3 is needed for claims about shared-store behaviour, window resets or counter races.
- **Not a finding:** a limit that a determined actor with many real IPs can bypass, where the design accepts that and a second control (verification, cost) holds.
- **CWE:** CWE-799 (improper control of interaction frequency). CWE-348 (use of less trusted source) when the key comes from a client-set header.

### AB-06 Costly features without quotas

- **What fails:** a feature that costs money or shared capacity per use has no per-actor quota, so one actor can spend the owner's budget or crowd out others.
- **Where to look:** outbound email and SMS (verification codes, invites, resets); exports and reports; media processing; search; storage growth; model or paid third-party API calls triggered by a user; webhook sends; free tiers and trials; self-service creation of projects, keys or integrations; platform email with attacker-chosen recipients (mail bombing; SMS pumping to premium numbers).
- **Questions:**
  - What does one use cost? Who pays?
  - What caps the number of uses per actor, per tenant and in total? Does the cap hold across paths and across identities (AB-01)?
  - Can the actor choose the recipient of an email or SMS? Is there a cap per recipient and per destination range?
  - Does a free or unverified account reach the costly feature?
- **Sad-path inputs:** the costly action repeated just above the stated cap; a send to the same recipient many times; use by an unverified account.
- **Evidence for confirmed:** the feature, the cost, the missing quota or cap, and the amount one actor can spend under the stated limits. A cost claim should use code-based numbers (for example a count of messages) and not a guess. E1 is enough for a missing cap. A claim about a measured cost needs E3.
- **Not a finding:** a feature that is cheap and bounded; slow performance alone (that is resource exhaustion).
- **CWE:** CWE-770 (allocation of resources without limits or throttling). CWE-799 where frequency is the missing control.

### AB-07 Sanction and block evasion

- **What fails:** a ban, suspension, block or restriction does not hold. The actor returns by re-registering, by another path, or by a changed identifier.
- **Where to look:** ban and suspension implementation; which credentials a ban revokes (sessions, API keys, tokens, refresh tokens, webhooks, invites); re-registration with the same email, phone or device; block checks on one delivery path only; deletion that frees the identifier for re-use; restore after deletion; shadow bans; reinstatement paths.
- **Questions:**
  - What exactly does the sanction stop? Does it stop every credential and every path (web, API, mobile, bulk, background jobs)?
  - Is the banned identifier recorded, in a normalised form, so a trivial change does not avoid it?
  - Does a block stop delivery on every path (direct message, mention, invite, group, notification)?
- **Sad-path inputs:** a banned account's API key and refresh token; re-registration with an alias of the banned email; a block checked against a message sent through the alternate route; a deleted account's name taken again.
- **Evidence for confirmed:** the sanction, the path it does not cover, and the action the sanctioned actor can still do. E1 is normally enough. Revocation timing gaps go to the authz time and revocation class (AZ-09).
- **Not a finding:** a sanction that a human decision lifted; evasion that needs a new real-world identity at the cost the design accepts.
- **CWE:** no close CWE entry. Weakness in words: a sanction is bound to an identifier the actor can replace.

### AB-08 Vote, rating and reward manipulation

- **What fails:** counters that rank or reward content (votes, likes, ratings, reviews, follows, karma, points, leaderboard scores) accept inflated or repeated input, and the rule that should stop it is absent.
- **Where to look:** vote and rating endpoints; one-per-user enforcement; weighting by account age or reputation; undo and re-vote paths; counters updated from several paths; leaderboards; engagement rewards; review gating.
- **Questions:**
  - What enforces one vote per actor: a unique key on actor and object, or only a UI check?
  - Does an undo or change create a second count? Does the counter use a stored total with no recount?
  - Does a new or unverified account carry full weight?
  - Does a reward depend on a metric that the actor can raise by self-interaction or by farmed accounts?
- **Sad-path inputs:** the same vote twice; vote, undo and vote; a vote by a new unverified account; a vote on the actor's own content; a vote through the alternate path.
- **Evidence for confirmed:** the counter update, the missing uniqueness, weight or self-vote control, and a result shift beyond the design. E1 is enough for missing uniqueness. Races need E3.
- **Not a finding:** a metric with no reward, ranking or trust effect; manipulation that needs a real account per vote and the design accepts it.
- **CWE:** CWE-837 (improper enforcement of a single, unique action); CWE-799 (class-level; improper control of interaction frequency).

## Variant search

When you find one abuse-control failure:
1. **Same control.** List every action that uses the same limiter, key function or verification helper. Check the key and the failure mode for each.
2. **Same action.** List every path to the same abuse-relevant action: web, API, mobile, bulk, import, webhook, admin, background job.
3. **Same identity gap.** If sign-up normalisation fails for one identifier, check email, phone, username and device paths and their update flows.
4. **Same cost.** List every other feature that sends email or SMS, or calls a paid service, and check its cap.
5. **Same oracle.** If one endpoint reveals existence, check sign-up, reset, invite, login and search.
6. **Same history.** If an earlier fix added a limit to one route, check that it reached its siblings.

## Chain primitives

This domain often **gives**:
- many identities (account farming), which defeat per-account limits and bind to later attacks;
- lists of valid accounts, names and emails, which feed credential attacks and targeted attacks;
- cost inflation (email, SMS, compute or paid APIs);
- unwanted reach to many users;
- many attempts per window, which weaken limits on secret checks.

This domain often **needs**:
- a feature that reaches users or spends money without a verified identity;
- a client-IP source or key from http-protocol and api;
- an existence oracle or identifier source from authn or authz (AZ-12);
- a race window from concurrency, for counters.

## Verification notes

- **Name the control.** Before verification, check that the finding names the anti-abuse control, the key it uses, and the way it fails. If it names none, reject it as "no failing control" and record a hardening note.
- **E1 is usually enough** for AB-01 (control absent on a path, or client-controlled key), AB-02, AB-03 (missing recipient-control check on a delivery path), AB-04, AB-06 (missing cap) and AB-07, when the whole path is in the repository.
- **E3 is needed** for AB-05 claims about shared-store behaviour, window boundaries or counter races, for AB-02 and AB-08 races, and for any claim about measured cost, rates or detection. Without T2, mark `needs-validation` with a reproduction plan that uses small counts and dummy data.
- **External controls:** a gateway, WAF, bot-management service, CAPTCHA provider or email-provider limit outside the repository makes the finding `needs-validation`. Name the one missing fact.
- **Design authority:** check the product documentation. Open sign-up, public listing and generous limits can be intended. Reject findings against intent unless the data is sensitive in bulk.
- **Impact discipline:** a control gap without a demonstrated consequence (spend, spam volume, data in bulk, sanction failure) is a hardening note.
- **E3 test shape:** on a local instance with dummy accounts, set the limit to a small value. Send the limit plus one request through each path. Record the result of the last request. Never send traffic to a deployed service or a real recipient.
- **Severity examples:**
  - critical – not usually reached by abuse alone;
  - high – bulk read of private personal data of all users through an uncapped endpoint; unbounded SMS or email spend by an anonymous actor; a bypass that voids a ban or a verification gate for all accounts and enables a harmful action;
  - medium – account farming that defeats the only control on rewards or votes; spam to arbitrary recipients from a new account; a limiter key that an actor controls on a secret-check endpoint;
  - low – enumeration of non-sensitive public names; a limit that is too high but still bounded;
  - informational – a missing control with no demonstrated consequence.

## Fix patterns

- **Make identities cost something.** Verify email or phone before powers are granted. Bind CAPTCHA and verification tokens to one request. Normalise identifiers for uniqueness (alias tags, case, Unicode form). Give new accounts low limits and raise them with age and good behaviour.
- **One limiter, many keys.** Apply limits per account, per source network (for IPv6 use the /64 prefix) and per target (recipient, resource), together. Enforce them in a shared store. Count each item in a batch.
- **Server-side keys.** Take the key from the authenticated principal and from a client IP that a listed proxy sets. Never take the key from a client header.
- **Caps on cost.** Set a per-actor, per-tenant and global quota on email, SMS, exports, storage and paid calls. Add a spend alarm and a kill switch. Cap sends per recipient and per destination range.
- **Fail closed on cost.** When the limiter or verification service fails, limit the feature or turn it off. Keep read-only public paths on a fail-open policy only when the cost is zero.
- **Rewards.** Grant after real use and verification. Check self-referral. Revoke on ban or refund. Make redemption atomic.
- **Recipient control.** Check block, mute and opt-out in one delivery function that every path calls.
- **Bulk-read caps.** Cap page size and total pages per actor. Use random IDs. Return the same response for existing and unknown identifiers, with the same timing, and move the difference to an out-of-band channel (an email).
- **Sanctions.** Revoke all credentials, jobs and connections at ban time. Store the normalised identifiers and check them at registration.
- **Votes.** Enforce one vote per actor and object with a unique database key. Recompute totals from the votes.
- **Looks right but is not:** a CAPTCHA on the web form only; a limit on IP only; a limit in the UI; a limit that counts HTTP requests when one request holds many items; a block list of exact email strings; a limiter that fails open; per-instance counters; trusting `X-Forwarded-For` for the key.

## Regression tests

- For each fixed limit, a test that sends the limit plus one request through every route, alias and version, and asserts rejection of the last one.
- For key choice, tests that change the client-controlled parts of the key (headers, case, trailing slash) and assert the same limit applies.
- For limiter failure, a test with the store down that asserts a limited or off feature.
- For sign-up, tests for alias-tag and case variants of one email, a replayed CAPTCHA token, and a sign-up through each client route.
- For invites and rewards, tests for double redemption, self-referral and reward reversal after a ban.
- For messaging, a test that block, mute and opt-out hold on each delivery path.
- For enumeration, a test that existing and unknown identifiers get identical responses, and that page and result maximums hold.
- For sanctions, a test that a banned account's sessions, keys, jobs and connections stop, and that re-registration with a variant identifier fails.
- For votes, tests for repeated votes, vote-undo-vote and self-votes.
