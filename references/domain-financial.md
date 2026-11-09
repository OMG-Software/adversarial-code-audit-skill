# Domain: Financial

## Scope

- **Load when:** the code moves, counts, prices or settles value. Signs: balances, credits, points, wallets, ledgers, invoices, subscriptions, usage metering, payouts, refunds, orders, order books, trading or market-making bots, payment-provider or exchange API clients, in-app currencies with real value, tokens that represent value, tax and fee calculation.
- **Covers:** arithmetic precision and rounding; currency and unit confusion; negative, zero and boundary amounts; double spend and idempotency; order and balance races; ledger consistency and reconciliation; fee and limit bypass; price and oracle trust; provider and exchange API keys and scopes; webhook trust from providers; replay of signed requests.
- **Hand off to:**
  - `domain-business-logic.md` – generic step order, limits and time rules that are not about value.
  - `domain-concurrency.md` – race mechanics and locking. This file states the balance and order invariants that races break (FIN-05).
  - `domain-authz.md` – who may spend or view. This file covers correctness of the value, not the right to act.
  - `domain-messaging.md` – webhook transport, queue delivery and ordering in general (FIN-09 covers payment-specific trust).
  - `domain-smart-contracts.md` – on-chain value logic and transaction signing.
  - `domain-crypto.md` and `domain-crypto-protocols.md` – signature primitives and protocol design.
  - `domain-secrets-config.md` – general key storage. FIN-09 covers the scope of provider keys.
  - `domain-client-trust.md` – amounts and prices that clients supply.
  - `domain-abuse.md` – promotion farming, refund abuse and fraud at scale.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Conservation:** For every transfer, the sum of debits equals the sum of credits, in the same currency and unit, and no path creates or destroys value except a documented mint or burn.
2. **Precision:** Every amount is held in an exact type with a fixed scale. Every rounding step uses one documented mode and favours <operator | no one>, never the actor.
3. **Units:** Every amount carries its currency or unit. Code never adds, compares or converts amounts of different units without an explicit rate.
4. **Sign and range:** Every amount is within <min> and <max>, is positive where the operation needs it, and a negative or zero value cannot reverse an effect or skip a check or fee.
5. **Single effect:** A payment, transfer, order, refund or payout takes effect at most once per intended request, across retries, duplicates and replays.
6. **No overdraw:** A balance, limit or reservation cannot go below its bound, also under concurrent requests.
7. **Ledger truth:** The ledger is append-only and balanced. Derived balances equal the ledger. External state (provider, exchange, chain) reconciles to the ledger and differences raise an alert.
8. **Server price:** The server decides price, fee, tax, discount and exchange rate from its own trusted sources at execution time.
9. **Authentic provider events:** The system acts on a provider event only after it verifies the event's origin and re-reads the amount and status from the provider or the ledger.
10. **Least key scope:** Every provider or exchange API key can do only what the component needs (for example no withdrawal right for a trading-only component).

## Recon additions

Add these to `threat-model.md` under a heading "Value flows". Keep it short.

1. **Value inventory.** Every kind of value (currency, points, credits, tokens, positions), its unit, scale and numeric type in code and in storage.
2. **Flow map.** Each path where value is created, moved, reserved, spent, refunded, expired or destroyed, with the code that does it.
3. **Ledger model.** Where truth lives (ledger table, balance column, provider, chain). Which values are derived. Which transactions and isolation level protect each update.
4. **Rate and price sources.** Every price, rate, fee schedule and oracle, its source, freshness check and who can influence it.
5. **Idempotency map.** For each value-changing operation: the idempotency key, its scope, its storage, its lifetime and what happens on a repeated key.
6. **Limits and tiers.** Transaction, daily, aggregate and per-tier limits, and the paths that count against each.
7. **Provider integrations.** Each payment, banking, exchange or billing integration: keys, scopes, webhooks received, return URLs, test and live modes.
8. **Reconciliation.** Jobs that compare internal and external state, their schedule and what they do on a mismatch.

## Lead searches

Adapt the patterns to the language. The language file adds numeric types and library calls.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `float\|double\|Number\(\|parseFloat\|toFixed\|round\(\|Math\.round\|ceil\|floor` near `amount\|price\|total\|balance\|fee\|tax\|rate\|qty` | Binary float or unsafe rounding (FIN-01) | Display formatting is fine. Check storage and arithmetic. |
| `int\(\|long\|uint\|i32\|u32\|atoi\|cast\|as i\|as u` on amounts, and multiplication of amount by rate or quantity | Overflow or truncation (FIN-01) | A wide checked type may hold. |
| `currency\|unit\|decimals\|cents\|minor_?unit\|precision\|scale\|base\|quote\|symbol` | Unit handling (FIN-02) | Check each conversion site. |
| `amount\s*[<>]=?\s*0`, missing comparison, `abs\(`, `-amount`, `negate` in transfer, refund, order and fee code | Sign and zero handling (FIN-03) | |
| `idempot\|dedup\|request_?id\|Idempotency-Key\|nonce\|unique` on payment and order routes | Idempotency design (FIN-04) | Read the scope and the storage. |
| `balance\|available\|reserved\|hold\|credit\|debit` read, then written after a gap, without `FOR UPDATE`, a conditional update, a lock or a serialisable transaction | Check-then-debit race (FIN-05) | An atomic conditional update holds. |
| Ledger inserts and balance updates in separate statements, calls to a provider between writes, `catch` after a provider call | Ledger gap (FIN-06) | |
| `fee\|commission\|limit\|cap\|tier\|threshold\|discount\|coupon\|promo\|referral\|bonus` | Fee or limit logic (FIN-07) | |
| `price\|quote\|rate\|oracle\|ticker\|mark\|index_?price\|last_?price` taken from request fields, caches or one source | Price trust (FIN-08) | |
| `webhook\|callback\|notify\|ipn\|return_?url\|success_?url\|event\.(type\|data)` in payment code | Provider event trust (FIN-09) | Check signature, amount and status checks. |
| `api_?key\|secret\|withdraw\|transfer\|trade\|permissions\|scope` near exchange or provider clients | Key scope (FIN-09) | |
| `sign\|hmac\|timestamp\|recv_?window\|nonce` on outbound or inbound signed requests | Replay of signed requests (FIN-04, FIN-09) | |

## Attack classes

### FIN-01 Precision, rounding and numeric type errors

- **What fails:** arithmetic on money loses or creates value, or an attacker steers the rounding.
- **Where to look:** binary floating point for amounts; mixed scales; rounding at each line instead of at the total (or the reverse); truncation instead of rounding; integer overflow in `amount × rate` or `price × quantity`; narrowing casts; parsing of user strings; minimum tick, lot and dust handling; interest and fee accrual; proration; metering of fractional usage.
- **Questions:**
  - Which numeric type holds the amount in code, in the database and on the wire? Does each conversion keep the scale?
  - Which rounding mode applies, where, and who gains from it? Can many small operations accumulate the gain?
  - Can quantity × price overflow, wrap or exceed the type range?
  - Does the code compare floats for equality?
  - What is the smallest amount that is accepted, and what fee does it pay?
- **Sad-path inputs:** 0.1 + 0.2 style sums; very small amounts (below one minor unit); very large amounts; many splits of one amount; amounts with more decimals than the currency allows; exponent notation; locale formats such as `1,000`.
- **Evidence for confirmed:** the arithmetic, a concrete input and output from a unit test or a computed trace, and the value gained or lost. A rounding gain is a finding when an actor can repeat it for profit or when it breaks a stated reconciliation rule.
- **Not a finding:** a display-only rounding difference; a loss of one minor unit with no way to repeat it and no reconciliation rule.
- **CWE:** CWE-1339 (insufficient precision or accuracy of a real number); CWE-190 (integer overflow or wraparound).

### FIN-02 Currency and unit confusion

- **What fails:** the code treats an amount in one unit as an amount in another.
- **Where to look:** minor units against major units (cents against whole units); tokens with different decimals; base and quote assets; amounts without a currency field; multi-currency totals; conversion code and rate direction; limits stated in one currency and checked in another; points and cash; API clients that expect a string or an integer scale from a provider.
- **Questions:**
  - Does the amount type carry a unit? If not, where does the unit come from?
  - Does every addition, comparison and limit check use amounts in the same unit?
  - Is the rate applied in the right direction, with the right scale?
  - Can the caller choose the currency after the price is fixed?
- **Sad-path inputs:** an amount in cents sent where whole units are expected; a currency code that differs between order and payment; a token with 6 decimals handled as 18; a zero-decimal currency; an unknown currency code.
- **Evidence for confirmed:** the two sites that disagree on the unit, an input that exploits the gap, and the value difference.
- **Not a finding:** a unit mismatch in a log message or a label.
- **CWE:** CWE-681 (incorrect conversion between numeric types).

### FIN-03 Negative, zero and boundary amounts

- **What fails:** an amount at the edge of its range reverses an effect, skips a check or avoids a fee.
- **Where to look:** transfer, refund, withdrawal, order, top-up, tip, donation and adjustment endpoints; fee and tax code; discount code; quantity fields; minimum and maximum checks; code that stores an absolute value and a separate direction.
- **Questions:**
  - Does the code reject negative and zero amounts before any other step?
  - If a negative amount passes, which way does value move?
  - Does a zero amount skip authorization, fee, limit or audit steps while still triggering an effect (a state change, a notification, a reward)?
  - Can a fee exceed the amount, leaving a negative net?
  - What happens at the maximum value and at the maximum plus one?
- **Sad-path inputs:** −1; −0; 0; the minimum accepted amount minus one; a very large amount; a refund larger than the original payment; a refund of a refund; an amount of `NaN` or an empty string.
- **Evidence for confirmed:** the missing range check, the input, and the reversed or free effect. E1 is usually enough.
- **Not a finding:** a negative amount that is a documented credit note with its own checks.
- **CWE:** CWE-1284 (improper validation of specified quantity in input); CWE-191 (integer underflow).

### FIN-04 Double spend, idempotency and replay

- **What fails:** one intended payment, transfer, order or payout takes effect twice, or a request that was meant to work once works again.
- **Where to look:** retry logic in clients and servers; idempotency keys; webhook and queue handlers with at-least-once delivery; signed requests with no nonce or with a long time window; "mark paid" written after the effect; refund and payout jobs that rerun; withdrawal requests; coupon and credit redemption.
- **Questions:**
  - What is the idempotency key, and who chooses it? Is it scoped to the principal and the operation?
  - What happens when the same key arrives with a different amount or target? The server must refuse it.
  - Is the key stored before the effect, in the same transaction? What if the key expires?
  - Does a signed request include a nonce or a short validity window that the server enforces and stores?
  - Can a retry after a timeout run a second effect at the provider?
- **Sad-path inputs:** the same request twice, in sequence and in parallel; the same key with different parameters; a key reused after expiry; a captured signed request replayed after its intended use; a webhook delivered twice or out of order.
- **Evidence for confirmed:** the effect, the absent or late idempotency record, and the repeated effect. Double-spend and replay claims that need concurrent requests need E3 (SKILL.md section 6): use a deterministic schedule and a test double for the provider. A sequential replay with no record can be E1.
- **Not a finding:** a repeat that is a no-op by design; a retry that the provider deduplicates by a key that the code sends.
- **CWE:** CWE-837 (improper enforcement of a single, unique action); CWE-294 (capture-replay).

### FIN-05 Order and balance races

- **What fails:** two concurrent operations both pass a balance, limit or state check and both take effect.
- **Where to look:** read-modify-write on balances; "check available, then debit" in separate statements; reservations and holds; order placement and cancellation; order matching and fills; withdrawal queues; position and margin updates; inventory of limited stock; leaderboards that pay prizes.
- **Questions:**
  - Is the check and the update one atomic statement, a locked read, or a serialisable transaction?
  - What is the database isolation level, and does the code rely on a lock that the database does not give?
  - Can a cancel and a fill, or two withdrawals, interleave to overdraw?
  - Do cached balances feed the check?
  - In a distributed setting, does each node own the balance, or can two nodes both approve?
- **Sad-path inputs:** two simultaneous withdrawals of the full balance; a cancel at the instant of a fill; two orders that together exceed a limit; a request during a balance refresh.
- **Evidence for confirmed:** the unprotected read-modify-write, a deterministic schedule (barrier, injected delay or two transactions in a test) that shows the overdraw, and the resulting balance below the bound. E3 is required. Without T2, mark `needs-validation` with the reproduction plan.
- **Not a finding:** a race on a value with no bound and no effect on others; a race that a database constraint rejects.
- **CWE:** CWE-367 (time-of-check time-of-use race condition); CWE-820 (missing synchronisation).

### FIN-06 Ledger consistency and reconciliation

- **What fails:** internal records disagree with each other or with external systems, and the system lets the difference stand or lets an actor use it.
- **Where to look:** code that updates a balance and a ledger row separately; steps that call a provider between writes; refunds above the captured amount; partial captures and partial fills; chargebacks and reversals; pending states that count as available; derived totals cached for long; manual adjustment tools; failure and retry paths.
- **Questions:**
  - Does every value change write a ledger entry in the same transaction? Is the ledger append-only?
  - What happens if the provider call succeeds and the local write fails, or the reverse?
  - Can total refunds exceed total payments? Can a payout exceed the settled balance?
  - Which job reconciles, how often, and what does it do on a mismatch?
  - Do pending or unsettled amounts count as spendable?
- **Sad-path inputs:** a provider timeout after success; a refund repeated; a partial fill followed by a cancel; a reversal after the value was spent; a stuck pending state.
- **Evidence for confirmed:** the split write or the unchecked bound, the failure that an actor can cause or use, and the resulting extra value or lost value. Use a test double for the provider.
- **Not a finding:** a temporary mismatch that reconciliation repairs within the documented time without a window to spend it.
- **CWE:** CWE-1250 (improper preservation of consistency between independent representations of shared state).

### FIN-07 Fee, limit and policy bypass

- **What fails:** an actor pays less than the rule requires, or exceeds a limit that should stop them.
- **Where to look:** fee computed from client values; fee skipped on a path (internal transfer, batch, API, import); tier thresholds; limits per transaction but not per day or per account; splitting one large operation into many small ones; discount, coupon, promotion and referral stacking; free-trial and credit rules; withdrawal and trading limits; cost of metered usage.
- **Questions:**
  - Which paths produce the same value effect? Does each one charge the fee and count the limit?
  - Does the fee apply to the net or the gross, and after or before rounding? Can rounding bring the fee to zero?
  - Do discounts stack in an order that gives a negative price?
  - Do limits count the same unit across all paths and over the full window?
  - Can an actor create a second account or identity to reset a limit? (Hand scale to `domain-abuse.md`.)
- **Sad-path inputs:** amounts just under a threshold; many small transfers; two coupons together; a discount larger than the price; a fee on a zero-fee tier boundary; an internal path that has no fee.
- **Evidence for confirmed:** the rule, the path that skips it or miscounts, and the amount of value lost. Name the party that loses.
- **Not a finding:** a fee difference that the price list documents.
- **CWE:** CWE-799 (improper control of interaction frequency; class-level).

### FIN-08 Price and oracle trust

- **What fails:** the system acts on a price, rate or valuation that an attacker supplies, moves or delays.
- **Where to look:** price fields in requests or in client-built orders; quotes without expiry; stale cached prices; a single price source; prices derived from thin markets or from the system's own trades; mark and index prices for margin and liquidation; currency conversion at execution time; slippage and deviation bounds; trading bots that act on one data feed; wash trades and self-matching.
- **Questions:**
  - Who sets the price at execution time: the server from a trusted source, or the caller?
  - How old can the price be? What happens when the source is down, stale or returns zero or an outlier?
  - Can one actor move the source in a way that profits it (a small market, a single venue, a self-trade)?
  - Is there a bound on deviation, a median over sources or a time-averaged price?
  - Does a quote bind price, amount, pair and expiry?
- **Sad-path inputs:** a price of zero or negative; a stale timestamp; an outlier far from other sources; a quote used after expiry; a quote reused for a different amount; a feed that returns an error and a default.
- **Evidence for confirmed:** the price source, the path where the attacker controls or delays it, the bound that is absent, and the resulting value difference. Test with fixture feeds only. Do not trade or probe a real venue.
- **Not a finding:** a price from a trusted internal source that only the operator can change; a documented delay that the product accepts.
- **CWE:** CWE-807 (reliance on untrusted inputs in a security decision).

### FIN-09 Provider keys, scopes and webhook trust

- **What fails:** a provider or exchange key can do more than needed, or the system trusts a provider event that is forged, replayed or incomplete.
- **Where to look:** API keys for payment, banking, billing and exchange accounts; the permissions that each key holds (read, trade, withdraw, refund, payout); test-mode and live-mode keys in the wrong place; webhook endpoints and their signature checks; return and success URLs treated as proof of payment; event types that the handler accepts; amount and status taken from the event body; event order and duplication.
- **Questions:**
  - What can this key do at the provider? Does the component need that right? Can the key withdraw or move funds off the account?
  - Does the webhook handler verify the provider's signature over the raw body, with a constant-time comparison and a timestamp check?
  - Does the handler re-read the payment from the provider by ID before it grants value? Does it compare amount, currency, status and the order reference?
  - Does a customer-visible return URL grant anything?
  - Can an event from test mode, another account or another merchant reach the handler?
  - Does the handler accept events in any order, and handle duplicates?
- **Sad-path inputs:** an unsigned event; a signed event with a changed amount; an old event replayed; an event for another order; a test-mode event on the live endpoint; a "paid" event before the "created" event; a success URL opened without payment.
- **Evidence for confirmed:** the handler, the missing verification or re-read, and the value granted without real payment. Use fixture events signed with a test secret. Key-scope findings name the right the key holds and the component that does not need it.
- **Not a finding:** a verified event that the handler re-reads; a key that the provider limits by scope and that the code cannot widen.
- **CWE:** CWE-272 (least privilege violation); CWE-347 (improper verification of cryptographic signature; webhook events).

## Variant search

When you find one financial defect:
1. **Same operation.** List every code path that creates the same value effect (payment, refund, payout, transfer, order). Compare checks.
2. **Same arithmetic.** Search for every use of the same numeric helper, rate, rounding call or conversion.
3. **Same key.** List every route that uses the same idempotency mechanism or provider client.
4. **Same table.** List every writer of the same balance or ledger table, including jobs, admin tools and migrations.
5. **Same integration.** Check every webhook or callback handler for the same missing verification.
6. **Same history.** Check earlier fixes in the same area for incomplete coverage.

## Chain primitives

This domain often **gives**:
- free or extra value (credit, goods, services, position);
- loss for a named victim (an overdrawn balance, a drained treasury or account);
- the ability to move funds through a powerful provider key;
- inconsistent state that hides other theft.

This domain often **needs**:
- an account with a balance or a limit (from authn);
- a race window (from concurrency);
- price or rate influence (from client-trust or market access);
- a leaked provider key (from obvious or secrets-config).

## Verification notes

- **E1 is usually enough** for FIN-02, FIN-03, FIN-07 and FIN-09 (missing signature or re-read) when the code path and the value effect are in the repository.
- **E1 is enough** for FIN-01 when you can compute the result by hand from the code and the type is exact. Add a unit test at E3 when rounding mode or library behaviour matters.
- **E3 is required** for FIN-04 and FIN-05 claims that depend on concurrency, and for FIN-06 claims that depend on a provider failure sequence. State this: race and double-spend claims need E3. Use a deterministic schedule and a test double for the provider. A single "saw it once" run does not count.
- **E3 is required** for FIN-08 claims that depend on feed or market behaviour outside the repository. Otherwise use `needs-validation`.
- **Safe testing:** use a local database, a local ledger and fixture providers. Never call a live payment provider, exchange, bank or chain. Never use real keys.
- **Victim check:** name who loses value: a customer, the operator, a counterparty, a liquidity pool. A user who only affects its own balance is not a boundary failure.
- **Severity examples:**
  - critical – any user creates unlimited value or drains the treasury, or an unauthenticated forged provider event grants value;
  - high – repeatable double spend or overdraw; a signed-request replay that moves funds; a key with withdrawal rights exposed to a lower-trust component;
  - medium – a fee or limit bypass with real cost to the operator; a rounding gain that is repeatable but small per use; a price staleness with a bounded window;
  - low – a one-off loss of a minor unit; a mismatch that reconciliation repairs;
  - informational – a unit confusion that has no path to value.

## Fix patterns

- **Exact types.** Hold money as integers of the minor unit, or as a decimal type with fixed scale. Store the currency with the amount. Never use binary floating point.
- **One rounding rule.** Define the mode and the point of rounding once. Round the operator's way. Allocate remainders explicitly.
- **Validate range first.** Reject negative, zero and out-of-range amounts at the boundary, before any effect.
- **Idempotency by design.** Scope the key to principal and operation. Store the key and the result in the same transaction as the effect. Reject a key that arrives with different parameters.
- **Atomic balance change.** Use one conditional update (`update ... where balance >= amount`), a row lock, or a serialisable transaction. Check the number of rows changed.
- **Double-entry ledger.** Append balanced entries in one transaction. Derive balances from the ledger. Reconcile with providers on a schedule and alert on any difference.
- **Server-side pricing.** Compute price, fee and tax on the server from trusted sources. Bind quotes to amount, pair and expiry. Use bounds, medians or time-averaged prices.
- **Provider events.** Verify the signature on the raw body, check the timestamp, and re-read the object by ID. Grant value only from the re-read state. Ignore events for unknown references.
- **Least-scope keys.** Give each component its own key with minimal rights. Disable withdrawal on trading-only keys. Rotate keys.
- **Signed requests.** Include a nonce and a short validity window. Store used nonces for the window.
- **Looks right but is not:** a client-side balance check; a "pending" flag set after the provider call; checking the balance in one statement and debiting in another; rounding only in the display; trusting a success redirect; verifying a webhook signature but not the amount; a unique constraint on the idempotency key without a check of the parameters.

## Regression tests

- Property tests on arithmetic: sum of parts equals the total, no value is created by splitting, rounding stays within one minor unit.
- Boundary tests for every amount field: −1, 0, minimum, maximum, maximum plus one, extra decimals, exponent notation.
- A currency-mix test: add, compare and convert amounts of different units and assert refusal or the explicit rate.
- An idempotency test: send each operation twice in sequence and in parallel, with the same and with different parameters. Assert one effect and a refusal for changed parameters.
- A concurrency test: two simultaneous withdrawals of the full balance, and a cancel at a fill. Assert that the balance never goes below the bound.
- A ledger invariant test after every scenario: the sum of entries is zero, derived balances equal the ledger, and provider state equals the fixture.
- A webhook test with fixture events: unsigned, wrong signature, old timestamp, changed amount, duplicate, out of order, unknown reference. Assert no value is granted.
- A key-scope test: assert that each component's configured credentials lack rights it does not need.
