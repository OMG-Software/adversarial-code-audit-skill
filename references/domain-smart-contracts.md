# Domain: Smart Contracts

## Scope

- **Load when:** the code is a program that runs on a blockchain or similar shared ledger, or it builds, signs, relays or verifies transactions and signed messages for one. Signs: Solidity, Vyper, Move, Rust programs for account-model chains, CosmWasm, Cairo or similar contract sources; ABI files; deployment and upgrade scripts; relayer, keeper, bot and wallet code; signed-message (permit-style) flows.
- **Covers:** reentrancy and unexpected callbacks; access control on functions; integer and rounding issues; oracle and price manipulation; ordering and front-running; signature replay; upgradeability and storage collisions; unchecked external calls and token assumptions; gas, compute and denial of service; off-chain signing, nonce handling and key storage.
- **Chain model:** the attacker can call any public function with any arguments, from any account or contract, in any order, inside one transaction, with borrowed funds. The attacker can see pending transactions on chains that expose them. Code cannot be patched after deployment unless it is upgradeable. Examples below use EVM names. Look for the same weakness under other models (programs with explicit account lists, resource-oriented modules, message-passing contracts).
- **Hand off to:**
  - `domain-financial.md` – off-chain accounting, payment providers and exchange APIs. This file covers on-chain value logic.
  - `domain-crypto.md` and `domain-crypto-protocols.md` – primitive choice and protocol design. This file covers use of signatures inside contracts.
  - `domain-authn.md` and `domain-secrets-config.md` – general key and credential handling (SCT-10 covers signing keys of chain accounts).
  - `domain-authz.md` – general role logic. SCT-02 covers contract-specific function access.
  - `domain-concurrency.md` – races in off-chain services. Ordering on chain stays here (SCT-05).
  - `domain-supply-chain.md` – dependency and build trust, including contract libraries and deployment scripts.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Solvency:** The contract's recorded liabilities never exceed the assets it holds, and no call sequence in one transaction makes them differ.
2. **State before call:** All state that a function relies on is updated before the function makes an external call, or a guard prevents re-entry into every function that shares that state.
3. **Access:** Only <role or account> can call <privileged function>, including initialisers, upgraders, pausers, minters and parameter setters.
4. **Arithmetic:** Every calculation is within range, uses the documented decimals, and rounds in the direction that favours the protocol, not the caller.
5. **Price:** The contract uses a price that a caller cannot move inside one transaction at a profit, that is fresh, and that is bounded against outliers.
6. **Ordering:** The outcome of a call does not give a third party a risk-free profit by placing a transaction before or after it, unless bounds (slippage, deadline, minimum output) limit the loss.
7. **Signature:** A signed message is valid once, for one chain, one contract, one purpose, one signer and one time window, and its signer is never the zero address.
8. **Upgrade:** Only <governance> can change code. Each upgrade keeps storage compatible. An implementation cannot be initialised or destroyed by an outsider.
9. **External calls:** The contract checks the result of every external call and does not assume token or callee behaviour that the standard does not guarantee.
10. **Liveness:** No caller can block a critical function (withdrawal, liquidation, settlement) for others at a low cost.

## Recon additions

Add these to `domain-notes.md` under a heading "Contract surface". Keep it short.

1. **Contract inventory.** Each contract or program, its inheritance or modules, proxy pattern, deployed addresses (if known), and the admin or upgrade authority.
2. **External entry map.** Every public or external function, its caller restrictions, state it changes, external calls it makes and value it moves.
3. **Roles and keys.** Each privileged role, who holds it (account, multisig, timelock), and how it changes.
4. **Asset flows.** Tokens and native currency that enter and leave, accounting variables for each, and the invariant that ties them to balances.
5. **Dependencies.** External contracts called, tokens accepted (and their non-standard behaviour), oracles and feeds, bridges and routers.
6. **Signed messages.** Each off-chain signature scheme: domain, fields, nonce, deadline, signer and verifier.
7. **Off-chain components.** Relayers, keepers, bots, signing services and wallets: key storage, nonce handling, chain IDs and fee settings.
8. **Chain assumptions.** Target chains, block time, ordering rules, gas or compute limits and mempool visibility.

## Lead searches

Adapt the patterns to the language. The language file adds compiler version, library and framework names.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `.call{\|.call(\|.send(\|.transfer(\|safeTransfer\|onERC\w+Received\|tokensReceived\|invoke\|CPI\|send_message\|submessage` followed by a state write | State written after external call (SCT-01) | A reentrancy guard or a pull pattern may hold. |
| Public or external functions without modifiers, role checks or signer checks; `initialize\|init\|setOwner\|upgrade\|mint\|burn\|pause\|setFee\|withdraw` | Missing access control (SCT-02) | Check internal-only visibility and initialiser guards. |
| `tx.origin`, `msg.sender` compared to a stored value, signer or owner account checks absent | Weak caller identity (SCT-02) | |
| `unchecked\s*{`, `as uint\d+`, `wrapping_`, `overflow-checks`, division before multiplication, `decimals` | Arithmetic risk (SCT-03) | Compiler-checked arithmetic covers plain operators only. |
| `getReserves\|slot0\|balanceOf(address(this))\|spot\|latestRoundData\|updatedAt\|price\|oracle\|twap` | Price source (SCT-04) | A manipulable spot value is the lead. Check freshness and bounds. |
| `block.timestamp\|block.number\|blockhash\|prevrandao\|random\|deadline\|minOut\|amountOutMin\|slippage` | Ordering and weak randomness (SCT-05) | |
| `ecrecover\|ECDSA\|recover(\|SignatureChecker\|isValidSignature\|permit\|DOMAIN_SEPARATOR\|chainId\|nonce\|verify_signature` | Signature handling (SCT-06) | Check the signed fields and the nonce. |
| `delegatecall\|upgradeTo\|_authorizeUpgrade\|Initializable\|initializer\|reinitializer\|selfdestruct\|__gap\|storage slot\|assembly` | Upgrade and storage (SCT-07) | |
| Low-level `call` result unused; `transferFrom\|approve\|IERC20` without a safe wrapper; `balanceBefore\|balanceAfter`; user-supplied target and calldata | External call assumptions (SCT-08) | |
| Unbounded `for\|while` over storage arrays; push payments in loops; `require(address(this).balance ==` | Gas and liveness (SCT-09) | |
| Transaction builders: `signTransaction\|sendRawTransaction\|eth_sendTransaction\|privateKey\|mnemonic\|nonce\|chainId\|gasPrice\|maxFeePerGas\|trustedForwarder\|_msgSender` | Off-chain signing and relaying (SCT-10) | |

## Attack classes

### SCT-01 Reentrancy and unexpected callbacks

- **What fails:** a call to another contract hands control back before the caller has finished updating its state. The callee, or a hook, re-enters and acts on stale state.
- **Where to look:** external calls before state writes; native currency sends; token transfer hooks and receiver callbacks (for example ERC-777 hooks and ERC-721 safe-transfer callbacks); flash-loan and swap callbacks; calls into other functions of the same contract that share state (cross-function); calls into other contracts of the same system (cross-contract); view functions that read state mid-update and feed another protocol (read-only reentrancy); reply or callback handlers on message-passing chains.
- **Questions:**
  - Which state does the function change after the external call? Could the callee observe or use the old value?
  - Does a guard cover every function that shares the state, or only this one?
  - Does any token or callee in scope have hooks?
- **Sad-path inputs:** a local test contract that re-enters on receive or on a hook; a malicious token with a callback; a callee that calls a second function of the same system.
- **Evidence for confirmed:** the call before the write, the re-entry function, and a local test (local test chain or fork in the sandbox) that shows the invariant failing (for example withdrawn twice). E3 is required for the claim that the re-entry works. A source trace supports the reproduction but does not replace it.
- **Not a finding:** a call to a trusted, fixed contract with no callback and no shared state; state already updated before the call.
- **CWE:** CWE-1265 (unintended reentrant invocation of non-reentrant code via nested calls).

### SCT-02 Access control on functions

- **What fails:** a caller reaches a privileged function, or an initialiser runs twice.
- **Where to look:** missing modifiers; initialisers on proxies and on implementations; `tx.origin` as identity; owner and role setters; two-step ownership transfer; functions that were `internal` in the design but are `public`; role admin chains; on account-based chains, missing checks that an account signed or that an account is owned by the expected program; on module chains, capability handling.
- **Questions:**
  - Which functions change privileged state, move funds or change configuration? Does each check the caller?
  - Can anyone call `initialize`, or call it again?
  - Does the check use the immediate caller or a forwarded sender? Can a contract caller satisfy it?
  - On chains with explicit account lists: does the program check signer, owner and type of every passed account?
- **Sad-path inputs:** a call from an unrelated account; a call to initialise a deployed implementation; a call with a substituted account; a call through an intermediate contract.
- **Evidence for confirmed:** the function, the absent or wrong check, and a local test where an unprivileged account performs the action. E1 is usually enough for a plain missing check.
- **Not a finding:** a function that exposes only the caller's own funds; a role that the design gives to anyone.
- **CWE:** CWE-862 (missing authorization; class-level); CWE-837 (improper enforcement of a single, unique action; initialiser run twice).

### SCT-03 Integer, rounding and share-accounting issues

- **What fails:** arithmetic overflows, truncates or rounds in the caller's favour, and breaks solvency.
- **Where to look:** explicitly unchecked blocks; casts to narrower types; compilers or build profiles that wrap on overflow; division before multiplication; mixed decimals; share-price and vault maths; fee and interest accrual; first-depositor and donation cases (share inflation); rounding direction in mint, redeem, borrow and liquidation.
- **Questions:**
  - Is each unchecked or wrapping operation provably in range?
  - Does rounding favour the protocol on deposit, withdrawal and fees? Can repeated small actions extract the difference?
  - Can the first depositor, or a direct token transfer to the contract, change the share price so that others lose?
- **Sad-path inputs:** zero; one unit; maximum value; amounts just under and over a threshold; an empty vault; a donation to the contract; tokens with 6 and 18 decimals.
- **Evidence for confirmed:** the formula, concrete inputs, and the output that breaks the solvency invariant, from a local test or a computed trace. Rounding and share-inflation claims need a numeric test, so E3.
- **Not a finding:** a rounding loss below the smallest unit that nobody can repeat for profit; an overflow that the compiler reverts.
- **CWE:** CWE-190 (integer overflow or wraparound); CWE-197 (numeric truncation error).

### SCT-04 Oracle and price manipulation

- **What fails:** the contract takes a price that an attacker can move inside one transaction, or that is stale or wrong.
- **Where to look:** spot prices from a pool's current reserves or balances; use of a token balance as a value; feeds read without a freshness, round or sanity check; feeds with different decimals; single-source oracles; time-weighted prices with a short window; collateral valuation; liquidation prices; a sequencer-uptime check on layer-2 chains.
- **Questions:**
  - Can a caller change the source inside the transaction (a swap, a donation, a flash loan) and then use the changed price?
  - Does the code check that the feed answer is recent, positive and within bounds?
  - Do the decimals of the feed and the asset match the formula?
- **Sad-path inputs:** a price from a pool after a large local swap; a stale answer; a zero or negative answer; a feed with a different decimal count; an asset with a thin market.
- **Evidence for confirmed:** the price source, the manipulation steps on a local fork or test pool, and the profit or insolvency. Use a local fork or mocked pools. Never touch a live chain. Claims that depend on live market depth are `needs-validation`.
- **Not a finding:** a price source that a caller cannot move at a profit within the transaction and that has freshness checks.
- **CWE:** CWE-807 (reliance on untrusted inputs in a security decision).

### SCT-05 Ordering, front-running and weak randomness

- **What fails:** a third party profits by placing its transaction before, after or around a victim's, or a miner or validator picks the outcome.
- **Where to look:** swaps and trades without minimum-output and deadline bounds; approvals that change a value in two steps; first-come claims, auctions and reveals; commit-reveal steps missing; randomness from block fields or hashes; time-based rules using block time; liquidation races; governance proposals executable in one transaction with borrowed voting power.
- **Questions:**
  - Does the user supply and the contract enforce a bound (minimum out, maximum in, deadline)?
  - Does a pending transaction reveal profit that another account can take?
  - Where does randomness come from? Can a block producer or caller predict or bias it?
- **Sad-path inputs:** a transaction with zero minimum output; an old transaction executed late; a call that reads randomness in the same transaction that sets it.
- **Evidence for confirmed:** the missing bound or the predictable source, and a local test that shows a transaction in a chosen order gives profit or fixed outcome. Ordering claims depend on chain rules and need E3 on a local test chain or are `needs-validation`.
- **Not a finding:** ordering effects limited by enforced slippage and deadline; randomness used only for non-value outcomes.
- **CWE:** CWE-362 (race condition; class-level); CWE-341 (predictable from observable state; weak randomness).

### SCT-06 Signature replay and off-chain signed messages

- **What fails:** a valid signature works again, on another chain, in another contract, for another purpose or with other parameters.
- **Where to look:** permit-style approvals; meta-transactions; vouchers, whitelist signatures and claim proofs; cross-chain messages; typed-data hashing and domain separators; signature recovery that returns an empty signer; signature malleability; contract-account signature checks; nonces and deadlines.
- **Questions:**
  - Does the signed data include chain ID, contract address, purpose, all parameters, nonce and deadline? Is the domain separator recomputed after a chain split?
  - Is the nonce consumed on use and bound to the signer?
  - Does the code reject the zero address from a failed recovery?
  - Does a signature in two parts (or its malleable twin) count as a different message, so a used-signature list can be dodged?
- **Sad-path inputs:** the same signature twice; a signature from chain A on chain B; a signature for contract X on contract Y; a signature with an expired deadline; an invalid signature that recovers to zero; a malleated signature.
- **Evidence for confirmed:** the signed fields, the missing binding, and a local test that reuses the signature. Replay by one transaction after another is sequential, so E1 or E3 on a local chain. Concurrent claims need E3.
- **Not a finding:** a signature that binds every needed field and is single-use by nonce.
- **CWE:** CWE-294 (capture-replay); CWE-347 (improper verification of cryptographic signature).

### SCT-07 Upgradeability and proxy storage

- **What fails:** upgrade logic lets an outsider change code, or storage layout errors corrupt state.
- **Where to look:** proxy patterns (transparent, UUPS-style, beacon, diamond-style, minimal clones); initialisers; implementation contracts left uninitialised; `delegatecall` to a target the caller can influence; storage layout across versions; inherited variable order; reserved gaps; code that can destroy the implementation; upgrade authorisation functions; admin keys without delay.
- **Questions:**
  - Who can upgrade, and is there a timelock or a multisig?
  - Can anyone initialise the implementation or a clone, and then use it to run code?
  - Do old and new versions share the same storage layout for every variable?
  - Does `delegatecall` have a fixed, trusted target?
- **Sad-path inputs:** an initialise call on the bare implementation; an upgrade by a non-admin; a new version that inserts a variable; a delegate call with attacker-chosen code.
- **Evidence for confirmed:** the pattern, the unprotected step or the layout diff, and a local test or storage-layout tool output that shows the corruption or takeover. A layout diff from the compiler's own layout output counts as E2.
- **Not a finding:** an upgrade key held by a governed multisig with delay, when the design states that trust.
- **CWE:** CWE-862 (missing authorization; class-level).

### SCT-08 Unchecked external calls and token assumptions

- **What fails:** the contract assumes that a call succeeded or that a token behaves like the standard, and the assumption is false.
- **Where to look:** low-level calls with unused results; token calls that return no value or return false; fee-on-transfer, rebasing and callback tokens; approvals to arbitrary targets; functions that call a caller-chosen target with caller-chosen data while the contract holds approvals or balances; balance reads used as accounting; tokens that can be blocklisted or paused; account substitution on chains with explicit accounts.
- **Questions:**
  - Is the return value or success flag of every external call checked?
  - Does the contract use the amount it asked for or the amount it received?
  - Can a caller make the contract call an arbitrary address with arbitrary data? What can that address do with the contract's approvals?
- **Sad-path inputs:** a token that returns false; a token that takes a fee; a token with a hook; a callee that reverts; a callee that returns less data than expected; a caller-chosen target that is a token contract.
- **Evidence for confirmed:** the unchecked call or the assumption, a mock token or callee in a local test, and the accounting error or the unauthorised transfer.
- **Not a finding:** a call to a fixed, audited contract whose behaviour the code checks; a token list restricted to well-behaved tokens by the design.
- **CWE:** CWE-252 (unchecked return value).

### SCT-09 Gas, compute and denial of service

- **What fails:** a caller blocks a function for others, or makes it too costly to run.
- **Where to look:** loops over unbounded storage arrays; payments pushed to many recipients in one call; a single failing recipient that reverts the batch; balance-equality checks that forced currency can break; auctions where the previous bidder must be refunded first; queues that anyone can fill; large return data copied by default; compute-unit and account-size limits on other chains; keepers that must process every item.
- **Questions:**
  - Can a caller grow a list that a critical function must iterate?
  - Does one failing external call block the whole operation?
  - Can a caller force a balance or state so that a strict equality check always fails?
- **Sad-path inputs:** thousands of dust entries; a recipient contract that always reverts; a forced transfer of currency to the contract; a callee that returns huge data.
- **Evidence for confirmed:** the unbounded loop or blocking dependency, a local test that exceeds the gas or compute limit or reverts, and the blocked critical function. Name the cost to the attacker.
- **Not a finding:** a loop bounded by an admin-controlled small list; a failure that only blocks the caller's own action.
- **CWE:** CWE-770 (allocation of resources without limits or throttling); CWE-1050 (excessive platform resource consumption within a loop).

### SCT-10 Off-chain signing, relaying and key handling

- **What fails:** code that builds, signs or relays transactions signs the wrong thing, leaks a key, or lets a caller spend authority that it does not own.
- **Where to look:** wallet and signing services; relayers and meta-transaction forwarders; bots and keepers with hot keys; nonce management; chain ID and fee settings; transaction simulation against execution; key and mnemonic storage and logging; multisig and approval flows; user interfaces that show data different from the signed data; RPC endpoints trusted for state.
- **Questions:**
  - Does the signer sign exactly what the user sees? Are chain ID, recipient, value, data and fee all fixed before signing?
  - Where is the key stored? Does it appear in logs, environment dumps, client bundles or backups? Does the hot key hold more funds than needed?
  - In a trusted-forwarder design, does the contract read the appended sender only when the caller is the forwarder?
  - How does the relayer handle nonces, replacement and failed transactions? Can a caller make it sign many transactions or burn its fee balance?
- **Sad-path inputs:** a request with a different chain ID; a spoofed appended sender from a non-forwarder; a request that makes the relayer pay for a reverting call; a signing request with unexpected calldata.
- **Evidence for confirmed:** the signing path, the missing binding or check, and the spend or leak, shown on a local test chain with dummy keys. Never use real keys or a live chain.
- **Not a finding:** a key stored in a hardware module or a managed key service with scoped use; a relayer limited to a fixed call list and a fee cap.
- **CWE:** CWE-312 (cleartext storage of sensitive information; key handling); CWE-441 (unintended proxy or intermediary, confused deputy; class-level).

## Variant search

When you find one contract defect:
1. **Same function pattern.** List every function with the same call-then-write shape, the same missing modifier or the same unchecked arithmetic.
2. **Same dependency.** List every place the contract reads the same price source, calls the same token or uses the same library function.
3. **Same state.** List every function that reads or writes the same accounting variable.
4. **Same inheritance.** Check all contracts that inherit or copy the flawed code, including older deployments and forks.
5. **Same signature scheme.** List every signed-message verifier and compare the signed fields.

## Chain primitives

This domain often **gives**:
- theft or lock of funds held by the contract (the value source for financial chains);
- privileged control of a protocol (admin, upgrade, mint);
- a manipulated price that other protocols consume;
- a key or signing authority that moves assets off chain.

This domain often **needs**:
- a flash loan or large temporary balance (assumed attacker capability);
- an initial state or token listing (from governance or deployment);
- knowledge of deployed addresses and storage (public by design).

## Verification notes

- **E1 is usually enough** for SCT-02 (plain missing check), SCT-07 (unprotected initialiser or upgrade) and SCT-10 (key in logs or source), when the code path is in the repository.
- **E3 is required** for SCT-01, SCT-03 (rounding and share inflation), SCT-04 (price manipulation), SCT-05 and SCT-09 claims, and for race and double-spend claims. Use a local test chain or a local fork in the sandbox, mock tokens, and dummy accounts. Never send transactions to a live chain, never use real keys, never probe deployed contracts.
- **E2 is useful** for SCT-03 and SCT-07 with a static analyser, a storage-layout dump from the compiler, or a property fuzzer.
- **Without T2:** reentrancy, rounding, price and ordering claims are `needs-validation`, with a test plan.
- **Deployment facts:** deployed code, admin addresses, token lists and oracle addresses are often outside the repository. If a decisive fact is external, the finding is `needs-validation`.
- **Chain rules:** state the chain model and compiler version that the claim assumes (for example compiler-checked arithmetic).
- **Profit check:** state the attacker's cost (including borrowed capital and fees) and the gain. A claim without a plausible profit or loss is lower in severity.
- **Severity examples:**
  - critical – anyone drains or locks all funds, takes ownership, or upgrades the code;
  - high – a repeatable theft of a share of the funds; a price manipulation with profit; a signature replay that moves funds; a key with real funds exposed;
  - medium – a loss limited by caps; a denial of service on a critical function at real cost; a front-running loss bounded by slippage;
  - low – a rounding loss not repeatable for profit; griefing with no gain;
  - informational – a pattern that other code already blocks.

## Fix patterns

- **Checks, effects, interactions.** Update all state before external calls. Add a re-entry guard on every function that shares state. Prefer pull payments.
- **Deny by default.** Give every state-changing function an explicit access rule. Guard initialisers once. Disable initialisation of bare implementations.
- **Safe arithmetic.** Use checked arithmetic. Limit unchecked blocks to proven ranges. Multiply before dividing. Round against the caller. Protect against first-depositor share inflation with virtual shares or a minimum first deposit.
- **Robust prices.** Use time-averaged or multi-source prices. Check freshness, positivity and bounds. Do not value assets by their balances in a pool that the caller can move.
- **User bounds.** Require minimum output and a deadline. Use commit-reveal where order matters. Do not use block fields as randomness.
- **Bound signatures.** Use typed structured data with chain ID, contract address, purpose, parameters, nonce and deadline. Reject the zero signer. Consume the nonce.
- **Safe upgrades.** Use a timelock and multisig for the upgrade authority. Use layout checks in the build. Lock implementations.
- **Safe calls.** Check results. Use safe token wrappers. Measure received amounts, not requested amounts. Never call a caller-chosen target with the contract's approvals.
- **Bounded work.** Cap loops. Use pull-based withdrawal. Isolate a failing recipient.
- **Safe signing.** Keep keys in a hardware module or key service. Fix chain ID and fee caps. Limit hot-wallet balance. Validate calldata against an allow-list before signing.
- **Looks right but is not:** a guard on one function while another shares the state; checking `msg.sender` is a contract; a deadline set to the current block; hiding admin functions by name; trusting a flash-loan-safe claim without testing; a signature without a nonce; a pause switch held by one hot key.

## Regression tests

- A reentrancy test with a malicious receiver and a hooked token, for every function that calls out.
- An access test: every state-changing function called by an unprivileged account, asserting revert; initialisers called twice.
- Property or fuzz tests for solvency: total liabilities never exceed assets across random call sequences, including donations and extreme amounts.
- A price test with a manipulated pool and a stale, zero and outlier feed, asserting refusal or bounded loss.
- A signature test: replay, wrong chain, wrong contract, expired, zero signer and malleated forms, asserting rejection.
- An upgrade test: a storage layout comparison between versions in CI, and a test that the implementation cannot be initialised or destroyed.
- A token-behaviour test with mock tokens that return false, take a fee or call back.
- A gas test with a large list and a reverting recipient, asserting that critical functions still run.
- An off-chain signing test: wrong chain ID, spoofed sender and unexpected calldata are refused.
