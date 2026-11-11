# Domain: Cryptography (use of primitives)

## Scope

- **Load when:** the code calls cryptographic primitives. Signs: encryption or decryption, MACs, signatures, hashing of passwords or secrets, key derivation, random-number calls for security values, key files or key stores, certificate handling, "secure" storage of tokens, custom `encrypt` and `sign` helpers, crypto library imports.
- **Covers:** algorithm and mode choice; nonce and IV handling; authenticated encryption and padding oracles; randomness for security values; key derivation and password hashing; key generation, storage, rotation and destruction; constant-time comparison; signature-verification API misuse; certificate validation inside crypto libraries; error paths that fall back to no crypto.
- **Hand off to:**
  - `domain-crypto-protocols.md` – handshakes, key exchange, ratchets, downgrade, transcript binding, what is signed. Crypto owns a single primitive call. Protocols owns how calls combine into a protocol.
  - `domain-authn.md` – which token, claim or key source a login accepts. Crypto owns how the signature or MAC check works.
  - `domain-secrets-config.md` – config secrets, API credentials, hard-coded values, and rotation of secrets that are not cryptographic keys in use.
  - `domain-outbound-network.md` – outbound TLS clients that fetch URLs. Crypto owns chain and name checks in code that implements or configures validation for other purposes (code signing, custom PKI, mTLS servers).
  - `domain-memory-safety.md` – buffer errors in native crypto code.
  - `domain-embedded.md` – secure boot and constrained-device crypto choices. `domain-supply-chain.md` – signing of releases and updates.
  - `domain-smart-contracts.md`, `domain-financial.md` – transaction signing and replay rules.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Primitive:** Every security decision uses a current, reviewed algorithm and mode, with parameters at or above <policy>. The code does not invent its own construction.
2. **Confidentiality with integrity:** Encrypted data that an attacker can store or modify is authenticated, and the code verifies authenticity before it uses any plaintext.
3. **Uniqueness:** A (key, nonce) pair is never used for two messages in any mode that forbids it, including after restart, restore, fork and parallel workers.
4. **Randomness:** Every secret, key, token, salt, nonce and challenge comes from the operating system's cryptographic random source, with full length and no bias.
5. **Stretching:** A password or low-entropy secret passes through a salted, slow, memory-hard or equivalent function before storage or key use. One key serves one purpose.
6. **Key life:** Keys are generated with a secure source, stored where only <principal> can read them, rotated on a schedule and on compromise, and destroyed when no longer needed.
7. **Comparison:** Secret-dependent comparisons (MAC, token, hash, signature) do not leak through timing.
8. **Verification:** A verification result is checked, uses the intended key and algorithm, and covers the data that the code then trusts.
9. **Trust anchors:** Certificate chains and names are validated against the intended anchors for the intended peer.
10. **Failure:** When a crypto operation fails, errors out or is unavailable, the code refuses. It never continues with plaintext, unsigned data or a default key.

## Recon additions

Add these to `domain-notes.md` under a heading "Cryptographic inventory". Keep it short.

1. **Use table.** One row per use: purpose | primitive and mode | key source | nonce or IV source | what it protects | attacker who can modify the data | file:line.
2. **Key table.** Each key and secret: generation | storage | access | rotation | backup | destruction | purposes it serves.
3. **Random sources.** Every call that produces a security value, and its source.
4. **Password and secret hashing.** Each stored password, token or API key: function, parameters, salt.
5. **Verification points.** Each place that verifies a signature, MAC or certificate, and what happens to the result.
6. **Custom code.** Any hand-written cipher, MAC, padding, key wrap, token format or "obfuscation" that protects a security value.
7. **Dependencies.** Crypto libraries and versions, and any vendored or forked copies.

## Lead searches

Adapt the patterns to the language. The language file adds library calls.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `\b(md5\|sha-?1\|md4\|des\|3des\|rc4\|rc2\|blowfish)\b`; `\becb\b`; key sizes below 128 bits symmetric or 2048 bits RSA | Weak primitive or mode (CR-01) | MD5 or SHA-1 as a non-security checksum or cache key is not a finding. Ask what an attacker gains from a collision. |
| `\b(xor)\b` with a key, `base64` used as "encryption", `H\(key *\|\| *msg\)`, hand-written padding | Home-made construction (CR-01, CR-03) | |
| `(iv\|nonce)\s*[:=]` with a constant, zero, counter, time or a value stored per key; encryption in a loop with one nonce | Reuse or prediction (CR-02) | A unique key per message makes a fixed nonce safe. Check how the key is derived. |
| `(cbc\|ctr\|cfb\|ofb)` with no MAC or tag nearby; `decrypt` followed by a separate error path for bad padding | Unauthenticated encryption, oracle (CR-03) | The data may be authenticated at another layer. Trace the callers. |
| `(rand\|random\|mt19937\|srand\|drand\|math\.random\|time\(\)\|uuid\|nanoid)` near `token\|key\|salt\|nonce\|password\|session\|otp\|code\|secret` | Weak randomness (CR-04) | A random source for UI or test data is not a hit. |
| `(sha(1\|256\|512)\|md5)\(.*(password\|passwd\|pwd)`; `iterations\|rounds\|cost\|work_?factor` with low numbers; `salt` empty or constant | Weak password storage (CR-05) | |
| `(hkdf\|kdf\|derive)` with an empty or shared `info` or context value; one key used for encrypt and MAC | Key separation (CR-05) | |
| `(generate\|load\|wrap\|unwrap\|rotate\|destroy\|zeroi[sz]e\|memset\|explicit_?bzero\|secure_?zero)` near `key` | Key life cycle (CR-06) | |
| `(==\|!=\|equals\|strcmp\|memcmp\|bcmp\|compare)` near `mac\|hmac\|tag\|digest\|signature\|token\|secret` | Timing leak (CR-07) | Comparison of public values is not a hit. |
| `(verify\|check_?sig\|validate_?sig)` whose return value is unused or only logged; `ecdsa\|rsa\|ed25519\|pkcs1\|pss` verify calls | Verification misuse (CR-08) | |
| `verify_?(peer\|host)`, `check_?hostname`, `skip_?verify`, `insecure`, `trust_?all`, `cert_?none`, `verify\s*=\s*(false\|0)` | Disabled validation (CR-09) | Test-only code is a false hit unless it ships. |
| `(catch\|except\|rescue\|if err\|== *null)` near `decrypt\|verify\|unseal\|open\|sign` | Fail-open (CR-10) | Read what the handler returns. |
| `(ecdh\|x25519\|curve\|point\|public_?key)` followed by key agreement with no validation of the peer value | Invalid public value (CR-01) | Libraries often validate. Read the call. |

## Attack classes

### CR-01 Algorithm, mode, parameter and construction choice

- **What fails:** the code uses a primitive, mode, size or construction that an attacker can break or exploit at realistic cost.
- **Where to look:** encryption helpers; token and cookie formats; file and database encryption; key wrap; custom hash-based MACs; RSA encryption; elliptic-curve key agreement; "encrypt" functions built from XOR or encoding; configuration that picks the algorithm.
- **Questions:**
  - What does an attacker gain if this primitive is broken? Use the attacker model, not a checklist.
  - Is a block cipher in ECB mode, or a stream or counter mode without integrity, used on structured data?
  - Is a MAC built as `H(key || message)` (length extension), or a hash used where a MAC is needed?
  - Is RSA encryption used with PKCS#1 v1.5 padding where an oracle is possible, or without OAEP?
  - Do key sizes and curve choices meet <policy>?
  - Does key agreement validate the peer's public value (point on curve, not a low-order or zero value)?
  - Does the algorithm name come from the data, so that an attacker picks a weaker one?
- **Sad-path inputs:** an invalid curve point; a zero or low-order public value; an algorithm field set to the weakest value; a short key; identical plaintext blocks.
- **Evidence for confirmed:** the use, the attacker who can reach the weakness, and the asset at risk. E1 is normally enough for a plainly broken choice on a security value. A claim that needs a cryptanalytic attack at scale is `needs-validation` unless the weakness is a known break.
- **Not a finding:** MD5 or SHA-1 for a non-security checksum; ECB on a single random block; a weak primitive in a test or a legacy-read path that never writes new data and has no security role.
- **CWE:** CWE-327, CWE-326 (class-level), CWE-328, CWE-780, CWE-1240.

### CR-02 Nonce and IV reuse or prediction

- **What fails:** the same key and nonce encrypt two messages, or an IV is predictable where the mode needs it unpredictable.
- **Where to look:** AEAD calls; stream and counter modes; CBC IV creation; counters stored in files or databases; nonces from time or message counters; random nonces in high-volume systems; multiple workers or replicas with one key; backup restore, VM snapshot and fork; signature schemes that use per-signature random values.
- **Questions:**
  - Where does each nonce come from? Is it unique per key across restarts, restores, processes and machines?
  - For random 96-bit nonces in GCM: how many messages can one key protect before a collision is likely? Does the code rotate before that?
  - Does a counter roll back after a crash, restore or snapshot?
  - Is the CBC IV unpredictable, and different for each message?
  - For ECDSA and similar schemes: does each signature use a fresh, unbiased secret value, or a deterministic one?
- **Sad-path inputs:** two messages in one second; restart after a crash; two workers that start with the same counter; restore of an old counter file; a very long message stream.
- **Evidence for confirmed:** the nonce source and a path that repeats it. Show the repeat by reading the code and, at T2, with a test that encrypts twice. E1 is enough when the nonce is constant or zero in the source. A claim that depends on restart or race behaviour needs E3.
- **Not a finding:** a fixed nonce with a unique key per message; a counter nonce that is persisted before use.
- **CWE:** CWE-323, CWE-329, CWE-1204.

### CR-03 Unauthenticated encryption, malleability and padding oracles

- **What fails:** an attacker changes ciphertext and the change is accepted, or error differences reveal plaintext.
- **Where to look:** CBC, CTR, CFB and OFB modes without a MAC; encrypt-and-MAC or MAC-then-encrypt constructions; cookies, URLs, tickets and database fields that hold encrypted values; decrypt code with several different errors (bad padding, bad MAC, bad format); RSA decryption with distinct failure paths.
- **Questions:**
  - Does the code verify a MAC or AEAD tag before it decrypts, parses or acts on the data?
  - Is the MAC computed over everything that the code trusts: IV, header, context and ciphertext?
  - Do all failure cases return the same error, take the same path and cost the same work?
  - Does the application treat encryption as if it gave integrity (for example an encrypted role or price that the client stores)?
- **Sad-path inputs:** a flipped bit in each ciphertext block; a truncated ciphertext; a modified IV; a ciphertext moved to another record; a valid ciphertext of another user.
- **Evidence for confirmed:** the decrypt path, the missing integrity check or the distinguishable errors, and what an attacker gains. Explicit distinguishable errors are E1. An oracle that needs timing differences needs E3.
- **Not a finding:** unauthenticated encryption of data the attacker cannot store, modify or replay, where another layer already gives integrity (cite it).
- **CWE:** CWE-649, CWE-353, CWE-354, CWE-327.

### CR-04 Randomness for security values

- **What fails:** a secret or identifier can be predicted or guessed.
- **Where to look:** session IDs, reset tokens, API keys, CSRF tokens, nonces, salts, key generation, challenges, invite codes, temporary passwords, game or lottery seeds, share-link IDs.
- **Questions:**
  - Is the source the operating system's cryptographic generator, or a general-purpose PRNG, a clock, a counter or a hash of a guessable value?
  - Is the seed small, fixed or derived from time or process ID?
  - After `fork`, in a container clone or in a VM snapshot, do two processes produce the same stream?
  - Is the value long enough? Is it truncated, or reduced with a modulo that biases it?
  - What does the code do when the secure source fails and a fallback exists?
- **Sad-path inputs:** two values created in the same millisecond; values created after restart; the first values after boot on a device with little entropy; values after a fork.
- **Evidence for confirmed:** the source, the missing entropy, and the attack that predicts or searches the value. E1 is enough for a clearly non-cryptographic source on a security value. A claim of statistical bias or boot-time entropy shortage needs E3 or stays `needs-validation`.
- **Not a finding:** a non-cryptographic generator for jitter, load balancing, UI choices or test data.
- **CWE:** CWE-330 (class-level), CWE-338.

### CR-05 Key derivation, stretching and password hashing

- **What fails:** a password or low-entropy secret is cheap to test offline, or one key serves several purposes.
- **Where to look:** password storage; API-key storage; key derivation from passphrases; token hashing; disk and backup encryption; key-hierarchy code; HKDF-like helpers.
- **Questions:**
  - Is the password hash salted, slow and memory-hard, with parameters in the code and the stored record? Can the code raise parameters over time (rehash on login)?
  - Is a fast hash used for a password or a low-entropy secret?
  - Does the function truncate input (for example some bcrypt libraries stop at 72 bytes) or silently handle null bytes?
  - Does one key serve two purposes (encrypt and MAC, or two protocols)? Does derivation use separate context labels?
  - Is a pepper or server key used, and where is it stored?
  - For high-entropy random API keys: is a fast hash acceptable and unsalted? (It can be, because the input is random.)
- **Sad-path inputs:** an empty password; a very long password; passwords that differ only after byte 72; a stored hash with old parameters.
- **Evidence for confirmed:** the function, its parameters, and the stored data that an attacker could obtain. Pair with a data-exposure path, or state that the attacker model includes database disclosure. E1 is normally enough.
- **Not a finding:** a fast hash on a random 128-bit or longer secret; a slow hash with parameters that meet <policy>.
- **CWE:** CWE-916, CWE-759, CWE-328.

### CR-06 Key generation, storage, rotation and destruction

- **What fails:** a key is weak, exposed, shared too widely, never rotated, or kept after use.
- **Where to look:** key generation code; key files; environment variables and config that hold keys; key-management service calls; key wrap and unwrap; backup and export; code that logs or serialises keys; process memory, core dumps and swap; rotation scripts; keys shared between environments or tenants.
- **Questions:**
  - Is the key generated with a secure source and full length, or derived from a short or guessable value?
  - Who can read the key at rest and in memory? Are file permissions and process boundaries enough?
  - Does the same key serve several tenants, environments or purposes?
  - Can the system rotate the key without data loss? Do old ciphertexts carry a key version?
  - Does the code erase key material after use, and does the compiler keep the erase?
  - Does a compromise of one key expose all past data (no key hierarchy)?
- **Sad-path inputs:** missing key at start (does it generate a weak default?); two environments with one key; a key version that the code no longer holds; a backup that contains the key next to the data.
- **Evidence for confirmed:** the key path from generation to use, and the principal who can reach it. E1 is enough for a hard-coded or shared key. Memory-erase claims depend on compiler output and need E3. Hard-coded secrets that are not cryptographic keys go to `domain-secrets-config.md`.
- **Not a finding:** a key readable only by the process owner on a single-tenant host, when the threat model excludes local root.
- **CWE:** CWE-321, CWE-324, CWE-226, CWE-922 (class-level), CWE-312, CWE-798.

### CR-07 Constant-time comparison and timing

- **What fails:** a comparison or operation takes different time for different secret values, and an attacker can measure it.
- **Where to look:** comparisons of MACs, tags, tokens, password hashes, API keys and signatures with ordinary equality; early-exit loops; secret-dependent branches and table lookups in custom crypto; error paths that differ in cost.
- **Questions:**
  - Does the code use the library's constant-time comparison (for example `CRYPTO_memcmp` in OpenSSL or `hmac.compare_digest` in Python), or ordinary equality?
  - Can the attacker send many guesses and measure response time with enough precision (network jitter, rate limits)?
  - Is the compared value a hash of the secret, which already removes useful timing?
- **Sad-path inputs:** a guess with a correct prefix of growing length; guesses of different lengths.
- **Evidence for confirmed:** a timing claim needs E3: a harness that shows a statistically significant difference under stated conditions. Without T2, the status is `needs-validation` with a measurement plan. Report ordinary equality on a secret as a hardening note unless the attacker can measure.
- **Not a finding:** equality on public values; a comparison that follows a hash with a secret salt that the attacker cannot choose.
- **CWE:** CWE-208.

### CR-08 Signature and MAC verification API misuse

- **What fails:** the code accepts data whose signature or MAC does not prove what the code assumes.
- **Where to look:** every call to verify, validate or check for signatures, MACs and certificates; code signing and update checks; webhook and license checks; token libraries; wrapper functions named `verify_*`.
- **Questions:**
  - Is the return value or exception checked on every path? Does a function return an error code that the caller treats as success (for example `-1` is truthy)?
  - Does the verification use the pinned, intended key, or a key supplied by the message?
  - Does the algorithm come from configuration, or from the signed object?
  - Does the signature cover all fields that the code trusts after verification?
  - Does the code verify one parse of the data and use another?
  - Are empty, missing and truncated signatures rejected? Are malleable encodings handled where uniqueness matters?
- **Sad-path inputs:** an empty signature; a signature from another key; an unsigned object; a signature over a prefix of the data; a verify call that throws; a result of `-1`.
- **Evidence for confirmed:** the call, the unchecked or mismatched result, and the trusted action that follows. E1 is normally enough. Two-parser claims need E3.
- **Not a finding:** a verify call that is paired with an equivalent check in the caller (cite it).
- **CWE:** CWE-347, CWE-354, CWE-345 (class-level).

### CR-09 Certificate validation in crypto libraries

- **What fails:** the code accepts a certificate chain or name that it must reject.
- **Where to look:** trust-store setup; hostname and identity checks; custom verification callbacks; code that disables verification "for now"; pinning code; client-certificate validation on servers; code-signing and document-signing chains; revocation and expiry checks.
- **Questions:**
  - Does a verification callback return success on error? Does it check the chain but not the name, or the name but not the chain?
  - Is the trust store limited to the intended roots, or does it add a user-supplied or system-wide set that is too wide?
  - Are expiry, key usage and basic constraints checked? Can a leaf certificate act as a CA?
  - Does the name check compare the right field (SAN, not only a common name) with the right rules for wildcards?
  - Does a flag, environment variable or config value disable validation in a production build?
- **Sad-path inputs:** a valid chain for another host; a self-signed certificate; an expired certificate; a leaf certificate used to sign another; a wildcard that spans labels.
- **Evidence for confirmed:** the validation code or flag and the connection or object that it accepts. E1 is enough for a disabled check that ships by default or a callback that returns success. Library internals that you did not read make the claim `needs-validation`.
- **Not a finding:** disabled validation in a test fixture that is not built into releases; an internal development flag that is off by default and absent in production configuration.
- **CWE:** CWE-295, CWE-297.

### CR-10 Error paths that fall back to no crypto

- **What fails:** a failure in a crypto step causes the code to continue without the protection.
- **Where to look:** `catch`, `except`, `rescue` and error returns around encrypt, decrypt, sign and verify; "if key is missing, skip"; feature flags that turn encryption off; migration code that reads old plaintext; compatibility paths for old clients; code that stores a flag such as `encrypted: false`.
- **Questions:**
  - If decrypt or verify throws, does the code return the raw input or a default value?
  - If the key is missing or unreadable, does the code start and run without encryption?
  - Can an attacker choose the unprotected path (a flag in the data, an old version number, a missing header)?
  - Is data that was meant to be encrypted ever written in plaintext on an error path or in a log?
- **Sad-path inputs:** a corrupt key file; a missing key; a ciphertext with a truncated header; a record that claims the plaintext format; a verify call that times out.
- **Evidence for confirmed:** the failing step, the fall-back branch, and how an attacker triggers it. E1 is enough when the branch is plain in the source.
- **Not a finding:** a fall-back that only runs for data with no security value, or one that an attacker cannot trigger (record as a hardening note).
- **CWE:** CWE-636 (class-level; use a more specific child if one fits), CWE-311 (class-level), CWE-325.

## Variant search

When you find one cryptographic failure:
1. **Same helper.** List every caller of the helper or wrapper. A weak `encrypt()` helper spreads to all callers.
2. **Same primitive.** Search for the same algorithm, mode string, parameter or constant in all files, including scripts, tests that ship, and vendored code.
3. **Same pattern.** Search for every verify, compare and decrypt call and check each against the class questions.
4. **Same key.** List every use of the same key or secret. A flaw in the key affects all of them.
5. **Same source of randomness.** List every security value that uses the same generator or seed.
6. **Other languages.** Check clients, firmware, scripts and services written in other languages that implement the same format.

## Chain primitives

This domain often **gives**:
- forged tokens, signatures or update packages (authn, supply-chain);
- plaintext of protected data (padding oracle, nonce reuse, key exposure);
- predictable secrets (session, reset, invite);
- offline password recovery from a leaked store;
- the ability to modify ciphertext in a meaningful way.

This domain often **needs**:
- a way to read or modify the ciphertext, hash or signature (from authz, data-lifecycle, logging, backup exposure);
- an oracle channel with a usable response difference (from api or messaging);
- a key or secret leak (from `domain-secrets-config.md`);
- a measurement channel for timing (from network position).

## Verification notes

- **E1 is usually enough** for CR-01 (plainly broken choice), CR-02 (constant or zero nonce), CR-03 (missing integrity, explicit error differences), CR-04 (non-cryptographic source on a security value), CR-05, CR-06 (hard-coded or shared key), CR-08, CR-09 (disabled or success-on-error validation) and CR-10.
- **E3 is required** for timing claims (CR-07 and timing-only oracles in CR-03). They stay `needs-validation` without a measurement. E3 is also required for claims that depend on restart or race behaviour (CR-02), entropy at boot or statistical bias (CR-04), and compiler removal of key erasure (CR-06).
- **Attacker model first.** A weak primitive is a finding only when an attacker can reach the data it protects. Name the asset and the attacker position.
- **Library behaviour:** state the library and version. Many libraries add safe defaults (random IV, key checks, name checks). Read the code or documentation of the pinned version.
- **Hash use:** decide whether a hash protects against an attacker. A fast hash on a random secret, or a checksum for corruption, is fine.
- **No live keys:** do not test a found key against a real service. Record file, line and key type only.
- **Severity examples:**
  - critical – the code accepts forged signatures or tokens for any user, or an update package without a valid signature; a hard-coded key protects all customers' data;
  - high – nonce reuse or padding oracle that reveals protected data; predictable reset tokens or session IDs; password hashes that fall to fast offline attack after a store leak;
  - medium – a weak mode on data of limited value; disabled name validation that needs a network position; a missing key rotation path;
  - low – a weak algorithm on low-value data; a timing claim that stays `needs-validation`;
  - informational – a non-constant comparison on a value the attacker cannot measure.

## Fix patterns

- **Use high-level authenticated APIs.** Use an AEAD interface (for example AES-GCM, ChaCha20-Poly1305, or a library "secretbox") and let the library manage nonces where it can. Do not combine low-level primitives by hand.
- **Make nonce uniqueness structural.** Use a random nonce with a large enough space and a key rotation limit, or a persisted counter written before use, or a misuse-resistant mode.
- **Authenticate first.** Verify the tag before decryption or parsing. Return one error for all failures.
- **Use the OS random source.** Use it for every secret. Fail closed if it is unavailable.
- **Use a password-hashing function.** Use Argon2id, scrypt, bcrypt or PBKDF2 with stored parameters, a per-record salt, and rehash on login. Derive separate keys with a labelled KDF.
- **Protect keys in a key service or hardware module** where one exists. Version keys, rotate them, and separate them by purpose, tenant and environment.
- **Compare secrets in constant time** with the library function.
- **Check every verify result.** Pin the key and algorithm in code. Verify the exact bytes that the code then uses.
- **Validate chains and names** with the platform verifier. Never replace it with a callback that returns success.
- **Fail closed.** Refuse on any crypto error.
- **Looks right but is not:** encrypting without authenticating; hashing a password with a fast hash plus a salt; a random-looking token from a non-cryptographic generator; a long key with a repeated nonce; comparing in constant time after converting to a string; catching a verify exception and logging it; disabling certificate checks only in "internal" code paths; base64 or XOR as encryption.

## Regression tests

- Known-answer tests for each primitive, and a test that fails when the algorithm or parameters change below <policy>.
- Tamper tests: flip each byte or bit of the ciphertext, tag, IV and header, and assert the same refusal each time.
- Nonce tests: encrypt many messages and assert that no (key, nonce) pair repeats; simulate restart and restore.
- Randomness tests: assert the source used, and that two calls differ. Do not test randomness with statistics in unit tests.
- Verification tests: an empty, truncated, wrong-key and wrong-algorithm signature each cause refusal; a verify failure stops the action.
- Certificate tests: wrong host, expired, self-signed and wrong-CA certificates are refused.
- Failure tests: with a missing key or a decrypt error, the code refuses and writes no plaintext.
- Password tests: a stored record carries salt and parameters, and an old record is rehashed after a successful login.
