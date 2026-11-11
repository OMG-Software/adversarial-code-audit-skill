# Domain: Embedded and firmware

## Scope

- **Load when:** the repository builds firmware for a constrained device that runs without a general-purpose operating system, or with a small real-time one. Signs: bootloaders; image-signing code; update clients (over-the-air, USB, SD card); linker scripts and vector tables; hardware abstraction layers; debug and test ports; bus and radio stacks (I2C, SPI, UART, USB, BLE, CAN, Modbus, NFC, LoRa); real-time operating systems; secure elements; device provisioning. Products: sensors, locks, vehicles, medical and industrial controllers, wearables, routers, payment terminals, game peripherals.
- **Covers:** secure boot and image verification; update authenticity and rollback; debug and test interfaces; hardware interfaces as input surfaces; secrets in firmware and device storage; task isolation; constrained-device crypto choices; fault and glitch resistance claims; safe reproduction.
- **Hand off to:**
  - `domain-crypto.md` – use of primitives. This file covers what is special on constrained devices: entropy at boot, counters in volatile memory, missing clocks.
  - `domain-supply-chain.md` – build pipeline, signing-key custody, release authority and update servers.
  - `domain-memory-safety.md` – generic bounds, integer and lifetime defects in firmware parsers.
  - `domain-kernel.md` – drivers on devices that run a full kernel.
  - `domain-concurrency.md` – race mechanics, including interrupt-versus-task sharing and priority inversion.
  - `domain-outbound-network.md` – TLS verification in the device's network client.
  - `domain-messaging.md` – device-to-cloud brokers and message authentication at the service side.
  - `domain-secrets-config.md` – configuration precedence and defaults that are not hardware locks.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Boot:** At every boot stage, including recovery and update modes, the device runs only code that verifies against <root-of-trust key or hash> that an attacker cannot change.
2. **Verified is executed:** The bytes that run are the bytes that were verified. Nothing an attacker controls can change them between check and use.
3. **Update:** The device installs an image only if it is authentic, intact, built for this device class, and not older than <minimum version> held in storage the attacker cannot write. A failed update leaves a verified, bootable image.
4. **Debug:** In the shipped state, <debug, test or service interface> gives no access to <code, memory, secrets> without <authorization>. The attacker cannot clear the lock.
5. **Bus input:** Every message from <bus or radio> passes checks of length, type, state and <authenticity> before it changes <state> or reaches <parser>.
6. **Secrets:** Each secret in firmware, flash or logs is unique per device, and removed at decommission.
7. **Isolation:** Code in <low-privilege task or partition> reaches the memory and peripherals of <higher-privilege code> only through checked interfaces.
8. **Entropy and counters:** Keys and nonces come from <entropy source> with enough entropy at first use. Counters persist across reset. No two devices share a key or nonce stream.
9. **Fault:** Where the product claims fault resistance, one fault at <security check> does not grant what the check blocks.

## Recon additions

Add these to `domain-notes.md` under a heading "Device security map". Keep it short.

1. **Boot chain.** Table: stage | location (ROM, internal flash, external flash, RAM) | verified by | where the key or hash lives | action on failure | modes that skip verification (recovery, firmware load, manufacturing).
2. **Image format.** Header fields, bytes that the signature covers, where version and rollback counter live, slot layout, how the verified bytes are found again at run time.
3. **Update path.** Transport, who can trigger it, how the trigger is authenticated, swap method, behaviour on power loss.
4. **Debug and test interfaces.** Table: interface (JTAG/SWD, UART, ROM bootloader, test pins, factory commands) | shipped state (fuse, option byte, readout level) | authentication | whether the debug key is also a production key.
5. **Hardware input surfaces.** Bus or radio | protocol | pairing or authentication | parser location | interrupt or task.
6. **Secrets inventory.** Keys, certificates and credentials: storage place, provisioning flow, per-device or fleet-wide. Record locations only. Never copy values.
7. **Memory protection.** Protection-unit regions and permissions, privileged and unprivileged tasks, stack sizes, flash lock bits.
8. **Entropy and time.** Random source at boot, clock present or not, where counters live.
9. **Physical attacker.** Whether the product claims to resist an attacker with physical access. This statement decides the rating of many findings.

## Lead searches

Adapt the patterns to the toolchain. The language file adds vendor library names.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `JTAG\|SWD\|debug_?(enable\|unlock)\|readout\|RDP\|option_?byte\|e?fuse\|OTP\|lock_?bit\|CRP` | Debug-port state and lock (EM-03) | Lock code in the application can run after the port is already open in early boot. |
| `uart\|console\|shell\|cli\|debug_?cmd\|factory\|manuf\|test_?mode\|diag` | Service command in production firmware (EM-03) | Check the build flag that includes it. |
| `verify\|signature\|ecdsa\|ed25519\|rsa\|hmac\|sha256\|crc\|checksum` in boot and update code | Image or message check (EM-01, EM-02, EM-04) | A CRC or plain hash does not give authenticity. |
| `SKIP_?VERIFY\|NO_?SECURE\|DISABLE_?(SECURE\|VERIFY)\|#ifdef (DEBUG\|DEV\|TEST)` near verify code; `return (0\|OK\|true)` or `goto boot` after a failed verify | Verification switched off, or fail-open boot (EM-01) | Check whether release builds define the macro. |
| `rollback\|anti_?rollback\|min_?version\|security_?counter\|svn\|monotonic` | Version policy (EM-02) | A version in plain flash that an attacker can write gives no protection. |
| Copy to RAM or a staging slot, then `jump\|start_application\|VTOR\|boot_address` | Gap between verify and execute (EM-01) | Check which copy is verified and which runs. |
| `static const .*(key\|secret\|psk\|token\|passw)`; byte arrays of 16 or more `0x..` values; `default\|admin\|1234` near credentials | Embedded secret or default credential (EM-05) | Public keys and test vectors are not secrets. Record the location, not the value. |
| `rand\(\|srand\|time\(NULL\)\|HAL_GetTick\|systick\|trng\|entropy` near key, nonce or token creation; `nonce\|iv\|counter` held in RAM | Weak entropy; reuse after reset (EM-07) | |
| `mpu\|MPU_\|privileged\|SVC_Handler\|syscall\|xTaskCreateRestricted\|user_mode\|stack_?size\|canary` | Isolation set-up, system-call surface, stack guards (EM-06) | |
| `IRQHandler\|_isr\|i2c\|spi\|usb\|gatt\|hci\|can_rx\|modbus\|nfc\|lora` with `memcpy` or a length from the frame | Bus parser reachable by a peer (EM-04) | |
| `pairing\|bond\|just_?works\|passkey\|GATT_PERM\|rolling_?code\|replay` | Radio authentication and replay (EM-04) | |
| `erase\|wipe\|zeroi[sz]e\|factory_?reset\|decommission` | Clearing of secrets (EM-05) | Check that the wipe covers external flash. |

## Attack classes

### EM-01 Secure boot and image verification

- **What fails:** the boot chain runs code that it did not verify, or verifies something other than what it runs. The attacker's firmware, boot configuration or recovery image gains the device's trust.
- **Where to look:** each stage handoff; signature coverage (header, payload or both); where the key or hash lives; a verify result that code ignores or inverts; error handling that boots anyway; recovery, download and manufacturing modes that skip checks; an image verified in external flash and run from it; header length and offset fields parsed before the signature check; one key for debug and production images; configuration blocks outside the signed range.
- **Questions:**
  - Does the signature cover every byte that influences execution (header, version, load address, entry point, configuration)?
  - Can the attacker write the place where the trust anchor lives?
  - What does the code do when verification fails or errors?
  - Is the verified buffer the one that runs? Can anything change it in between (external flash, shared RAM, DMA)?
  - Does any boot mode skip verification? Who can select it?
- **Sad-path inputs:** a changed header field with a valid payload; zero length; a length larger than the slot; an image for another device class; a truncated image; recovery mode entered by a pin or flag; content that changes after the verification read.
- **Evidence for confirmed:** the signature coverage gap or fail-open path in source (E1 can be enough for pure logic), or a host harness with a fake flash that serves different bytes after the verification read, showing that unverified bytes run (E3). A memory defect in a pre-verification parser needs E3 with a sanitizer.
- **Not a finding:** the check sits in immutable boot ROM outside the repository (record an external assumption); a debug build that is not shipped; a physical attacker that the threat model excludes.
- **CWE:** CWE-347 (improper verification of cryptographic signature); CWE-1326 (missing immutable root of trust in hardware); CWE-1282 (assumed-immutable data is stored in writable memory); CWE-1291 (public key re-use for signing both debug and production code); CWE-354 (improper validation of integrity check value) when a checksum replaces a signature.

### EM-02 Update authenticity, rollback and integrity

- **What fails:** the device accepts an update that is unauthentic, for another device, older than allowed, incomplete, or triggered by an unauthorized party. An interrupted update leaves the device unbootable or unverified.
- **Where to look:** update triggers over radio, USB or network; metadata parsing; signature check placement relative to staging; version comparison; where the minimum version is stored and who can write it; swap and slot-confirm logic; power-loss handling; delta updates; update of the bootloader itself.
- **Questions:**
  - Who can start an update? How is the trigger authenticated?
  - Is the signature checked on the complete image before any slot becomes bootable?
  - Does the version check use a counter that the attacker cannot write? Is the comparison numeric, and correct for equal and wrap-around values?
  - Does the image bind the device class, so that an image for another product fails?
  - What state is the device in if power fails at each sector write?
- **Sad-path inputs:** an older signed image; the same version; a signed image for another product; an interrupted transfer; a power cut at each write step.
- **Evidence for confirmed:** the missing signature, version or binding check on the path (E1 can be enough for pure logic). Power-loss and swap claims need a host harness or emulator run with a flash model that cuts writes at each step (E3). A rollback claim must show the writable storage of the version counter.
- **Not a finding:** a documented downgrade through an authenticated service tool; a counter that only the manufacturer can write.
- **CWE:** CWE-494 (download of code without integrity check); CWE-347 (improper verification of cryptographic signature); CWE-1277 (firmware not updateable); CWE-1310 (missing ability to patch ROM code). For rollback, name the weakness in words: the security version number can move back to an older value.

### EM-03 Debug ports and manufacturing modes

- **What fails:** a debug, test or service interface gives access to code, memory or secrets in a shipped device, or an attacker can clear its lock.
- **Where to look:** debug-port enable and lock settings in build and provisioning scripts; readout-protection levels and downgrade paths; serial consoles with a shell or bootloader prompt; ROM bootloaders that read and write memory; factory commands in production firmware; debug-unlock credentials shared across the fleet, derived from the serial number, or equal to a production key; test pins that select a mode.
- **Questions:**
  - In the shipped state, is the port locked in hardware (fuse, option byte)? Where is that step in the repository?
  - Does the lock hold from the first instruction after reset, or does the application set it later?
  - Can the lock level be lowered without erasing secrets?
  - Does a release-build command read memory, write flash or print secrets? Is it authenticated?
  - Is the unlock credential unique per device and independent of production keys?
- **Sad-path inputs:** a reset with a test pin held; undocumented serial commands; a command with no authentication; a downgrade of the protection level.
- **Evidence for confirmed:** a command or mode in the release build that works without authorization (E1 when build flags and handler are in the repository). A claim about the factory lock state depends on a process outside the repository, so it is `needs-validation` unless the provisioning script is in scope.
- **Not a finding:** a debug interface on a development board that is not shipped; a locked port whose unlock needs a protected per-device secret.
- **CWE:** CWE-1191 (on-chip debug and test interface with improper access control); CWE-1244 (internal asset exposed to unsafe debug access level or state); CWE-1313 (hardware allows activation of test or debug logic at runtime); CWE-489 (active debug code); CWE-1269 (product released in non-release configuration); CWE-1273 (device unlock credential sharing).

### EM-04 Hardware interfaces as input surfaces

- **What fails:** a bus, radio or port delivers attacker-chosen frames to firmware that trusts them. The frames reach a parser, change state or command an actuator without the checks that a network service applies.
- **Where to look:** interrupt handlers and driver callbacks that copy frames; BLE pairing mode and attribute permissions; CAN, Modbus and similar buses with no sender authentication; USB descriptor handling; NFC payloads; rolling-code remote controls; configuration writes over any link; handlers that act before authentication.
- **Questions:**
  - Who can send on this link: someone in radio range, a connected cable, a shared bus, a malicious peripheral?
  - Is the sender authenticated before the frame changes state? Does replay protection cover actuator commands?
  - Are length, type and state checked before parsing?
- **Sad-path inputs:** a frame longer than the buffer; an unknown type; a recorded frame sent twice; a command before pairing; a frame during update.
- **Evidence for confirmed:** a missing authentication check on a state-changing command (E1 can be enough for pure logic, when the threat model includes the link). A parser defect needs a host harness or emulator run with a sanitizer (E3). A replay claim needs a test where a recorded frame gives two effects.
- **Not a finding:** the link is inside a sealed enclosure and the threat model excludes that attacker; the command has no safety effect.
- **CWE:** CWE-306 (missing authentication for critical functionality); CWE-294 (authentication bypass by capture-replay); CWE-1299 (missing protection mechanism for alternate hardware interface). For memory defects in a frame parser, use `domain-memory-safety.md`.

### EM-05 Secrets and identity in firmware and device storage

- **What fails:** secrets or identity material in the image or device storage are shared, readable, predictable or not removed. One extracted secret then opens many devices.
- **Where to look:** keys, tokens and service credentials in source, images and flash dumps; fleet-wide symmetric keys; default or serial-number-derived passwords; secrets in external or plain internal flash; secrets printed by logs and consoles; test keys that ship; factory reset and decommission paths; a secure element that the code can bypass.
- **Questions:**
  - Is each secret unique per device? If one device is opened, what else does the secret unlock?
  - Who can read the storage at rest (debug port, flash chip, bus probe)?
  - Is a default credential forced to change before first use?
  - Does decommission clear every copy, including external flash?
- **Sad-path inputs:** a freshly flashed device; a device after factory reset; images from two devices compared for common bytes.
- **Evidence for confirmed:** the location and kind of the secret (never the value) and the way it unlocks more than one device or principal (E1). Extraction from a flash chip is physical and `needs-validation` unless the threat model includes it.
- **Not a finding:** a public key or certificate; a per-device secret in a secure element with no read path; a test key that the release build excludes.
- **CWE:** CWE-798 (use of hard-coded credentials); CWE-321 (use of hard-coded cryptographic key); CWE-1392 (use of default credentials); CWE-312 (cleartext storage of sensitive information); CWE-226 (sensitive information in resource not removed before reuse). For data left after an erase, name the weakness in words: remanent data stays readable.

### EM-06 Memory protection and task isolation

- **What fails:** low-privilege tasks, partitions or peripherals reach memory or functions of higher-privilege code, or the memory map allows writing and executing the same region.
- **Where to look:** protection-unit set-up (regions, permissions, overlap); tasks that run privileged without need; supervisor-call handlers that take pointers from tasks; shared heaps and queues between trust levels; small stacks without guard regions; bootloader flash that the application can write; peripheral registers reachable from untrusted tasks; hardware locks left unset.
- **Questions:**
  - Which tasks run unprivileged? Which regions can each task read, write and execute?
  - Do system-call handlers check that task-supplied pointers and lengths lie inside the task's own regions?
  - Can a stack overflow in one task reach another task's data?
  - Can the application write the bootloader or key storage?
- **Sad-path inputs:** a task that passes a pointer into another task's memory; a deep call chain that overruns a small stack; a write to the bootloader region.
- **Evidence for confirmed:** the protection configuration in source (E1 can be enough for a plainly writable and executable region, or an unchecked pointer in a system-call handler). When the claim depends on protection-unit behaviour, an emulator run shows the access succeeding (E3).
- **Not a finding:** a single-trust-level device where all code is the vendor's and no untrusted code can run.
- **CWE:** CWE-1252 (CPU hardware not configured to support exclusivity of write and execute operations); CWE-1282 (assumed-immutable data is stored in writable memory); CWE-1274 (improper access control for volatile memory containing boot code).

### EM-07 Constrained-device crypto choices

- **What fails:** device limits lead to weak keys, repeated nonces, skipped checks or predictable tokens. Devices share keys, or a reset replays a nonce.
- **Where to look:** random generators at first boot (little entropy, no clock); seeds from the tick counter or serial number; nonce or counter variables held in RAM; counters written to flash without crash safety; certificate checks that skip expiry because no clock exists; secure-element errors that code ignores.
- **Questions:**
  - How much entropy does the first key get? Is the hardware generator started and health-checked?
  - Do two devices from one image produce the same key, token or nonce stream?
  - Is each counter persisted before use, and safe against power loss?
  - What does certificate validation do with no trusted time?
- **Sad-path inputs:** two fresh devices started together; a reset right after a nonce is used; a power cut during a counter write; a generator that returns an error.
- **Evidence for confirmed:** a host or emulator run that shows the same output for two boots with equal state, or a repeated nonce after a simulated reset (E3). A tick-seeded generator for a long-term key can be E1 when nothing else mixes into the seed.
- **Not a finding:** the value has no security role; a hardware generator with documented health tests feeds the value.
- **CWE:** CWE-338 (use of cryptographically weak pseudo-random number generator); CWE-1241 (use of predictable algorithm in random number generator); CWE-323 (reusing a nonce, key pair in encryption).

### EM-08 Fault and glitch resistance claims

- **What fails:** a security decision rests on one instruction, flag or comparison, and a voltage, clock, electromagnetic or timing fault skips it. This matters only where the product or its standards claim resistance to physical attack.
- **Where to look:** single-branch checks on verification results, debug-lock state and rollback counters; boolean flags with values 0 and 1; documents that claim glitch resistance; secure-boot code in payment, lock, vehicle and identity products; brown-out and watchdog states in the middle of a security step.
- **Questions:**
  - Does the product claim resistance to fault injection or tampering? Where is that written?
  - Is the decisive check redundant, with complemented values, and does its failure path stay locked?
  - What state does the device take after a brown-out in the middle of a security step?
- **Sad-path inputs:** a skipped branch at the decision; a brown-out in the middle of an update or unlock; a reset between the check and the flag write.
- **Evidence for confirmed:** physical fault injection is outside this skill. A fault claim is `needs-validation`. State the exact check, the claim, and the lab test (equipment and the one fact to observe). Do not give glitch parameters. A forced branch in an emulator build supports the claim but is not a physical proof.
- **Not a finding:** the product does not claim physical-attack resistance and the threat model excludes it (record a hardening note).
- **CWE:** CWE-1319 (improper protection against electromagnetic fault injection) is attack-oriented and may not fit. For voltage and clock glitches and instruction skipping, name the weakness in words: the security check has no protection against injected faults.

## Variant search

When you find one embedded defect:
1. **Same stage.** Check every boot stage and mode (normal, recovery, update, factory) for the same missing check.
2. **Same field.** For a signature that misses a field, check the coverage of every header and metadata field.
3. **Same interface.** Check every bus and radio handler for the same missing authentication or length check.
4. **Same secret.** Search images, scripts, fixtures and vendored code for the same key or credential.
5. **Same configuration.** Compare build and product variants for the same debug or test flag.
6. **Same history.** If an earlier fix closed one path, check the other update triggers and boot modes.

## Chain primitives

This domain often **gives**:
- code execution on a device with its firmware's privileges (from an unsigned or rolled-back image);
- extraction of device or fleet secrets, which opens the service side and other devices;
- control of an actuator through an unauthenticated bus or radio command;
- a foothold inside the customer's network.

This domain often **needs**:
- a link to the device (radio range, USB, a network update path, or physical access);
- the firmware version (often from public images).

## Verification notes

- **E1 is normally enough** (with a waiver that names every layer checked and the ROM or hardware behaviour assumed) for logic claims: signature coverage gaps (EM-01, EM-02), fail-open boot, missing authentication on a command (EM-04), debug commands in release builds (EM-03), hard-coded secrets (EM-05) and unsafe memory-protection settings in source (EM-06).
- **E3 is required** for verify-then-use gaps, power-loss behaviour, memory defects in parsers and boot code, repeated-nonce claims (EM-07) and any claim about emulated hardware behaviour.
- **Physical attacks** (glitching, probing, chip-level extraction, EM-08) cannot reach `confirmed` from source reading. They are `needs-validation` with a bench plan. A claim about the factory state of fuses or option bytes is also `needs-validation`, unless the provisioning step is in the repository.
- **Safe reproduction.**
  - Host harness first. Compile the verification, update or parser logic on the host with a fake hardware layer (flash array, counter, clock). Run it under the address and undefined-behaviour sanitizers. A flash model that changes bytes after the first read, or cuts a write at step N, gives a deterministic schedule. State what the fake hides.
  - Emulator second. Run the image in a system emulator such as QEMU (Cortex-M boards such as `lm3s6965evb` and `mps2-an385` exist) or Renode, with a serial pipe for input and no network. Emulators do not model fuses, timing faults or analogue effects.
  - Real hardware only if the user supplies a bench device with test keys. Never test production devices or fleets. This skill does not cover flashing, probing or fault injection.
  - Follow `execution.md`. Firmware build scripts and emulator runs are target code.
- **Minimum effect.** A rejected image that boots anyway, an unsigned test image accepted by a harness, a command that returns memory in an emulator, or a sanitizer report proves the defect. Stop there. Do not build an implant or a bypass tool.
- **Reachability.** Show how the attacker reaches the interface (radio range, cable, update service) and in which product variant. Check that the shipped build includes the code.
- **False-positive checks.** An immutable ROM check outside the repository; build flags that remove debug code in release; a hardware lock set by the factory; a link inside a sealed enclosure.
- **Severity examples:**
  - critical – a device or fleet accepts unsigned or attacker-signed firmware from a remote or radio attacker; a fleet-wide key lets anyone forge device identity;
  - high – an attacker in radio or cable range runs commands or reads secrets on a device with no authentication; a network attacker rolls devices back to a vulnerable version; a release-build service interface exposes keys;
  - medium – an attack that needs physical access to one device, when the product claims no tamper resistance; replay of a low-impact command;
  - low – a leak of the firmware version or hardware identifiers;
  - informational – missing stack guards or similar hardening with no reachable defect.

## Fix patterns

- **Anchor trust in hardware.** Keep the root key or its hash in immutable or one-time-programmable memory. Verify every stage from it.
- **Sign everything that influences execution:** header, version, device class, load address, entry point, configuration. Verify before you parse any length or offset.
- **Execute what you verified.** Copy the image to memory the attacker cannot change, verify that copy, run it.
- **Fail closed.** On any error, stay in a locked recovery state that accepts only authenticated images.
- **Keep an anti-rollback counter** in storage the attacker cannot write. Compare numerically. Update it atomically and safely against power loss.
- **Lock debug in hardware** from the first instruction in the shipped state. Use per-device unlock credentials that differ from production keys. Remove factory and shell code from release builds.
- **Authenticate bus and radio commands** that change state, with replay protection. Check length, type and state before parsing.
- **Provision per-device secrets** at manufacture, ideally into a secure element. Wipe every copy at decommission.
- **Seed and persist.** Use the hardware random generator with health tests. Persist counters before use, with crash-safe writes.
- **Configure the protection unit** with least privilege, no writable-and-executable regions, stack guards and checked system-call arguments.
- **Looks right but is not:** a CRC or plain hash as authentication; a signature on the payload but not the header; a hash stored in the same writable flash as the image; XOR or encoding of a key; a debug lock set by application code after early boot; a console command hidden behind a magic string; random delays as the only glitch defence; a version compared as text; a rollback counter in ordinary flash; one signing key for debug and production.

## Regression tests

- **Boot-verification tests on the host:** tamper with each header field, the payload, the version and the length; truncate the image; use an image for another device class; force a verification error. Each must fail closed.
- **Rollback tests:** an older signed image, the same version, a wrap-around version. Each must fail.
- **Power-loss tests:** cut the flash write at every sector of an update in a flash model. The device must boot a verified image each time.
- **Verify-then-use test:** a flash model that serves different bytes after the verification read. The device must not run them.
- **Parser fuzz targets** for the boot, update and bus parsers, built on the host with sanitizers.
- **Release-image check:** a build step that fails when the image contains the shell, factory commands, test keys or debug macros.
- **Provisioning check:** assert the lock settings in the provisioning script.
- **Isolation test in an emulator:** an unprivileged task that touches protected memory must fault.
- **Authentication tests** for each bus command: unauthenticated and replayed frames must fail.
- **Persistence test:** reset the device model between nonce uses. No nonce may repeat.
