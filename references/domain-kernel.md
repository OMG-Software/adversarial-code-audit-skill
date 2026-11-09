# Domain: Kernel

## Scope

- **Load when:** the code runs in a privileged mode and accepts input from a less privileged one. Signs: kernel modules and drivers; syscall, ioctl, netlink, character-device, sysfs, procfs or debug-file handlers; file-system and network-stack hooks; hypervisors, virtual machine monitors and emulated devices; hypercall and device-register handlers; DMA-capable drivers; namespace and sandbox enforcement in the kernel.
- **Covers:** interface validation and access control; user-copy bounds; double fetch; reference counting, lifetime and concurrent entry points; privilege checks; namespace and container boundaries; guest-to-host interfaces; DMA and device-controlled input; information leaks to user space; safe reproduction of kernel claims.
- **Hand off to:**
  - `domain-memory-safety.md` – generic bounds, integer, lifetime and type defects. This file covers the kernel interface that reaches them.
  - `domain-concurrency.md` – general races and lock misuse. This file keeps races between kernel entry points.
  - `domain-embedded.md` – device-side firmware and bootloaders. This file covers the host driver that trusts the device.
  - `domain-sandbox.md` – runtimes that run untrusted code in user space.
  - `domain-cloud-deploy.md` – container and cluster configuration in manifests.
  - `domain-filesystem-process.md` – user-space files, permissions, setuid and privilege dropping.
  - `domain-input-parsing.md` – format logic of packets and file systems.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Argument:** Every value that <interface> takes from a less privileged caller (command, size, flag, version, index, handle, pointer) is validated against <the real limit> before use. Unknown values are rejected.
2. **Copy:** The kernel copies user data once into kernel memory, with a length it has checked. It uses only the kernel copy afterwards.
3. **Pointer:** The kernel never dereferences a user-supplied pointer directly. It never accepts a kernel address where it expects a user address.
4. **Lifetime:** No entry point (call, close, timer, work item, interrupt, unload) uses an object after another entry point has released the last reference.
5. **Privilege:** An operation that needs <capability or privilege> checks it on the credential and in the namespace that the design names, at the time of the operation.
6. **Isolation:** An object is looked up in the caller's namespace or container, and a caller never gets host or sibling state.
7. **Device input:** Values that a device or guest writes (descriptors, lengths, indexes, status) are untrusted. The driver validates each one before use.
8. **Disclosure:** Bytes copied to a less privileged caller are all defined, and none is a kernel address or secret.

## Recon additions

Add these to `threat-model.md` under a heading "Kernel interface map". Keep it short.

1. **Entry points.** Table: type (syscall, ioctl, netlink, sysfs/procfs/debug file, device node, file-system operation, hypercall, register handler, virtual queue, interrupt) | registration site | who can reach it (node mode, capability, namespace, sandbox filter) | arguments | copy routines.
2. **Reach.** Device-node permissions and rules that the repository ships; module auto-load; whether unprivileged user namespaces reach the interface; whether the hardware exists on a default system.
3. **Object lifetime.** Table: object | allocation | lookup | reference rule | release | entry points that can run at the same time.
4. **Contexts and locks.** Table: lock | contexts that take it | what it guards | order.
5. **User-memory access sites.** Every copy in, copy out and direct user-pointer use. Mark each location that is read more than once.
6. **Compat and ABI.** 32-bit layouts, versioned structures, reserved fields.
7. **Device and guest inputs.** DMA mappings, descriptor rings, device registers read as lengths or indexes, guest memory read by a monitor.
8. **Target and config.** Kernel or OS version that the code builds against, in-tree or out-of-tree, and the hardening options enabled (user-copy hardening, memory initialisation, supervisor-mode access protection, module signing, address hiding).

## Lead searches

Names below are examples from common kernels. The language file and the kernel version give the exact set.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `copy_from_user\|copy_to_user\|get_user\|put_user\|access_ok\|ProbeForRead\|ProbeForWrite\|copyin\|copyout` | User-memory access site (KN-02, KN-03) | List every one. A length that comes from the user and is not capped is the lead. |
| Two copies from the same user address in one handler | Double fetch (KN-03) | A second copy into the same kernel buffer after validation of the first is still a lead. |
| `unlocked_ioctl\|compat_ioctl\|DeviceIoControl\|IRP_MJ_DEVICE_CONTROL\|METHOD_NEITHER\|netlink\|genl\|debugfs\|sysfs\|file_operations\|SYSCALL_DEFINE` | Interface entry (KN-01) | Build the entry-point table first. |
| `case [A-Z_]+_(DEBUG\|TEST\|DUMP\|PEEK\|POKE\|RAW)` in a command switch | Debug or raw command left in (KN-01) | |
| Node creation with mode `0666` or `0777`, or a device created without a secure-open flag | Interface open to all users (KN-01, KN-05) | System rules outside the repository may tighten the mode. |
| `capable\(\|ns_capable\|file_ns_capable\|CAP_[A-Z_]+\|SeSinglePrivilegeCheck\|IoValidateDeviceIoControlAccess` | Privilege check inventory (KN-05) | Compare with the list of privileged operations. |
| `current_cred\|f_cred\|init_user_ns\|init_net\|init_pid_ns\|nsproxy\|current_user_ns` | Credential or namespace choice (KN-05, KN-06) | |
| `kref\|refcount\|atomic_(inc\|dec)\|fget\|fput\|rcu_read_lock\|call_rcu\|kfree_rcu\|list_del\|del_timer\|cancel_work` | Reference counting and teardown (KN-04) | |
| `spin_lock\|local_irq\|preempt_disable` followed by `msleep\|schedule\|mutex_lock\|GFP_KERNEL`; `module_exit\|DriverUnload` | Sleep in atomic context; unload while callbacks are pending (KN-04) | |
| `mmap\|remap_pfn_range\|vm_insert_page\|MmMapIoSpace` | Mapping of kernel or device memory to user space (KN-02) | Check the size and offset against the object. |
| `in_compat_syscall\|compat_\|X32` | Compat path with another layout (KN-01) | |
| `dma_map\|dma_alloc\|dma_sync\|virt_to_phys\|ioremap\|readl\|readb` where the value is used as an index or length | Device-controlled input (KN-08) | |
| `virtqueue\|vring\|hypercall\|vmexit\|VMCALL\|mmio\|ioport` | Guest-controlled input (KN-07) | |
| `%p\|%px\|seq_printf\|pr_info\|printk` with addresses; `= \{ *\}` or `memset` missing before `copy_to_user` | Disclosure (KN-09) | Hashed pointer printing is safe. |

## Attack classes

### KN-01 Interface validation and access control

- **What fails:** a kernel interface accepts a command, size, flag, version, index or handle that it should reject, or the interface is open to callers who must not reach it.
- **Where to look:** command switches; commands whose size comes from the user and not from the command code; extensible structures that accept unknown flags and non-zero reserved fields; indexes into driver arrays; handles of the wrong type; compat handlers with another layout; debug and test commands; device-node permissions and rule files; mapping handlers that map more than the object holds; the `METHOD_NEITHER` style of transfer, where the caller gives raw addresses.
- **Questions:**
  - Which principals can open or call this interface? Which check enforces that, and where?
  - Is each command argument checked against a real limit? Are unknown commands, flags and versions rejected?
  - Does the 32-bit path decode the same structure as the 64-bit path?
  - Does a debug command give access that a normal command withholds?
- **Sad-path inputs:** an unknown command; a size smaller and larger than the structure; non-zero reserved fields; an index equal to the array length; a handle of another type; a call from an unprivileged user; a 32-bit caller on a 64-bit kernel.
- **Evidence for confirmed:** for access control, the registration or node mode and an unprivileged call that succeeds (E1 can be enough, see verification notes). For an unchecked index or size, a sanitizer report from the handler (E3).
- **Not a finding:** only root can open the node by design, and no unprivileged namespace reaches it; a core layer already rejects the value; the code is compiled out by default.
- **CWE:** CWE-781 (improper address validation in IOCTL with `METHOD_NEITHER` I/O control code); CWE-782 (exposed IOCTL with insufficient access control); CWE-129 (improper validation of array index); CWE-1285 (improper validation of specified index, position, or offset in input); CWE-749 (exposed dangerous method or function) for left-over debug commands.

### KN-02 User-copy bounds and pointer trust

- **What fails:** the kernel copies with a length that the user controls, copies out more than it owns, dereferences a user pointer directly, or accepts a kernel address where it expects a user address.
- **Where to look:** copy-in into fixed-size buffers; copy-out with a user-supplied length; allocation sizes from user fields; variable-length messages (a header with a length, then a payload); copy-routine results that code ignores; kernel-mode copies applied to user data; mapping handlers.
- **Questions:**
  - Is the length capped against the destination size before the copy? Is the cap and the copy size the same value?
  - Does the code check the result of the copy routine?
  - Can a user pass a kernel address and reach a path that treats it as a user address (or the reverse)?
- **Sad-path inputs:** length 0, 1, limit, limit plus one, and 2^32; a length smaller than the header; an unmapped user address; a kernel address.
- **Evidence for confirmed:** a kernel address-sanitizer report in a test VM, or a user-space harness report with stubbed copy routines that shows the out-of-bounds access (E3).
- **Not a finding:** a cap in the core layer; a length that the command code fixes and the core checks.
- **CWE:** CWE-130 (improper handling of length parameter inconsistency); CWE-805 (buffer access with incorrect length value); CWE-822 (untrusted pointer dereference); CWE-252 (unchecked return value); CWE-787 (out-of-bounds write).

### KN-03 Double fetch

- **What fails:** the kernel reads the same user-controlled memory twice. It validates the first value and uses the second, which the caller changed in between.
- **Where to look:** a header copied and checked, then the whole message copied again; a length read from a shared mapping and read again for the copy; repeated `get_user` of one field; shared ring buffers; guest memory read twice by a monitor; direct use of a user buffer after a probe.
- **Questions:**
  - Does the code copy the data once and use only the copy?
  - Does any validated field come from memory that the caller can still write?
- **Sad-path inputs:** a value that differs on the second read (small on read one, large on read two); a length that grows between the header copy and the payload copy.
- **Evidence for confirmed:** a harness whose copy stub returns a different value on the second read of the same address, plus the sanitizer report that follows (E3). This gives a deterministic schedule. A race that you saw once is not E3.
- **Not a finding:** the second read rejects a changed value; the memory is kernel-owned and the caller cannot write it.
- **CWE:** CWE-367 (time-of-check time-of-use race condition).

### KN-04 Lifetime, reference counting and concurrent entry points

- **What fails:** one entry point frees or changes an object while another entry point uses it. A reference count is wrong on an error path. A lookup returns an object without a reference. A teardown does not wait for callbacks.
- **Where to look:** `close`/`release` racing with `ioctl`, `read` or `mmap`; duplicated or passed descriptors; error paths that put a reference twice or not at all; lookup-then-use without a reference taken under the lock; lock-free read sections that use the object after the grace period; timers, work items and interrupt handlers that outlive the object; unload while callbacks are pending; a sleeping call under a spin lock; lock-order inversion between process and interrupt context.
- **Questions:**
  - Which references does each entry point hold? Is the count balanced on every error path?
  - Does the lookup take its reference while the object cannot yet be freed?
  - Does teardown stop and flush every timer, work item and interrupt before the free?
  - Can a sleeping call run under a spin lock?
- **Sad-path inputs:** `close` during a long `ioctl`; two `close` calls on duplicated descriptors; an error at each step of setup; unload during traffic; a reference count at its maximum.
- **Evidence for confirmed:** a kernel sanitizer report (use after free, or a lock-order or sleep-in-atomic report from the lock debugger) from a test that forces the order with a delay at the gap (E3). Run in a test VM only.
- **Not a finding:** the same lock protects the count on every path; a teardown that waits for callbacks; two sides that run in one context and cannot overlap.
- **CWE:** CWE-911 (improper update of reference count); CWE-416 (use after free); CWE-415 (double free); CWE-826 (premature release of resource during expected lifetime); CWE-833 (deadlock).

### KN-05 Privilege and capability checks

- **What fails:** a privileged operation runs without a check, with the wrong check, or with a check on the wrong subject or at the wrong time.
- **Where to look:** operations that change hardware, memory, other processes, network or system state; checks of the opener's credential instead of the caller's, or the reverse; checks in the initial namespace instead of the caller's; a check at `open` and none at `ioctl` (descriptor passing); a capability broader than the operation needs; missing security-module hooks; helpers that act for a user without checking that user.
- **Questions:**
  - Which operations need privilege? Does each one check it on every path, including the compat path?
  - Is the checked credential the one that the design names (caller, opener, effective, real)?
  - Is the capability checked in the right namespace?
  - Can an unprivileged process obtain a descriptor that a privileged process opened, and then call the privileged command?
- **Sad-path inputs:** an unprivileged caller; root inside an unprivileged user namespace; a descriptor passed from a privileged process.
- **Evidence for confirmed:** the privileged operation, the missing or wrong check on the full path, and an unprivileged call that succeeds in a test VM or harness (E1 for a plain missing check, E3 when helper behaviour is outside the repository).
- **Not a finding:** only root can reach the interface by design and no namespace gives root-like reach; the operation is harmless to other principals.
- **CWE:** CWE-862 (missing authorization, class-level); CWE-863 (incorrect authorization, class-level); CWE-782 (exposed IOCTL with insufficient access control).

### KN-06 Namespace, container and sandbox boundaries

- **What fails:** kernel code looks up an object in the wrong namespace, shows host or sibling state to a container, gives a feature to root in a user namespace that is not safe to give, or a sandbox filter misses a path to the same call.
- **Where to look:** lookups of processes, network devices, mounts or IPC objects by global ID; use of the initial namespace where the caller's is right; files that expose host data; operations that a namespace-scoped root can reach (device creation, module or firmware loading, raw hardware access, unusual mounts); system-call filters that match by call number and arguments (the filter sees a pointer, not the content; other ABIs have other numbers); process tracing.
- **Questions:**
  - Which namespace does each lookup use? Is it the caller's?
  - Which operations become reachable for a caller with capabilities inside its own namespace? Is each safe there?
  - Does the sandbox filter cover every ABI and call number with the same effect?
  - Can a container read host-wide counters, logs or addresses?
- **Sad-path inputs:** a caller in a new user namespace; a caller in a container with its own process-ID or network namespace; a call by an alternate-ABI number; a filter argument that changes after the check.
- **Evidence for confirmed:** a test in a disposable VM where a container or namespace caller reaches host state or a forbidden operation (E3).
- **Not a finding:** host state that is public by design; an operation that the design gives to namespace-scoped root.
- **CWE:** CWE-653 (improper isolation or compartmentalization, class-level); CWE-863 (incorrect authorization, class-level); CWE-497 (exposure of sensitive system information to an unauthorized control sphere).

### KN-07 Hypervisor and guest-to-host interfaces

- **What fails:** the host side trusts a value that the guest controls. A guest reaches host memory, other guests or host state, or hangs the host.
- **Where to look:** emulated device handlers (register offsets, queue indexes, descriptor chains and lengths); hypercall arguments; control-register writes; guest memory that the monitor reads twice; descriptor chains with loops; emulated device state machines driven in odd order; nested virtualisation; balloon and hot-plug requests.
- **Questions:**
  - Does the handler validate each guest-written value (index, length, address, count) against the real limits?
  - Does the monitor copy guest memory once and use the copy?
  - Does a loop over a guest-controlled chain have a bound?
- **Sad-path inputs:** an index equal to the queue size; a chain with a cycle; a zero or huge length; an address outside guest memory; a reset in the middle of a request.
- **Evidence for confirmed:** a sanitizer report from the device model, driven by a guest-side test or a fuzz harness (E3), in a disposable VM or a sandbox. For a hang, show the unbounded loop with the crafted chain.
- **Not a finding:** the threat model trusts the guest; a limit in a lower layer stops the value.
- **CWE:** CWE-787 (out-of-bounds write); CWE-125 (out-of-bounds read); CWE-129 (improper validation of array index); CWE-367 (time-of-check time-of-use race condition). For an unbounded loop, name the weakness in words: a loop whose exit the guest controls.

### KN-08 Driver DMA and device-controlled input

- **What fails:** a driver trusts values that hardware writes, or lets a device reach memory it should not.
- **Where to look:** descriptor rings where the device writes length, status or index; completion handlers that use a device-written index; drivers for removable or external devices (USB, Thunderbolt, PCIe, virtual devices from an untrusted host); DMA without an I/O memory-management unit or with a window larger than the buffer; buffers freed while DMA is active; wrong sync direction; DMA into the stack or into pages that hold other data.
- **Questions:**
  - Is each device-written value checked before use as an index, length or pointer?
  - Is the buffer unmapped before it is freed or reused?
  - Does the DMA window cover only the intended buffer?
  - Does the threat model say the device is untrusted (external peripheral, confidential virtual machine)?
- **Sad-path inputs:** a completion with an index outside the ring; a length larger than the buffer; a duplicate completion; a descriptor that points to unexpected memory.
- **Evidence for confirmed:** a sanitizer report from a test with an emulated or fake device that writes the hostile value (E3). For real hardware, the claim is `needs-validation`.
- **Not a finding:** the threat model trusts the device; an I/O memory-management unit confines it by default.
- **CWE:** CWE-129 (improper validation of array index); CWE-130 (improper handling of length parameter inconsistency); CWE-125 (out-of-bounds read); CWE-416 (use after free).

### KN-09 Information leaks to user space

- **What fails:** the kernel returns bytes that the caller must not see: uninitialised memory, padding, stale buffer content, kernel addresses or secrets.
- **Where to look:** structures copied out whole; buffers copied out after a partial fill; read handlers that return more than they filled; log, procfs, trace and debug files that print addresses; error messages with pointers; buffered-transfer output buffers that are not cleared; debug files that expose keys.
- **Questions:**
  - Does the code clear the structure before it fills fields, or copy field by field?
  - Is the copy length the filled length?
  - Does any readable file print a raw kernel address or a secret?
- **Sad-path inputs:** the shortest valid request; each error branch before the fill; a request for a larger output than the data.
- **Evidence for confirmed:** a memory sanitizer report on the copy-out (in a test VM), or a harness that poisons memory with a known pattern and finds it in the output (E3). For addresses, E1 shows the print, but address hiding is an external fact, so the claim is `needs-validation` until you test the configuration.
- **Not a finding:** all output bytes are defined; the print routine hashes the address; only root can read the file by design.
- **CWE:** CWE-457 (use of uninitialized variable); CWE-908 (use of uninitialized resource); CWE-497 (exposure of sensitive system information to an unauthorized control sphere); CWE-226 (sensitive information in resource not removed before reuse).

## Variant search

When you find one kernel defect:
1. **Same interface.** List every other command, file and handler of the same driver. Check each for the same missing check.
2. **Same copy shape.** Search all user-memory access sites for the same shape (header then payload, user length then copy).
3. **Same object.** List every entry point that uses the same object. Check the reference rules for each.
4. **Same compat path.** Check the compat handler of every command that you fixed.
5. **Same family.** Check sibling drivers that came from the same template or vendor code.
6. **Same device input.** List every device-written field that the driver reads. Check each for the same missing validation.

## Chain primitives

This domain often **gives**:
- kernel memory corruption or read at the minimum proven level (state the proven effect only);
- disclosure of kernel addresses and layout, which helps other kernel defects;
- a container or guest escape to the host;
- a host panic or hang by an unprivileged caller;
- a descriptor or capability that opens a privileged interface.

This domain often **needs**:
- local code execution as an unprivileged user, a guest or a device (from other domains);
- reach to the device node or interface (node mode, user-namespace reach).

Do not chain past the proven effect.

## Verification notes

- **E3 is required** for `confirmed` in KN-02, KN-03, KN-04, KN-07, KN-08 and in any memory, lifetime or race claim. Without T2, they are `needs-validation` with a reproduction plan.
- **E1 can be enough** (with a waiver) for logic-only claims: a privileged operation with no check (KN-05) and a device node open to all users by a mode in the repository (KN-01), when the full path is in the repository and no helper outside it decides. In-tree code reads kernel helpers that you can read. Out-of-tree code depends on the kernel version it builds against, so name the version. If the helper's behaviour is not read, the claim is `needs-validation`.
- **Never load target kernel code into the host kernel.** A fault there can panic the host or corrupt data. Run kernel code only in a disposable virtual machine with no network and no shared folder except scratch (I3 when the user confirms it). At I1 or I0, use a user-space harness or stay with `needs-validation`.
- **User-space harness.** Compile the handler in scratch with stubs for the copy routines, the allocator and the locks. Run it under the address and undefined-behaviour sanitizers. A double-fetch stub returns a second value on the second read of an address. A poison stub fills output memory with a known pattern. State what the stubs hide. A harness result proves the handler logic, not the hardening state of a real kernel.
- **Test VM.** Use QEMU (for example `qemu-system-x86_64 -nographic -nic none`) with a kernel built with debug options where it has them: KASAN, KCSAN, KMSAN (Clang), UBSAN, `CONFIG_PROVE_LOCKING`, `CONFIG_DEBUG_ATOMIC_SLEEP`, KFENCE. A kernel fuzzer such as syzkaller can drive the interface inside the VM with a time limit. For Windows-style drivers, use a VM with the Driver Verifier (including special pool) and a kernel debugger. For devices, use an emulated device that you control.
- **Minimum effect.** A sanitizer report in the VM log (access, size, stacks) proves the defect. Stop there. Do not build privilege escalation. A panic proves a crash, not code execution.
- **Reachability.** Confirm who can open the node, whether the module loads by default, whether unprivileged user namespaces reach the interface, and whether the hardware exists in the default setup. Name the configuration options that your test used.
- **False-positive checks.** A core layer that validates before the handler; an option that is off by default; a harness-only state; a caller that the threat model trusts. A hardening option that stops the effect lowers likelihood; the defect stays.
- **Severity examples:**
  - critical – a remote, unauthenticated peer reaches kernel memory corruption through a network-facing driver; a guest escapes to the host;
  - high – an unprivileged local user reaches a kernel out-of-bounds write, use after free or missing privilege check; a container escape; a repeatable panic of a shared host by an unprivileged user;
  - medium – a kernel address leak that needs another defect to matter; a host hang that needs sustained effort; a corruption path that needs a rare configuration;
  - low – a small leak of defined but non-sensitive data; a crash only reachable by root;
  - informational – a missing validation that a core layer already stops.

## Fix patterns

- **Copy once, validate, then use the copy.** Copy the user data into a kernel structure with a checked length. Use the versioned-structure copy helper where the kernel offers one. Reject unknown flags and non-zero reserved fields.
- **Cap every user length** against the destination size, and use overflow-checked helpers for allocation sizes.
- **Never dereference user pointers directly.** Use the copy routines and check their results.
- **Check privilege at the operation.** Check the credential and namespace that the design names, on every path including compat, and at each privileged command and not only at open. Set the narrowest device-node mode.
- **Take a reference at lookup**, under the lock that keeps the object alive. Use a saturating reference-count type. Balance every error path. Stop and flush timers, work and interrupts before the free.
- **Document lock order and context.** Do not sleep under a spin lock.
- **Look up in the caller's namespace.** Gate unsafe features so that namespace-scoped root cannot reach them.
- **Validate device and guest values.** Copy descriptors once, check every index and length, bound every loop, use an I/O memory-management unit, unmap before free.
- **Clear outputs.** Zero structures before they are filled. Copy field by field. Print hashed pointers.
- **Looks right but is not:** checking privilege in `open` only; `access_ok` and nothing else; clamping the first read of a length and using the second; checking a reference count without the lock; a node mode of `0600` that a rule file changes; blocking one call number in a filter; address hiding or user-copy hardening as the fix; zeroing a structure and then copying out a longer length.

## Regression tests

- For each fixed command, a **boundary test** of size, flag, version and index values, including unknown ones, expecting rejection.
- A **double-fetch test** with a stub that changes the value on the second read. It must show that the handler uses the first value or rejects the change.
- A **principal matrix test**: each privileged command against root, an unprivileged user, root in a user namespace, and a container, expecting deny where the design says so. Include the compat path.
- A **teardown race test**: `close` during a long call, duplicated descriptors, and unload during traffic, run under the kernel sanitizers.
- **Error-injection tests** that fail each allocation and setup step, then check reference counts.
- A **poison test**: fill the stack and heap with a known pattern before the call, then check that the output contains no pattern bytes beyond defined fields.
- A **fake-device test** that writes extreme descriptors, with sanitizers on.
- A fuzz corpus for the interface, run in the test VM.
