# Language: Swift and Objective-C

## Scope
- Covers: Swift 5.x and 6 (including Swift 6 language mode), Objective-C and Objective-C++ on iOS, iPadOS, macOS, watchOS, tvOS and visionOS; app extensions; privileged helpers and XPC services on macOS; server-side Swift on Linux. Read `lang-c.md` for C and C++ parts of mixed targets.
- Common frameworks: Foundation; UIKit, SwiftUI and AppKit; WebKit (`WKWebView`); Security (Keychain); CryptoKit and CommonCrypto; Network; Core Data and SQLite wrappers (GRDB, FMDB); Alamofire and AFNetworking; Vapor and Hummingbird on the server.
- Many findings are platform settings, not code. Read `Info.plist`, entitlements files and Xcode build settings as source.

## Entry points

- **App start.** `@main`, `UIApplicationDelegate`, `NSApplicationDelegate`, `application(_:didFinishLaunchingWithOptions:)`, SwiftUI `App`.
- **URL schemes.** `application(_:open:options:)`, `scene(_:openURLContexts:)`, SwiftUI `.onOpenURL`. The schemes are in `Info.plist` under `CFBundleURLTypes`. Any other app can register the same scheme on iOS.
- **Universal links.** `application(_:continue:restorationHandler:)`, `scene(_:continue:)`, `.onContinueUserActivity`. The domains are in the `com.apple.developer.associated-domains` entitlement (`applinks:`).
- **Push and background.** `application(_:didReceiveRemoteNotification:fetchCompletionHandler:)`, `UNUserNotificationCenterDelegate`, `BGTaskScheduler`.
- **Inter-process.**
  - XPC: `NSXPCListenerDelegate.listener(_:shouldAcceptNewConnection:)`, `NSXPCListener(machServiceName:)`, `NSXPCListener.service()`, `NSXPCConnection`.
  - macOS: `DistributedNotificationCenter`, `CFMessagePort`, `NSPasteboard`, Apple Events (`NSAppleEventManager`), privileged helpers installed with `SMJobBless` (deprecated) or `SMAppService` (macOS 13).
  - iOS: `UIPasteboard.general`, App Intents (`AppIntent.perform()`), share and action extensions (`NSExtensionContext`), `UIDocumentPickerViewController`, `UIActivityViewController` return paths, keyboard extensions.
- **Web bridges.** `WKScriptMessageHandler.userContentController(_:didReceive:)`, `WKNavigationDelegate.webView(_:decidePolicyFor:)`, `WKURLSchemeHandler`, JavaScriptCore exports (`JSExport`).
- **Network.** `URLSessionDelegate` callbacks, `NWListener`, `GCDAsyncSocket`, `WebSocket` tasks, Multipeer Connectivity, Bluetooth (`CBPeripheralManagerDelegate`, `CBCentralManagerDelegate`).
- **Server-side.** Vapor: `app.get(`, `app.post(`, `routes(_ app:)`, `req.content.decode(`, `req.parameters`, route groups with `grouped(`. Hummingbird: `router.get(`, `router.post(`.
- **Files.** `Data(contentsOf:)`, `FileManager` reads from the app group, Documents with `UIFileSharingEnabled`, imported documents.

Find the `Info.plist` first. It lists schemes, extension points, exported document types and ATS settings.

## Sinks by domain

| Domain | Dangerous API or pattern | Safer alternative | Notes |
|---|---|---|---|
| injection | `NSPredicate(format: "name == '\(x)'")`; `NSExpression(format:)` with input | `NSPredicate(format: "name == %@", x)` | A predicate string with input allows added clauses and `FUNCTION` calls. |
| injection | SQLite C API `sqlite3_exec` with string-built SQL; FMDB or GRDB with interpolated SQL | `sqlite3_prepare_v2` plus `sqlite3_bind_*`; GRDB arguments; FMDB `executeQuery(_:withArgumentsIn:)` | Table and column names cannot be bound. |
| injection | `webView.evaluateJavaScript("f('\(x)')")`; `loadHTMLString` with input; `WKUserScript` built from input | Pass data with `callAsyncJavaScript(_:arguments:in:contentWorld:)` (iOS 14, macOS 11) or `JSONSerialization` | Quote escaping is not enough. |
| injection | `Process` or `NSTask` with `/bin/sh -c`; `NSAppleScript(source:)`; `osascript` strings | `Process` with `executableURL` and an `arguments` array; no shell | macOS only. Command, argument and AppleScript injection. |
| injection | `String(format: userString, ...)`, `NSString(format:)`, `NSLog(userString)` | `NSLog("%@", s)` | A user-controlled format string can crash or leak. |
| input-parsing | `JSONSerialization.jsonObject` cast with `as!`; custom `Decodable` with `try!`; `XMLParser` custom delegates; `URL(string:)` on untrusted text | Typed `Decodable`; check `URLComponents` fields | `URL(string:)` parsing changed with the iOS 17 and macOS 14 SDKs. Test the real OS version. |
| input-parsing | Archive libraries (ZIPFoundation, SSZipArchive) or `Process` calling `unzip` with names joined to a path | Check each resolved destination | Handoff: `domain-input-parsing.md`. |
| input-parsing | `String.count` used as a length for `NSString`/`NSRange` APIs | `Range(nsRange, in: string)`; `utf16.count`; `utf8.count` | `String.count` counts grapheme clusters. `NSString.length` counts UTF-16 units. A mismatch breaks bounds and ranges. |
| filesystem-process | `FileManager.createFile(atPath:contents:attributes:)` with default protection; `NSTemporaryDirectory()` on macOS with fixed names; `URL.appendingPathComponent(name)` with `..` | `FileManager.url(for: .itemReplacementDirectory, ...)`; `standardizedFileURL` and `resolvingSymlinksInPath()` then check the prefix | On macOS, `/tmp` and `/var/tmp` are shared. APFS is case-insensitive by default and normalisation-insensitive: path checks on strings can be bypassed. |
| filesystem-process | `fileExists(atPath:)` then read or write | Open then use the handle | TOCTOU. |
| filesystem-process | `Data.write(to:)` without `.completeFileProtection`; files in `Documents` or app groups that hold secrets | `NSFileProtectionComplete`; Keychain for secrets | Default protection is `completeUntilFirstUserAuthentication`. |
| filesystem-process | macOS privileged helper that runs a path or a command from the client; `com.apple.security.cs.allow-dyld-environment-variables`; `com.apple.security.cs.disable-library-validation` | Check the caller; fixed commands | Both entitlements allow code injection into a hardened process. |
| crypto | CommonCrypto `CCCrypt` with `kCCOptionECBMode`; `CC_MD5`, `CC_SHA1`; CryptoKit `Insecure.MD5`, `Insecure.SHA1`; fixed IV; `AES.GCM.seal(_:using:nonce:)` with a reused nonce | CryptoKit `AES.GCM.seal(_:using:)` (random nonce), `ChaChaPoly` | The `Insecure` namespace is named so on purpose. |
| crypto | `arc4random` replaced by `rand()`, `random()`, `drand48()`, `Int.random` seeded manually; ignoring the `SecRandomCopyBytes` status | `SecRandomCopyBytes` with the status checked; `SymmetricKey(size:)` | A failed call leaves the buffer unfilled. |
| crypto | `==` on `Data` for MACs or tokens; `SecKeyVerifySignature` result ignored | `HMAC<SHA256>.isValidAuthenticationCode(_:authenticating:using:)` | |
| secrets-config | Keys, tokens or API secrets in `Info.plist`, string literals, `UserDefaults`, plists in the bundle; `kSecAttrAccessibleAlways` (deprecated) | Keychain; `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; server-side secrets | The app bundle is readable by the device owner. |
| secrets-config | `SecItemAdd` with no `kSecAttrAccessible`; `kSecAttrSynchronizable` true; shared `kSecAttrAccessGroup` | Explicit accessibility; `...ThisDeviceOnly` for device-bound secrets; check each access group | `kSecAttrAccessibleAfterFirstUnlock` keeps items readable after the first unlock, including in the background. Keychain items can survive an app delete. |
| authn | `LAContext.evaluatePolicy` used as the only gate (a Bool callback); token kept in `UserDefaults` | Keychain item with `SecAccessControlCreateWithFlags` (`.biometryCurrentSet`, `.userPresence`) | A Bool result is a client-side check. Handoff: `domain-authn.md`, `domain-client-trust.md`. |
| outbound-network | `NSAllowsArbitraryLoads` true in `NSAppTransportSecurity`; `NSAllowsArbitraryLoadsInWebContent`; `NSExceptionDomains` with `NSExceptionAllowsInsecureHTTPLoads` or low `NSExceptionMinimumTLSVersion` | HTTPS only; `NSPinnedDomains` (iOS 14) | See Build and runtime settings. |
| outbound-network | `urlSession(_:didReceive:completionHandler:)` that calls `completionHandler(.useCredential, URLCredential(trust: trust))` with no `SecTrustEvaluateWithError`; `sec_protocol_options_set_verify_block` that returns true; Alamofire `DisabledTrustEvaluator`; AFNetworking `allowInvalidCertificates` | Default handling (`.performDefaultHandling`); evaluate trust and host name | Pinning code must fail closed on error. |
| outbound-network | `URLSession` follows redirects by default; `req.client.get(URI(string: input))` (Vapor); AsyncHTTPClient with input URLs | `willPerformHTTPRedirection` delegate; address checks | Server-side SSRF. Handoff: `domain-outbound-network.md`. |
| web-client / local-ipc | `WKWebView` with `loadFileURL(_:allowingReadAccessTo:)` on a wide directory; `WKScriptMessageHandler` with no `frameInfo` check; `isInspectable` true (iOS 16.4, macOS 13.3) in release; `UIApplication.shared.open(url)` with input; custom scheme for OAuth | Check `message.frameInfo.securityOrigin` and `isMainFrame`; `ASWebAuthenticationSession`; universal links | A bridge handler is exposed to every frame the web view loads. Setting `allowFileAccessFromFileURLs` by key-value coding is a known weakening. |
| local-ipc | `NSXPCListenerDelegate` that returns `true` for every caller; no `setCodeSigningRequirement(_:)` (macOS 13, iOS 16); client identity from a PID | `connection.setCodeSigningRequirement("anchor apple generic and ...")`; audit token checks | A privileged helper that accepts any caller is a confused deputy. |
| logging-privacy | `print`, `NSLog`, `debugPrint` with tokens or personal data; `os_log` with `privacy: .public`; analytics and crash SDKs that get user IDs; screenshots on app switch | `Logger` with default (private) interpolation; redact | `os_log` and `Logger` redact dynamic strings by default. `NSLog` and `print` do not. |
| data-lifecycle | `UIPasteboard.general` for secrets; iCloud Keychain or `NSUbiquitousKeyValueStore` sync of secrets; backups that include secrets | `UIPasteboard` with `setItems(_:options:)` using `.localOnly` and `.expirationDate`; `isExcludedFromBackup` | |
| memory-safety | `unsafeBitCast`, `unsafeDowncast`, `UnsafePointer`, `UnsafeMutableRawPointer.load(fromByteOffset:as:)`, `withUnsafeBytes`, `Unmanaged`, `unowned(unsafe)`, `Array(unsafeUninitializedCapacity:)`; ObjC `__unsafe_unretained`, `assign` on object properties, `getBytes:range:`, `memcpy`, `strcpy` | Safe buffer types; checked ranges | Handoff: `domain-memory-safety.md`. Plain Swift checks bounds and traps on overflow. |
| business-logic / financial | `Double` or `Float` for money; `Int` arithmetic with `&+`; `Decimal` from `Double` | `Decimal(string:)`; `addingReportingOverflow` | |
| concurrency | See the Concurrency section | | |
| supply-chain | SwiftPM `unsafeFlags`; branch dependencies; CocoaPods with git sources; run-script build phases | Exact versions in `Package.resolved`; review build phases | Build phases are target code. |
| sandbox | `JSContext.evaluateScript`; `NSExpression` with input | Fixed script, no user functions | Handoff: `domain-sandbox.md`. |

## Language traps

- **Force operations trap.** `!`, `as!`, `try!`, array index out of range, `Int(someDouble)` for NaN or out-of-range values, and integer overflow end the process. Attacker input that reaches them is a denial-of-service lead. `&+` and `&*` wrap without a trap.
  - Wrong: `let n = Int(json["count"] as! Double)`
  - Right: `guard let d = json["count"] as? Double, let n = Int(exactly: d) else { return }`
- **Release builds remove some checks.** `assert` is removed in `-O`. `precondition` stays in `-O` and is removed in `-Ounchecked`. `NSAssert` is off when `NS_BLOCK_ASSERTIONS` is set. A security check in `assert` is absent in release.
- **Unicode equality.** Swift `String ==` uses canonical equivalence: `"é"` equals `"e\u{301}"`. Byte comparison (`utf8`) does not. An allow-list in one form and a file or database lookup in the other differ. Case folding differs by locale.
- **Objective-C messages to `nil`** return zero. `[user isAdmin]` on `nil` gives `NO`; a deny-list check such as `![user isBlocked]` on `nil` gives allow.
  - Wrong: `if (![session.user isBanned]) { grant(); }` when `session.user` can be `nil`
  - Right: `if (session.user && ![session.user isBanned])`
- **ObjC type confusion.** JSON and plist values are `id`. Calling a method of the wrong class raises an "unrecognised selector" exception. The app crashes. With `performSelector` or KVC, the call may reach unexpected code.
- **Key-value coding.** `value(forKey:)`, `setValue(_:forKey:)` and `value(forKeyPath:)` with a key from input can reach private properties and key-path operators (`@sum`, `@count`). Mass assignment through `setValuesForKeys(_:)` sets whatever keys the dictionary holds.
- **`atomic` properties** protect only the getter and setter. A read-modify-write is not atomic.
- **ARC and bridging.** `CFBridgingRetain` and `__bridge_transfer` errors cause leaks or over-release. `unowned` references to freed objects crash. Retain cycles in blocks keep secrets alive.
- **Optional chaining on checks.** `user?.isAdmin == true` is false when `user` is nil. `user?.isBanned == false` is false for nil too. A nil may mean "allow" in one form and "deny" in another. Read each check for the nil case.
- **`defer` and early return.** Cleanup in `defer` runs on every exit, including a thrown error that skips the code after a check.
- **Completion handlers.** A handler may run twice, never, or on another thread. State changes in a handler that runs after the user logs out apply to the wrong session.
- **Value types.** Swift structs copy. A check on a copy does not protect the original. Reference types (classes) share state.
- **Weak linking.** `if #available` checks guard APIs by OS version. A missing security API on older OS versions can fall back to weaker code. Read the fallback branch.

## Deserialisation and reflection

- **NSKeyedUnarchiver.** The old API `unarchiveObject(with:)` and `NSKeyedUnarchiver(forReadingWith:)` with `requiresSecureCoding` false can create any class that conforms to `NSCoding`. Use `unarchivedObject(ofClass:from:)` or `unarchivedObject(ofClasses:from:)` and set `requiresSecureCoding = true`. Allowed class sets must be narrow. Do not include `NSObject`. In `init?(coder:)`, use `decodeObject(of:forKey:)`, not `decodeObject(forKey:)`.
- **Core Data transformers.** The name `NSKeyedUnarchiveFromDataTransformerName` is the old, insecure transformer. Use `NSSecureUnarchiveFromDataTransformer` with an allowed-class list.
- **Codable.** `JSONDecoder`, `PropertyListDecoder` and custom `Decodable` code do not run code. Risks: optional fields that default to unsafe values; types decoded into server-owned fields; deep nesting; large numbers.
- **Property lists.** `PropertyListSerialization` is data only. Plists of type `NSDictionary` from files can carry unexpected types.
- **Reflection.** `NSClassFromString`, `NSSelectorFromString`, `perform(_:)`, `performSelector:`, `NSInvocation`, `objc_getClass`, `method_exchangeImplementations` and `Mirror`. A class or selector name from input reaches any class in the process. Look for deep link parameters that become class names (for example screen routers).
- **Dynamic loading.** `Bundle(path:)?.load()`, `dlopen`, and loading frameworks from writable paths run native code on macOS.
- **Web code.** `WKWebView.evaluateJavaScript` and `JSContext.evaluateScript` run code. Check the source of the script string.

## Concurrency

- **Swift concurrency.** `async`/`await`, `Task`, `TaskGroup`, `actor`, `@MainActor`, `Sendable`.
- **Actor reentrancy.** An actor lets other calls run at each `await`. State read before an `await` can change by the time the code resumes. This is a check-then-act defect.
  - Wrong: `guard balance >= amount else { throw }; await audit(); balance -= amount`
  - Right: change `balance` before the `await`, or check again after it.
- **Cancellation is cooperative.** Cancelling a `Task` sets a flag. Code that does not call `Task.checkCancellation()` or check `Task.isCancelled` keeps running. Code that catches the `CancellationError` and continues may leave partial state.
- **Escape hatches.** `@unchecked Sendable`, `nonisolated(unsafe)`, and `@preconcurrency` remove compiler checks. Read each use.
- **Language mode.** Swift 6 mode reports data races as errors. Swift 5 mode only warns, and only with strict concurrency settings (`SWIFT_STRICT_CONCURRENCY = complete`). Many projects run in Swift 5 mode.
- **GCD and locks.** `DispatchQueue.sync` on the current queue deadlocks. `DispatchSemaphore` waits on the main thread block the UI. Locks: `NSLock`, `os_unfair_lock` (needs a stable address), `OSAllocatedUnfairLock` (iOS 16), `@synchronized`.
- **Main thread.** UIKit state belongs to the main thread. The Main Thread Checker reports misuse.
- **Core Data.** A managed object context belongs to its queue. Use `perform` or `performAndWait`.
- **Keychain races.** `SecItemCopyMatching` followed by `SecItemAdd` is check-then-act. Use `SecItemAdd` and handle `errSecDuplicateItem`.
- **Continuations.** `withCheckedContinuation` crashes on a second resume and leaks the task if never resumed.

## Build and runtime settings

- **App Transport Security (ATS).** In `Info.plist`, key `NSAppTransportSecurity`.
  - `NSAllowsArbitraryLoads` = true turns ATS off for all domains. This is a strong lead.
  - `NSAllowsArbitraryLoadsInWebContent`, `NSAllowsLocalNetworking`.
  - `NSExceptionDomains` with `NSExceptionAllowsInsecureHTTPLoads`, `NSExceptionMinimumTLSVersion`, `NSExceptionRequiresForwardSecrecy`, `NSIncludesSubdomains`. Check each domain: a wildcard-like exception for a production host is a lead. A localhost exception for development is a false hit.
  - `NSPinnedDomains` adds public-key pinning (iOS 14).
- **Entitlements (macOS and iOS).** `com.apple.security.app-sandbox`; `com.apple.security.get-task-allow` (must not ship in release); `com.apple.security.cs.allow-jit`; `com.apple.security.cs.allow-unsigned-executable-memory`; `com.apple.security.cs.disable-library-validation`; `com.apple.security.cs.allow-dyld-environment-variables`; `keychain-access-groups`; `com.apple.security.application-groups`; `com.apple.security.network.server`; file-access entitlements such as `com.apple.security.files.user-selected.read-write`. Read each as a widening of the sandbox.
- **Hardened Runtime** (macOS notarisation) is the build setting `ENABLE_HARDENED_RUNTIME`.
- **Keychain.** `kSecAttrAccessible` values, from weak to strong: `kSecAttrAccessibleAlways` (deprecated), `AfterFirstUnlock`, `WhenUnlocked` (the default when none is set), `WhenPasscodeSetThisDeviceOnly`. The `ThisDeviceOnly` forms stay off backups and sync. `kSecAttrSynchronizable` sends the item to iCloud Keychain.
- **Data protection.** `NSFileProtectionComplete`, `CompleteUnlessOpen`, `CompleteUntilFirstUserAuthentication`. The default for new files is the last one.
- **Info.plist exposure keys.** `UIFileSharingEnabled`, `LSSupportsOpeningDocumentsInPlace`, `LSApplicationQueriesSchemes`, `CFBundleURLTypes`, `NSExtension`.
- **Compiler settings.** `-Ounchecked` removes overflow and bounds traps. `-enforce-exclusivity=checked` is the default in release builds since Swift 5. Objective-C: `-fobjc-arc`; `-Wformat-nonliteral -Wformat-security`. SwiftPM `unsafeFlags` blocks use as a dependency.
- **Debug paths.** `#if DEBUG` blocks, `-DDEBUG` in release schemes, `ENABLE_TESTABILITY` in release, `isInspectable`, and test endpoints. Check the release build configuration, not the default scheme.

## Tools

Run only what is installed. Most Apple tooling needs macOS and Xcode. `phase-leads.md` section 2.1 has no Swift row, so use the C/C++ compiler-warning row for Objective-C, then the multi-language row (semgrep, codeql). The tools below are extras.

- **Plist and signing checks (read only).** `plutil -p path/Info.plist`; `codesign -d --entitlements :- App.app`; `codesign -dvv App.app`; `otool -L binary`. These read built artefacts. They do not run target code.
- **Compiler and analyser.** `xcodebuild analyze -scheme <Scheme>` runs the Clang static analyser. A build runs build phases (target code): follow `execution.md`. For Objective-C files: `clang --analyze -Xanalyzer -analyzer-output=text file.m`.
- **SwiftLint (if present).** `swiftlint lint --quiet --reporter json`. It uses local configuration. Rules are style-focused; use them for `force_try`, `force_cast`, `force_unwrapping`.
- **SwiftPM offline.** `swift build --disable-automatic-resolution` and `swift test --disable-automatic-resolution` use `Package.resolved` and do not fetch. A missing package fails.
- **Sanitisers.** `swift test --sanitize=address` or `--sanitize=thread`. In Xcode: Address Sanitizer, Thread Sanitizer, Undefined Behavior Sanitizer (C and Objective-C code) and the Main Thread Checker.
- **Fuzzing.** `-sanitize=fuzzer` with a `@_cdecl("LLVMFuzzerTestOneInput")` entry (toolchain support varies). Check that it works before relying on it.
- **Multi-language.** `semgrep --metrics=off --config <local rules>`; CodeQL for Swift if a database can be built offline.

## Lead searches

| regex | meaning | false-hit notes |
|---|---|---|
| `NSAllowsArbitraryLoads\|NSExceptionAllowsInsecureHTTPLoads\|NSAllowsArbitraryLoadsInWebContent` | ATS off or weakened | Debug-only plists; localhost exceptions. |
| `kSecAttrAccessibleAlways\|kSecAttrSynchronizable\|kSecAttrAccessGroup` | Keychain exposure | Check the value and the data stored. |
| `UserDefaults.*(token\|password\|secret\|key\|session)` | Secret in preferences | Names like `keyboardType` are false hits. |
| `useCredential.*URLCredential\(trust\|allowInvalidCertificates\|DisabledTrustEvaluator\|set_verify_block` | TLS validation bypass | Read the code before the call for a trust check. |
| `evaluateJavaScript\|loadHTMLString\|WKUserScript\|callAsyncJavaScript` | Script or HTML built at run time | Constant strings are false hits. |
| `WKScriptMessageHandler\|add\(.*name:\|addScriptMessageHandler` | Web-to-native bridge | Check the origin and frame checks. |
| `onOpenURL\|openURLContexts\|application\(.*open url\|continue userActivity` | Deep link handler | Read how the URL parts are used. |
| `shouldAcceptNewConnection\|NSXPCListener\|setCodeSigningRequirement` | XPC caller check | Missing `setCodeSigningRequirement` is a lead, not proof. |
| `NSPredicate\(format:\s*"[^"]*\\\(\|NSPredicate\(format:\s*\w+` | Predicate from string | Format with `%@` arguments is fine. |
| `sqlite3_exec\|executeQuery\(.*\\\(\|\.execute\(sql:.*\\\(` | SQL by interpolation | Constants are false hits. |
| `unarchiveObject\|NSKeyedUnarchiver\(forReadingWith\|requiresSecureCoding\s*=\s*false\|NSKeyedUnarchiveFromDataTransformerName` | Insecure unarchive | Check the allowed classes in the secure form. |
| `NSClassFromString\|NSSelectorFromString\|performSelector\|value\(forKey(Path)?:\|setValuesForKeys` | Reflection or KVC on input | Constants are false hits. |
| `try!\|as!\|\w+!\.\|\)!\s` | Force operation | A lead only if input reaches it. IBOutlets and bundled resources are false hits. |
| `unsafeBitCast\|UnsafeMutable(Raw)?Pointer\|withUnsafe(Mutable)?Bytes\|Unmanaged\|@unchecked Sendable\|nonisolated\(unsafe\)` | Unsafe code | Read the invariant. |
| `Insecure\.(MD5\|SHA1)\|CC_MD5\|CC_SHA1\|kCCOptionECBMode\|\brand\(\)\|arc4random` | Weak crypto or RNG | Non-security uses are false hits. |
| `print\(\|NSLog\(\|debugPrint\(` near `token\|password\|secret` | Secret in logs | `#if DEBUG` code is a false hit if the release build removes it. |
| `get-task-allow\|disable-library-validation\|allow-dyld-environment-variables\|allow-unsigned-executable-memory` | Entitlement that widens attack surface | Debug entitlements files. |
| `swiftlint:disable\|// NOLINT\|#pragma clang diagnostic ignored` | Silenced tool | A suppressed warning is a strong lead. |

## Verification notes

- **Evidence by claim.** Settings in `Info.plist`, entitlements and Keychain attributes are visible in source: E1 is often enough. Show the setting and the release configuration that uses it. Runtime behaviour of the OS (for example, how ATS handles an exception, or how a universal link resolves) is outside the repository: use `needs-validation`, or E3 on a simulator.
- **Smallest harness.** A SwiftPM test target or an XCTest case that imports the pure logic (parser, URL validation, access check) and asserts the safe result. Run `swift test --disable-automatic-resolution`. Code that imports UIKit, AppKit or WebKit needs macOS and Xcode (`xcodebuild test -destination 'platform=iOS Simulator,name=<device>'`). Move the logic into a plain Swift file for the test when you can, and say that you did.
- **Deep link claims.** Call the handler function with a crafted `URL` and a stub app state. Assert that no privileged action runs. Do not use a real account or server.
- **Authorisation and XPC claims.** Create two dummy callers. Show that the listener accepts the one that must be refused. A real signature check needs a signed build: if you cannot sign, state a `needs-validation` fact.
- **Crash claims.** A forced unwrap or index trap on attacker input is a denial-of-service lead. Show the input in a test. A crash in an app extension or a background daemon can have more impact than a crash in a foreground app that restarts.
- **Memory claims.** Need E3: run the test with Address Sanitizer on the Unsafe or Objective-C code.
- **Race and reentrancy claims.** Need E3. Use two tasks that call the actor method with a suspended step (an `await Task.yield()` in a test copy or a stub) to show the interleaving. The Thread Sanitizer report is evidence for data races.
- **False positives.**
  - ATS exceptions for local development hosts or for domains that serve only public static data.
  - `try!` and `as!` on bundled resources.
  - Keychain items with `ThisDeviceOnly` for non-secret data.
  - `print` in code under `#if DEBUG` that the release configuration excludes.
  - A custom URL scheme that carries no sensitive action.
  - `NSAllowsArbitraryLoadsInWebContent` in an app that shows only trusted content.
- **Platform differences.** Check the deployment target. Keychain, ATS, XPC and `WKWebView` behaviour changes by OS version. State the version you assumed.
