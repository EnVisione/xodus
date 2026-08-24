# Authenticated Target Package Discovery

## Scope

This record captures the current package-discovery evidence obtained on August 24, 2026 for the two Tier 1 local targets. An owner-authorized interactive Microsoft sign-in completed through the Xodus CLI. The CLI then used its Linux D-Bus Secret Service keyring backend to reuse the persisted session for entitled package discovery.

No credential, token, account identifier, signed download URL, package byte, protected executable, or game save was recorded. The checks selected every reported package file in `download --dry-run`; that command printed redacted URLs only and did not request or write package content.

## Authentication and Persistence Evidence

- The interactive login closed normally after Microsoft accepted the authorization.
- Non-secret Secret Service presence checks confirmed both the Xodus user record and user-token bundle exist after login.
- The target package calls completed from a new CLI process using that persisted state. The result establishes reusable account state for the current desktop session without reading credential values.

## Current Target Results

| Target | Product ID | Content ID | Package ID | Current base artifact | Format and architecture | Entitled dry-run result |
| --- | --- | --- | --- | --- | --- | --- |
| Minecraft for Windows | `9NBLGGH2JHXJ` | `7792d9ce-355a-493c-afbd-768f4a77c3b0` | `f3d5f025-2d08-471d-9851-390f1c702dd3` | `Microsoft.MinecraftUWP_1.26.4403.0_x64__8wekyb3d8bbwe.msixvc`, 2,490,064,896 bytes | MSIXVC, x64 | Success. 12 XSP update objects, totaling 143,904 bytes, were listed. |
| Forza Horizon 5 | `9NNX1VVR3KNQ` | `3d263e92-93cd-4f9b-90c7-5438150cecbf` | `b41e5a9c-6ed9-47e7-8afd-7c6d356fb7aa` | `Microsoft.624F8B84B80_3.688.109.0_x64__8wekyb3d8bbwe.msixvc`, 159,934,996,480 bytes | MSIXVC, x64 | Success. 14 XSP update objects, totaling 516,112 bytes, were listed. The smallest XSP was also inspected under the bounded metadata workflow below. |

The public DisplayCatalog result and the authenticated `GetBasePackage` result agree on the product, content, package format, and x64 architecture for both targets. The authenticated dry-run completed successfully for every selected file without a package download.

### Isolated Minecraft Package Inspection

The owner authorized one isolated Minecraft base-package acquisition. Only `Microsoft.MinecraftUWP_1.26.4403.0_x64__8wekyb3d8bbwe.msixvc` was selected. It reached the authenticated metadata size exactly, 2,490,064,896 bytes, in a disposable directory. No XSP update, Forza package, install directory, save, license, content key, or decrypted executable was retained.

The current `XvdFile` metadata reader opened the encrypted container and enumerated only its unencrypted package records. It found the expected content ID and six user package records: `MicrosoftGame.config`, `appxmanifest.xml`, `Metadata.json`, `Summary.json`, `P7X`, and `SegmentMetadata.bin`. It then read only the four textual metadata records from the container. No game payload segment was copied out of the container, mounted, decrypted, or executed.

The recorded metadata proves the following current compatibility facts:

- The package identity is `Microsoft.MinecraftUWP`, version `1.26.4403.0`, x64, with entrypoint `Minecraft.Windows.exe`.
- The title declares Store ID `9NBLGGH2JHXJ`, Title ID `35760C07`, and MSA application ID `0000000040159362`.
- Desktop registration declares `VC14` and `Microsoft.WindowsAppRuntime.1.8` with minimum version `8000.770.947.0`.
- The title exposes the `minecraft`, `ms-xbl-35760c07`, and `ms-xbl-multiplayer` protocols, declares multiplayer support, and requests `internetClient`, `runFullTrust`, `appLicensing`, and `unvirtualizedResources` capabilities.
- `SegmentMetadata.bin` describes 37,630 files. Exactly one segment is marked to remain encrypted on disk, and its executable path is `Minecraft.Windows.exe`.

This is a metadata and protected-file inventory exercise only. The current downloader does not validate the response hash before reporting success, so the exact byte count is acquisition evidence, not complete transport-integrity evidence.

### Isolated Minecraft Update Plan Inspection

One current Minecraft XSP update plan was selected from the entitled package listing and read in a disposable directory under a 1 MiB response limit. The response size matched its 4,304 byte package-listing entry. The current `XspFile` parser accepted it and reported 13 patch records, 10 new-data records, and 3 copy-data records.

The plan declares an update from version `1.26.301.0` to `1.26.4403.0`, 2,489,819,136 update bytes, and 2,490,064,896 required disk bytes. No XSP, base package, payload segment, key, signed URL, or decrypted executable was retained after inspection.

This proves a current Minecraft update-plan metadata shape and parser exercise. It is not a downloaded source package, applied update, integrity verification, rollback, recovery drill, or XODUS-REQ-015 lifecycle result. It therefore does not satisfy EXT-011 or reduce the remaining EXT-002 gate.

### Isolated Forza Update Plan Inspection

One current Forza XSP update plan was selected from the entitled package listing and read under the same 1 MiB response limit. The response size matched its 35,920 byte package-listing entry. The current `XspFile` parser accepted it and reported 1,989 patch records, 1,986 new-data records, and 3 copy-data records.

The plan declares an update from version `3.687.302.0` to `3.688.109.0`, 159,925,977,088 update bytes, and 159,934,996,480 required disk bytes. The matching package-listing `FileHash` field was empty. The inspection therefore confirms exact response-size consistency but had no source-supplied file hash to verify. No XSP, base package, payload segment, key, signed URL, or decrypted executable was retained after parsing.

This is current Forza update-plan metadata and parser evidence only. It does not inspect the 159,934,996,480 byte base package, prove a source-to-target update, establish transport integrity, apply a plan, perform rollback or recovery, demonstrate Game Runtime or online-service compatibility, classify anti-cheat behavior, or satisfy a lifecycle requirement.

### Bounded Forza Base Header Boundary

One separate authenticated probe read and parsed only the 4,096 byte XVD header from the current Forza base package. The header calculates the XVC metadata offset as 943,964,160 bytes. A 512 MiB `PrefixCacheFile` probe therefore cannot reach that offset. The current `XvdFile` path cached 7,772 bytes, then panicked when it attempted the bounded seek. The probe retained no package response, payload segment, key, signed URL, or decrypted executable.

The declared offset then supported one separate direct HTTP range request for exactly 4,096 bytes. The server returned `206 Partial Content`, the `Content-Range` exactly matched the request, and the current `XvcInfo` parser accepted the response. The parsed structural metadata reports XVC version 2, 1,964 regions, 1,990 region specifiers, and 21,490 update segments. The response existed only in process memory and was not written to disk or retained. No payload segment, key, signed URL, or decrypted executable was retained.

Together, these probes establish a successful limited base-package metadata inspection at the declared XVC location and prove that the current prefix-only reader cannot reach it under a 512 MiB cap. They do not establish complete package parsing, transport-integrity verification, a source-to-target update, Game Runtime or online-service compatibility, anti-cheat classification, a package apply, rollback or recovery, or Phase 2 implementation authority.

### Current Base Integrity Metadata

One separate authenticated metadata-only query checked only whether the current selected base-package records expose a nonempty `FileHash` or `HashOfHashes` field. Both fields were absent for both Minecraft for Windows and Forza Horizon 5. No hash value, package response, payload, key, signed URL, or decrypted executable was retained.

This establishes that the current entitlement metadata cannot itself bind either complete base-package transfer to a source-supplied digest. It does not establish failed TLS transport, a package corruption, or any full transport-integrity result. EXT-002 still requires a trustworthy full-transfer integrity path and verification evidence.

### Bounded Forza User Metadata Directory

One separate authenticated range probe read only unencrypted user-metadata records. Each exact range response was checked for `206 Partial Content`, matching `Content-Range`, and a fixed 8 MiB maximum. The package directory has six records and includes `MicrosoftGame.config`, `AppxManifest.xml`, and `SegmentMetadata.bin`. Neither configuration file contained the inspected `xgameruntime`, `Microsoft.Gaming.Services`, or `GamingServices` markers. The bounded segment-metadata path inventory contained an online-service filename signal, but no match for the inspected known anti-cheat filename patterns.

All responses were used only in process memory and were not written to disk or retained. The signal scan does not prove or disprove PE imports, actual online-service behavior, Game Runtime compatibility, or anti-cheat presence. It does not authorize Phase 2 implementation.

## Reproduction Boundary

Use the current `xodus-cli` release binary with the persisted account state, the neutral market, and the product ID:

```text
xodus-cli download <product-id> --market neutral --dry-run
```

This flow is interactive because the current CLI asks which package files to enumerate. It is a discovery operation, not an installation workflow. The command exposes time-limited download URLs, so terminal capture must redact them before retention.

## Remaining EXT-002 Work

This evidence is intentionally incomplete. Minecraft now has an isolated manifest, dependency, entrypoint, protocol, capability, protected-file inventory, and current update-plan record. Forza now has bounded current header-boundary, XVC metadata, user-directory, signal-scan, and update-plan records. Neither target has a source-supplied base-package digest in the current entitlement metadata, or freezes Game Runtime imports, online-service behavior, anti-cheat classification, a trustworthy transport-integrity path, or a source-to-target update pair. Those remaining facts require subsequent authorized, isolated workflows. The only retained acquisition evidence is the sanitized metadata described above.

Consequently, EXT-002 remains partial and does not open XODUS-PHASE-002. EXT-009 is independently available as synthetic entry evidence only; it does not replace any real target-package requirement.
