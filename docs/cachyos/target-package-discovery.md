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
| Forza Horizon 5 | `9NNX1VVR3KNQ` | `3d263e92-93cd-4f9b-90c7-5438150cecbf` | `b41e5a9c-6ed9-47e7-8afd-7c6d356fb7aa` | `Microsoft.624F8B84B80_3.688.109.0_x64__8wekyb3d8bbwe.msixvc`, 159,934,996,480 bytes | MSIXVC, x64 | Success. 14 XSP update objects, totaling 516,112 bytes, were listed. |

The public DisplayCatalog result and the authenticated `GetBasePackage` result agree on the product, content, package format, and x64 architecture for both targets. The authenticated dry-run completed successfully for every selected file without a package download.

## Reproduction Boundary

Use the current `xodus-cli` release binary with the persisted account state, the United States market, and the product ID:

```text
xodus-cli download <product-id> --market US --dry-run
```

This flow is interactive because the current CLI asks which package files to enumerate. It is a discovery operation, not an installation workflow. The command exposes time-limited download URLs, so terminal capture must redact them before retention.

## Remaining EXT-002 Work

This evidence is intentionally incomplete. It does not freeze either target's dependency graph, manifest entrypoint, protected-file inventory, Game Runtime imports, online services, anti-cheat classification, or a source-to-target update pair. Those facts require a separately authorized, isolated acquisition and inspection workflow. No content download began in this discovery run.

Consequently, EXT-002 remains partial and does not open XODUS-PHASE-002. The independent EXT-009 legal MSIXVC2 and XSP fixture-manifest prerequisite also remains blocked.
