# CachyOS Runtime Readiness

## Verification Record

| Field | Observed value |
| --- | --- |
| Verification date | August 25, 2026 |
| Distribution | CachyOS rolling |
| Kernel | `7.2.0-1-cachyos`, `PREEMPT_DYNAMIC` |
| Session | Hyprland on native Wayland, `wayland-1`, XWayland display `:1` |
| Compositor | Hyprland `0.56.2` |
| GPU | NVIDIA GeForce RTX 5090 Laptop GPU, 24,463 MiB |
| NVIDIA driver | `610.57.04` |
| Vulkan | Loader `1.4.357`, NVIDIA device API `1.4.341` |
| Active display | `eDP-1`, 3840 by 2400 at 240 Hz |
| Display scale | 2.0, or 200 percent |
| Active HDMI output | None observed |

## Available Local Components

The bounded package and command checks found these relevant components installed:

- `wine` 11.16
- `wine-cachyos-opt` 10.0
- `proton-cachyos-slr` 11.0
- Steam Proton GE in the local compatibility tools directory
- Gamescope 3.16.25
- MangoHud 0.8.4
- Hyprland 0.56.2
- NVIDIA PRIME and Vulkan tooling

These components establish a usable CachyOS graphics and Wine baseline. They do not prove Xodus target compatibility, protected executable behavior, or Game Runtime behavior.

## Missing or Unverified Runtime Prerequisites

No local `xgameruntime`, `XGameRuntime`, WineGDK, or GDK Proton artifact was found in the bounded search of system libraries, local compatibility tools, and standard local runtime paths. The installed Wine and Proton packages are not treated as substitutes for the pinned EXT-003 and EXT-004 artifacts because their exact Game Runtime surface, patch provenance, and protected executable compatibility are not established.

An external GDK Proton candidate is now visible upstream. The `release10-32` release is based on GE-Proton10-32 and publishes `GDK-Proton10-32.tar.gz` with the recorded SHA-256 digest `1e80f4e714f877f42101d5775bd38ca0a15a38d304e24af1f15c6deec4ebac2d` and a size of 524743374 bytes. A disposable download matched that digest and its archive manifest contains `xgameruntime.dll` and `xgameruntime.dll.threading`. The extracted `xgameruntime.dll` is a 64 bit Wine PE DLL with SHA-256 `d68dab5b5e8e8252dbcc9d12e43fa4e7c2c85a333721ee504a46716ac55e3b06`; its export table exposes only the component initialization and error entrypoints, and its strings include XUser and repeated `not implemented, returning E_NOINTERFACE` stubs. The upstream README also states that XUser is not implemented. The candidate was not installed or used to launch a target, so it does not satisfy the required account backed Game Runtime or target title lifecycle gates. See the [release](https://github.com/Weather-OS/GDK-Proton/releases/tag/release10-32) and [upstream README](https://github.com/Weather-OS/GDK-Proton) for the source records.

No HDMI connector was exposed by the current Hyprland monitor state. HDMI resolution and refresh verification therefore remains pending until the connector is present.

No account, keychain, browser storage, package content, or protected executable was accessed during this check.

## Gate Classification

This record verifies the Tier 1 presentation baseline only. It does not close EXT-003, EXT-004, XODUS-REQ-007, XODUS-REQ-008, XODUS-REQ-010, XODUS-REQ-011, XODUS-REQ-012, XODUS-REQ-013, XODUS-REQ-015, or XODUS-REQ-016. The missing versioned runtime artifacts and absent HDMI connector are external prerequisites for the corresponding runtime and display gates.
