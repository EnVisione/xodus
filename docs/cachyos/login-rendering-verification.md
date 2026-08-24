# Login Rendering Verification

## Scope

This record covers only the owner directed repair for a blank Xodus CLI login surface on the Tier 1 CachyOS, Hyprland, and NVIDIA session. It does not prove Microsoft authentication, entitlement, licensing, package access, runtime compatibility, or game execution.

The existing CLI device credential lifecycle runs before the login UI and is outside this maintenance change. The renderer fallback adds no account, token, or keyring operation of its own.

## Observed Failure

The existing `xodus-cli login` command created an XWayland window titled `Xodus login`, but its WebKitGTK content was blank. The process reported a GBM allocation failure with `Invalid argument`. The application used the NVIDIA dmabuf renderer path through the Hyprland session.

## Fix

`crates/xodus-cli/src/webview.rs` now selects `WEBKIT_DISABLE_DMABUF_RENDERER=1` only before a Linux WebKitGTK webview starts when all of these conditions are true:

1. The process has no existing `WEBKIT_DISABLE_DMABUF_RENDERER` value.
2. The session exposes `WAYLAND_DISPLAY`.
3. `/proc/driver/nvidia/version` identifies an installed NVIDIA driver.

The setting is process local. It leaves Hyprland, shell profiles, system environment files, NVIDIA settings, game presentation, and explicit user renderer choices unchanged.

## Verification

- Ran the original release binary without the renderer setting. The login window was blank and emitted the NVIDIA GBM allocation error.
- Ran the same binary with `WEBKIT_DISABLE_DMABUF_RENDERER=1`. The Microsoft sign in page rendered at the 200 percent desktop scale without the GBM error. No credential was submitted and no user account sign in was completed.
- Built the updated workspace release binary. The renderer selection predicate passed four Linux unit cases for the intended fallback, explicit override, non Wayland, and no NVIDIA conditions.
- Started the updated release binary with no preexisting renderer setting. The `Xodus login` XWayland window remained mapped and visible for the check interval with no GBM allocation error. It was then dismissed without interaction.
- Ran `cargo fmt --check --all`, `cargo check --workspace --all-targets`, `cargo test --workspace --all-targets --no-run`, the offline workspace tests with account backed tests skipped, and `cargo build --release --workspace`. All passed.
- Ran `cargo clippy --workspace --all-targets --all-features`. It passed with the four preexisting warnings recorded by the Phase 001 baseline. This maintenance change added no new warning.
- Ran `scripts/cachyos/verify-baseline.sh --source`. It correctly rejected this branch because the source sensitive CLI path now differs from the frozen Phase 001 baseline. The Phase 001 baseline remains historical evidence and cannot authorize the changed source.

The visual check was performed without retaining or committing the runtime screenshot because a login surface can contain account identifying information.

## Recovery

If an operator needs a different WebKitGTK renderer policy, setting `WEBKIT_DISABLE_DMABUF_RENDERER` before launching Xodus prevents the CLI from changing it. Future platform work must compare native Wayland and XWayland login paths with the final runtime profile.
