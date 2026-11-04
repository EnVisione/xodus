<p align="center"><img width="128" src="assets/Icon/Icon.ico" /></p>
<h1 align="center">Xodus</h1>
<p align="center">The great gaming migration to Linux</p>
<p align="center">
    <a href="https://discord.gg/ZG774FK4tq">
        <img src="https://img.shields.io/discord/1123890623586504714?logo=discord&style=for-the-badge&color=red&label=Game+Launchers+Reverse+Engineering" alt="Discord" />
    </a>
</p>

> [!CAUTION]
> This is an unofficial project - use at your own risk. It is not affiliated with, endorsed by, or sponsored by Microsoft or XBOX; all trademarks, product names, and company names or logos mentioned herein are the property of their respective owners.

## Current state of the project

The project can now login, download packages and obtain licenses for games.

The CLI can also install an owned, validated local MSIXVC2 fixture archive through a journaled transaction. Retail encrypted package execution and game lifecycle support remain incomplete.

These parts are still quite scattered arround.

- [x] Device login
- [x] User login
- [x] XBOX authorization
- [x] MSIXVC download
- [x] On-demand .exe decryption [#50](https://github.com/xodus-gaming/xodus/issues/50)
- [ ] MSIXVC2 support [#53](https://github.com/xodus-gaming/xodus/issues/53)

## FAQ

**Q: What is Xodus**  
Xodus aims to bring XBOX PC games to Linux and possibly Mac devices.

**Q: When can I play my Minecraft Bedrock?**  
While Xodus is quickly maturing, there is still a lot of work to support it from Wine standpoint to provide necessary XBOX Services to games.  
_TL;DR_ soon<sup>tm</sup>

**Q: How to get involved?**  
Start by joining our Discord or review any open GitHub issues .

**Q: What games will be supported?**  
We hope to manage to support most of the catalog, the limitation is the game has to be GDK and in MSIXVC format.  
So far `Gears of War 4` is a prominent unsupported title for the time being.

**Q: Will XBOX Backward Compatibility on PC work?**  
While Xodus is capable of downloading and running those titles. It's possible these games will work only after additional patches to wine, dxvk or vkd3d-proton.

## Building

The project structure is as follows.

```
.
├── msixvc - [rlib] common rlib crate for utilities for parsing MSIXVC and XSP files
├── xodus - [rlib] common rlib crate that contains core xodus functionality, API calls abstractions and utilities
├── xodus-cli - [bin] CLI currently used for iterating over new xodus features
└── xodus-service - [bin] service process exposing a xodus.sock for IPC communication, it takes care of xgameruntime.dll integration.
```

> [!NOTE]
> xodus-service aims to become a main point of integration. All xodus clients will connect to it to interact with games and XBOX services.

### Prerequisites

- Rust version 1.98 or later
- Right now CLI relies on wry and tao to show a login page. Consult https://docs.rs/wry/latest/wry/#platform-considerations
- xodus-service relies on `protoc` to compile `proto/` definitions make sure to install it for your platform

### Running

Building all crates in release mode

```bash
cargo build --release --workspace
```

Running cli in debug

```
cargo run -- --help
```

Running xodus-service in debug

```
cargo run --bin xodus-service
```

### Verification

The repository dependency policy is checked with cargo deny. It validates the allowed license and source set, duplicate dependency review, and the reviewed GTK3 advisory exceptions. The XAL authentication library is vendored from the audited upstream commit and uses the maintained OAuth2 and Reqwest transport stack.

```bash
cargo fmt --all --check
cargo deny --all-features check
```

Run `cargo audit` separately when refreshing the advisory database. Its remaining findings must be checked against the GTK3 desktop dependency path recorded in `deny.toml` before a release is accepted.

> [!WARNING]
> For better performance when decrypting MSIXVC files, the `aes` and `ssse3` features are enabled on `x86_64`,
> and the `aes` feature is enabled on `aarch64`. This means that the program will crash with an illegal instruction
> error when running on a CPU which doesn't support those instructions.
>
> See https://en.wikipedia.org/wiki/AES_instruction_set for a list of compatible CPUs (every processor from
> 2011 onwards should be supported).

### CLI Usage

```
Usage: xodus-cli <COMMAND>

Commands:
  download    Download msixvc or xsp files fo given game
  license     Dump CIKs for use with XvdTool
  extract     Extract locally stored msixvc file
  inspect     Inspect a local MSIXVC2 archive without extracting it
  install-msixvc2  Install a validated local MSIXVC2 archive transactionally
  repair-msixvc2  Repair a local MSIXVC2 archive transactionally
  uninstall-msixvc2  Uninstall files represented by a local MSIXVC2 archive transactionally
  login       
  streaming   Download and extract the game through streaming algorithm
  clep        Generate or decrypt base64-encoded CLEP challenge data
  sp-license  Validate SPLicenseBlock key material
  help        Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
      --transaction-window  Open a native status window after a package operation
```

`--transaction-window` is opt-in and opens a local status window after a supported package command returns. It reports the final outcome rather than live progress, and a window error does not replace the command exit status. It supports `download` when `--dry-run` is not set, `extract`, `install-msixvc2`, `repair-msixvc2`, `uninstall-msixvc2`, `apply-xsp`, `apply-xsp-packages`, and `streaming`. The global option can appear before or after the subcommand.

Pressing `Ctrl+C` during `download`, `streaming`, `install-msixvc2`, `repair-msixvc2`, or `apply-xsp` cancels work before promotion and normally returns exit status `130`. If rollback cannot restore the prior package state, the quarantined outcome takes precedence: the command returns `76` and retains the recovery journal. Transaction results use `0` for success and `1` for ordinary failure; `74` means a failed operation was rolled back and the prior package state was restored; `75` means a failed download left a nonempty, durably synchronized partial eligible for a later resume; and `76` means rollback did not complete and the journaled recovery transaction was retained. A later operation attempts recovery first and fails closed if the retained transaction is still unrecoverable. A download retains a hidden partial only when its transfer identity is tied to an authenticated provider hash or a pinned signed XVD identity and expected package identity. The fixed size sidecar stores the transfer identity digest and declared size, not the URL or credentials. A later invocation checks that identity, hashes the partial again, and accepts only a matching byte range response. Before atomic promotion, the transfer must satisfy the applicable provider hash and package signature checks; direct HTTPS with certificate and host validation also authenticates the response in transit. An `.msixvc` from an approved Xbox HTTP endpoint on port 80 is accepted only when authenticated service metadata selects its identity and the pinned Microsoft retail XVD key verifies the complete 12 KiB signed header, exact extent, and every hash tree page before promotion, with no embedded or mutable unsigned region. If the XVD contains mutable unsigned data, `download` accepts it only when the final response uses HTTPS with certificate and host validation from an approved Xbox CDN host under the redirect policy. Approved HTTP provides XVD integrity, not transport confidentiality. An XSP descriptor may be fetched over approved HTTP only as untrusted transform input. MSIXVC2 requires an authenticated native package root or direct HTTPS with certificate and host validation to the endpoint selected by service metadata. The local Xodus package catalog records sanitized metadata and the locally computed complete file digest only after transfer authentication; that digest never authorizes first use. Until promotion succeeds, the last verified file remains active. Other staging that is not committed is cleaned; an atomic promotion already in progress finishes and reports its actual result.

## Special Thanks

- [XvdTool.Streaming](https://github.com/LukeFZ/XvdTool.Streaming) and [CikExtractor](https://github.com/LukeFZ/CikExtractor) by LukeFZ
