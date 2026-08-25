# Xodus service architecture

## Requirements

- Games downloaded through Xodus retain executable in encrypted form - following in Windows footsteps
- Users shouldn't need to login multiple times - auth confirmations are fine
- Steam games using Microsoft services should be able to use Xodus login
- Users want to use their launcher of preference, not another launcher. Integration should be simple

## Package transaction safety

Package segment paths are untrusted input. Before the streaming writer creates any package output, it rejects empty, absolute, drive prefixed, traversal, mixed separator, and Windows invalid or reserved path components. On Linux, output files and intermediate directories are opened relative to the transaction root with `openat2` resolution flags that forbid root escape, magic links, and symlinks. A rejected path makes the command fail and must not create a file outside the transaction root.

This is only the first package containment boundary. MSIXVC and XSP parser hardening, complete integrity validation, atomic promotion, rollback, and recovery remain Phase 2 work. The account backed Xbox Live development token test is not part of ordinary offline verification and currently requires an explicit bounded opt in.
