# Xodus service architecture

## Requirements

- Games downloaded through Xodus retain executable in encrypted form - following in Windows footsteps
- Users shouldn't need to login multiple times - auth confirmations are fine
- Steam games using Microsoft services should be able to use Xodus login
- Users want to use their launcher of preference, not another launcher. Integration should be simple

## Package transaction safety

Package segment paths are untrusted input. Before the streaming writer creates any package output, it rejects empty, absolute, drive prefixed, traversal, mixed separator, and Windows invalid or reserved path components. On Linux, output files and intermediate directories are opened relative to the transaction root with `openat2` resolution flags that forbid root escape, magic links, and symlinks. A rejected path makes the command fail and must not create a file outside the transaction root.

The Phase 2 XSP parser slice accepts only tables that begin after the fixed 860-byte header, end within the seekable input length, and declare no more than 1,048,576 fixed-size records. It returns typed header, record, I/O, count, offset, overflow, and bounds errors before allocating records or writing a filesystem path. Synthetic in-memory tests cover valid and rollback descriptors plus invalid-magic, invalid-record, truncated, interrupted-recovery, oversized-count, and before-header-offset cases.

MSIXVC parser hardening, complete integrity validation, atomic promotion, rollback policy, and transaction recovery remain Phase 2 work. The account backed Xbox Live development token test is not part of ordinary offline verification and currently requires an explicit bounded opt in.
