# Xodus service architecture

## Requirements

- Games downloaded through Xodus retain executable in encrypted form - following in Windows footsteps
- Users shouldn't need to login multiple times - auth confirmations are fine
- Steam games using Microsoft services should be able to use Xodus login
- Users want to use their launcher of preference, not another launcher. Integration should be simple

## Package transaction safety

Package segment paths are untrusted input. Before the streaming writer creates any package output, it rejects empty, absolute, drive prefixed, traversal, mixed separator, and Windows invalid or reserved path components. On Linux, output files and intermediate directories are opened relative to the transaction root with `openat2` resolution flags that forbid root escape, magic links, and symlinks. A rejected path makes the command fail and must not create a file outside the transaction root.

The Phase 2 XSP parser slice accepts only tables that begin after the fixed 860-byte header, end within the seekable input length, and declare no more than 1,048,576 fixed-size records. It returns typed header, record, I/O, count, offset, overflow, and bounds errors before allocating records or writing a filesystem path. Synthetic in-memory tests cover valid and rollback descriptors plus invalid-magic, invalid-record, truncated, interrupted-recovery, oversized-count, and before-header-offset cases.

The XVD parser returns a typed I/O failure when a metadata-directed seek to XVC information fails. It rejects an XVC region count above 4,096 with a typed error before it reads region headers or reserves their vector, rejects an unsupported encrypted XVC key ID with a typed error rather than aborting, rejects an encrypted region offset below the computed user-data base before subtraction, checks encrypted-region end arithmetic before page calculation, and uses checked page-count conversion with fallible reservations for encrypted-region data units and hashes. Its regression tests use only in-memory synthetic XVD headers and metadata, including a reader that fails the seek, an oversized region-count layout, supported and unsupported key-ID layouts, a below-base region offset, an overflowing region end, and an unreservable maximal region length. They prove propagation and bounded region parsing without inspecting a package or mutating the filesystem. The XVD virtual stream also validates its current cursor against the virtual extent, bounds each read by the remaining extent, rejects overreported counts, and verifies the post-read cursor before returning success.

MSIXVC parser hardening, complete integrity validation, atomic promotion, rollback policy, and transaction recovery remain Phase 2 work. The account backed Xbox Live development token test is not part of ordinary offline verification and currently requires an explicit bounded opt in.
