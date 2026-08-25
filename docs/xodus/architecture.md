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

The HTTP reader validates pending chunk offsets before slicing, uses checked arithmetic for logical and active stream positions, rejects received data beyond the declared response extent or total length, and requires resumed responses to preserve the requested start and original total length. Partial responses must also report a content length matching the inclusive content range. Transport failures and short streams consume a three-attempt reader-wide retry budget, while nonretryable range and extent failures return immediately; exhaustion returns a typed retry or premature-EOF error. These checks return typed errors before the reader exposes an invalid position or extent.

The XVD HTTP download path requires partial-content responses with an exact inclusive Content-Range, a stable total length across reconnects, and a matching Content-Length before activating a stream. Transport failures, timeouts, empty chunks, and short streams use one bounded download-wide retry budget; invalid status, range, total, and length metadata fail immediately. Received body bytes cannot exceed the aligned page span, and retry exhaustion returns a typed error before output promotion.

The shared binary parser now builds nested generic-array chunk references through checked slice bounds instead of an unsafe layout transmute. A nested-array regression proves that the parser preserves chunk order and rejects no valid fixed-size input while keeping the type-level reader extent contract.

Xbox package authentication now propagates token, exchange, HTTP status, JSON, unsupported-response, empty-collection, and missing-user-claim failures as typed results. It no longer panics on a malformed or incomplete service response before package metadata access.

SOAP passport token conversion now returns typed failures for missing encrypted legacy data, missing compact binary data, unsupported token types, and legacy serialization errors. Device, Xbox, refresh, login, and license callers propagate or report these failures before storing or using a token. Empty refresh collections also fail explicitly instead of indexing an absent response.

Device and user token exchange now validates the stored binary secret before constructing the fixed-size signing state. Missing, undecodable, and non-4096-byte secrets return typed RST failures before signing or network activity. The service path also reports missing device state and unsupported or empty exchange responses instead of panicking or using a placeholder.

Device credential provisioning now propagates request serialization, HTTP status, transport, response-body, and XML deserialization failures. Provisioning logs the typed failure and stops without persisting a partial device record.

The BCrypt RSA private-key parser now validates magic, component extents, prime factors, modular inversion, and RSA construction through typed errors. Malformed persisted key blocks are rejected before slicing or signing, and device reauthentication logs the failure without aborting the service.

SOAP key-info conversion now returns typed errors for missing key names or security-token references. Encrypted response handling validates reference prefixes and IV length, maps decryption and UTF 8 failures, and parses only the authenticated padded plaintext instead of indexing or unwrapping malformed data.

Shared-key derivation now rejects empty secrets, unsupported output lengths, and checked length arithmetic failures through typed errors. HMAC signing and encrypted response handling propagate those failures without indexing or unwrapping invalid key material.

The service startup path now returns typed initialization, token, runtime-directory, socket, permission, accept, and cleanup failures. Per-connection request-client construction also reports errors and closes the connection without a process panic.

The login command now reports missing or wrong device token state, webview startup errors, unsupported response bodies, and user persistence failures through explicit exit paths. Native webview creation also validates the GTK container and propagates builder errors for Wayland and XWayland sessions.

The CLI startup now reports HTTP client and credential-store initialization failures through a nonzero exit code instead of panicking before command dispatch.

Linux SMBIOS probing now validates the raw header length, UUID extent, string-table bounds, and version or serial indexes. Malformed firmware data falls back to the existing component error markers instead of panicking during device provisioning.

The legacy package download command now rejects missing CDN roots and invalid sizes, checks HTTP status, and returns failure for output creation, stream, and write errors instead of reporting success after a partial operation or panicking on service data.

MSIXVC parser hardening, complete integrity validation, atomic promotion, rollback policy, and transaction recovery remain Phase 2 work. The account backed Xbox Live development token test is not part of ordinary offline verification and currently requires an explicit bounded opt in.
