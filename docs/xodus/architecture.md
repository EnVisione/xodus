# Xodus service architecture

## Requirements

- Games downloaded through Xodus retain executable in encrypted form - following in Windows footsteps
- Users shouldn't need to login multiple times - auth confirmations are fine
- Steam games using Microsoft services should be able to use Xodus login
- Users want to use their launcher of preference, not another launcher. Integration should be simple

## Package transaction safety

Package segment paths are untrusted input. Before the streaming or download writer creates any package output, it rejects empty, absolute, drive prefixed, traversal, mixed separator, and Windows invalid or reserved path components. On Linux, output files and intermediate directories are opened relative to the selected root with `openat2` resolution flags that forbid root escape, magic links, and symlinks. A rejected path makes the command fail and must not create a file outside that root.

The Phase 2 XSP parser slice accepts only tables that begin after the fixed 860-byte header, end within the seekable input length, and declare no more than 1,048,576 fixed-size records. It rejects new-data and copy-data block ranges whose start plus count overflows before returning any entry. It returns typed header, record, I/O, count, offset, overflow, and bounds errors before allocating records or writing a filesystem path. Synthetic in-memory tests cover valid and rollback descriptors plus invalid-magic, invalid-record, truncated, interrupted-recovery, oversized-count, before-header-offset, and new-data or copy-data range-overflow cases.

XSP update preflight now validates the active content identity and source version, forward versus rollback version direction, expected source block hashes, target range ordering and bounds, copy source bounds, target hash coverage, and available disk space before a transaction can be considered eligible. A bounded in-memory apply helper copies new-data and copy-data records into a new buffer and verifies truncated SHA-256 block hashes without mutating the source image. A separate bounded async stream helper verifies every source block before writing, applies copy and new-data records one block at a time, verifies every target block, and limits its working buffer to 64 MiB. The stream helper writes to a caller-owned staging output, while atomic promotion and crash recovery remain the transaction layer's responsibility. The in-memory helper refuses outputs larger than 64 MiB, so neither helper alone proves a real title update.

The MSIXVC2 boundary inspector reads ZIP central-directory metadata without extracting package files. It rejects excessive entry counts, duplicate or unsafe paths, symbolic links, unsupported compression methods, missing required metadata, and oversized metadata entries. The bounded visitor validates that structure before rewinding, exposes each safe entry to a caller-owned sink, and drains every entry through the ZIP CRC checker under a caller-supplied uncompressed-size limit, so callers cannot bypass the path and metadata boundary by invoking verification or visiting entries directly. The offline CLI `inspect` command exposes the metadata check without initializing device credentials. This establishes safe archive inspection and corruption evidence for the owned fixtures, but it does not yet install or decrypt retail MSIXVC2 content.

The XVD parser returns a typed I/O failure when a metadata-directed seek to XVC information fails. It rejects XVC information versions above 2 with a typed error before reading region headers, preserves the existing version 0 no-region behavior, and rejects an XVC region count above 4,096 before it reads region headers or reserves their vector. It rejects an unsupported encrypted XVC key ID with a typed error rather than aborting, rejects an encrypted region offset below the computed user-data base before subtraction, checks encrypted-region end arithmetic before page calculation, and uses checked page-count conversion with fallible reservations for encrypted-region data units and hashes. Its regression tests use only in-memory synthetic XVD headers and metadata, including a reader that fails the seek, an unsupported information version, an oversized region-count layout, supported and unsupported key-ID layouts, a below-base region offset, an overflowing region end, and an unreservable maximal region length. They prove propagation and bounded region parsing without inspecting a package or mutating the filesystem. The XVD virtual stream also validates its current cursor against the virtual extent, bounds each read by the remaining extent, rejects overreported counts, and verifies the post-read cursor before returning success.

XVD header layout arithmetic is calculated once through a checked layout object before any metadata-directed seek. Page-to-byte conversion, metadata and hashed-page accumulation, hash-tree depth, resilient page counts, and each derived offset return typed arithmetic failures. Hash-tree block lookup also rejects unsupported XVD types, invalid levels, depth underflow, and checked result overflow. An adversarial maximum drive-size header is rejected before the XVC information seek, and valid sector conversions retain their normal values.

The HTTP reader validates pending chunk offsets before slicing, uses checked arithmetic for logical and active stream positions, rejects received data beyond the declared response extent or total length, and requires resumed responses to preserve the requested start and original total length. Partial responses must also report a content length matching the inclusive content range. Transport failures and short streams consume a three-attempt reader-wide retry budget, while nonretryable range and extent failures return immediately; exhaustion returns a typed retry or premature-EOF error. These checks return typed errors before the reader exposes an invalid position or extent.

The XVD HTTP download path requires partial-content responses with an exact inclusive Content-Range, a stable total length across reconnects, and a matching Content-Length before activating a stream. Transport failures, timeouts, empty chunks, and short streams use one bounded download-wide retry budget; invalid status, range, total, and length metadata fail immediately. Received body bytes cannot exceed the aligned page span, and retry exhaustion returns a typed error before output promotion.

When a segment carries data-integrity hashes, both HTTP download and local extraction verify the complete encrypted 4 KiB page against the first 20 bytes of its SHA-256 digest before decryption or output writes. Missing hash entries and mismatches return typed errors, so an unverified page cannot be promoted. Segments without an integrity table retain the format's explicit no-hash behavior.

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

The in-memory token backend now reports poisoned mutex state as a typed storage error. Expired entries are removed on read, and neither expiry handling nor lock poisoning uses an unchecked mutex operation.

License acquisition and CIK export now propagate token, exchange, entitlement, SPLicense, key derivation, directory, file, and flush failures with nonzero command results. CIK paths are joined beneath the requested export directory and existing files are truncated before replacement.

Content license responses now require a successful HTTP status, a nonempty key list, valid base64, valid UTF-8, and valid license XML. Malformed or incomplete service data returns typed `LicenseContentError` variants instead of indexing or decoding through unchecked operations.

SP license key derivation now rejects unsupported key versions and device-key mismatches through `SpLicenseKeyError`. CLEP signing and HMAC state extraction propagate the same typed version failure through device reauthentication and live token exchange, while the CLI reports derivation failures as nonzero results. Unsupported key material is never accepted through an assertion or unchecked slice conversion.

The service IPC boundary now enforces a 60 KiB payload limit before allocation, rejects unknown message types instead of defaulting them, emits stable machine-readable error codes with XML-escaped text for malformed or unsupported requests, and returns `PONG` or `MSA_TOKEN_RESPONSE` only for recognized operations. The protobuf handler supports bounded ping responses and explicit unsupported-operation responses instead of reaching an unimplemented branch. Socket startup removes only an existing socket owned by the runtime-directory user, refuses regular files or other-user paths, and each accepted peer must match that user identity. Raw XML request buffers and verbose HTTP connection logging are not emitted, and failed device or user token exchanges no longer become empty successful responses.

Packed content key unwrapping now maps authentication, invalid wrapped-key states, and unexpected output lengths to explicit typed errors. Key-wrap library variants are no longer treated as unreachable process paths.

The legacy package download command now rejects missing CDN roots, malformed or non-HTTPS CDN URLs, credential-bearing URLs, and invalid sizes, checks HTTP status, and returns failure for output creation, stream, and write errors instead of reporting success after a partial operation or panicking on service data.

The CLI run and streaming commands now report path, parser, cache, license, key-unpack, extraction, descriptor, process, and promotion failures as nonzero results. Endpoint selection rejects malformed globs and hostless URLs without panicking. The streaming, direct download, and local run paths reject unsafe package names and open package files relative to a rooted no-symlink descriptor. Package CDN URLs are parsed centrally and require HTTPS, a host, and no user information. The streaming path also rejects missing CDN roots, overflowing package totals, unsafe path shortening, and invalid local cache metadata.

Completed segment files and the package cache are synchronized before promotion. Each streaming run writes the cache and changed sidecars beneath a unique transaction directory, records staged, backed-up, and promoted states in a synchronized journal, and promotes them only after all extraction or download work succeeds. Existing package files are backed up before replacement, and a failed promotion or a discovered interrupted transaction restores the prior files. Remote page hashes are preserved through job construction so nonempty hash tables reach the downloader and extractor. Crash injection, stale-sidecar removal, and full update workflow coverage remain Phase 2 work.

Complete MSIXVC integrity coverage, crash injection, stale-sidecar removal, the full rollback policy, and complete update workflow coverage remain Phase 2 work. The account backed Xbox Live development token test is not part of ordinary offline verification and currently requires an explicit bounded opt in.
