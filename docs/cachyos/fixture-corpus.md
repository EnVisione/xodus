# MSIXVC2 Fixture Corpus

**Status:** PARTIAL

This record freezes the first owned MSIXVC2 fixtures for XODUS-REQ-002 through XODUS-REQ-004. It is evidence of controlled package generation, not a claim that the fixtures are Microsoft Store ready, installable on a retail system, or a substitute for a real title lifecycle.

## Authorization and Provenance

The owner explicitly authorized fixture creation, retention, and publication on August 24, 2026. That assertion authorizes this corpus work. It does not place Microsoft GDK components, account data, title content, content keys, decrypted executables, or signed download URLs into the repository.

The fixture producer was the official [Microsoft GDK April 2026 Update 3 release](https://github.com/microsoft/GDK/releases/tag/April-2026-Update-3-v2604.3.7874), archive `GDK_2604.3.7874.zip`, 1,311,966,126 bytes.

| Artifact | SHA-256 | SHA-512 |
| --- | --- | --- |
| GDK archive, not tracked | `3610ab593dfe8a382e3750400b5c060435c775a9c358b8a9f85a513a0e4c6158` | `89a80b2960dd46f11934892d83db91cf7465bc9ec0ae0d8be5b37cd61e0b7c2628c67173659230efc62470d95f4791252663b5b86d4e697c1a0970c0434fdfc5` |

Only the GDK common packaging component was administratively extracted to a disposable isolated Wine prefix. The invoked producer was `makepkg2.exe` version `2604.407.20000.0`. The prefix and all untracked GDK material are outside this repository and must be removed after the source, fixture, and manifest verification steps complete.

## Source Construction

Each fixture uses only project owned synthetic inputs:

- A minimal x64 PE fixture executable built from a single local entry point.
- Four locally generated opaque RGBA PNG shell assets at the dimensions required by `MicrosoftGame.config`.
- A minimal `MicrosoftGame.config` using a synthetic identity.
- A base text payload and an update payload differing by one line.

`makepkg2 pack /msixvc2` created the base package. The update package used the base package through `/priorpackage`, producing the producer's update comparison report. The source content did not contain Microsoft title content or any GDK binary.

The XSP fixtures are separately authored byte layouts for the current Xodus `XspHeader` and `XspPatchRecord` parser. They use fixed synthetic identifiers, one new data record, and one copy data record. They do not claim to be a captured title update or replace an authorized real XSP exercise.

## Tracked Fixtures

| File | Role | SHA-256 | SHA-512 |
| --- | --- | --- | --- |
| `crates/msixvc/testdata/msixvc2/xodus-fixture-base.msixvc` | Generated MSIXVC2 base package | `5d484eb68d1ab7ae7936e0a0f6b7c8a53c93c38cc088c44992a0fe2cb8b95cbe` | `991cfdd87c9d164a8762e2fedc57e724c294f81028bd9c2dfb1a8a6814a9af7be2fef7c851c0d2d96e8bd6a0541b7153898d3b2ab0917052b460297af856ed22` |
| `crates/msixvc/testdata/msixvc2/xodus-fixture-update.msixvc` | Generated MSIXVC2 update candidate with `/priorpackage` comparison evidence | `f4233cd546a4d9a1bd588520dea7f986b7ee6e1dd7f39acb4b60d0484cabd0f6` | `f255c52d7b903b3664b082a85c21d996ac3ff87942d7c737eed041b018ade09f31e35b5bfd249aed30b849e417b4a039738cda5f9b8ba9e01820300bf23b1b45` |
| `crates/msixvc/testdata/msixvc2/xodus-fixture-truncated.msixvc` | First 4,096 bytes of the owned base package, expected archive truncation failure | `c3c2db6307d2cde576ea5e046384515b8e93eff5b966e40b4494de6510bcbc78` | `6e9e08ef9bb71ffdaf76bba78945924de1b4533337868984bef4186c101845c74f5f5bbb9b92f8c6f635d15c436b78285f29ed2e4968691b164ef8ebd215e9d2` |
| `crates/msixvc/testdata/msixvc2/xodus-fixture-integrity-mismatch.msixvc` | Owned base package with one stored fixture byte changed, expected ZIP CRC mismatch | `0c454376bfcca5b6d855f200fddb2506c75f7e6bd11c231f22a4416db8c5e76f` | `aad33ae153c9ce7f11b3b253c1242bb73d5df06fd3449680459216980dcf6836f32119ba5ab93f9987065532c911216ff6f56ffe9c57d480319c4e4ff0163649` |
| `crates/msixvc/testdata/msixvc2/xodus-fixture-adversarial-path.msixvc` | Tiny owned ZIP carrier whose only member is `../escape.txt`, expected containment rejection | `a484df97196814ca2feff3cf273eb4a576e3888347f9fef42257bbb6bbf6b325` | `822f4af0b5c3a07062e600a85a37c0f5f74e6d0cbc634d9a3566a421291124428f174c076677b223b918423aec2ea02f804305923fe05ed0bdf0b6a16d490197` |
| `crates/msixvc/testdata/xsp/xodus-fixture-valid.xsp` | Parser valid header with one new data and one copy data record | `0777950c130d53b888cce54ea6172d0f9af63ccca1611b6a06ed34733879d7ba` | `3dd58347909c3f9335221d35ed76251b3c5636a37707387eb07ce66671b81cc252be50312e844a6b7400698fbd9701bfb1293c73000ffb6fc8aeba17bec8e724` |
| `crates/msixvc/testdata/xsp/xodus-fixture-invalid-magic.xsp` | Header magic rejection | `694b7d4fb8208955e843d619c69a14e3fcc57352d76c49dc62bb4f573514da45` | `cf008715b63e9980dd1f4976b710d44a4789876faa8596e0b33924fd1619cba60d81f975a716bbe08f5baa32ecbae0e9b66841a7f66a30747af24010d4c73c87` |
| `crates/msixvc/testdata/xsp/xodus-fixture-invalid-record.xsp` | Unknown patch record flag rejection | `62873b898a3d3e375430a39fe6a54a645ae59abfb824e414ebf58cb8b2163fb9` | `71d83f4ec7ecc6558e57b35b21341dd39ca53c565a0be908b38b9b3b1a231a881be74d2915b2448b57e2daef63157e08d08dbd4d5b2e17c49498781af7c4ac66` |
| `crates/msixvc/testdata/xsp/xodus-fixture-truncated.xsp` | Header truncation rejection | `04f9eaecdff0b76a65002f829dfc8caa0a200ad1fd946f8a2be374378f4bddc1` | `4ad80b32862b0d84378671bde8b0b0a42f90317cbb03f7c4d748ab92710032d63b58cdf28a41feaa228660e4f863284d99efc0b2ab147df2b6d468f633a37656` |

Both packages are ZIP based MSIXVC2 package containers. Their visible package members are only generated metadata, signatures, chunk maps, and encrypted fixture boxes. Review found no title identity, Microsoft title content, GDK component, credential, content key, or decrypted executable. The generated `.ekb` files are local content key material and are intentionally excluded.

## Verification Record

- `makepkg2 genmap` generated a layout for each source directory.
- `makepkg2 pack /msixvc2 /pc` completed successfully for the base and update candidate.
- The update comparison reported 14.070 KB downloaded and 1.779 KB preserved from a 15.850 KB total package size.
- The GDK Submission Validator accepted the synthetic executable and corrected RGBA assets, but reported expected preview authorization and resolver limitations. It also noted the intentionally skipped symbol bundling and missing optional `Resources.pri`. These diagnostics mean the packages are not certification evidence.
- The truncated fixture fails ZIP validation because its end-of-central-directory record is absent. The integrity fixture fails ZIP validation with a CRC mismatch. The adversarial-path carrier passes structural ZIP validation and inventories exactly one intentionally unsafe member path, `../escape.txt`.
- `unzip -Z1` was used to inventory package members, and byte scans found no prohibited title, credential, key, or GDK component strings.
- An isolated clean Cargo harness invoked the current `XspFile::parse_file` implementation. It accepted the valid XSP fixture with the expected two records and rejected the bad magic, bad record, and truncated variants.

## Security Review

The August 24, 2026 containment review covered all nine tracked fixture files without reading or retaining any Secret Service value, package key, or title package. The two valid MSIXVC2 archives passed `unzip -tqq`; the deliberately truncated and integrity-mismatch archives were rejected as expected. Their member names contain no absolute path, parent traversal, drive prefix, backslash path, or `.ekb` entry, except for the dedicated adversarial-path fixture whose sole `../escape.txt` member is documented above and must never be extracted. Their uncompressed payloads are small generated metadata and fixture boxes, not an archive expansion hazard.

Static scans found no bearer authorization value, XBL authorization form, password, client secret, access token, refresh token, content key, or `.ekb` marker. The only URL-like strings are fixed OpenXML, W3C XML signature, and `xbox.com/MSIXVC2` namespace identifiers. They are package format schema identifiers, not endpoints or signed download URLs.

This review confirms containment of the tracked corpus. It does not certify the current package parsers or transaction paths. A bounded remote XVD inspection also confirmed that the current parser can panic on a failed seek; that independent Phase 2 defect is tracked in [issue 9](https://github.com/EnVisione/xodus/issues/9). The corpus has no repository test consumers yet, so Phase 2 must add them before format or transaction safety can be claimed.

## Remaining Work

EXT-009 remains partial. The containment security review is complete, and the corpus now has deterministic malformed, truncated, adversarial-path, and integrity MSIXVC2 variants. Before it can become available, it still needs XSP update rollback and recovery cases plus a final provenance and security review of the completed entry set. Repository test coverage that consumes each artifact is XODUS-PHASE-002 implementation and exit evidence. A real authorized package exercise remains mandatory evidence for XODUS-REQ-004 and cannot be replaced by these synthetic fixtures.
