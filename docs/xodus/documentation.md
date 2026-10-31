# Xodus package libraries

The `msixvc-common` library parses a Package Resource Index through `resources::pri::Pri`. The input stream is limited to 16 MiB. Hierarchical names and paths have additional limits to bound memory and traversal. Malformed or oversized data returns a parsing error. Resource lookup and qualifier explanations operate on the parsed index.

The `msixvc` library exposes page and byte types, a hash tree stream, and an XVD layout view. `XvdHeader::layout` validates the existing checked header layout before constructing the view. It rejects unsupported integrity-disabled or resilient layouts and page counts outside the supported range. The hash tree stream checks the supplied hash count before reading and terminates on read or integrity errors without exposing entries from a failed page.

The `PinnedXvdKey` library type checks an RSA public key blob against a caller supplied SHA-256 fingerprint and verifies the first XVD page using RSA-PSS with SHA-256. The caller must obtain the fingerprint from an independent trusted source. Signature verification alone does not validate the package identity, the remaining hash tree, or update descriptors. Existing download and installation paths do not yet use this verifier and do not gain a new transport option from it.

The local EAppx extraction command is not available. The upstream extractor writes package-supplied paths directly and needs path containment, integrity, protected executable handling, and transactional output before it can be safely exposed here. Existing MSIXVC2 fixture commands and their limitations remain unchanged.

Xbox user authentication accepts newer compact encrypted delegation tickets by selecting the ticket prefix expected by the Xbox user authentication endpoint. Opaque and signed-only tickets retain their existing representation, and the stored session and other service endpoints are unchanged.
