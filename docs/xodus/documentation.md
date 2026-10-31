# Xodus package libraries

The `msixvc-common` library parses a Package Resource Index through `resources::pri::Pri`. The input stream is limited to 16 MiB. Hierarchical names and paths have additional limits to bound memory and traversal. Malformed or oversized data returns a parsing error. Resource lookup and qualifier explanations operate on the parsed index.

The `msixvc` library exposes page and byte types, a hash tree stream, and an XVD layout view. `XvdHeader::layout` validates the existing checked header layout before constructing the view. It rejects unsupported integrity-disabled or resilient layouts and page counts outside the supported range. The hash tree stream checks the supplied hash count before reading.

The local EAppx extraction command is not available. The upstream extractor writes package-supplied paths directly and needs path containment, integrity, protected executable handling, and transactional output before it can be safely exposed here. Existing MSIXVC2 fixture commands and their limitations remain unchanged.
