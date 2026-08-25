Objective:
Complete every mandatory requirement XODUS-REQ-001 through XODUS-REQ-022 and every stable-release gate, excluding optional and future work; Phase 2 continues with XODUS-REQ-002 parser hardening. Successful completion is permitted only when runtime verification passes, artifacts are bound to the authoritative default-branch commit, every evidence gate passes, and the final plan-wide audit finds no known mandatory repository-owned defect.

Immediate checkpoint:
Refresh and inspect `origin` without altering the remote. Verify `origin` is the intended repository; fetch `origin` without altering the remote; verify the fetched remote-tracking ref against the current remote default-branch head. Classify the local default branch as equal, behind, ahead, or diverged; fast-forward only when safe. Do not reset, force, discard, or overwrite unexpected history. Search local branches, remote branches, and repository-wide open pull requests; resume applicable work, otherwise branch from the verified authoritative baseline. Do not invent a branch while an applicable active branch exists. Create or resume an implementation branch before modifying tracked files.

SRC-024 through SRC-038 remain valid. SRC-038 typed table bounds and fallible reservation; its `u32::MAX` fixture read only the 100-byte header. Phase 2 and XODUS-REQ-002 remain open; the excluded account test prevents an unfiltered-suite claim. Next harden `parse_user_package_files`: derive the package-files header offset and count-derived table end with checked arithmetic, validate the table against the declared XVD user-data extent before entry reads, and return typed failures. Prove overflowing header offsets or oversized counts read no entries and insert no map records using deterministic in-memory evidence and no filesystem mutation. Defer per-entry payload offset and length validation, segment path arithmetic, hash-slice bounds, and downstream boundaries. No title-package, download, stream, secret-store, package-content, or runtime work. Do not begin XODUS-REQ-003 or Phase 3 until XODUS-REQ-002 closes.

Perform one bounded inspection that ends as soon as each mandatory criterion is classified as implemented with valid evidence, incomplete, stale evidence, or externally blocked. Immediately execute the first incomplete or stale-evidence criterion. The map is not a deliverable: do not stop after producing it, do not rebuild it while unchanged evidence remains valid, and do not produce a narrative audit before implementation.

Authoritative plan:
/home/envy/Documents/Codex/2026-08-20/ca/work/xodus/docs/cachyos/plan.md
Plan SHA-256: 709c56070de9f3234308e4d3fcff03d740bffd2a8b21cd094f3ba27a95e491ce
Validated handoff plan-set SHA-256: 2e08bc4b9c5c7eab5918c97cfe9d02addd222334872bcc1a93ef262a608633a2
Completion endpoint: Xodus stable release is complete only when the signed public CachyOS release and repository local PKGBUILD install on the Tier 1 Lenovo Legion 9 18IAX10, Minecraft for Windows and Forza Horizon 5 each pass the authorized local login, entitlement, license, clean install, update, two consecutive launch, runtime, save, shutdown, repair, and uninstall workflows, Forza passes both absolute performance profiles, Tier 2 compatibility gates pass, MSIXVC2 and XSP update support pass, unsupported anti cheat titles hand off separately to Xbox cloud gaming, all mandatory security, recovery, documentation, and release evidence passes, and no cloud result substitutes for either local target.

Observed checkout branch: envy/target-metadata-evidence
Observed checkout commit: b82973a02b4b59c86abcb0d765affc02ffe78bd2
Repository root: /home/envy/Documents/Codex/2026-08-20/ca/work/xodus

Authoritative remote:
origin
https://github.com/EnVisione/xodus.git

Observed local default branch: main
Observed local default-branch commit: 5b77e06eaa5e3cea78af122436d35a9b02992834
Observed local remote-tracking ref: origin/main
Observed local remote-tracking commit: 5b77e06eaa5e3cea78af122436d35a9b02992834
Current remote default-branch head: 5b77e06eaa5e3cea78af122436d35a9b02992834
Remote-head evidence: git ls-remote read-only query observed 2026-08-25 at 05:25:58Z, corroborated by gh repo view EnVisione/xodus defaultBranchRef main
Authoritative working baseline: established
Applicable implementation branch: envy/target-metadata-evidence
Applicable open pull request: none identified at checkpoint

Verify that the plan, repository identity, package metadata, and remote describe the same project. Never switch revisions silently.

Execution behavior:
Inspect, implement, test, audit, fix, verify, integrate when required, verify resulting state, and continue through every remaining mandatory requirement. Protect valid evidence until regression. Execute Phase 2 without stacking; after integration, execute later phases sequentially as prerequisites permit. For each defect, preserve evidence, fix the smallest root cause, add regression coverage, rerun affected gates, inspect adjacent behavior, and continue.

Reuse evidence only while affected code, dependencies, configuration, environment, schemas, fixtures, and paths remain unchanged; otherwise mark it stale. Documentation changes do not substitute for implementation. Do not modify `plan.md` or status documents merely to restate a checkpoint, decision, blocker, or unchanged evidence.

Guardrails and authority:
DEC-001 through DEC-011 are locked; optional and future scope is excluded. Preserve tracked modifications, recovery paths, and unrelated files. EXT-002A authorizes only Phase 2 entry; broader EXT-002 and later gates remain mandatory.

Never weaken, skip, disable, delete, or narrow a valid test, and never suppress a valid failure. Never ignore a required exit code, reduce a required threshold, or mark a check allowed to fail. Never introduce a production bypass solely for tests or substitute mocked behavior for required real integration, signing, publication, recovery, or runtime evidence. If a test contradicts the plan or contract, prove it and replace it with equal or stronger coverage.

Do not commit directly to main. Keep the default branch safe: permit a safe fast-forward and require authorized pull-request integration. Use an approved secret mechanism and credential store. Never inspect or list credentials, keyring content, browser storage, or package content; never print, echo, log, commit, serialize, cache, or place secrets in a ledger, fixture, report, command output, or outside that store. Reject secret-bearing files. Repository defects, failed tests, and missing implementation are work, not external blockers.

This blocker-tolerant run covers only: EXT-002 Complete target runtime, service, anti cheat, and lifecycle evidence; EXT-003 Versioned xgameruntime artifact; EXT-004 Versioned Xodus compatible Wine or Proton artifact; EXT-007 Scoped public release publication approval; EXT-010 Tier 2 CachyOS Hyprland NVIDIA compatibility hardware; and EXT-011 Authorized Minecraft and Forza update revision pairs. It grants no publication approval and does not broaden DEC-004.

Verification and stopping:
Use highest-fidelity proof across deterministic, security, corpus, real-package, runtime, performance, Tier 2, release, rollback, and recovery gates. Compilation and mocks cannot replace real behavior.

After integration, inspect the merged default-branch commit, rerun affected gates, and verify the authoritative remote branch, pull request, merge commit, artifact digest, release, and runtime identities. Inspect `git status`, `git diff --check`, and `git log`; leave no intended change stranded and no unexplained temporary, generated, unrelated, or secret-bearing file.

Permitted terminal states: SUCCESS; NOT COMPLETE — EXTERNALLY BLOCKED; OWNER_INPUT_REQUIRED — REPOSITORY MISMATCH; REPOSITORY_STATE_CONFLICT. SUCCESS requires the endpoint and final audit. NOT COMPLETE — EXTERNALLY BLOCKED is permitted only when a named prerequisite is proven unavailable, every independent mandatory action is complete, and the attempted operation, external action, remaining verification, and resumable checkpoint are recorded. When a prerequisite becomes available or authorized, perform the blocked operation and verification. When independent mandatory work is exhausted, report immediately. Before returning either repository state, attempt every safe, non-destructive resolution available from repository metadata and remote evidence. No other early stopping state is permitted.

Continuity:
Update a ledger only after meaningful implementation, verification, integration, or blocker changes; record pinned hashes, evidence, blocker, and next action. The requirement map and ledger are temporary internal continuity state; unless the plan requires an evidence artifact, do not commit or publish them or add them to `plan.md`, `status.md`, issues, pull requests, or repository documentation.

After interruption, resume without reopening completed work. Do not repeat the decision checklist. Check unavailable prerequisites through one approved bounded mechanism; do not wait, sleep, or poll indefinitely. Do not rerun the same unchanged failing check more than twice without changing code, configuration, environment, instrumentation, or diagnostic hypothesis. If a pinned plan hash changes, compare only the changed sections, request owner input only for owner-sensitive drift, update the pinned hash after acceptance, and never switch revisions silently.
