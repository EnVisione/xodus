Objective:
Complete every mandatory requirement XODUS-REQ-001 through XODUS-REQ-022 and every stable-release gate while Phase 2 XODUS-REQ-002 remains active; exclude optional and future work. Successful completion is permitted only when runtime verification passes, artifacts bind to the authoritative default-branch commit, every evidence gate passes, and the final plan-wide audit finds no known mandatory repository-owned defect.

Immediate checkpoint:
Refresh and inspect `origin` without altering the remote. Verify `origin` is the intended repository; fetch `origin` without altering the remote; verify the fetched remote-tracking ref against the current remote default-branch head. Classify the local default branch as equal, behind, ahead, or diverged; fast-forward only when safe. Do not reset, force, discard, or overwrite unexpected history. Search local branches, remote branches, and repository-wide open pull requests; resume applicable work, otherwise branch from the verified authoritative baseline. Do not invent a branch while an applicable active branch exists. Create or resume an implementation branch before modifying tracked files.

SRC-052 is verified working-tree evidence, not committed state: typed `SyncSubstream` extent and checked I/O target, count, and position behavior passed formatting, 79 `msixvc` tests, zero-warning workspace Clippy, release build, filtered 99-test suite, CodeGraph sync, and diff inspection. Account test excluded; no unfiltered, package, account, runtime, secret, title-transfer, or external-service validation is claimed.

Continue XODUS-REQ-002 at `XvdStream` reads. Validate the current relative position, checked-subtract the bounded remainder, and constrain the inner read to it. Reject any returned count above the requested slice with stable `io::ErrorKind::InvalidData`; checked-derive expected next relative and absolute positions; and validate the observed inner position equals that expectation and remains within the virtual extent before success. Test overreported count, before-start, beyond-end, and position-drift failures plus valid partial and exact-end reads. Defer extraction and HTTP response or retry semantics, other runtime arithmetic, property, fuzz, unsafe-reshape, and static-inventory work. Do not begin XODUS-REQ-003 or Phase 3.

Perform one bounded inspection that ends as soon as each mandatory criterion is classified as implemented with valid evidence, incomplete, stale evidence, or externally blocked. Immediately execute the first incomplete or stale-evidence criterion. The map is not a deliverable. Do not stop after producing it or rebuild it while unchanged evidence remains valid. Do not produce a narrative audit before implementation.

Authoritative plan:
/home/envy/Documents/Codex/2026-08-20/ca/work/xodus/docs/cachyos/plan.md
Plan SHA-256: 5a7497f9fd9c339905a7b7e00dcf02015ae616a788941b24ca2e0b4c12d8f5bd
Validated handoff plan-set SHA-256: d09ccf4c5de2b1dc64e17a6c3eb2bee669bac76ce2f41b982faa66386ae6d570
Completion endpoint: Xodus stable release is complete only when the signed public CachyOS release and repository local PKGBUILD install on the Tier 1 Lenovo Legion 9 18IAX10, Minecraft for Windows and Forza Horizon 5 each pass the authorized local login, entitlement, license, clean install, update, two consecutive launch, runtime, save, shutdown, repair, and uninstall workflows, Forza passes both absolute performance profiles, Tier 2 compatibility gates pass, MSIXVC2 and XSP update support pass, unsupported anti cheat titles hand off separately to Xbox cloud gaming, all mandatory security, recovery, documentation, and release evidence passes, and no cloud result substitutes for either local target.

Observed checkout branch: envy/target-metadata-evidence
Observed checkout commit: b27010b9ec7a90690392ab0d46843aa696159d8d
Repository root: /home/envy/Documents/Codex/2026-08-20/ca/work/xodus

Authoritative remote:
origin
https://github.com/EnVisione/xodus.git

Observed local default branch: main
Observed local default-branch commit: 5b77e06eaa5e3cea78af122436d35a9b02992834
Observed local remote-tracking ref: origin/main
Observed local remote-tracking commit: 5b77e06eaa5e3cea78af122436d35a9b02992834
Current remote default-branch head: 5b77e06eaa5e3cea78af122436d35a9b02992834
Remote-head evidence: git ls-remote read-only query observed 2026-08-25 at 10:18:21Z
Authoritative working baseline: established
Applicable implementation branch: envy/target-metadata-evidence
Applicable open pull request: none identified at checkpoint

Verify the plan, repository identity, package metadata, and remote describe the same project. Never switch revisions silently.

Execution behavior:
Inspect, implement, test, audit, fix, verify, integrate when required, verify resulting state, and continue through every remaining mandatory requirement. Execute phases sequentially without stacking. For each defect, fix the smallest root cause, strengthen regression coverage, rerun narrow and affected higher-level gates, inspect adjacent behavior, and continue.

Reuse evidence only while affected code, dependencies, configuration, environment, schemas, fixtures, and paths remain unchanged; otherwise mark it stale. Documentation changes do not substitute for implementation. Do not modify `plan.md` or status documents merely to restate a checkpoint, decision, blocker, or unchanged evidence.

Guardrails and authority:
DEC-001 through DEC-012 are locked; optional and future scope is excluded. Preserve tracked work, including SRC-052 and recovery paths. EXT-002A authorizes only Phase 2 entry; broader EXT-002 and later gates remain mandatory. Keep workspace Clippy warning-free without allowances, suppression, lint-level reduction, test weakening, or behavior loss.

Never weaken, skip, disable, delete, or narrow a valid test; suppress a valid failure; ignore a required exit code; reduce a required threshold. Never mark a required check allowed to fail. Never add a production bypass solely for tests or substitute mocked behavior for required real integration, signing, publication, recovery, or runtime evidence. If a test contradicts the plan or contract, prove it and replace it with equal or stronger coverage.

Do not commit directly to main. Keep the default branch safe: permit a safe fast-forward and require authorized pull-request integration. Use approved secret mechanisms only. Never inspect or list credentials, keyring content, browser storage, or package content; never print, echo, log, commit, serialize, cache, or place secrets in a ledger, fixture, report, command output, or outside the authorized credential store. Repository defects, failed tests, and missing implementation are work, not external blockers.

This blocker-tolerant run covers only: EXT-002 Complete target runtime, service, anti cheat, and lifecycle evidence; EXT-003 Versioned xgameruntime artifact; EXT-004 Versioned Xodus compatible Wine or Proton artifact; EXT-007 Scoped public release publication approval; EXT-010 Tier 2 CachyOS Hyprland NVIDIA compatibility hardware; and EXT-011 Authorized Minecraft and Forza update revision pairs. It grants no publication approval and does not broaden DEC-004.

Verification and stopping:
Use highest-fidelity proof; compilation and mocks cannot replace required real behavior. Zero-warning workspace Clippy is mandatory.

After integration, inspect the merged default-branch commit, rerun affected gates, and verify authoritative remote branch, pull request, merge commit, artifact digest, release, and runtime identities. Inspect `git status`, `git diff`, `git diff --check`, and `git log`; leave no intended change stranded and no unexplained temporary, generated, unrelated, or secret-bearing file.

Permitted terminal states: SUCCESS; NOT COMPLETE — EXTERNALLY BLOCKED; OWNER_INPUT_REQUIRED — REPOSITORY MISMATCH; REPOSITORY_STATE_CONFLICT. SUCCESS requires the completion endpoint and final audit. NOT COMPLETE — EXTERNALLY BLOCKED is permitted only when a prerequisite is proven unavailable, independent mandatory actions are complete, and the attempted operation, external action, remaining verification, and resumable checkpoint are recorded. When a prerequisite becomes available, perform the blocked operation and run its remaining verification. Before returning either repository state, attempt every safe, non-destructive resolution available from repository metadata and remote evidence. No other early stopping state is permitted.

Continuity:
Update a ledger only after meaningful implementation, verification, integration, or blocker changes; record pinned hashes, evidence, blocker, and next action. The requirement map and ledger are temporary internal continuity state; unless the plan requires an evidence artifact, do not commit or publish them or add them to `plan.md`, `status.md`, issues, pull requests, or repository documentation.

After interruption, resume without reopening completed work. Do not repeat the decision checklist. Check unavailable prerequisites through one approved bounded mechanism; do not wait, sleep, or poll indefinitely. When independent mandatory work is exhausted, report immediately. Do not rerun the same unchanged failing check more than twice without changing code, configuration, environment, instrumentation, or diagnostic hypothesis. If a pinned plan hash changes, compare only the changed sections, request owner input only for owner-sensitive drift, update the pinned hash after acceptance, and never switch revisions silently.
