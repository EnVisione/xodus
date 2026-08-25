Objective:
Complete every mandatory requirement XODUS-REQ-001 through XODUS-REQ-022 and every stable-release gate while Phase 2 XODUS-REQ-002 remains active; exclude optional and future work. Successful completion is permitted only when runtime verification passes, release artifacts bind to the authoritative default-branch commit, every evidence gate passes, and the final plan-wide audit finds no known mandatory repository-owned defect.

Immediate checkpoint:
Refresh and inspect `origin` without altering the remote. Verify `origin` is the intended repository; fetch `origin` without altering the remote; verify the fetched remote-tracking ref against the current remote default-branch head. Classify the local default branch as equal, behind, ahead, or diverged; fast-forward only when safe. Do not reset, force, discard, or overwrite unexpected history. Search local branches, remote branches, and repository-wide open pull requests; resume applicable work, otherwise branch from the verified authoritative baseline. Do not invent a branch while an applicable active branch exists. Create or resume an implementation branch before modifying tracked files.

SRC-053 is verified evidence against signed commit `8a15ef369fc38a0b1866192b534f899f41aa8f93`: source SHA-256 `f4ad36ba9952d1406b91ad6f107ab103dd812c01c6af0945c1be455b9ad99d98`, patch SHA-256 `9e98e589d25000789f158094185e76c8cafd19b6c1d7e87dd6aa6f32663021af`. Formatting, 85 `msixvc` tests, zero-warning Clippy, release build, filtered 105-test suite, CodeGraph sync at 358 nodes, and diff inspection passed. Account test excluded; no unfiltered suite or real-package/runtime claim.

Continue XODUS-REQ-002 at `HttpRead`. Validate pending-chunk offsets before slicing; checked-convert copied and received lengths; checked-advance pending, logical, and active-next offsets; reject positions or received extents beyond the declared total with `io::ErrorKind::InvalidData`; and require reopened responses to preserve total length and exact requested start. Test pending-offset, logical-position, active-offset, total-length-drift, overlong-chunk, initial-read, and resumed-read behavior. Defer retry-budget, premature-EOF, extraction response, property, fuzz, unsafe-reshape, and static-inventory work. Do not begin XODUS-REQ-003 or Phase 3.

Perform one bounded inspection that ends as soon as each mandatory criterion is classified as implemented with valid evidence, incomplete, stale evidence, or externally blocked. Immediately execute the first incomplete or stale-evidence criterion. The map is not a deliverable. Do not stop after producing it, do not rebuild it while unchanged evidence remains valid, and do not produce a narrative audit before implementation.

Authoritative plan:
/home/envy/Documents/Codex/2026-08-20/ca/work/xodus/docs/cachyos/plan.md
Plan SHA-256: 1a48fdad5439d99a99587f434a930352674178540c0e658aabf115073ac49e99
Plan handoff: /home/envy/Documents/Codex/2026-08-20/ca/work/xodus/docs/cachyos/plan.handoff.json
Plan handoff SHA-256: aad9a760585fa22f3e05b4d1d52c932de0d2dde0d81f8d466567cb71203d0533
Validated handoff plan-set SHA-256: 3edd72f1bf2cb49fbde90aec200eab645bcef35892cfb27526a2a840057ce424
Completion endpoint: Xodus stable release is complete only when the signed public CachyOS release and repository local PKGBUILD install on the Tier 1 Lenovo Legion 9 18IAX10, Minecraft for Windows and Forza Horizon 5 each pass the authorized local login, entitlement, license, clean install, update, two consecutive launch, runtime, save, shutdown, repair, and uninstall workflows, Forza passes both absolute performance profiles, Tier 2 compatibility gates pass, MSIXVC2 and XSP update support pass, unsupported anti cheat titles hand off separately to Xbox cloud gaming, all mandatory security, recovery, documentation, and release evidence passes, and no cloud result substitutes for either local target.

Observed checkout branch: envy/target-metadata-evidence
Observed checkout commit: 8a15ef369fc38a0b1866192b534f899f41aa8f93
Repository root: /home/envy/Documents/Codex/2026-08-20/ca/work/xodus

Authoritative remote:
origin
https://github.com/EnVisione/xodus.git

Observed local default branch: main
Observed local default-branch commit: 5b77e06eaa5e3cea78af122436d35a9b02992834
Observed local remote-tracking ref: origin/main
Observed local remote-tracking commit: 5b77e06eaa5e3cea78af122436d35a9b02992834
Current remote default-branch head: 5b77e06eaa5e3cea78af122436d35a9b02992834
Remote-head evidence: git ls-remote read-only query observed 2026-08-25 at 10:51:01Z
Authoritative working baseline: established
Applicable implementation branch: envy/target-metadata-evidence
Applicable open pull request: none identified

Verify the plan, repository identity, package metadata, and remote describe the same project. Never switch revisions silently.

Execution behavior:
Inspect, implement, test, audit, fix, verify, integrate when required, verify resulting state, and continue through every subsequent mandatory criterion and phase without stacking. Fix the smallest root cause, strengthen regression coverage, rerun narrow and affected higher-level gates, inspect adjacent behavior, and continue.

Treat `plan.md`, `plan.handoff.json`, and `/home/envy/Documents/Codex/2026-08-20/ca/work/xodus/docs/plan/goal.md` as pinned immutable read-only execution inputs and creator artifacts. Never invoke Plan Creator or Goal Creator, never spawn their authors, and never refresh, rewrite, rebind, overwrite, or replace creator artifacts, `plan.md`, `plan.handoff.json`, or `goal.md`. Documentation changes do not substitute for implementation.

Reuse evidence only while affected code, dependencies, configuration, environment, schemas, fixtures, and paths remain unchanged; otherwise mark it stale. Do not modify status documents merely to restate unchanged evidence.

Guardrails and authority:
DEC-001 through DEC-012 are locked. Preserve tracked work and recovery paths. Optional and future scope is excluded. EXT-002A and EXT-009 authorize Phase 2 entry; EXT-009 supplies synthetic fixture evidence only and proves no real-package apply, rollback, or recovery. Broader EXT-002 remains mandatory later. Keep workspace Clippy warning-free without suppression, allowances, lint-level reduction, test weakening, or behavior loss.

Never weaken, skip, disable, delete, or narrow a valid test; never suppress a valid failure; never ignore a required exit code; never reduce a required threshold; never mark a required check allowed to fail. Never add a production bypass solely for tests or substitute mocked behavior for required real integration, signing, publication, recovery, or runtime evidence. If a test contradicts the plan or contract, prove it and replace it with equal or stronger coverage.

Do not commit directly to main. Keep the default branch safe: permit a safe fast-forward and require authorized pull-request integration. Use approved secret mechanisms only. Never inspect or list credentials, keyring content, browser storage, or package content, and never expose secrets in output or secret-bearing files. Repository defects, failed tests, and missing implementation are work, not external blockers.

This approved blocker-tolerant run covers only: EXT-002 Complete target runtime, service, anti cheat, and lifecycle evidence; EXT-003 Versioned xgameruntime artifact; EXT-004 Versioned Xodus compatible Wine or Proton artifact; EXT-007 Scoped public release publication approval; EXT-010 Tier 2 CachyOS Hyprland NVIDIA compatibility hardware; and EXT-011 Authorized Minecraft and Forza update revision pairs. It grants no publication approval.

Verification and stopping:
Use highest-fidelity real behavior proof; compilation and mocks cannot replace required behavior. After integration, inspect the authoritative merged state, rerun affected gates, and verify the authoritative remote branch, pull request, merge commit, artifact digest, release, and runtime identities. Inspect `git status`, `git diff`, `git diff --check`, and `git log`; leave no intended change stranded and no unexplained temporary, generated, unrelated, or secret-bearing file.

Permitted terminal states: SUCCESS; NOT COMPLETE — EXTERNALLY BLOCKED; OWNER_INPUT_REQUIRED — REPOSITORY MISMATCH; REPOSITORY_STATE_CONFLICT; PLAN_REVISION_CONFLICT. SUCCESS requires the completion endpoint and final audit. NOT COMPLETE — EXTERNALLY BLOCKED is permitted only when a prerequisite is proven unavailable, independent mandatory actions are complete, and the attempted external action, remaining verification, and resumable checkpoint are recorded. When a prerequisite becomes available or authorized, perform the blocked operation and remaining verification. Before returning either repository state, attempt every safe, non-destructive resolution available from repository metadata and remote evidence. No other early stopping state is permitted.

Continuity:
Update a ledger only after meaningful implementation, verification, integration, or blocker changes; record pinned hashes, evidence, blocker, and next action. The requirement map and ledger are temporary internal continuity state; do not commit or publish them or add them to `plan.md`, `status.md`, issues, pull requests, or repository documentation.

After interruption, resume without reopening completed work. Do not repeat the decision checklist. Check unavailable prerequisites through one approved bounded mechanism; do not wait, sleep, or poll indefinitely. When independent mandatory work is exhausted, report immediately. Do not rerun the same unchanged failing check more than twice without changing code, configuration, environment, instrumentation, or diagnostic hypothesis. On PLAN_REVISION_CONFLICT, stop and report the exact changed path, expected digest, and observed digest. Compare only the changed files and sections; request owner input for owner-sensitive drift, and never switch revisions silently.
