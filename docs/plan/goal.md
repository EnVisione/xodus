Objective:
Complete every mandatory requirement XODUS-REQ-001 through XODUS-REQ-022 and every stable-release gate, excluding optional and future work and leaving no known mandatory repository-owned defect. Successful completion is permitted only when runtime verification passes, artifacts are bound to the verified commit, and local-target, performance, Tier 2, package, security, recovery, publication, fresh-install, rollback, and final plan-wide audit gates pass.

Immediate checkpoint:
Refresh and inspect origin without altering the remote. Verify origin is the intended repository, fetch origin without altering the remote, and verify the fetched remote-tracking ref against the current remote default-branch head. Classify the local default branch as equal, behind, ahead, or diverged; fast-forward only when safe. Do not reset, force, discard, or overwrite unexpected history. Search local branches and remote branches plus repository-wide open pull requests; resume applicable work, otherwise branch from the verified authoritative baseline. Do not invent a branch when an applicable active branch exists. Create or resume an implementation branch before modifying tracked files.

The applicable branch is `envy/target-metadata-evidence`; phase 001 is verified. Close only EXT-002 metadata and EXT-009 XSP rollback, recovery, provenance, and security evidence. Retain no payload; do not begin phase 002 implementation until both contracts pass. Issue 9's bounded XVD seek panic is evidence, not compatibility proof or implementation authority.

Perform one bounded inspection that ends as soon as each mandatory criterion is classified as implemented with valid evidence, incomplete, stale evidence, or externally blocked. Immediately execute the first incomplete or stale-evidence criterion. The map is not a deliverable: do not stop after producing it, do not rebuild it while unchanged evidence remains valid, and do not produce a narrative audit before implementation.

Authoritative plan:
/home/envy/Documents/Codex/2026-08-20/ca/work/xodus/docs/cachyos/plan.md
Plan SHA-256: b93447b78702f41abff3e6b7cc061a5bda7198d9a1a3158449ae96b9e2a31116
Validated handoff plan-set SHA-256: 0081a3c5b11ae85059f97aa68ba86a8742bf3884371c0ad1f572bced530715e1
Completion endpoint: Xodus stable release is complete only when the signed public CachyOS release and repository local PKGBUILD install on the Tier 1 Lenovo Legion 9 18IAX10, Minecraft for Windows and Forza Horizon 5 each pass the authorized local login, entitlement, license, clean install, update, two consecutive launch, runtime, save, shutdown, repair, and uninstall workflows, Forza passes both absolute performance profiles, Tier 2 compatibility gates pass, MSIXVC2 and XSP update support pass, unsupported anti cheat titles hand off separately to Xbox cloud gaming, all mandatory security, recovery, documentation, and release evidence passes, and no cloud result substitutes for either local target.

Observed checkout branch: envy/target-metadata-evidence
Observed checkout commit: a15433f9fbc6de5c7ce324533ab737a994a477ed
Repository root: /home/envy/Documents/Codex/2026-08-20/ca/work/xodus

Authoritative remote:
origin
https://github.com/EnVisione/xodus.git

Observed local default branch: main
Observed local default-branch commit: 5b77e06eaa5e3cea78af122436d35a9b02992834
Observed local remote-tracking ref: origin/main
Observed local remote-tracking commit: 5b77e06eaa5e3cea78af122436d35a9b02992834
Current remote default-branch head: 5b77e06eaa5e3cea78af122436d35a9b02992834
Remote-head evidence: git ls-remote --symref origin HEAD refs/heads/main, observed on 2026-08-24 at 06:35:24 America/Chicago
Authoritative working baseline: established
Applicable implementation branch: envy/target-metadata-evidence
Applicable open pull request: none identified at checkpoint

Verify that the authoritative plan, repository identity, package metadata, and remote describe the same project before edits. Never switch revisions silently.

Execution behavior:
Inspect, implement, test, audit, fix, verify, integrate when required, verify the resulting state, and continue through every subsequent remaining mandatory requirement. Close both entry contracts first; after they pass, execute all phases sequentially. Defects, builds, branches, pull requests, phases, and documentation are intermediate checkpoints. For each defect, preserve evidence, find the root cause, make the smallest correct fix, add regression coverage, rerun affected gates, inspect adjacent behavior, and continue.

Reuse evidence only while affected code, dependencies, configuration, environment, schemas, fixtures, and paths remain unchanged; otherwise mark it stale and rerun the affected proof. Documentation changes do not substitute for implementation. Do not modify plan.md or status documents merely to restate a checkpoint, decision, blocker, or unchanged evidence.

Guardrails and authority:
Protect phase 001 and completed evidence unless regression reopens it. Preserve persisted sign-in, sanitized discovery, owned synthetic fixtures, the signed evidence branch, and issue 9 without reacquisition or compatibility claims. DEC-001 through DEC-010 are locked; optional or future scope remains excluded. Do not repeat owner decisions. Escalate only owner-sensitive changes.

Four Clippy warnings remain unfinished; neither they nor the seek panic bypasses the entry gate. Never weaken, skip, disable, delete, or narrow a valid test or suppress a valid failure. Never ignore a required exit code, reduce a required threshold, or mark a check allowed to fail. Never introduce a production bypass solely for tests or substitute mocked behavior for required real integration, signing, publication, recovery, or runtime evidence. If a test contradicts the plan or contract, prove the contradiction and replace it with equal or stronger coverage.

Do not commit directly to main. Keep the default branch safe: permit a safe fast-forward and require authorized pull-request integration. Preserve unrelated work. Use an approved secret mechanism and credential store; never print, echo, log, commit, serialize, cache, place in the ledger, fixtures, reports, or command output, or disclose game content, secrets, credentials, license material, keys, signed URLs, protected plaintext, account identifiers, or unrelated user paths. Reject secret-bearing files.

This blocker-tolerant run covers only: Verified target entitlements and current package metadata; Versioned xgameruntime artifact; Versioned Xodus compatible Wine or Proton artifact; Scoped public release publication approval; Versioned MSIXVC2 and XSP fixture corpus; Tier 2 CachyOS Hyprland NVIDIA compatibility hardware; and Authorized Minecraft and Forza update revision pairs. It does not authorize purchases, broaden DEC-004, or grant EXT-007 publication approval. A repository-owned defect, failed test, missing implementation, or difficult problem is work, not an external blocker.

Verification and stopping:
Use the plan's highest-fidelity proof: warning-free deterministic and security gates, real-package and account exercises, service and runtime conformance, Wayland behavior, local target and performance runs, Tier 2 results, package lifecycle, signed release evidence, documentation, public inspection, fresh install, and rollback. Compilation and mocks cannot replace real behavior.

After integration, inspect the exact authoritative merged default-branch commit, rerun affected gates, verify the authoritative remote branch and pull-request state, and bind artifact and runtime identities to that commit. Run git status, git diff, git diff --check, and git log; reject unintended, generated, temporary, unrelated, or secret-bearing files.

Permitted terminal states: SUCCESS; NOT COMPLETE — EXTERNALLY BLOCKED; OWNER_INPUT_REQUIRED — REPOSITORY MISMATCH; REPOSITORY_STATE_CONFLICT. SUCCESS requires the completion endpoint and final plan-wide audit with no known mandatory repository-owned defect. NOT COMPLETE — EXTERNALLY BLOCKED is permitted only when a named mandatory prerequisite is proven unavailable, every independent mandatory action is complete, and the evidence, attempted operation, external action, remaining verification, and exact resumable checkpoint are recorded. When a prerequisite becomes available or authorized, perform the blocked operation and remaining verification. When independent mandatory work is exhausted, immediately report that state.

Before returning either repository state, attempt every safe, non-destructive resolution available from repository metadata and remote evidence. No other early stopping state is permitted.

Continuity:
Update the ledger after work or blocker changes. The requirement map and ledger are temporary internal continuity state; unless required, do not commit or publish them or add them to plan.md, status.md, issues, pull requests, or repository documentation. Record pinned hashes, revisions, criterion, evidence, blocker, and next action.

Use an approved bounded check for external availability; do not wait, sleep, or poll indefinitely. Do not rerun the same unchanged failing check more than twice without changing the code, configuration, environment, instrumentation, or diagnostic hypothesis. If either pinned hash changes, compare only the changed sections, request owner input only for owner-sensitive drift, update the pinned hash after accepting it, and never change revisions silently.
