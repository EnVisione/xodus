Objective:
Complete every mandatory requirement XODUS-REQ-001 through XODUS-REQ-022 and every stable-release gate in the pinned plan, with optional and future work excluded and no known mandatory repository-owned defect. Successful completion is permitted only when runtime verification passes, signed release artifacts are bound to the verified source commit, and the local-target, performance, Tier 2, package, security, recovery, publication, fresh-install, rollback, and final plan-wide audit gates pass.

Immediate checkpoint:
At the verified XODUS-PHASE-001 checkpoint, execute XODUS-REQ-001 first. Refresh and inspect origin without altering the remote: verify origin is the intended repository, fetch origin without altering the remote, verify the fetched remote-tracking ref against the current remote default-branch head, classify the local default branch as equal, behind, ahead, or diverged, and fast-forward only when safe. Do not reset, force, discard, or overwrite unexpected history. Search local branches and remote branches plus repository-wide open pull requests; resume applicable work, otherwise create an implementation branch from the verified authoritative baseline. Do not invent a branch when an applicable active branch exists, and create or resume an implementation branch before modifying tracked files.

Perform one bounded inspection that ends as soon as each mandatory criterion is classified as implemented with valid evidence, incomplete, stale evidence, or externally blocked. Immediately execute the first incomplete or stale-evidence criterion. The map is not a deliverable: do not stop after producing it, do not rebuild it while unchanged evidence remains valid, and do not produce a narrative audit before implementation.

Authoritative plan:
/home/envy/Documents/Codex/2026-08-20/ca/work/xodus/docs/cachyos/plan.md
Plan SHA-256: bac5341fe675eb488b5e0070c931feb1d54703143f69e414d8c733e3c431725d
Completion endpoint: Xodus stable release is complete only when the signed public CachyOS release and repository local PKGBUILD install on the Tier 1 Lenovo Legion 9 18IAX10, Minecraft for Windows and Forza Horizon 5 each pass the authorized local login, entitlement, license, clean install, update, two consecutive launch, runtime, save, shutdown, repair, and uninstall workflows, Forza passes both absolute performance profiles, Tier 2 compatibility gates pass, MSIXVC2 and XSP update support pass, unsupported anti cheat titles hand off separately to Xbox cloud gaming, all mandatory security, recovery, documentation, and release evidence passes, and no cloud result substitutes for either local target.

Observed checkout branch: envy/cachyos-audit
Observed checkout commit: b3d7fb210301aac66b8aaef16c0450dcfadd451c
Repository root: /home/envy/Documents/Codex/2026-08-20/ca/work/xodus

Authoritative remote:
origin
https://github.com/EnVisione/xodus.git

Observed local default branch: main
Observed local default-branch commit: b3d7fb210301aac66b8aaef16c0450dcfadd451c
Observed local remote-tracking ref: origin/main
Observed local remote-tracking commit: b3d7fb210301aac66b8aaef16c0450dcfadd451c
Current remote default-branch head: b3d7fb210301aac66b8aaef16c0450dcfadd451c
Remote-head evidence: git ls-remote origin refs/heads/main and the GitHub API, observed on 2026-08-24 at 03:33:04 America/Chicago
Authoritative working baseline: established
Applicable implementation branch: none identified at checkpoint
Applicable open pull request: none identified at checkpoint

Verify that the plan, repository identity, package metadata, and remote describe the same project before edits. Never switch revisions silently.

Execution behavior:
Inspect, implement, test, audit, fix, verify, integrate when required, verify the resulting state, and continue through every subsequent remaining mandatory requirement. Defect fixes, builds, phases, branches, pull requests, and documentation are intermediate checkpoints. For each confirmed defect, preserve decisive evidence, find the root cause, make the smallest correct fix, add regression coverage when possible, rerun narrow and affected higher-level gates, inspect adjacent behavior, then continue.

Reuse evidence only while affected code, dependencies, configuration, environment, schemas, fixtures, and paths remain unchanged; otherwise mark it stale and rerun the affected proof. Documentation changes do not substitute for implementation. Do not modify plan.md or status documents merely to restate a checkpoint, decision, blocker, or unchanged evidence.

Guardrails and authority:
Protect completed work unless regression evidence reopens it. DEC-001 through DEC-010 are locked; optional or future scope remains excluded. Do not repeat owner decision checklists. Escalate only a new choice that materially changes scope, cost, licensing, publication, trust boundaries, destructive behavior, credentials, external communication, or irreversible remote state.

Treat Clippy's four warnings as unfinished; compilation and offline tests are not real behavior proof. Prevent false-success exits, unsafe package paths, remotely influenced panics, and secret-bearing files. Never weaken, skip, disable, delete, or narrow a valid test or suppress a valid failure. Never ignore a required exit code, reduce a required threshold, or mark a check allowed to fail. Never introduce a production bypass solely for tests or substitute mocked behavior for required real integration, signing, publication, recovery, or runtime evidence. If a test contradicts the plan or contract, prove the contradiction and replace it with equal or stronger coverage.

Do not commit directly to main. Keep the default branch safe: permit a safe fast-forward to verified remote state and require authorized pull-request integration for later changes. Preserve uncommitted and unrelated work. Use credentials only through an approved secret mechanism and credential store; never print, echo, log, commit, serialize, cache, place in the ledger, fixtures, reports, or command output, or disclose them.

This blocker-tolerant run covers only: Verified target entitlements and current package metadata; Versioned xgameruntime artifact; Versioned Xodus compatible Wine or Proton artifact; Scoped public release publication approval; Versioned MSIXVC2 and XSP fixture corpus; Tier 2 CachyOS Hyprland NVIDIA compatibility hardware; and Authorized Minecraft and Forza update revision pairs. It does not authorize purchases, broaden DEC-004, or grant EXT-007 publication approval.

Verification and stopping:
Use the highest-fidelity proof required by the plan: formatting, warning-free Clippy, deterministic and security tests, fixtures and fuzz regressions, account-backed and real-package exercises, service and runtime conformance, accessible Wayland UI, Tier 1 presentation and local title lifecycles, Forza telemetry, independent Tier 2 results, clean-chroot package lifecycle, signatures, checksums, SBOM, provenance, documentation, public-release inspection, fresh install, and rollback. After integration, inspect the exact authoritative merged default-branch commit, rerun affected gates, verify the authoritative remote branch and pull-request state, and bind artifact digests and runtime identity to that commit. Finish with git status, git diff, git diff --check, and git log, rejecting unintended, generated, temporary, unrelated, or secret-bearing files.

Permitted terminal states: SUCCESS; NOT COMPLETE — EXTERNALLY BLOCKED; OWNER_INPUT_REQUIRED — REPOSITORY MISMATCH; REPOSITORY_STATE_CONFLICT. SUCCESS requires the completion endpoint and final plan-wide audit with no known mandatory repository-owned defect. NOT COMPLETE — EXTERNALLY BLOCKED is permitted only when a named mandatory prerequisite is proven unavailable, every independent mandatory action is complete, and the evidence, attempted operation, required external action, remaining verification, and exact resumable checkpoint are recorded. When independent mandatory work is exhausted, immediately report that state. When a prerequisite becomes available or authorized, perform the blocked operation and remaining verification.

Before returning either repository state, attempt every safe, non-destructive resolution available from repository metadata and remote evidence. No other early stopping state is permitted.

Continuity:
Maintain a terse operational ledger only after meaningful implementation, verification, integration, or blocker changes. The requirement map and ledger are temporary internal continuity state; unless the plan explicitly requires an evidence artifact, do not commit or publish them or add them to plan.md, status.md, issues, pull requests, or repository documentation. Record the pinned plan hash, starting and current revisions, active criterion, valid and stale evidence, blocker, and next action so compaction or restart resumes without repeating completed work.

Use an approved bounded check for external availability; do not wait, sleep, or poll indefinitely. Do not rerun the same unchanged failing check more than twice without changing the code, configuration, environment, instrumentation, or diagnostic hypothesis. If the plan hash changes, compare only the changed sections, request owner input only for owner-sensitive drift, update the pinned hash after accepting it, and never change revisions silently.
