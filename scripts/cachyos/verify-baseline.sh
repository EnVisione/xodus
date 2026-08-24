#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly manifest_path="$repository_root/docs/cachyos/baseline.json"

fail() {
    printf 'baseline verification failed, %s\n' "$1" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable, $1"
}

assert_equals() {
    local label="$1"
    local expected="$2"
    local actual="$3"

    [ "$expected" = "$actual" ] || fail "$label expected $expected, observed $actual"
}

validate_manifest() {
    require_command jq
    [ -f "$manifest_path" ] || fail "baseline manifest is unavailable, $manifest_path"

    jq -e '
        .schema_version == 1 and
        (.source_revision.xodus_commit | test("^[0-9a-f]{40}$")) and
        (.source_revision.cargo_lock_sha256 | test("^[0-9a-f]{64}$")) and
        (.source_revision.cargo_metadata_sha256 | test("^[0-9a-f]{64}$")) and
        (.source_revision.source_sensitive_paths | length > 0) and
        (.platform.packages | length > 0) and
        (.runtime_candidates | length > 0) and
        (.evidence_invalidation.invalidating_identity_fields | length > 0) and
        (.capture_contract.excluded_content | length > 0)
    ' "$manifest_path" >/dev/null || fail "baseline manifest violates schema version 1"
}

verify_source() {
    require_command git
    require_command sha256sum
    require_command jq

    local expected_commit
    local expected_lock_digest
    local expected_metadata_digest
    local expected_origin
    local expected_upstream
    local expected_origin_main
    local expected_upstream_main
    local metadata_digest
    local -a source_sensitive_paths

    expected_commit="$(jq -r '.source_revision.xodus_commit' "$manifest_path")"
    expected_lock_digest="$(jq -r '.source_revision.cargo_lock_sha256' "$manifest_path")"
    expected_metadata_digest="$(jq -r '.source_revision.cargo_metadata_sha256' "$manifest_path")"
    expected_origin="$(jq -r '.remotes.origin' "$manifest_path")"
    expected_upstream="$(jq -r '.remotes.upstream' "$manifest_path")"
    expected_origin_main="$(jq -r '.source_revision.origin_main_commit' "$manifest_path")"
    expected_upstream_main="$(jq -r '.source_revision.upstream_main_commit' "$manifest_path")"
    mapfile -t source_sensitive_paths < <(jq -r '.source_revision.source_sensitive_paths[]' "$manifest_path")

    git -C "$repository_root" merge-base --is-ancestor "$expected_commit" HEAD || fail "frozen source commit is not an ancestor of the checkout"
    git -C "$repository_root" diff --quiet "$expected_commit" -- "${source_sensitive_paths[@]}" || fail "source-sensitive paths differ from the frozen baseline"
    assert_equals "origin remote" "$expected_origin" "$(git -C "$repository_root" remote get-url origin)"
    assert_equals "upstream remote" "$expected_upstream" "$(git -C "$repository_root" remote get-url upstream)"
    git -C "$repository_root" merge-base --is-ancestor "$expected_origin_main" origin/main || fail "frozen origin main commit is not an ancestor of origin main"
    git -C "$repository_root" diff --quiet "$expected_origin_main" origin/main -- "${source_sensitive_paths[@]}" || fail "origin main source-sensitive paths differ from the frozen baseline"
    assert_equals "upstream main commit" "$expected_upstream_main" "$(git -C "$repository_root" rev-parse upstream/main)"
    assert_equals "Cargo.lock digest" "$expected_lock_digest" "$(sha256sum "$repository_root/Cargo.lock" | awk '{print $1}')"

    require_command cargo
    metadata_digest="$(cd "$repository_root" && cargo metadata --format-version 1 --no-deps | jq -S . | sha256sum | awk '{print $1}')"
    assert_equals "Cargo metadata digest" "$expected_metadata_digest" "$metadata_digest"
}

verify_environment() {
    require_command jq
    require_command pacman
    require_command uname
    require_command hyprctl
    require_command nvidia-smi
    require_command vulkaninfo

    local expected_kernel
    local expected_hyprland
    local expected_driver
    local expected_gpu
    local expected_vulkan
    local expected_scale
    local expected_zero_scaling
    local expected_package_database_digest
    local package_name
    local expected_package_version
    local installed_package_version

    expected_kernel="$(jq -r '.platform.kernel' "$manifest_path")"
    expected_hyprland="$(jq -r '.graphics.compositor.version' "$manifest_path")"
    expected_driver="$(jq -r '.hardware.gpu.driver_version' "$manifest_path")"
    expected_gpu="$(jq -r '.hardware.gpu.name' "$manifest_path")"
    expected_vulkan="$(jq -r '.graphics.vulkan.loader_version' "$manifest_path")"
    expected_scale="$(jq -r '.hardware.display.scale' "$manifest_path")"
    expected_zero_scaling="$(jq -r '.graphics.compositor.xwayland_force_zero_scaling' "$manifest_path")"
    expected_package_database_digest="$(jq -r '.platform.distribution.package_database_sha256' "$manifest_path")"

    assert_equals "kernel" "$expected_kernel" "$(uname -r)"
    assert_equals "package database digest" "$expected_package_database_digest" "$(pacman -Q | LC_ALL=C sort | sha256sum | awk '{print $1}')"
    assert_equals "Hyprland version" "$expected_hyprland" "$(hyprctl version | awk 'NR == 1 { print $2 }')"
    assert_equals "NVIDIA driver" "$expected_driver" "$(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -n 1)"
    assert_equals "NVIDIA GPU" "$expected_gpu" "$(nvidia-smi --query-gpu=name --format=csv,noheader | head -n 1)"
    assert_equals "Vulkan loader" "$expected_vulkan" "$(vulkaninfo --summary | awk -F': ' '/Vulkan Instance Version/ { print $2; exit }')"
    assert_equals "Hyprland XWayland scale policy" "$expected_zero_scaling" "$(hyprctl getoption xwayland:force_zero_scaling -j | jq -r '.bool')"

    hyprctl monitors -j | jq -e --argjson expected_scale "$expected_scale" '
        any(.[]; .name == "eDP-1" and .width == 3840 and .height == 2400 and .refreshRate == 240 and .scale == $expected_scale)
    ' >/dev/null || fail "internal display mode differs from the frozen baseline"

    while IFS=$'\t' read -r package_name expected_package_version; do
        installed_package_version="$(pacman -Q "$package_name" | awk '{print $2}')"
        assert_equals "package $package_name" "$expected_package_version" "$installed_package_version"
    done < <(jq -r '.platform.packages[] | "\(.name)\t\(.version)"' "$manifest_path")
}

reproduce_workspace_checks() {
    require_command cargo

    cd "$repository_root"
    cargo fmt --check --all
    cargo metadata --format-version 1 --no-deps >/dev/null
    cargo check --workspace --all-targets
    cargo clippy --workspace --all-targets --all-features
    cargo test --workspace --all-targets --no-run
    cargo test --workspace --all-targets -- --skip test_get_xbox_live_dev_token --skip test_minecraft_win_auth
    cargo build --release --workspace
}

usage() {
    printf '%s\n' 'usage: scripts/cachyos/verify-baseline.sh [--manifest|--source|--environment|--workspace|--all]'
}

main() {
    local mode="${1:---all}"

    [ "$#" -le 1 ] || {
        usage
        exit 2
    }

    validate_manifest

    case "$mode" in
        --manifest)
            ;;
        --source)
            verify_source
            ;;
        --environment)
            verify_environment
            ;;
        --workspace)
            reproduce_workspace_checks
            ;;
        --all)
            verify_source
            verify_environment
            reproduce_workspace_checks
            ;;
        *)
            usage
            exit 2
            ;;
    esac

    printf 'baseline verification passed, %s\n' "$mode"
}

main "$@"
