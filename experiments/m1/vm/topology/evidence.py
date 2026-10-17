#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Validate curated, sanitized M1 topology observations; never inspect a VM."""
import argparse
import json
import os
from pathlib import Path
import re
import stat

LIMIT = 65536
FIXTURE = "M1 genuine KDE topology observations"
KINDS = ("same-uid-two-desktops", "independent-second-seat")


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def keys(value, expected, where):
    require(type(value) is dict and set(value) == set(expected), f"unexpected {where} fields")


def boolean(value, where):
    require(type(value) is bool, f"invalid {where} boolean")


def choice(value, choices, where):
    require(type(value) is str and value in choices, f"invalid {where}")


def count(value, maximum, where):
    require(type(value) is int and 0 <= value <= maximum, f"invalid {where} count")


DESKTOP_BOOLEANS = (
    "local_nonclosing_user_session", "logind_and_process_mapping_verified",
    "native_drm_compositor", "live_packaged_kwin", "live_packaged_plasmashell",
    "independent_console_observed", "input_route_verified", "actual_locker_observed",
    "one_entry_password_unlock_confirmed", "unlocked_state_observed",
)
LOCKER_BOOLEANS = ("actual_locker_observed", "one_entry_password_unlock_confirmed", "unlocked_state_observed")
ENV_BOOLEANS = (
    "disposable_clone_verified", "clean_snapshot_verified", "exact_vm_guard_verified",
    "selinux_enforcing_before", "selinux_enforcing_after", "no_host_device_passthrough",
    "audit_enabled", "audit_records_reviewed", "unexpected_avcs_found",
)
RECOVERY_BOOLEANS = (
    "owned_launch_units_and_scopes_stopped", "fixture_processes_gone",
    "original_pam_account_and_profile_restored", "temporary_access_keys_removed",
    "clone_restored_or_discarded",
)


def validate(record):
    keys(record, ("schema_version", "fixture", "record_date", "source_archive_sha256",
                  "component_versions", "environment", "cases", "recovery", "claims"), "record")
    require(type(record["schema_version"]) is int and record["schema_version"] == 1, "unsupported schema")
    require(record["fixture"] == FIXTURE, "unexpected fixture")
    require(type(record["record_date"]) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", record["record_date"]),
            "invalid record date")
    require(type(record["source_archive_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", record["source_archive_sha256"]),
            "invalid source digest")
    versions = record["component_versions"]
    require(type(versions) is list and 1 <= len(versions) <= 16, "invalid component versions")
    for version in versions:
        require(type(version) is str and len(version) <= 160 and
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+:~-]*", version), "invalid component version")
    env = record["environment"]
    keys(env, (*ENV_BOOLEANS, "audit_lost_before", "audit_lost_after"), "environment")
    for name in ENV_BOOLEANS:
        boolean(env[name], name)
    for name in ("audit_lost_before", "audit_lost_after"):
        count(env[name], 2**63 - 1, name)
    cases = record["cases"]
    require(type(cases) is list and len(cases) == 2, "two topology cases required")
    require(all(type(case) is dict and "kind" in case for case in cases), "invalid topology case")
    require([case["kind"] for case in cases] == list(KINDS), "unexpected topology case order")
    for case in cases:
        keys(case, ("kind", "status", "launch_method", "stock_components_unmodified",
                    "concurrent_observation_verified", "failure_stage", "desktops", "routing"), "case")
        choice(case["status"], ("passed", "failed", "blocked", "not-run"), "case status")
        choice(case["launch_method"], ("stock-login-manager", "reviewed-private-pam-launcher", "not-run"), "launch method")
        choice(case["failure_stage"], ("none", "preflight", "devices", "session", "desktop", "locker", "routing", "cleanup"), "failure stage")
        for name in ("stock_components_unmodified", "concurrent_observation_verified"):
            boolean(case[name], name)
        desktops = case["desktops"]
        require(type(desktops) is list and 0 <= len(desktops) <= 2, "invalid desktop list")
        for desktop in desktops:
            keys(desktop, ("alias", "account_alias", "seat_alias", "gpu_alias", "input_alias",
                           *DESKTOP_BOOLEANS), "desktop")
            choice(desktop["alias"], ("desktop-a", "desktop-b"), "desktop alias")
            choice(desktop["account_alias"], ("target", "other", "root"), "account alias")
            choice(desktop["seat_alias"], ("seat-a", "seat-b", "none"), "seat alias")
            choice(desktop["gpu_alias"], ("gpu-a", "gpu-b", "none"), "GPU alias")
            choice(desktop["input_alias"], ("input-a", "input-b", "none"), "input alias")
            for name in DESKTOP_BOOLEANS:
                boolean(desktop[name], name)
        routing = case["routing"]
        keys(routing, ("observed_actual_greeter", "direct_mapping", "user_manager_owner_matches",
                       "candidate_source", "own_uid_candidate_count", "decision", "same_entry_fallback_confirmed"), "routing")
        for name in ("observed_actual_greeter", "user_manager_owner_matches", "same_entry_fallback_confirmed"):
            boolean(routing[name], name)
        choice(routing["direct_mapping"], ("eligible", "ineligible", "absent", "unobserved"), "direct mapping")
        choice(routing["candidate_source"], ("live-logind", "unobserved"), "candidate source")
        count(routing["own_uid_candidate_count"], 128, "candidate")
        choice(routing["decision"], ("direct-own-session", "unique-own-session", "unavailable", "unobserved"), "routing decision")
    keys(record["recovery"], RECOVERY_BOOLEANS, "recovery")
    for name in RECOVERY_BOOLEANS:
        boolean(record["recovery"][name], name)
    claims = record["claims"]
    keys(claims, ("production_authorization_proven", "uid_lifecycle_solved", "m1_complete"), "claim")
    require(all(value is False for value in claims.values()), "unsupported product or milestone claim")


def evaluate(record):
    """Return fixed missing-evidence labels. This is consistency, not attestation."""
    validate(record)
    gaps = []
    if record["source_archive_sha256"] == "0" * 64 or record["component_versions"] == ["unobserved"]:
        gaps.append("provenance:unobserved-source-or-versions")
    env = record["environment"]
    for name in ENV_BOOLEANS:
        if env[name] != (name != "unexpected_avcs_found"):
            gaps.append(f"environment:{name}")
    if env["audit_lost_after"] != env["audit_lost_before"]:
        gaps.append("environment:audit-loss-changed")
    for case in record["cases"]:
        prefix = case["kind"]
        if case["status"] != "passed" or case["failure_stage"] != "none":
            gaps.append(f"{prefix}:not-passed")
        if case["launch_method"] == "not-run" or not case["stock_components_unmodified"]:
            gaps.append(f"{prefix}:launch-provenance")
        if not case["concurrent_observation_verified"]:
            gaps.append(f"{prefix}:concurrency")
        desktops = case["desktops"]
        if len(desktops) != 2 or {d["alias"] for d in desktops} != {"desktop-a", "desktop-b"}:
            gaps.append(f"{prefix}:two-distinct-desktops")
        for desktop in desktops:
            if desktop["account_alias"] == "root" or desktop["seat_alias"] == "none" or desktop["gpu_alias"] == "none":
                gaps.append(f"{prefix}:eligible-desktop")
            for name in DESKTOP_BOOLEANS:
                # The same-UID scenario needs the ambiguous shared-manager
                # locker's fallback; a direct classic session need not have
                # its own additional manual unlock. Both independent seats do.
                if prefix == "same-uid-two-desktops" and name in LOCKER_BOOLEANS:
                    continue
                if not desktop[name]:
                    gaps.append(f"{prefix}:{desktop['alias']}:{name}")
        if prefix == "same-uid-two-desktops":
            if len(desktops) != 2 or any(d["account_alias"] != "target" for d in desktops):
                gaps.append(f"{prefix}:same-target-uid")
            if not any(all(desktop[name] for name in LOCKER_BOOLEANS) for desktop in desktops):
                gaps.append(f"{prefix}:actual-locker-password-fallback")
            routing = case["routing"]
            if not (routing["observed_actual_greeter"] and routing["direct_mapping"] == "absent" and
                    routing["user_manager_owner_matches"] and routing["candidate_source"] == "live-logind" and
                    routing["own_uid_candidate_count"] == 2 and routing["decision"] == "unavailable" and
                    routing["same_entry_fallback_confirmed"]):
                gaps.append(f"{prefix}:ambiguous-user-manager-fallback")
        elif len(desktops) != 2 or any(len({d[field] for d in desktops}) != 2 or
                                      any(d[field] == "none" for d in desktops)
                                      for field in ("seat_alias", "gpu_alias", "input_alias")):
            gaps.append(f"{prefix}:independent-seat-gpu-input")
        routing = case["routing"]
        if not (routing["observed_actual_greeter"] and routing["candidate_source"] == "live-logind" and
                routing["direct_mapping"] != "unobserved" and routing["decision"] != "unobserved"):
            gaps.append(f"{prefix}:routing-observation")
        # A direct ineligible mapping can never be repaired by another session;
        # an absent mapping requires a verified unique owner/candidate or refusal.
        if routing["direct_mapping"] == "ineligible" and routing["decision"] != "unavailable":
            gaps.append(f"{prefix}:ineligible-direct-mapping-overridden")
        if routing["direct_mapping"] == "eligible" and routing["decision"] != "direct-own-session":
            gaps.append(f"{prefix}:eligible-direct-mapping-not-used")
        if routing["decision"] == "direct-own-session" and not (
                routing["direct_mapping"] == "eligible" and routing["own_uid_candidate_count"] >= 1):
            gaps.append(f"{prefix}:direct-mapping-not-established")
        if routing["decision"] == "unique-own-session" and not (
                routing["direct_mapping"] == "absent" and routing["user_manager_owner_matches"] and
                routing["candidate_source"] == "live-logind" and routing["own_uid_candidate_count"] == 1):
            gaps.append(f"{prefix}:unique-mapping-not-established")
    for name in RECOVERY_BOOLEANS:
        if not record["recovery"][name]:
            gaps.append(f"recovery:{name}")
    return {"schema_version": 1, "topology_evidence_consistent": not gaps,
            "missing_evidence": sorted(set(gaps)), "independent_attestation": False,
            "m1_completion_assessed": False, "production_authorization_proven": False}


def read_record(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= LIMIT, "record must be a bounded regular file")
        data = source.read(LIMIT + 1)
        require(len(data) <= LIMIT, "record exceeds bound")
    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique_fields)


def template():
    cases = []
    for kind in KINDS:
        cases.append({"kind": kind, "status": "not-run", "launch_method": "not-run",
                      "stock_components_unmodified": False, "concurrent_observation_verified": False,
                      "failure_stage": "none", "desktops": [], "routing": {
                          "observed_actual_greeter": False, "direct_mapping": "unobserved",
                          "user_manager_owner_matches": False, "candidate_source": "unobserved",
                          "own_uid_candidate_count": 0, "decision": "unobserved",
                          "same_entry_fallback_confirmed": False}})
    return {"schema_version": 1, "fixture": FIXTURE, "record_date": "2026-10-17",
            "source_archive_sha256": "0" * 64, "component_versions": ["unobserved"],
            "environment": {**dict.fromkeys(ENV_BOOLEANS, False), "audit_lost_before": 0, "audit_lost_after": 0},
            "cases": cases, "recovery": dict.fromkeys(RECOVERY_BOOLEANS, False),
            "claims": {"production_authorization_proven": False, "uid_lifecycle_solved": False, "m1_complete": False}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--template", action="store_true")
    group.add_argument("--record", type=Path)
    args = parser.parse_args()
    result = template() if args.template else evaluate(read_record(args.record))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if args.template or result["topology_evidence_consistent"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceError, OSError, ValueError, TypeError, UnicodeError):
        # Never echo the input JSON, path or parser exception: it may not have
        # passed the sanitized-schema check yet.
        print("Invalid or unreadable sanitized topology record", file=__import__("sys").stderr)
        raise SystemExit(1)
