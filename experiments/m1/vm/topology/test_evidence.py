"""Synthetic consistency checks only; no VM, PAM, logind or graphical operation."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("m1_topology_evidence", Path(__file__).with_name("evidence.py"))
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


def synthetic_consistent_record():
    """Made-up booleans for validator tests, never a guest observation."""
    record = evidence.template()
    record["source_archive_sha256"] = "a" * 64
    record["component_versions"] = ["kscreenlocker-6.7.5-1.fc44.x86_64"]
    record["environment"].update(dict.fromkeys(evidence.ENV_BOOLEANS, True))
    record["environment"]["unexpected_avcs_found"] = False
    record["recovery"].update(dict.fromkeys(evidence.RECOVERY_BOOLEANS, True))
    for case in record["cases"]:
        case.update(status="passed", launch_method="reviewed-private-pam-launcher",
                    stock_components_unmodified=True, concurrent_observation_verified=True)
        for suffix in ("a", "b"):
            case["desktops"].append({"alias": f"desktop-{suffix}", "account_alias": "target",
                                     "seat_alias": f"seat-{suffix}", "gpu_alias": f"gpu-{suffix}",
                                     "input_alias": f"input-{suffix}",
                                     **dict.fromkeys(evidence.DESKTOP_BOOLEANS, True)})
        case["routing"].update(observed_actual_greeter=True, direct_mapping="absent",
                               user_manager_owner_matches=True, candidate_source="live-logind",
                               own_uid_candidate_count=2, decision="unavailable", same_entry_fallback_confirmed=True)
    return record


class TopologyEvidenceTests(unittest.TestCase):
    def test_template_cannot_count_as_executed_evidence(self):
        result = evidence.evaluate(evidence.template())
        self.assertFalse(result["topology_evidence_consistent"])
        self.assertFalse(result["m1_completion_assessed"])

    def test_consistent_synthetic_fixture_is_not_attestation(self):
        result = evidence.evaluate(synthetic_consistent_record())
        self.assertTrue(result["topology_evidence_consistent"])
        self.assertFalse(result["independent_attestation"])
        self.assertFalse(result["m1_completion_assessed"])

    def test_unknown_fields_and_product_claims_refused(self):
        for path in ("raw_session_id", "password"):
            record = synthetic_consistent_record()
            record[path] = "never export this field"
            with self.assertRaises(evidence.EvidenceError):
                evidence.evaluate(record)
        record = synthetic_consistent_record()
        record["claims"]["m1_complete"] = True
        with self.assertRaises(evidence.EvidenceError):
            evidence.evaluate(record)

    def test_boolean_is_not_integer_truthiness(self):
        record = synthetic_consistent_record()
        record["cases"][0]["concurrent_observation_verified"] = 1
        with self.assertRaises(evidence.EvidenceError):
            evidence.evaluate(record)

    def test_different_uid_desktops_do_not_close_same_uid_case(self):
        record = synthetic_consistent_record()
        record["cases"][0]["desktops"][1]["account_alias"] = "other"
        self.assertIn("same-uid-two-desktops:same-target-uid", evidence.evaluate(record)["missing_evidence"])

    def test_two_heads_or_shared_input_are_not_two_seats(self):
        for field in ("seat_alias", "gpu_alias", "input_alias"):
            record = synthetic_consistent_record()
            pair = record["cases"][1]["desktops"]
            pair[1][field] = pair[0][field]
            self.assertIn("independent-second-seat:independent-seat-gpu-input", evidence.evaluate(record)["missing_evidence"])

    def test_nested_or_metadata_desktop_does_not_pass(self):
        for field in ("native_drm_compositor", "live_packaged_kwin", "logind_and_process_mapping_verified"):
            record = synthetic_consistent_record()
            record["cases"][0]["desktops"][0][field] = False
            self.assertFalse(evidence.evaluate(record)["topology_evidence_consistent"])

    def test_real_ambiguous_greeter_must_refuse_and_fallback(self):
        for field, value in (("own_uid_candidate_count", 1), ("decision", "unique-own-session"),
                             ("observed_actual_greeter", False), ("same_entry_fallback_confirmed", False)):
            record = synthetic_consistent_record()
            record["cases"][0]["routing"][field] = value
            self.assertIn("same-uid-two-desktops:ambiguous-user-manager-fallback", evidence.evaluate(record)["missing_evidence"])

    def test_direct_ineligible_mapping_cannot_use_another_session(self):
        record = synthetic_consistent_record()
        record["cases"][1]["routing"].update(direct_mapping="ineligible", decision="unique-own-session", own_uid_candidate_count=1)
        self.assertIn("independent-second-seat:ineligible-direct-mapping-overridden", evidence.evaluate(record)["missing_evidence"])

    def test_absent_mapping_cannot_claim_direct_authorization(self):
        record = synthetic_consistent_record()
        record["cases"][1]["routing"].update(direct_mapping="absent", decision="direct-own-session")
        self.assertIn("independent-second-seat:direct-mapping-not-established", evidence.evaluate(record)["missing_evidence"])

    def test_routing_and_provenance_must_be_observed(self):
        record = synthetic_consistent_record()
        record["cases"][1]["routing"]["observed_actual_greeter"] = False
        self.assertIn("independent-second-seat:routing-observation", evidence.evaluate(record)["missing_evidence"])
        record = synthetic_consistent_record()
        record["source_archive_sha256"] = "0" * 64
        self.assertIn("provenance:unobserved-source-or-versions", evidence.evaluate(record)["missing_evidence"])

    def test_failed_stock_launch_is_evidence_not_gate_closure(self):
        record = synthetic_consistent_record()
        record["cases"][1].update(status="blocked", failure_stage="desktop")
        self.assertFalse(evidence.evaluate(record)["topology_evidence_consistent"])

    def test_each_console_needs_human_unlock_and_state_observation(self):
        for field in ("independent_console_observed", "input_route_verified", "one_entry_password_unlock_confirmed", "unlocked_state_observed"):
            record = synthetic_consistent_record()
            record["cases"][1]["desktops"][1][field] = False
            self.assertFalse(evidence.evaluate(record)["topology_evidence_consistent"])

    def test_same_uid_direct_classic_desktop_needs_no_extra_unlock_case(self):
        record = synthetic_consistent_record()
        for field in evidence.LOCKER_BOOLEANS:
            record["cases"][0]["desktops"][1][field] = False
        self.assertTrue(evidence.evaluate(record)["topology_evidence_consistent"])
        for field in evidence.LOCKER_BOOLEANS:
            record["cases"][0]["desktops"][0][field] = False
        self.assertIn("same-uid-two-desktops:actual-locker-password-fallback", evidence.evaluate(record)["missing_evidence"])

    def test_audit_loss_or_incomplete_recovery_keeps_gap_open(self):
        record = synthetic_consistent_record()
        record["environment"]["audit_lost_after"] = 1
        self.assertIn("environment:audit-loss-changed", evidence.evaluate(record)["missing_evidence"])
        for field in evidence.RECOVERY_BOOLEANS:
            with self.subTest(field=field):
                value = synthetic_consistent_record()
                value["recovery"][field] = False
                self.assertFalse(evidence.evaluate(value)["topology_evidence_consistent"])

    def test_reader_refuses_symlink_fifo_and_oversized_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            regular = base / "record"
            regular.write_text("{}")
            link = base / "link"
            link.symlink_to(regular)
            fifo = base / "fifo"
            os.mkfifo(fifo)
            large = base / "large"
            with large.open("wb") as output:
                output.truncate(evidence.LIMIT + 1)
            for path in (link, fifo, large):
                with self.subTest(path=path.name), self.assertRaises((OSError, evidence.EvidenceError)):
                    evidence.read_record(path)

    def test_duplicate_fields_cannot_hide_unreviewed_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "record"
            path.write_text('{"fixture":"first", "fixture":"second"}')
            with self.assertRaises(evidence.EvidenceError):
                evidence.read_record(path)


if __name__ == "__main__":
    unittest.main()
