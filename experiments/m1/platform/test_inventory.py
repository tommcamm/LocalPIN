"""Synthetic inventory fixtures only. No host PAM or real accounts are read."""

import json
import os
from pathlib import Path
import tempfile
import unittest

from inventory import MAX_PAM_BYTES, collect_pam_graph, session_candidate


class PamGraphTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, name, contents):
        (self.root / name).write_text(contents)

    def graph(self):
        return collect_pam_graph(self.root, "synthetic-locker")

    def codes(self, graph):
        return {error["code"] for error in graph["errors"]}

    def test_all_phases_include_and_substack_are_preserved(self):
        self.write("synthetic-locker", "auth substack common\naccount include policy\npassword include common\nsession include policy\n")
        self.write("common", "auth required pam_permit.so\n")
        self.write("policy", "account required pam_deny.so\n")
        graph = self.graph()
        self.assertTrue(graph["complete"])
        self.assertEqual(len(graph["files"]), 3)
        self.assertEqual([edge["phase"] for edge in graph["edges"]], ["auth", "account", "password", "session"])
        self.assertEqual(graph["edges"][0]["kind"], "substack")
        self.assertFalse(graph["service_identity_verified"])
        self.assertTrue(all(len(node["sha256"]) == 64 for node in graph["files"]))

    def test_cycle_is_an_error(self):
        self.write("synthetic-locker", "auth include common\n")
        self.write("common", "auth include synthetic-locker\n")
        graph = self.graph()
        self.assertFalse(graph["complete"])
        self.assertIn("include_cycle", self.codes(graph))

    def test_missing_include_is_an_error_but_other_edges_are_visited(self):
        self.write("synthetic-locker", "auth include missing\naccount include present\n")
        self.write("present", "account required pam_permit.so\n")
        graph = self.graph()
        self.assertFalse(graph["complete"])
        self.assertIn("missing_file", self.codes(graph))
        self.assertEqual(next(node for node in graph["files"] if node["service"] == "present")["status"], "read")

    def test_comments_and_module_arguments_are_not_exported(self):
        secret = "SYNTHETIC_PRIVATE_ARGUMENT"
        self.write("synthetic-locker", f"# {secret}\nauth [success=done default=ignore] /lib64/security/pam_permit.so {secret}\n")
        graph = self.graph()
        self.assertTrue(graph["complete"])
        self.assertNotIn(secret, json.dumps(graph))
        self.assertEqual(graph["files"][0]["modules"][0]["control_form"], "extended")

    def test_at_include_and_continuation(self):
        self.write("synthetic-locker", "@include common\n-auth required \\\n pam_permit.so argument\n")
        self.write("common", "auth required pam_permit.so\n")
        graph = self.graph()
        self.assertTrue(graph["complete"])
        self.assertEqual(graph["edges"][0]["phase"], "all")

    def test_unsupported_include_paths_are_reported_without_echoing(self):
        self.write("synthetic-locker", "auth include ../../PRIVATE_PATH\n")
        graph = self.graph()
        self.assertFalse(graph["complete"])
        self.assertNotIn("PRIVATE_PATH", json.dumps(graph))
        self.assertIn("unsupported_include_target", self.codes(graph))

    def test_unrecognized_line_is_not_silently_skipped(self):
        self.write("synthetic-locker", "this is not a recognized PAM line\n")
        self.assertIn("unsupported_syntax", self.codes(self.graph()))

    def test_unknown_control_is_not_silently_accepted(self):
        self.write("synthetic-locker", "auth invented_control pam_permit.so\n")
        self.assertIn("unsupported_control", self.codes(self.graph()))

    def test_unterminated_continuation_is_reported(self):
        self.write("synthetic-locker", "auth required pam_permit.so \\\n")
        self.assertIn("unterminated_continuation", self.codes(self.graph()))

    def test_nul_is_not_accepted(self):
        self.write("synthetic-locker", "auth required pam_permit.so\0\n")
        self.assertIn("nul_byte", self.codes(self.graph()))

    def test_symlink_requires_explicit_external_read_root(self):
        with tempfile.TemporaryDirectory() as external:
            target = Path(external) / "synthetic-target"
            target.write_text("auth required pam_permit.so\n")
            (self.root / "synthetic-locker").symlink_to(target)
            self.assertIn("symlink_outside_allowed_roots", self.codes(self.graph()))
            graph = collect_pam_graph(self.root, "synthetic-locker", [Path(external)])
            self.assertTrue(graph["complete"])
            self.assertTrue(graph["files"][0]["symlink"])
            self.assertNotIn(external, json.dumps(graph))

    def test_missing_root_and_broken_symlink_are_reported(self):
        self.assertIn("missing_file", self.codes(self.graph()))
        (self.root / "synthetic-locker").symlink_to(self.root / "absent")
        self.assertIn("missing_file", self.codes(self.graph()))

    def test_directory_and_fifo_are_rejected_without_blocking(self):
        path = self.root / "synthetic-locker"
        path.mkdir()
        self.assertIn("not_regular_file", self.codes(self.graph()))
        path.rmdir()
        os.mkfifo(path)
        self.assertIn("not_regular_file", self.codes(self.graph()))

    def test_oversized_file_is_reported(self):
        self.write("synthetic-locker", "#" * (MAX_PAM_BYTES + 1))
        self.assertIn("file_too_large", self.codes(self.graph()))

    def test_invalid_service_never_traverses(self):
        with self.assertRaises(ValueError):
            collect_pam_graph(self.root, "../outside")


class SessionDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.props = {"User": "1200", "Remote": "no", "Type": "wayland",
                      "Class": "user", "State": "active", "Seat": "seat0", "Desktop": "KDE"}

    def test_local_kde_candidate_and_locked_inactive_session(self):
        self.assertTrue(session_candidate(self.props, 1200))
        # Active-seat status is not required: a locked graphical session can be
        # online while another session owns the seat. Ambiguity is resolved later.
        self.props["State"] = "online"
        self.assertTrue(session_candidate(self.props, 1200))

    def test_other_uid_root_remote_tty_greeter_and_seatless_are_rejected(self):
        self.assertFalse(session_candidate(self.props, 1300))
        self.assertFalse(session_candidate({**self.props, "User": "0"}, 0))
        for key, value in [("Remote", "yes"), ("Type", "tty"), ("Class", "greeter"),
                           ("State", "closing"), ("Seat", ""), ("Desktop", "GNOME")]:
            with self.subTest(key=key):
                self.assertFalse(session_candidate({**self.props, key: value}, 1200))

    def test_multiple_seats_are_discovered_independently_not_arbitrarily_selected(self):
        sessions = [self.props, {**self.props, "Seat": "seat1", "Type": "x11"}]
        self.assertEqual(sum(session_candidate(item, 1200) for item in sessions), 2)


if __name__ == "__main__":
    unittest.main()
