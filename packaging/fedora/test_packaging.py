#!/usr/bin/python3
"""Confinement and package transaction invariants; never install artifacts."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

try:
    import setools
except ImportError:
    setools = None

ROOT = Path(__file__).resolve().parents[2]
FEDORA = ROOT / "packaging/fedora"


class PackagingTests(unittest.TestCase):
    def test_service_keeps_required_worker_audit_and_no_ip(self):
        unit = (ROOT / "crates/localpind/systemd/localpin.service").read_text()
        self.assertIn("SELinuxContext=system_u:system_r:localpin_broker_t:s0", unit)
        self.assertIn("NoNewPrivileges=yes", unit)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_NETLINK", unit)
        self.assertNotRegex(unit, r"AF_INET|CAP_SYS_ADMIN|CAP_SYS_PTRACE|CAP_DAC_OVERRIDE|CAP_CHOWN")
        self.assertEqual(re.findall(r"^DeviceAllow=(.*)$", unit, re.M), ["/dev/tpmrm0 rw"])
        self.assertIn("ReadWritePaths=/var/lib/localpin /var/lib/faillock", unit)
        self.assertIn("LimitCORE=0", unit)
        self.assertIn("SystemCallFilter=~setsid", unit)
        self.assertIn("SystemCallErrorNumber=EPERM", unit)
        self.assertNotIn("\nRestrictSUIDSGID=yes\n", unit)

    def test_private_paths_and_persistent_tally_are_not_aged_out(self):
        rules = [line.split() for line in (FEDORA / "localpin.tmpfiles").read_text().splitlines() if line and not line.startswith("#")]
        indexed = {r[1]: r for r in rules}
        self.assertEqual(indexed["/var/lib/localpin-integration"][2], "0755")
        self.assertEqual(indexed["/var/lib/localpin-integration/control"][2], "0700")
        self.assertEqual(indexed["/var/lib/faillock"][2], "0755")
        self.assertTrue(all(r[0] == "d" and r[-1] == "-" for r in rules))

    def test_rpm_lifecycle_keeps_recovery_tool_before_module_removal(self):
        spec = (FEDORA / "localpin.spec").read_text()
        pre = spec.split("%pre\n", 1)[1].split("%post\n", 1)[0]
        post = spec.split("%post\n", 1)[1].split("%preun\n", 1)[0]
        preun = spec.split("%preun\n", 1)[1].split("%postun\n", 1)[0]
        self.assertLess(pre.index("package-check --candidate-evr"), pre.index("package-suspend || exit 1"))
        self.assertNotIn("package-cache-begin", pre)
        self.assertIn("--candidate-schema 2 || exit 1", pre)
        self.assertIn("Requires(pre):  python3-rpm", spec)
        self.assertLess(preun.index("localpin-integration disable || exit 1"), preun.index("package-check --removal || exit 1"))
        self.assertLess(preun.index("package-check --removal || exit 1"), preun.index("systemctl stop"))
        self.assertNotRegex(post, r"systemctl (start|enable)|localpin-integration (prepare|activate|trial)")
        self.assertNotIn("package-resume", post)
        final_trigger = spec.split('%transfiletriggerin -P 50000 -- %{_libexecdir}/localpin\n', 1)[1].split('%files\n', 1)[0]
        self.assertIn("localpin-integration package-resume || exit 1", final_trigger)
        self.assertNotRegex(spec, r'--notriggers|--noscripts|chattr\s')
        self.assertNotIn("restorecon -RF", post)
        self.assertIn("%config(noreplace) %{_sysconfdir}/pam.d/localpin-enroll", spec)
        self.assertIn("%config(noreplace) %{_sysconfdir}/pam.d/localpin-kde-password", spec)
        self.assertIn("%config(noreplace) %{_sysconfdir}/pam.d/localpin-kde-fingerprint", spec)
        self.assertNotIn("%{_sysconfdir}/security/faillock.conf", spec)
        self.assertNotRegex(spec, r"chmod (?:[0-7]*[46][0-7]{3}|u\+s)")

    def test_native_and_policy_builder_are_host_read_only(self):
        source = (FEDORA / "build-rpm.py").read_text()
        self.assertIn('"--release", "--workspace", "--locked", "--offline"', source)
        self.assertNotIn('"--nodeps"', source)
        self.assertNotRegex(source, r'run\(\["(?:sudo|semodule|systemctl|dnf)"')
        policy = (FEDORA / "selinux/build.py").read_text()
        self.assertNotIn('"semodule",', policy)

    def test_selinux_client_and_backend_boundaries(self):
        source = (FEDORA / "selinux/localpin.te").read_text()
        rules = [rule.strip() for rule in source.split(";") if re.search(r"\ballow\b", rule)]
        client = [rule[rule.index("allow userdomain"):] for rule in rules if "allow userdomain" in rule]
        self.assertEqual(len(client), 5)
        self.assertFalse(any("localpin_state_t" in rule or "shadow_t" in rule or "tpm_device_t" in rule or "localpin_backup_t" in rule for rule in client))
        tpm = [rule for rule in rules if "tpm_device_t:chr_file" in rule]
        self.assertEqual(len(tpm), 2)
        self.assertTrue(any("localpin_backend_t tpm_device_t:chr_file { open read write" in rule for rule in tpm))
        self.assertTrue(any("localpin_broker_t tpm_device_t:chr_file getattr" in rule for rule in tpm))
        self.assertNotRegex(source, r"allow (?:domain|unconfined_t) ")
        self.assertNotIn("auth_use_pam", source)
        self.assertIn("allow userdomain localpin_integration_t:dir { search open read getattr };", source)
        self.assertIn("allow localpin_broker_t sysctl_kernel_t:file { open read getattr };", source)
        self.assertIn("allow localpin_broker_t fs_t:filesystem getattr;", source)
        self.assertIn("allow localpin_broker_t system_dbusd_var_run_t:dir { search getattr };", source)
        self.assertIn("signal signull sigkill", source)
        self.assertIn("allow init_t localpin_broker_t:unix_stream_socket { create", source)
        self.assertIn("allow { localpin_auth_t localpin_eligibility_t } faillog_t:file { open read write getattr lock };", source)
        self.assertNotRegex(source, r"allow [^;]+ faillog_t:(?:file|dir) [^;]*(?:create|unlink|setattr|add_name)")
        for process in ('broker', 'auth', 'eligibility'):
            self.assertIn(f'typeattribute localpin_{process}_t can_read_shadow_passwords;', source)
        self.assertNotIn('can_write_shadow_passwords', source)
        self.assertIn("allow systemd_tmpfiles_t { localpin_state_t localpin_accounts_t localpin_integration_t localpin_backup_t localpin_runtime_t }:dir { search open read getattr create setattr };", source)
        self.assertNotRegex(source, r'allow systemd_tmpfiles_t [^;]+:file')
        self.assertIn("ld_so_t:file { open read getattr execute map }", source)
        self.assertIn("ld_so_cache_t:file { open read getattr map }", source)
        setpgid_rules = [rule for rule in rules if 'self:process' in rule and 'setpgid' in rule]
        self.assertEqual(len(setpgid_rules), 1)
        self.assertIn('allow localpin_broker_t self:process setpgid', setpgid_rules[0])
        for process in ('auth', 'eligibility'):
            self.assertIn(f'type_transition localpin_{process}_t chkpwd_exec_t:process chkpwd_t;', source)
        self.assertNotIn('type_transition localpin_broker_t chkpwd_exec_t', source)
        self.assertIn('allow localpin_broker_t chkpwd_t:process { signal signull sigkill sigstop getpgid };', source)
        self.assertNotIn("SELinuxContext=", (ROOT / "crates/localpind/systemd/localpin.socket").read_text())

    @unittest.skipUnless(shutil.which("checkmodule") and shutil.which("semodule_package"), "SELinux build tools unavailable")
    def test_selinux_source_builds_without_host_policy_load(self):
        with tempfile.TemporaryDirectory(prefix="localpin-policy-test-") as directory:
            subprocess.run(["python3", str(FEDORA / "selinux/build.py"), "--output", directory], check=True, capture_output=True)
            self.assertGreater((Path(directory) / "localpin.pp").stat().st_size, 0)

    @unittest.skipUnless(setools and Path('/etc/selinux/targeted/policy/policy.35').is_file(), "installed Fedora policy introspection unavailable")
    def test_policy_imports_exist_in_actual_fedora_targeted_policy(self):
        policy = setools.SELinuxPolicy('/etc/selinux/targeted/policy/policy.35')
        require = (FEDORA / 'selinux/localpin.te').read_text().split('require {', 1)[1].split('\n}', 1)[0]
        for kind, names in re.findall(r'^\s*(attribute|type)\s+([^;]+);', require, re.M):
            for name in names.split(','):
                lookup = policy.lookup_typeattr if kind == 'attribute' else policy.lookup_type
                lookup(name.strip())
        for classname, declared in re.findall(r'^\s*class\s+(\w+)\s+([^;]+);', require, re.M):
            actual = policy.lookup_class(classname)
            permissions = set(actual.perms)
            try:
                permissions.update(actual.common.perms)
            except setools.exception.NoCommon:
                pass
            expected = set(declared.replace('{', '').replace('}', '').split())
            self.assertLessEqual(expected, permissions, classname)
    @unittest.skipUnless(setools and Path('/etc/selinux/targeted/policy/policy.35').is_file(), "effective Fedora chkpwd_t policy query unavailable")
    def test_effective_native_expiry_helper_cannot_change_process_group(self):
        # Inspect the complete installed base policy, including attribute-based
        # allows, because chkpwd_t is maintained outside our local module.
        # The unit additionally denies setsid for every descendant.
        policy = setools.SELinuxPolicy('/etc/selinux/targeted/policy/policy.35')
        helper_group_changes = list(setools.TERuleQuery(
            policy, source='chkpwd_t', target='chkpwd_t', tclass=['process'],
            perms=['setpgid'], ruletype=['allow']).results())
        self.assertEqual(helper_group_changes, [])


if __name__ == "__main__":
    unittest.main()
