# Project-distributed RPM; build-rpm.py prepares native release artifacts.
# This is intentionally not a Fedora repository source-RPM recipe.
%global debug_package %{nil}
%global _build_id_links none
%global __brp_strip %{nil}
%global __brp_strip_comment_note %{nil}
%global __brp_strip_static_archive %{nil}

Name:           localpin
Version:        0.1.0
Release:        0.1.alpha1%{?dist}
Summary:        Opt-in local PIN unlock for Fedora KDE local accounts
License:        MIT OR Apache-2.0
Source0:        localpin-%{version}-native.tar.gz
ExclusiveArch:  x86_64

BuildRequires:  checkpolicy
BuildRequires:  policycoreutils
BuildRequires:  python3
Requires:       pam >= 1.7.2
Requires:       pam < 1.8
Requires:       authselect
Requires:       kscreenlocker
Requires:       systemd >= 259
Requires:       selinux-policy-targeted >= 44
Requires:       policycoreutils
Requires:       python3 >= 3.11
Requires:       python3-rpm
Requires:       sudo
Requires:       tpm2-tss >= 4.0.0
Requires:       tpm2-tss < 5.0.0
Requires(pre):  systemd
Requires(pre):  python3-rpm
Requires(pre):  rpm >= 6.0.2
Requires(preun): systemd
Requires(post): systemd
Requires(post): policycoreutils
Requires(postun): systemd
Requires(postun): policycoreutils

%description
LocalPIN supplies a socket-activated native broker, bounded privileged workers,
a PAM adapter, and explicit root administration for a reviewed Fedora 44 KDE
local-account desktop. Installation does not enroll users, start or
enable the broker, or edit KDE, authselect or faillock configuration. Activation
is a separate guarded operation and requires a tested password recovery route.

%prep
%setup -q -n localpin-%{version}-native

%build
python3 packaging/fedora/selinux/build.py --output policy-build

%install
install -d %{buildroot}%{_libexecdir}/localpin %{buildroot}%{_bindir} %{buildroot}%{_sbindir}
for executable in localpind localpin-worker localpin-auth-worker localpin-eligibility-worker localpin-account; do
    install -m 0755 native/$executable %{buildroot}%{_libexecdir}/localpin/$executable
done
install -m 0755 native/localpinctl %{buildroot}%{_bindir}/localpinctl
ln -s localpinctl %{buildroot}%{_bindir}/localpin
install -m 0755 tools/localpin-integration.py %{buildroot}%{_libexecdir}/localpin/localpin-integration
ln -s ../libexec/localpin/localpin-integration %{buildroot}%{_sbindir}/localpin-integration
install -D -m 0755 native/liblocalpin_pam.so %{buildroot}%{_libdir}/security/pam_localpin.so
install -D -m 0644 crates/localpind/systemd/localpin.service %{buildroot}%{_unitdir}/localpin.service
install -D -m 0644 crates/localpind/systemd/localpin.socket %{buildroot}%{_unitdir}/localpin.socket
install -D -m 0644 packaging/fedora/95-localpin.preset %{buildroot}%{_presetdir}/95-localpin.preset
install -D -m 0644 packaging/fedora/localpin.tmpfiles %{buildroot}%{_tmpfilesdir}/localpin.conf
install -D -m 0644 packaging/fedora/software.conf %{buildroot}%{_datadir}/localpin/systemd/software.conf
install -D -m 0644 crates/localpin-auth/policy/localpin-enroll.disabled %{buildroot}%{_sysconfdir}/pam.d/localpin-enroll
install -D -m 0644 packaging/fedora/localpin-eligibility.disabled %{buildroot}%{_sysconfdir}/pam.d/localpin-eligibility
install -D -m 0644 packaging/fedora/localpin-eligibility.disabled %{buildroot}%{_sysconfdir}/pam.d/localpin-kde-password
install -D -m 0644 packaging/fedora/localpin-eligibility.disabled %{buildroot}%{_sysconfdir}/pam.d/localpin-kde-fingerprint
install -d %{buildroot}%{_datadir}/localpin/policy
install -m 0644 crates/localpin-auth/policy/*.review-required %{buildroot}%{_datadir}/localpin/policy/
install -D -m 0644 policy-build/localpin.pp %{buildroot}%{_datadir}/selinux/packages/localpin.pp
install -d -m 0700 %{buildroot}%{_sharedstatedir}/localpin %{buildroot}%{_sharedstatedir}/localpin-accounts
install -d -m 0755 %{buildroot}%{_sharedstatedir}/localpin-integration %{buildroot}%{_sharedstatedir}/faillock
install -d -m 0700 %{buildroot}%{_sharedstatedir}/localpin-integration/control

%check
python3 packaging/fedora/test_packaging.py

%pre
# OLD tool checks schema/policy before replacing files or closing an active gate.
if [ -x %{_libexecdir}/localpin/localpin-integration ]; then
    %{_libexecdir}/localpin/localpin-integration package-check --candidate-evr '0:%{version}-%{release}' --candidate-schema 2 || exit 1
    %{_libexecdir}/localpin/localpin-integration package-suspend || exit 1
fi

%post
# A failed upgrade leaves the activation gate closed for console recovery.
/usr/sbin/semodule -i %{_datadir}/selinux/packages/localpin.pp || exit 1
/usr/sbin/restorecon -R %{_libexecdir}/localpin %{_sharedstatedir}/localpin %{_sharedstatedir}/localpin-accounts %{_sharedstatedir}/localpin-integration %{_sharedstatedir}/faillock %{_sysconfdir}/pam.d/localpin-enroll %{_sysconfdir}/pam.d/localpin-eligibility %{_sysconfdir}/pam.d/localpin-kde-password %{_sysconfdir}/pam.d/localpin-kde-fingerprint || exit 1
/usr/bin/systemd-tmpfiles --create %{_tmpfilesdir}/localpin.conf || exit 1
/usr/bin/systemctl daemon-reload || exit 1
# Resumption must wait for the distribution's real ldconfig file triggers.

%preun
if [ "$1" -eq 0 ]; then
    # Keep PAM, tool, workers and policy installed throughout owned recovery.
    # Unknown/changed policy aborts erase rather than guessing an administrator merge.
    %{_libexecdir}/localpin/localpin-integration disable || exit 1
    %{_libexecdir}/localpin/localpin-integration package-check --removal || exit 1
    /usr/bin/systemctl stop localpin.socket localpin.service || exit 1
    /usr/bin/systemctl disable localpin.socket || exit 1
fi

%postun
/usr/bin/systemctl daemon-reload || :
if [ "$1" -eq 0 ]; then
    /usr/sbin/semodule -r localpin || :
fi

%transfiletriggerin -P 50000 -- %{_libexecdir}/localpin
# RPM6 runs the new package's transaction trigger after the installed-package
# transaction-in and transaction-postun triggers, including both glibc ldconfig
# triggers. Initial/disabled installs have no pending window and start nothing.
# Failure keeps the PIN gate closed. Account markers and all stored credentials
# and throttles must match the suspended binding before prior activation resumes.
%{_libexecdir}/localpin/localpin-integration package-resume || exit 1

%files
%license LICENSE-MIT LICENSE-APACHE
%doc packaging/fedora/README.md BUILD-INPUTS.json
%doc docs/integration-administration.md docs/account-administration.md
%doc docs/adr/0012-immutable-appliance-account-authority.md
%doc docs/adr/0013-pam-unlock-contract.md
%doc docs/adr/0014-persistent-faillock.md
%doc docs/adr/0015-m8-activation-and-rpm.md
%doc docs/adr/0016-package-cache-window.md
%doc docs/adr/0017-shadow-record-account-authority.md
%doc docs/adr/0018-kde-native-update-compatibility.md
%doc docs/adr/0019-guided-setup-orchestration.md
%{_bindir}/localpinctl
%{_bindir}/localpin
%{_sbindir}/localpin-integration
%{_libexecdir}/localpin/
%{_libdir}/security/pam_localpin.so
%{_unitdir}/localpin.service
%{_unitdir}/localpin.socket
%{_presetdir}/95-localpin.preset
%{_tmpfilesdir}/localpin.conf
%{_datadir}/localpin/
%{_datadir}/selinux/packages/localpin.pp
%config(noreplace) %{_sysconfdir}/pam.d/localpin-enroll
%config(noreplace) %{_sysconfdir}/pam.d/localpin-eligibility
%config(noreplace) %{_sysconfdir}/pam.d/localpin-kde-password
%config(noreplace) %{_sysconfdir}/pam.d/localpin-kde-fingerprint
%dir %attr(0700,root,root) %{_sharedstatedir}/localpin
%dir %attr(0700,root,root) %{_sharedstatedir}/localpin-accounts
%dir %attr(0755,root,root) %{_sharedstatedir}/localpin-integration
%dir %attr(0700,root,root) %{_sharedstatedir}/localpin-integration/control
%dir %attr(0755,root,root) %{_sharedstatedir}/faillock

%changelog
* Sat Oct 17 2026 LocalPIN contributors - 0.1.0-0.1.alpha1
- Initial opt-in Fedora appliance RPM and confinement sources.
