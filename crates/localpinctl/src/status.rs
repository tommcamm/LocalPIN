//! Stable nonsecret presentation separate from the binary wire format.

use localpin_core::secret::{CredentialKind, CredentialProfile};
use localpin_protocol::integration::Gate;
use localpin_protocol::{Availability, Backend, BackendPreference, Integration, Reason, Status};

/// JSON status schema version, independent of the IPC version.
pub const STATUS_SCHEMA_VERSION: u32 = 2;

/// Render status without serializing any secret-bearing protocol object.
pub fn json(status: Option<Status>, doctor: bool) -> String {
    json_with_gate(status, doctor, localpin_protocol::integration::gate())
}

fn json_with_gate(status: Option<Status>, doctor: bool, gate: Gate) -> String {
    let command = if doctor { "doctor" } else { "status" };
    let enrollment_unknown = status.is_none_or(enrollment_uninspected);
    let integration_unknown = status.is_none_or(|s| s.availability == Availability::Unavailable);
    let (configured, enrolled, availability, cooldown, integration, detected, usable, reason) =
        match status {
            Some(s) => (
                if enrollment_unknown {
                    "unknown"
                } else {
                    preference(s.configured)
                },
                s.enrolled.map(backend),
                available(s.availability),
                s.cooldown_ms,
                if integration_unknown {
                    "unknown"
                } else {
                    integrated(s.integration, gate)
                },
                s.tpm_detected,
                s.tpm_usable,
                failure(s.reason),
            ),
            None => (
                "unknown",
                None,
                "unavailable",
                0,
                "unknown",
                false,
                false,
                "service-unavailable",
            ),
        };
    let enrolled_backend =
        enrolled.map_or_else(|| "null".to_owned(), |value| format!("\"{value}\""));
    let enrolled_state = if !enrollment_unknown {
        enrolled.is_some().to_string()
    } else {
        "null".to_owned()
    };
    let active = if integration_unknown {
        "null".to_owned()
    } else {
        status
            .is_some_and(|s| s.integration == Integration::Active && gate == Gate::Active)
            .to_string()
    };
    let cooldown = if enrollment_unknown {
        "null".to_owned()
    } else {
        cooldown.to_string()
    };
    let usable = if usable { "true" } else { "null" };
    let usability = if usable == "true" {
        "established"
    } else {
        "not-established"
    };
    let tested = tested(status, gate);
    let profile = status.and_then(|s| s.profile).map_or_else(
        || "null".to_owned(),
        |profile| {
            format!(
                "{{\"kind\":\"{}\",\"length\":{},\"policy_version\":{}}}",
                kind(profile.kind),
                profile.length,
                profile.policy
            )
        },
    );
    let upgrade = if enrollment_unknown {
        "null".to_owned()
    } else {
        status.is_some_and(upgrade_recommended).to_string()
    };
    // All interpolated strings are closed enum mappings, not external input.
    format!(
        "{{\"schema_version\":{STATUS_SCHEMA_VERSION},\"command\":\"{command}\",\"installed\":\"client-present\",\"broker_available\":{},\"enrolled\":{enrolled_state},\"tested\":\"{tested}\",\"active\":{active},\"configured_backend\":\"{configured}\",\"enrolled_backend\":{enrolled_backend},\"credential_profile\":{profile},\"credential_upgrade_recommended\":{upgrade},\"availability\":\"{availability}\",\"cooldown_ms\":{cooldown},\"integration\":\"{integration}\",\"tpm_detected\":{detected},\"tpm_usable\":{usable},\"tpm_usability\":\"{usability}\",\"reason\":\"{reason}\"}}",
        status.is_some()
    )
}

/// Human-readable actionable status; reaching the broker is no integration test.
pub fn text(status: Option<Status>, doctor: bool) -> String {
    text_with_gate(status, doctor, localpin_protocol::integration::gate())
}

fn text_with_gate(status: Option<Status>, doctor: bool, gate: Gate) -> String {
    let Some(status) = status else {
        return "LocalPIN\n\nInstalled: CLI present\nBroker: unavailable\nEnrolled: unknown\nTested: not recorded\nActive: unknown\n\nNext: run localpin setup to check readiness, or ask an administrator to inspect the LocalPIN service. Keep the existing password recovery route available.".to_owned();
    };
    let enrollment_unknown = enrollment_uninspected(status);
    let integration_unknown = status.availability == Availability::Unavailable;
    let tested = tested(Some(status), gate);
    let mut output = format!(
        "LocalPIN\n\nInstalled: CLI present; broker reachable\nEnrolled: {}\nTested: {}\nActive: {}",
        if enrollment_unknown {
            "unknown"
        } else {
            status.enrolled.map(backend).unwrap_or("none")
        },
        if tested == "operator-attested" {
            "administrator attested"
        } else {
            "not recorded"
        },
        if integration_unknown {
            "unknown"
        } else if status.integration == Integration::Active && gate == Gate::Active {
            "yes"
        } else {
            "no"
        }
    );
    if let Some(profile) = status.profile {
        output.push_str(&format!(
            "\nCredential: {} · {} {}",
            match profile.kind {
                CredentialKind::NumericPin => "Numeric PIN",
                CredentialKind::Passcode => "Passcode",
            },
            profile.length,
            if profile.kind == CredentialKind::NumericPin {
                "digits"
            } else {
                "characters"
            }
        ));
    }
    if upgrade_recommended(status) {
        output.push_str("\nRecommended: replace your legacy six-digit software PIN with 8–16 digits (suggest 10), or an 8–64 character passcode (suggest 12+). Run localpin change.");
    }
    if doctor {
        output.push_str(&format!(
            "\n\nConfigured backend: {}\nAvailability: {}\nCooldown: {}\nIntegration: {}\nTPM detected: {}; usable: {}\nReason: {}",
            if enrollment_unknown { "unknown" } else { preference(status.configured) },
            available(status.availability),
            if enrollment_unknown { "unknown".to_owned() } else { format!("{} ms", status.cooldown_ms) },
            if integration_unknown { "unknown" } else { integrated(status.integration, gate) },
            status.tpm_detected,
            if status.tpm_usable { "established" } else { "not-established" },
            failure(status.reason)
        ));
        output.push_str(if tested == "operator-attested" {
            "\nPassword recovery and desktop unlock tests: administrator attested at activation; this status check does not repeat those tests."
        } else {
            "\nPassword recovery and desktop unlock tests: not recorded; verify both before activation"
        });
    }
    output.push_str("\n\nNext: ");
    output.push_str(next_action(status, gate));
    output
}

fn next_action(status: Status, gate: Gate) -> &'static str {
    match status.reason {
        Reason::Account => {
            "Account policy denies PIN use. Ask an administrator to inspect locks, expiry, required password changes, and restrictions; use the existing password recovery route."
        }
        Reason::AccountUnsupported => {
            "Run localpin setup to check account preparation. An administrator must establish a disabled baseline; enrollment cannot create account authority."
        }
        Reason::LifecycleUnavailable => {
            "Ask an administrator to inspect the account registry and native shadow-record binding. Missing, revoked, legacy, or corrupt authority requires deliberate recovery and fresh enrollment."
        }
        Reason::EligibilityUnavailable => {
            "Ask an administrator to inspect the supported Fedora policy, password format, authoritative restrictions, and persistent faillock state."
        }
        Reason::Session => {
            "Use this account's supported local graphical session, then run localpin setup."
        }
        Reason::Storage => {
            "Ask an administrator to inspect protected state ownership and permissions."
        }
        Reason::Backend => {
            "Run localpin doctor to inspect TPM readiness. Choosing software protection requires explicit enrollment and fresh password verification."
        }
        Reason::Policy => {
            "Ask an administrator to inspect LocalPIN policy with sudo localpin-integration status."
        }
        Reason::Busy => "Wait for the current bounded operation to finish, then retry.",
        Reason::Protocol => "Check that the CLI and broker versions are compatible.",
        Reason::None => {
            if status.availability == Availability::Cooldown {
                "Wait for the cooldown to finish before trying your PIN again. Password recovery remains available."
            } else if status.availability == Availability::Unavailable {
                "Ask an administrator to inspect the LocalPIN service; the available status does not establish readiness."
            } else if status.integration == Integration::NeedsAttention {
                "Inspect desktop integration with sudo localpin-integration status and follow its recovery guidance."
            } else if status.enrolled.is_none() {
                "run localpin setup to prepare your account and create a PIN."
            } else if status.integration == Integration::Active && gate == Gate::Active {
                "Your credential is active. Use localpin change to choose a new PIN or passcode, or localpin doctor for details."
            } else if status.integration == Integration::Active && gate == Gate::Trial {
                "A bounded test window is open. Run localpin setup to finish desktop and password recovery tests before activation."
            } else {
                "run localpin setup to test desktop unlocking and password recovery, then activate integration."
            }
        }
    }
}

/// Inspect only the sanitized, fixed root gate; no broker or enrollment needed.
pub fn integration_text(gate: Gate) -> String {
    match gate {
        Gate::Disabled => "Desktop integration gate: disabled or unavailable\nActive: no\nTests: not established by the readable activation state\nNext: run localpin setup to check readiness and continue onboarding\nAdministrator details: sudo localpin-integration status",
        Gate::Trial => "Desktop integration gate: trial\nActive: no; a bounded current-boot test window permits PIN testing\nTests: not recorded as complete; final activation is separate\nNext: run localpin setup to continue the required tests\nAdministrator details: sudo localpin-integration status",
        Gate::Active => "Desktop integration gate: active\nActive: yes\nTests: administrator attested at activation; this status check does not repeat them\nAdministrator details: sudo localpin-integration status",
    }.to_owned()
}

fn tested(status: Option<Status>, gate: Gate) -> &'static str {
    if gate == Gate::Active
        && status.is_some_and(|s| {
            s.availability != Availability::Unavailable && s.integration == Integration::Active
        })
    {
        "operator-attested"
    } else {
        "not-recorded"
    }
}

fn enrollment_uninspected(status: Status) -> bool {
    status.availability == Availability::Unavailable && status.enrolled.is_none()
}

fn kind(value: CredentialKind) -> &'static str {
    match value {
        CredentialKind::NumericPin => "numeric-pin",
        CredentialKind::Passcode => "passcode",
    }
}

fn upgrade_recommended(status: Status) -> bool {
    status.enrolled == Some(Backend::Software)
        && status.profile == Some(CredentialProfile::legacy())
}

fn backend(value: Backend) -> &'static str {
    match value {
        Backend::Tpm => "tpm2",
        Backend::Software => "software",
    }
}
fn preference(value: BackendPreference) -> &'static str {
    match value {
        BackendPreference::Auto => "auto",
        BackendPreference::Tpm => "tpm2-required",
        BackendPreference::Software => "software",
    }
}
fn available(value: Availability) -> &'static str {
    match value {
        Availability::Available => "available",
        Availability::NotEnrolled => "not-enrolled",
        Availability::Disabled => "disabled",
        Availability::Cooldown => "cooldown",
        Availability::Ineligible => "ineligible",
        Availability::Unavailable => "unavailable",
    }
}
fn integrated(value: Integration, gate: Gate) -> &'static str {
    match value {
        Integration::Inactive => "inactive",
        Integration::Active => match gate {
            Gate::Active => "active",
            Gate::Trial => "trial",
            Gate::Disabled => "needs-attention",
        },
        Integration::NeedsAttention => "needs-attention",
    }
}
fn failure(value: Reason) -> &'static str {
    match value {
        Reason::None => "none",
        Reason::Account => "account",
        Reason::Session => "session",
        Reason::Storage => "storage",
        Reason::Backend => "backend",
        Reason::Policy => "policy",
        Reason::Busy => "busy",
        Reason::Protocol => "protocol",
        Reason::AccountUnsupported => "account-unsupported",
        Reason::LifecycleUnavailable => "lifecycle-unavailable",
        Reason::EligibilityUnavailable => "eligibility-unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(status: Option<Status>, doctor: bool) -> String {
        json_with_gate(status, doctor, Gate::Disabled)
    }

    fn text(status: Option<Status>, doctor: bool) -> String {
        text_with_gate(status, doctor, Gate::Disabled)
    }
    fn enrolled() -> Status {
        Status {
            configured: BackendPreference::Tpm,
            enrolled: Some(Backend::Tpm),
            profile: Some(CredentialProfile::legacy()),
            availability: Availability::Available,
            cooldown_ms: 0,
            integration: Integration::Inactive,
            tpm_detected: true,
            tpm_usable: true,
            reason: Reason::None,
        }
    }
    #[test]
    fn legacy_software_credential_is_usable_with_upgrade_advice() {
        let mut status = enrolled();
        status.enrolled = Some(Backend::Software);
        let report = json(Some(status), false);
        assert!(report.contains("\"credential_upgrade_recommended\":true"));
        assert!(text(Some(status), false).contains("legacy six-digit software PIN"));
        status.profile = Some(CredentialProfile {
            kind: CredentialKind::Passcode,
            length: 14,
            policy: 1,
        });
        let report = json(Some(status), false);
        assert!(report.contains("\"kind\":\"passcode\",\"length\":14"));
        assert!(report.contains("\"credential_upgrade_recommended\":false"));
    }

    #[test]
    fn enrolled_is_not_tested_or_active() {
        let report = json(Some(enrolled()), false);
        for field in [
            "\"schema_version\":2",
            "\"installed\":\"client-present\"",
            "\"enrolled\":true",
            "\"tested\":\"not-recorded\"",
            "\"active\":false",
            "\"enrolled_backend\":\"tpm2\"",
        ] {
            assert!(report.contains(field), "{field}");
        }
    }
    #[test]
    fn schema_two_reports_the_public_credential_profile() {
        let expected = "{\"schema_version\":2,\"command\":\"status\",\"installed\":\"client-present\",\"broker_available\":true,\"enrolled\":true,\"tested\":\"not-recorded\",\"active\":false,\"configured_backend\":\"tpm2-required\",\"enrolled_backend\":\"tpm2\",\"credential_profile\":{\"kind\":\"numeric-pin\",\"length\":6,\"policy_version\":0},\"credential_upgrade_recommended\":false,\"availability\":\"available\",\"cooldown_ms\":0,\"integration\":\"inactive\",\"tpm_detected\":true,\"tpm_usable\":true,\"tpm_usability\":\"established\",\"reason\":\"none\"}";
        assert_eq!(json(Some(enrolled()), false), expected);
        assert_eq!(
            json(Some(enrolled()), true),
            expected.replace("\"command\":\"status\"", "\"command\":\"doctor\"")
        );
    }
    #[test]
    fn concise_status_guides_setup_and_distinguishes_trial_from_activation() {
        let mut status = enrolled();
        let report = text(Some(status), false);
        assert!(report.contains("Next: run localpin setup"));
        assert!(!report.contains("Configured backend:"));
        assert!(text(Some(status), true).contains("Configured backend:"));
        status.integration = Integration::Active;
        let trial = text_with_gate(Some(status), false, Gate::Trial);
        assert!(trial.contains("Active: no"));
        assert!(trial.contains("A bounded test window is open"));
        let active = text_with_gate(Some(status), false, Gate::Active);
        assert!(active.contains("Active: yes"));
        assert!(active.contains("Your credential is active"));
    }
    #[test]
    fn trial_is_distinct_from_administrator_attested_activation() {
        let mut status = enrolled();
        status.integration = Integration::Active;
        let trial = json_with_gate(Some(status), false, Gate::Trial);
        assert!(trial.contains("\"integration\":\"trial\""));
        assert!(trial.contains("\"active\":false"));
        assert!(trial.contains("\"tested\":\"not-recorded\""));
        let active = json_with_gate(Some(status), false, Gate::Active);
        assert!(active.contains("\"integration\":\"active\""));
        assert!(active.contains("\"active\":true"));
        assert!(active.contains("\"tested\":\"operator-attested\""));
        let active_text = text_with_gate(Some(status), true, Gate::Active);
        assert!(active_text.contains("Tested: administrator attested"));
        assert!(active_text.contains("does not repeat those tests"));
        assert!(
            !text_with_gate(Some(status), true, Gate::Trial)
                .contains("Tested: administrator attested")
        );
        let revoked = json_with_gate(Some(status), false, Gate::Disabled);
        assert!(revoked.contains("\"active\":false"));
        assert!(revoked.contains("\"tested\":\"not-recorded\""));
        assert!(!integration_text(Gate::Trial).contains("Tests: administrator attested"));
    }
    #[test]
    fn unavailable_status_does_not_claim_non_enrollment_or_inactivity() {
        let report = json(None, true);
        assert!(report.contains("\"broker_available\":false"));
        assert!(report.contains("\"integration\":\"unknown\""));
        assert!(report.contains("\"enrolled\":null"));
        assert!(report.contains("\"active\":null"));
        assert!(text(None, true).contains("Enrolled: unknown"));
        assert!(!report.contains("password"));
    }
    #[test]
    fn unavailable_broker_result_does_not_invent_enrollment_or_activation() {
        let mut status = enrolled();
        status.enrolled = None;
        status.profile = None;
        status.availability = Availability::Unavailable;
        status.reason = Reason::Account;
        status.tpm_usable = false;
        let report = json(Some(status), true);
        for field in [
            "\"broker_available\":true",
            "\"enrolled\":null",
            "\"active\":null",
            "\"configured_backend\":\"unknown\"",
            "\"integration\":\"unknown\"",
            "\"cooldown_ms\":null",
            "\"tpm_usable\":null",
            "\"tpm_usability\":\"not-established\"",
        ] {
            assert!(report.contains(field), "{field}");
        }
        let report = text(Some(status), true);
        assert!(report.contains("Enrolled: unknown"));
        assert!(report.contains("Active: unknown"));
        assert!(report.contains("usable: not-established"));
        assert!(report.contains("Account policy denies PIN use"));
    }
    #[test]
    fn unavailable_backend_preserves_an_authoritatively_known_enrollment() {
        let mut status = enrolled();
        status.availability = Availability::Unavailable;
        status.reason = Reason::Backend;
        let report = json(Some(status), true);
        assert!(report.contains("\"enrolled\":true"));
        assert!(report.contains("\"enrolled_backend\":\"tpm2\""));
        assert!(report.contains("\"active\":null"));
        assert!(text(Some(status), false).contains("Enrolled: tpm2"));
    }
    #[test]
    fn account_authority_failures_have_distinct_actionable_diagnostics() {
        for (reason, code, guidance) in [
            (
                Reason::AccountUnsupported,
                "account-unsupported",
                "disabled baseline",
            ),
            (
                Reason::LifecycleUnavailable,
                "lifecycle-unavailable",
                "fresh enrollment",
            ),
            (
                Reason::EligibilityUnavailable,
                "eligibility-unavailable",
                "faillock state",
            ),
        ] {
            let mut status = enrolled();
            status.enrolled = None;
            status.profile = None;
            status.availability = Availability::Unavailable;
            status.reason = reason;
            assert!(json(Some(status), true).contains(code));
            assert!(text(Some(status), true).contains(guidance));
            assert!(!text(Some(status), true).contains("sealed Fedora account domain"));
            assert!(!text(Some(status), true).contains("reseal the domain"));
            assert!(json(Some(status), true).contains("\"enrolled\":null"));
        }
    }
    #[test]
    fn status_reports_only_closed_nonsecret_fields() {
        let report = json(Some(enrolled()), true);
        for forbidden in [
            "\"pin\":",
            "password",
            "uid",
            "generation",
            "account",
            "nonce",
            "transaction",
            "record",
            "path",
        ] {
            // The deliberate tested value `not-recorded` is not protected state.
            if forbidden != "record" {
                assert!(!report.contains(forbidden), "{forbidden}");
            }
        }
    }
}
