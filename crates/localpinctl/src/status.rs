//! Stable nonsecret presentation separate from the binary wire format.

use localpin_protocol::{Availability, Backend, BackendPreference, Integration, Reason, Status};

/// JSON status schema version, independent of the IPC version.
pub const STATUS_SCHEMA_VERSION: u32 = 1;

/// Render status without serializing any secret-bearing protocol object.
pub fn json(status: Option<Status>, doctor: bool) -> String {
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
                    integrated(s.integration)
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
            .is_some_and(|s| s.integration == Integration::Active)
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
    // All interpolated strings are closed enum mappings, not external input.
    format!(
        "{{\"schema_version\":{STATUS_SCHEMA_VERSION},\"command\":\"{command}\",\"installed\":\"client-present\",\"broker_available\":{},\"enrolled\":{enrolled_state},\"tested\":\"not-recorded\",\"active\":{active},\"configured_backend\":\"{configured}\",\"enrolled_backend\":{enrolled_backend},\"availability\":\"{availability}\",\"cooldown_ms\":{cooldown},\"integration\":\"{integration}\",\"tpm_detected\":{detected},\"tpm_usable\":{usable},\"tpm_usability\":\"{usability}\",\"reason\":\"{reason}\"}}",
        status.is_some()
    )
}

/// Human-readable actionable status; reaching the broker is no integration test.
pub fn text(status: Option<Status>, doctor: bool) -> String {
    let Some(status) = status else {
        return "Installed: CLI present\nBroker: unavailable; ask the administrator to check the LocalPIN service\nEnrolled: unknown\nTested: not recorded\nActive: unknown; verify the existing password recovery route".to_owned();
    };
    let enrollment_unknown = enrollment_uninspected(status);
    let integration_unknown = status.availability == Availability::Unavailable;
    let mut output = format!(
        "Installed: CLI present; broker reachable\nEnrolled: {}\nTested: not recorded\nActive: {}\nConfigured backend: {}\nAvailability: {}\nCooldown: {}\nIntegration: {}\nTPM detected: {}; usable: {}\nReason: {}",
        if enrollment_unknown {
            "unknown"
        } else {
            status.enrolled.map(backend).unwrap_or("none")
        },
        if integration_unknown {
            "unknown"
        } else if status.integration == Integration::Active {
            "yes"
        } else {
            "no"
        },
        if enrollment_unknown {
            "unknown"
        } else {
            preference(status.configured)
        },
        available(status.availability),
        if enrollment_unknown {
            "unknown".to_owned()
        } else {
            format!("{} ms", status.cooldown_ms)
        },
        if integration_unknown {
            "unknown"
        } else {
            integrated(status.integration)
        },
        status.tpm_detected,
        if status.tpm_usable {
            "established"
        } else {
            "not-established"
        },
        failure(status.reason)
    );
    if doctor {
        output.push_str("\nPassword recovery and desktop unlock tests: not recorded; verify both before activation");
        output.push_str(match status.reason {
            Reason::None => "\nThe broker reports no current availability failure.",
            Reason::Account => "\nAccount policy denies PIN use. Ask the administrator to inspect locks, expiry, required password changes and applicable restrictions; use the existing password recovery route.",
            Reason::AccountUnsupported => "\nAccount unsupported: only explicitly provisioned accounts in the sealed Fedora account domain are supported. The administrator must establish a disabled baseline; enrollment cannot create lifecycle state.",
            Reason::LifecycleUnavailable => "\nLifecycle unavailable: the domain is revoked, busy, unsealed, or its required state is missing or corrupt. Ask the administrator to recover and reseal the domain; this requires fresh enrollment.",
            Reason::EligibilityUnavailable => "\nAccount eligibility unavailable: the reviewed Fedora policy, password format or authoritative restriction state could not be established. Ask the administrator to inspect the supported policy and faillock state.",
            Reason::Session => "\nUse the account's supported local graphical session.",
            Reason::Storage => {
                "\nAsk the administrator to inspect protected state ownership and permissions."
            }
            Reason::Backend => "\nCheck TPM usability or explicitly choose software enrollment.",
            Reason::Policy => "\nAsk the administrator to inspect LocalPIN policy and integration.",
            Reason::Busy => "\nWait for the current bounded operation to finish, then retry.",
            Reason::Protocol => "\nCheck that the CLI and broker versions are compatible.",
        });
    }
    output
}

fn enrollment_uninspected(status: Status) -> bool {
    status.availability == Availability::Unavailable && status.enrolled.is_none()
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
fn integrated(value: Integration) -> &'static str {
    match value {
        Integration::Inactive => "inactive",
        Integration::Active => "active",
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
    fn enrolled() -> Status {
        Status {
            configured: BackendPreference::Tpm,
            enrolled: Some(Backend::Tpm),
            availability: Availability::Available,
            cooldown_ms: 0,
            integration: Integration::Inactive,
            tpm_detected: true,
            tpm_usable: true,
            reason: Reason::None,
        }
    }
    #[test]
    fn enrolled_is_not_tested_or_active() {
        let report = json(Some(enrolled()), false);
        for field in [
            "\"schema_version\":1",
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
            status.availability = Availability::Unavailable;
            status.reason = reason;
            assert!(json(Some(status), true).contains(code));
            assert!(text(Some(status), true).contains(guidance));
            assert!(json(Some(status), true).contains("\"enrolled\":null"));
        }
    }
    #[test]
    fn status_reports_only_closed_nonsecret_fields() {
        let report = json(Some(enrolled()), true);
        for forbidden in [
            "pin",
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
