//! Fail-closed account/session eligibility contracts and deterministic fixtures.
//!
//! These fixtures do not query PAM, logind, process credentials, or Linux account
//! files. A production adapter must establish the supported account policy and
//! retain stable session/process references; no such adapter exists in M2.

use crate::types::{AccountId, Uid};

/// A stable, opaque reference supplied by a trusted session authority.
///
/// It must change when a session disappears and an identifier is reused. A
/// client-supplied session name or process ID is not a suitable reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionReference([u8; 16]);

impl SessionReference {
    /// Construct a reference supplied by a trusted adapter or a simulator.
    pub fn new(value: [u8; 16]) -> Result<Self, EligibilityError> {
        if value == [0; 16] {
            Err(EligibilityError::UnknownProperties)
        } else {
            Ok(Self(value))
        }
    }
}

/// Successful account and session checks, bound to a specific live session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EligibilitySnapshot {
    account: AccountId,
    session: SessionReference,
}

impl EligibilitySnapshot {
    /// Record checks performed by a trusted adapter, never by an IPC client.
    ///
    /// This constructor supplies no platform attestation. Production use remains
    /// blocked until the account/session adapter is implemented and tested.
    pub fn from_trusted_check(account: AccountId, session: SessionReference) -> Self {
        Self { account, session }
    }

    /// The account incarnation whose eligibility was checked.
    pub fn account(self) -> AccountId {
        self.account
    }

    /// The stable session reference whose eligibility was checked.
    pub fn session(self) -> SessionReference {
        self.session
    }
}

/// A trusted boundary which must repeat account and session checks on each call.
pub trait EligibilityAuthority {
    /// Validate current account restrictions and resolve a current live session.
    fn check(&mut self, account: AccountId) -> Result<EligibilitySnapshot, EligibilityError>;
}

/// Sanitized reasons that PIN eligibility cannot be established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EligibilityError {
    /// The account is locked, expired, restricted, or requires a password change.
    AccountRestricted,
    /// The requested account incarnation does not match the checked account.
    AccountChanged,
    /// The session belongs to another UID or account incarnation.
    WrongAccount,
    /// The direct session is not a supported local graphical user session.
    IneligibleSession,
    /// Required authoritative properties were not available.
    UnknownProperties,
    /// No eligible own-account session was found.
    NoSession,
    /// Several eligible own-account sessions were found.
    AmbiguousSession,
    /// The platform authority or its supported policy is unavailable.
    Unavailable,
}

/// Default production posture while platform eligibility remains unimplemented.
#[derive(Debug, Default)]
pub struct UnavailableEligibility;

impl EligibilityAuthority for UnavailableEligibility {
    fn check(&mut self, _account: AccountId) -> Result<EligibilitySnapshot, EligibilityError> {
        Err(EligibilityError::Unavailable)
    }
}

/// Explicitly simulated account restrictions, without invoking a password stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulatedAccountPolicy {
    /// The simulator declares that all supported account restrictions passed.
    Allowed,
    /// The account is locked.
    Locked,
    /// The account is expired.
    Expired,
    /// A password change is required.
    PasswordChangeRequired,
    /// Another supported restriction denies use.
    Restricted,
    /// The applicable policy or result is unknown.
    Unknown,
}

/// Session class in a simulated logind inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulatedSessionClass {
    /// An ordinary user session.
    User,
    /// A display-manager greeter session.
    Greeter,
    /// Another known class.
    Other,
    /// An unreadable or unrecognized property.
    Unknown,
}

/// Desktop support in a simulated inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulatedDesktop {
    /// A KDE desktop verified against the supported platform contract.
    SupportedKde,
    /// Another known desktop.
    Other,
    /// An unreadable or unrecognized desktop property.
    Unknown,
}

/// Session type in a simulated inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulatedSessionType {
    /// A Wayland graphical session.
    Wayland,
    /// An X11 graphical session.
    X11,
    /// Another known session type, including TTY.
    Other,
    /// An unreadable or unrecognized type.
    Unknown,
}

/// A simulator input; its fields are not evidence about a real host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulatedSession {
    /// The account incarnation owning this session.
    pub account: AccountId,
    /// A stable simulator reference that changes on session replacement.
    pub reference: SessionReference,
    /// Whether the session is live; `None` means unknown.
    pub live: Option<bool>,
    /// Whether it is local; `None` means unknown.
    pub local: Option<bool>,
    /// Whether it is closing; `None` means unknown.
    pub closing: Option<bool>,
    /// Whether it has a seat; `None` means unknown.
    pub seated: Option<bool>,
    /// Its session class.
    pub class: SimulatedSessionClass,
    /// Its desktop support status.
    pub desktop: SimulatedDesktop,
    /// Its graphical session type.
    pub kind: SimulatedSessionType,
}

impl SimulatedSession {
    fn eligible(&self, account: AccountId) -> Result<bool, EligibilityError> {
        if self.account != account {
            return Err(EligibilityError::WrongAccount);
        }
        let (Some(live), Some(local), Some(closing), Some(seated)) =
            (self.live, self.local, self.closing, self.seated)
        else {
            return Err(EligibilityError::UnknownProperties);
        };
        if self.class == SimulatedSessionClass::Unknown
            || self.desktop == SimulatedDesktop::Unknown
            || self.kind == SimulatedSessionType::Unknown
        {
            return Err(EligibilityError::UnknownProperties);
        }
        Ok(live
            && local
            && !closing
            && seated
            && self.class == SimulatedSessionClass::User
            && self.desktop == SimulatedDesktop::SupportedKde
            && matches!(
                self.kind,
                SimulatedSessionType::Wayland | SimulatedSessionType::X11
            ))
    }
}

/// Explicit simulated caller routing; direct mappings never use fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SimulatedRoute {
    /// A stable direct peer-to-session mapping exists.
    Direct(SimulatedSession),
    /// No direct mapping exists; verified user-manager ownership is required.
    UserManager {
        /// The kernel-verified UID owning the caller's user manager.
        owner: Uid,
        /// The complete simulated inventory, including inactive live sessions.
        sessions: Vec<SimulatedSession>,
    },
    /// Process/session authority could not establish a route.
    Unavailable,
}

/// A mutable deterministic fixture used to exercise repeated eligibility checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulatedEligibility {
    /// The account incarnation represented by this fixture.
    pub account: AccountId,
    /// The current simulated account restrictions.
    pub policy: SimulatedAccountPolicy,
    /// The current simulated caller route.
    pub route: SimulatedRoute,
}

impl EligibilityAuthority for SimulatedEligibility {
    fn check(&mut self, account: AccountId) -> Result<EligibilitySnapshot, EligibilityError> {
        if self.account != account {
            return Err(EligibilityError::AccountChanged);
        }
        match self.policy {
            SimulatedAccountPolicy::Allowed => {}
            SimulatedAccountPolicy::Unknown => return Err(EligibilityError::UnknownProperties),
            _ => return Err(EligibilityError::AccountRestricted),
        }
        let session = match &self.route {
            SimulatedRoute::Direct(session) => {
                if !session.eligible(account)? {
                    return Err(EligibilityError::IneligibleSession);
                }
                session.reference
            }
            SimulatedRoute::UserManager { owner, sessions } => {
                if *owner != account.uid {
                    return Err(EligibilityError::WrongAccount);
                }
                let mut candidate = None;
                for session in sessions {
                    if session.account.uid != account.uid {
                        continue;
                    }
                    // An unknown own-UID candidate might make routing ambiguous.
                    // Refuse instead of silently excluding that candidate.
                    if session.eligible(account)? {
                        if candidate.is_some() {
                            return Err(EligibilityError::AmbiguousSession);
                        }
                        candidate = Some(session.reference);
                    }
                }
                candidate.ok_or(EligibilityError::NoSession)?
            }
            SimulatedRoute::Unavailable => return Err(EligibilityError::Unavailable),
        };
        Ok(EligibilitySnapshot::from_trusted_check(account, session))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::types::Incarnation;

    pub(crate) fn account(uid: u32, incarnation: u8) -> AccountId {
        AccountId {
            uid: Uid::new(uid).unwrap(),
            incarnation: Incarnation::new([incarnation; 16]).unwrap(),
        }
    }

    pub(crate) fn session(account: AccountId, id: u8) -> SimulatedSession {
        SimulatedSession {
            account,
            reference: SessionReference::new([id; 16]).unwrap(),
            live: Some(true),
            local: Some(true),
            closing: Some(false),
            seated: Some(true),
            class: SimulatedSessionClass::User,
            desktop: SimulatedDesktop::SupportedKde,
            kind: SimulatedSessionType::Wayland,
        }
    }

    pub(crate) fn authority(account: AccountId) -> SimulatedEligibility {
        SimulatedEligibility {
            account,
            policy: SimulatedAccountPolicy::Allowed,
            route: SimulatedRoute::Direct(session(account, 1)),
        }
    }

    #[test]
    fn direct_ineligible_sessions_fail_without_a_fallback() {
        let account = account(1000, 1);
        for variation in 0..8 {
            let mut s = session(account, 1);
            match variation {
                0 => s.live = Some(false),
                1 => s.local = Some(false),
                2 => s.closing = Some(true),
                3 => s.seated = Some(false),
                4 => s.class = SimulatedSessionClass::Greeter,
                5 => s.desktop = SimulatedDesktop::Other,
                6 => s.kind = SimulatedSessionType::Other,
                _ => s.account = self::account(1001, 1),
            }
            let mut fixture = authority(account);
            fixture.route = SimulatedRoute::Direct(s);
            assert!(fixture.check(account).is_err());
        }
    }

    #[test]
    fn user_manager_requires_exactly_one_own_uid_candidate() {
        let account = account(1000, 1);
        let other = self::account(1001, 1);
        for count in 0..=4 {
            let mut fixture = authority(account);
            let mut sessions = vec![session(other, 10)];
            sessions.extend((1..=count).map(|id| session(account, id)));
            fixture.route = SimulatedRoute::UserManager {
                owner: account.uid,
                sessions,
            };
            let result = fixture.check(account);
            assert_eq!(result.is_ok(), count == 1);
        }
    }

    #[test]
    fn unknown_own_uid_candidate_cannot_hide_ambiguity() {
        let account = account(1000, 1);
        let mut unknown = session(account, 2);
        unknown.live = None;
        let mut fixture = authority(account);
        fixture.route = SimulatedRoute::UserManager {
            owner: account.uid,
            sessions: vec![session(account, 1), unknown],
        };
        assert_eq!(
            fixture.check(account),
            Err(EligibilityError::UnknownProperties)
        );
    }

    #[test]
    fn restrictions_and_unknown_properties_fail_closed() {
        let account = account(1000, 1);
        for policy in [
            SimulatedAccountPolicy::Locked,
            SimulatedAccountPolicy::Expired,
            SimulatedAccountPolicy::PasswordChangeRequired,
            SimulatedAccountPolicy::Restricted,
            SimulatedAccountPolicy::Unknown,
        ] {
            let mut fixture = authority(account);
            fixture.policy = policy;
            assert!(fixture.check(account).is_err());
        }
        for property in 0..7 {
            let mut s = session(account, 1);
            match property {
                0 => s.live = None,
                1 => s.local = None,
                2 => s.closing = None,
                3 => s.seated = None,
                4 => s.class = SimulatedSessionClass::Unknown,
                5 => s.desktop = SimulatedDesktop::Unknown,
                _ => s.kind = SimulatedSessionType::Unknown,
            }
            let mut fixture = authority(account);
            fixture.route = SimulatedRoute::Direct(s);
            assert_eq!(
                fixture.check(account),
                Err(EligibilityError::UnknownProperties)
            );
        }
    }

    #[test]
    fn mismatched_manager_or_account_incarnation_is_refused() {
        let account = account(1000, 1);
        let mut fixture = authority(account);
        fixture.route = SimulatedRoute::UserManager {
            owner: Uid::new(1001).unwrap(),
            sessions: vec![session(account, 1)],
        };
        assert_eq!(fixture.check(account), Err(EligibilityError::WrongAccount));
        fixture.route = SimulatedRoute::UserManager {
            owner: account.uid,
            sessions: vec![session(self::account(1000, 2), 1)],
        };
        assert_eq!(fixture.check(account), Err(EligibilityError::WrongAccount));
        assert_eq!(
            UnavailableEligibility.check(account),
            Err(EligibilityError::Unavailable)
        );
        assert!(SessionReference::new([0; 16]).is_err());
    }
}
