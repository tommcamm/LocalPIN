use super::*;
use localpin_core::{
    limits::{MAX_KDF_KIB, WorkPermit},
    throttle::{AttemptResponse, DurableThrottleStore, RestoredThrottle, Throttle, ThrottleRecord},
    types::{BootId, Incarnation, TimePoint, Uid, Unavailable},
};

const PHC: &str = "$argon2id$v=19$m=65536,t=3,p=1$BwcHBwcHBwcHBwcHBwcHBw$CUNrJW+K3R42xrH7g4MDA7wv0ihz8Hcf0glJGhH5HZ4";

fn account() -> AccountId {
    AccountId {
        uid: Uid::new(1000).unwrap(),
        incarnation: Incarnation::new([1; 16]).unwrap(),
    }
}

fn generation() -> Generation {
    Generation::new(1).unwrap()
}

fn now() -> TimePoint {
    TimePoint {
        boot: BootId::new([1; 16]).unwrap(),
        millis: 0,
    }
}

fn record() -> CredentialRecord {
    CredentialRecord::new(account(), generation(), Backend::Software, PHC.as_bytes()).unwrap()
}

struct FixedRandom;

impl Randomness for FixedRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), Unavailable> {
        destination.fill(7);
        Ok(())
    }
}

#[test]
fn independent_argon2id_v19_known_answers_include_leading_zeroes() {
    // Independently generated with the reference libargon2 argon2_hash API:
    // type=2, version=0x13, memory=65536, passes=3, lanes=1, output length=32.
    let vectors = [
        (
            b"000001",
            std::array::from_fn(|index| index as u8),
            "c23601e2e8a339c6ec92dfc1782b67ebac1ac0ca8c9c5f538806ce5307156a0d",
        ),
        (
            b"123456",
            [7; 16],
            "09436b256f8add1e36c6b1fb83830303bc2fd22873f0771fd209491a11f91d9e",
        ),
    ];
    let budget = ResourceBudget::default();
    for (bytes, salt, expected) in vectors {
        let work = budget
            .try_work(
                account().uid,
                KdfParameters::ENROLLMENT,
                WorkKind::TpmPinDerivation,
            )
            .unwrap();
        let actual = derive(
            &Pin::parse(bytes).unwrap(),
            &salt,
            KdfParameters::ENROLLMENT,
            &work,
        )
        .unwrap();
        let expected: Vec<u8> = expected
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(actual.expose().as_slice(), expected);
    }
}

#[test]
fn software_enrollment_is_exact_canonical_phc_and_trial_checks_candidate() {
    let budget = ResourceBudget::default();
    let pin = Pin::parse(b"123456").unwrap();
    let enrolled =
        enroll_with_random(account(), generation(), &pin, &budget, &mut FixedRandom).unwrap();
    assert_eq!(enrolled.account(), account());
    assert_eq!(enrolled.generation(), generation());
    assert_eq!(enrolled.backend(), Backend::Software);
    assert_eq!(enrolled.payload(), PHC.as_bytes());
    let parsed = SoftwareVerifier::new(&enrolled).unwrap();
    assert_eq!(parsed.parameters(), KdfParameters::ENROLLMENT);
    assert!(validate_enrollment(&enrolled, &pin, &budget).unwrap());
    assert!(!validate_enrollment(&enrolled, &Pin::parse(b"000001").unwrap(), &budget).unwrap());
    assert!(!format!("{enrolled:?}").contains("CUNrJW"));
}

#[test]
fn phc_bounds_are_checked_without_any_kdf() {
    for (memory, passes, lanes) in [(65536, 3, 1), (262144, 6, 1), (65537, 4, 1)] {
        let candidate = PHC.replace(
            "m=65536,t=3,p=1",
            &format!("m={memory},t={passes},p={lanes}"),
        );
        let parsed = Parsed::parse(candidate.as_bytes()).unwrap();
        assert_eq!(
            parsed.parameters,
            KdfParameters::new(memory, passes, lanes).unwrap()
        );
    }
    for costs in [
        "m=65535,t=3,p=1",
        "m=262145,t=3,p=1",
        "m=65536,t=2,p=1",
        "m=65536,t=7,p=1",
        "m=65536,t=3,p=0",
        "m=65536,t=3,p=2",
        "m=4294967295,t=3,p=1",
        "m=999999999999999999999,t=3,p=1",
        "m=065536,t=3,p=1",
        "m=65536,t=03,p=1",
        "m=65536,t=3,p=01",
        "m=+65536,t=3,p=1",
        "m=65536,t=3,p=1,foo=1",
        "m=65536,t=3,p=1,m=65536",
        "t=3,m=65536,p=1",
        "m=65536,t=3",
        "m=65536,,p=1",
        "m=65536,t=3,p=1 ",
    ] {
        assert!(
            Parsed::parse(PHC.replace("m=65536,t=3,p=1", costs).as_bytes()).is_err(),
            "{costs}"
        );
    }
}

#[test]
fn malformed_and_noncanonical_phc_is_refused_before_admission() {
    let budget = ResourceBudget::default();
    let _all_memory = budget
        .try_work(
            Uid::new(2000).unwrap(),
            KdfParameters::new(MAX_KDF_KIB, 6, 1).unwrap(),
            WorkKind::Enrollment,
        )
        .unwrap();
    let mut malformed = vec![
        PHC.replace("argon2id", "argon2i"),
        PHC.replace("argon2id", "argon2d"),
        PHC.replace("v=19", "v=16"),
        PHC.replace("v=19", "v=019"),
        PHC.replace("$v=19", ""),
        format!("{PHC}$"),
        format!(" {PHC}"),
        PHC.replace("BwcHBwcHBwcHBwcHBwcHBw", "BwcHBwcHBwcHBwcHBwcHBw=="),
        PHC.replace("BwcHBwcHBwcHBwcHBwcHBw", "BwcHBwcHBwcHBwcHBwcHBx"),
        PHC.replace("BwcHBwcHBwcHBwcHBwcHBw", "BwcHBwcHBwcHBwcHBwcH_w"),
        PHC.replace(
            "CUNrJW+K3R42xrH7g4MDA7wv0ihz8Hcf0glJGhH5HZ4",
            "CUNrJW+K3R42xrH7g4MDA7wv0ihz8Hcf0glJGhH5HZ5",
        ),
        "x".repeat(MAX_PHC_BYTES + 1),
    ];
    for length in 0..PHC.len() {
        malformed.push(PHC[..length].to_owned());
    }
    for payload in malformed {
        if payload.is_empty() {
            assert!(
                CredentialRecord::new(
                    account(),
                    generation(),
                    Backend::Software,
                    payload.as_bytes()
                )
                .is_err()
            );
            continue;
        }
        let bad = CredentialRecord::new(
            account(),
            generation(),
            Backend::Software,
            payload.as_bytes(),
        )
        .unwrap();
        assert!(matches!(
            SoftwareVerifier::new(&bad),
            Err(Error::InvalidRecord)
        ));
        assert_eq!(
            validate_enrollment(&bad, &Pin::parse(b"123456").unwrap(), &budget),
            Err(Error::InvalidRecord)
        );
    }
    assert!(Parsed::parse(&[0xff; 97]).is_err());
}

#[test]
fn entropy_failure_aborts_even_after_a_partial_fill_and_releases_admission() {
    struct FailingRandom;
    impl Randomness for FailingRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), Unavailable> {
            destination[..3].fill(7);
            Err(Unavailable)
        }
    }
    let budget = ResourceBudget::default();
    assert!(matches!(
        enroll_with_random(
            account(),
            generation(),
            &Pin::parse(b"123456").unwrap(),
            &budget,
            &mut FailingRandom
        ),
        Err(Error::Entropy)
    ));
    assert!(
        budget
            .try_work(
                account().uid,
                KdfParameters::ENROLLMENT,
                WorkKind::Enrollment
            )
            .is_ok()
    );
}

#[test]
fn enrollment_refuses_capacity_before_requesting_entropy() {
    struct NoEntropyCall;
    impl Randomness for NoEntropyCall {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), Unavailable> {
            panic!("refused work must not request entropy")
        }
    }
    let budget = ResourceBudget::default();
    let _occupied = budget
        .try_work(
            account().uid,
            KdfParameters::ENROLLMENT,
            WorkKind::Verification,
        )
        .unwrap();
    assert!(matches!(
        enroll_with_random(
            account(),
            generation(),
            &Pin::parse(b"123456").unwrap(),
            &budget,
            &mut NoEntropyCall
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(
        validate_enrollment(&record(), &Pin::parse(b"123456").unwrap(), &budget),
        Err(Error::Capacity)
    );
}

#[test]
fn shared_derivation_refuses_parameters_not_charged_by_permit() {
    let budget = ResourceBudget::default();
    let work = budget
        .try_work(
            account().uid,
            KdfParameters::ENROLLMENT,
            WorkKind::Enrollment,
        )
        .unwrap();
    assert!(matches!(
        derive(
            &Pin::parse(b"123456").unwrap(),
            &[7; 16],
            KdfParameters::new(131072, 3, 1).unwrap(),
            &work
        ),
        Err(Error::Binding)
    ));
}

#[test]
fn a_live_derivation_refuses_reentrant_and_concurrent_use_of_the_same_permit() {
    let budget = ResourceBudget::default();
    let work = budget
        .try_work(
            account().uid,
            KdfParameters::ENROLLMENT,
            WorkKind::Enrollment,
        )
        .unwrap();
    let active = work.try_derivation().unwrap();
    let pin = Pin::parse(b"123456").unwrap();
    assert!(matches!(
        derive(&pin, &[7; 16], KdfParameters::ENROLLMENT, &work),
        Err(Error::Capacity)
    ));
    std::thread::scope(|scope| {
        let result = scope
            .spawn(|| derive(&pin, &[7; 16], KdfParameters::ENROLLMENT, &work))
            .join()
            .unwrap();
        assert!(matches!(result, Err(Error::Capacity)));
    });
    drop(active);
    assert!(work.try_derivation().is_ok());
}

struct Store(ThrottleRecord);

impl DurableThrottleStore for Store {
    type Error = ();
    fn commit(
        &mut self,
        expected: &ThrottleRecord,
        replacement: &ThrottleRecord,
    ) -> Result<(), ()> {
        assert_eq!(&self.0, expected);
        self.0 = *replacement;
        Ok(())
    }
}

fn response(
    verifier: &mut SoftwareVerifier<'_>,
    account: AccountId,
    generation: Generation,
    backend: Backend,
    parameters: KdfParameters,
    pin: &[u8],
) -> AttemptResponse {
    let mut store = Store(ThrottleRecord::initial(account, generation, now()));
    let RestoredThrottle::Ready(mut throttle) =
        Throttle::restore(store.0, account, generation, now()).unwrap()
    else {
        panic!("fresh fixture")
    };
    let reservation = throttle.reserve(now()).unwrap().commit(&mut store).unwrap();
    let budget = ResourceBudget::default();
    let kind = match backend {
        Backend::Software => WorkKind::Verification,
        Backend::Tpm2 => WorkKind::TpmPinDerivation,
    };
    let work: WorkPermit = budget.try_work(account.uid, parameters, kind).unwrap();
    let job = VerificationJob::new(
        reservation,
        backend,
        Pin::parse(pin).unwrap(),
        work,
        parameters,
    )
    .unwrap();
    let completion = verifier.verify(job);
    // The finished KDF still retains its lease until durable completion starts.
    assert!(budget.try_work(account.uid, parameters, kind).is_err());
    let intent = completion.complete(now()).unwrap();
    assert!(budget.try_work(account.uid, parameters, kind).is_ok());
    intent
        .commit(&mut store, account, Some(generation))
        .unwrap()
}

#[test]
fn verifier_consumes_jobs_and_returns_match_or_mismatch_only_after_real_kdf() {
    let record = record();
    let mut verifier = SoftwareVerifier::new(&record).unwrap();
    assert_eq!(
        response(
            &mut verifier,
            account(),
            generation(),
            Backend::Software,
            KdfParameters::ENROLLMENT,
            b"123456"
        ),
        AttemptResponse::Success
    );
    assert_eq!(
        response(
            &mut verifier,
            account(),
            generation(),
            Backend::Software,
            KdfParameters::ENROLLMENT,
            b"000001"
        ),
        AttemptResponse::Mismatch
    );
}

#[test]
fn verifier_binds_uid_incarnation_generation_backend_and_exact_work() {
    let record = record();
    let mut verifier = SoftwareVerifier::new(&record).unwrap();
    let technical = AttemptResponse::Unavailable(BackendFailure::Technical);
    for wrong_account in [
        AccountId {
            uid: Uid::new(1001).unwrap(),
            ..account()
        },
        AccountId {
            incarnation: Incarnation::new([2; 16]).unwrap(),
            ..account()
        },
    ] {
        assert_eq!(
            response(
                &mut verifier,
                wrong_account,
                generation(),
                Backend::Software,
                KdfParameters::ENROLLMENT,
                b"123456"
            ),
            technical
        );
    }
    assert_eq!(
        response(
            &mut verifier,
            account(),
            Generation::new(2).unwrap(),
            Backend::Software,
            KdfParameters::ENROLLMENT,
            b"123456"
        ),
        technical
    );
    assert_eq!(
        response(
            &mut verifier,
            account(),
            generation(),
            Backend::Tpm2,
            KdfParameters::ENROLLMENT,
            b"123456"
        ),
        technical
    );
    assert_eq!(
        response(
            &mut verifier,
            account(),
            generation(),
            Backend::Software,
            KdfParameters::new(131072, 3, 1).unwrap(),
            b"123456"
        ),
        technical
    );
    let tpm =
        CredentialRecord::new(account(), generation(), Backend::Tpm2, PHC.as_bytes()).unwrap();
    assert!(matches!(SoftwareVerifier::new(&tpm), Err(Error::Binding)));
}
