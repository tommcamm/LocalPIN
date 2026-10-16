/* SPDX-License-Identifier: MIT OR Apache-2.0 */
#ifndef LOCALPIN_M1_PAM_FIXTURE_H
#define LOCALPIN_M1_PAM_FIXTURE_H

#include <stddef.h>

/* Synthetic test-only state, shared through PAM_CONV.appdata_ptr. Never ship. */
struct fixture {
    const char *user;
    const char *candidate;
    const char *password;
    int cancel;
    int mode;
    int eligibility_denied;
    int guard_denied;
    int prompts;
    int pin_attempts;
    int password_calls;
    int account_calls;
    int setcred_calls;
    int stale_token;
    int password_mismatch;
};

enum fixture_mode {
    FIXTURE_PIN_OK,
    FIXTURE_PIN_WRONG,
    FIXTURE_COOLDOWN,
    FIXTURE_DISABLED,
    FIXTURE_NOT_ENROLLED,
    FIXTURE_BROKER_DOWN,
    FIXTURE_TIMEOUT,
    FIXTURE_CORRUPT,
    FIXTURE_IDENTITY_MISMATCH,
    FIXTURE_UNSUPPORTED_SERVICE,
};

#endif
