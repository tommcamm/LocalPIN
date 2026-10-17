/* SPDX-License-Identifier: MIT OR Apache-2.0 */
#ifndef LOCALPIN_PAM_TEST_FIXTURE_H
#define LOCALPIN_PAM_TEST_FIXTURE_H

/* Synthetic, test-only state shared through the real Linux-PAM conversation. */
struct fixture {
    void *pamh;
    char *candidate;
    char *password;
    int cancel;
    int guard_denied;
    int account_denied;
    int prompts;
    int password_calls;
    int password_failures;
    int setcred_calls;
    int account_calls;
    int stale_tokens;
    int mutation;
};
#endif
