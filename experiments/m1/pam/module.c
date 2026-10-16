/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* EXPERIMENT ONLY: synthetic values; no broker, accounts, or credential storage. */
#define _DEFAULT_SOURCE
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdlib.h>
#include <string.h>
#include "fixture.h"

static struct fixture *state(pam_handle_t *pamh)
{
    const void *item = NULL;
    if (pam_get_item(pamh, PAM_CONV, &item) != PAM_SUCCESS || item == NULL)
        return NULL;
    return ((const struct pam_conv *)item)->appdata_ptr;
}

static int six_ascii_digits(const char *candidate)
{
    if (candidate == NULL || strlen(candidate) != 6)
        return 0;
    for (size_t i = 0; i < 6; ++i)
        if ((unsigned char)candidate[i] < '0' || (unsigned char)candidate[i] > '9')
            return 0;
    return 1;
}

static int capture(pam_handle_t *pamh, struct fixture *s)
{
    const void *previous = NULL;
    if (pam_get_item(pamh, PAM_AUTHTOK, &previous) != PAM_SUCCESS)
        return PAM_SYSTEM_ERR;
    if (previous != NULL)
        ++s->stale_token;
    /* Use PAM's allocator/conversation contract, then transfer a copy to PAM. */
    char *response = NULL;
    int rc = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &response, "Password: ");
    if (rc != PAM_SUCCESS || response == NULL) {
        if (response != NULL) {
            explicit_bzero(response, strlen(response));
            free(response);
        }
        return PAM_CONV_ERR;
    }
    int is_pin = six_ascii_digits(response);
    rc = pam_set_item(pamh, PAM_AUTHTOK, response);
    explicit_bzero(response, strlen(response));
    free(response);
    if (rc != PAM_SUCCESS)
        return rc;
    if (!is_pin)
        return PAM_IGNORE;
    if (s->eligibility_denied)
        return PAM_IGNORE;
    if (s->mode == FIXTURE_PIN_WRONG || s->mode == FIXTURE_PIN_OK)
        ++s->pin_attempts;
    switch (s->mode) {
    case FIXTURE_PIN_OK:
        return PAM_SUCCESS;
    case FIXTURE_PIN_WRONG:
        return PAM_AUTH_ERR;
    case FIXTURE_IDENTITY_MISMATCH:
    case FIXTURE_UNSUPPORTED_SERVICE:
        return PAM_PERM_DENIED;
    default:
        return PAM_IGNORE;
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
    (void)flags;
    struct fixture *s = state(pamh);
    if (s == NULL || argc != 1 || argv == NULL || argv[0] == NULL)
        return PAM_SYSTEM_ERR;
    if (strcmp(argv[0], "capture") == 0)
        return capture(pamh, s);
    if (strcmp(argv[0], "guard") == 0)
        return s->guard_denied ? PAM_PERM_DENIED : PAM_SUCCESS;
    if (strcmp(argv[0], "password") != 0)
        return PAM_SERVICE_ERR;
    ++s->password_calls;
    const char *token = NULL;
    /* Real Linux-PAM helper, same API used by pam_unix; not pam_unix evidence. */
    int rc = pam_get_authtok(pamh, PAM_AUTHTOK, &token, NULL);
    if (rc != PAM_SUCCESS)
        return rc;
    if (token == NULL || strcmp(token, s->password) != 0) {
        ++s->password_mismatch;
        return PAM_AUTH_ERR;
    }
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv)
{
    (void)flags;
    (void)argc;
    (void)argv;
    struct fixture *s = state(pamh);
    const void *token = NULL;
    if (s == NULL || pam_get_item(pamh, PAM_AUTHTOK, &token) != PAM_SUCCESS)
        return PAM_SYSTEM_ERR;
    ++s->setcred_calls;
    if (token != NULL)
        ++s->stale_token;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                int argc, const char **argv)
{
    (void)flags;
    (void)argc;
    (void)argv;
    struct fixture *s = state(pamh);
    if (s == NULL)
        return PAM_SYSTEM_ERR;
    ++s->account_calls;
    return s->eligibility_denied ? PAM_PERM_DENIED : PAM_SUCCESS;
}
