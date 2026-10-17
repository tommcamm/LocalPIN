/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Test fixture only: never install this permissive synthetic password module. */
#define _DEFAULT_SOURCE
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <string.h>
#include "fixture.h"

static struct fixture *state(pam_handle_t *pamh)
{
    const void *item = NULL;
    if (pam_get_item(pamh, PAM_CONV, &item) != PAM_SUCCESS || item == NULL)
        return NULL;
    return ((const struct pam_conv *)item)->appdata_ptr;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv)
{
    (void)flags;
    struct fixture *s = state(pamh);
    if (s == NULL || argc != 1 || argv == NULL)
        return PAM_SYSTEM_ERR;
    if (strcmp(argv[0], "inspect") == 0) {
        const void *token = NULL;
        if (pam_get_item(pamh, PAM_AUTHTOK, &token) != PAM_SUCCESS)
            return PAM_SYSTEM_ERR;
        s->stale_tokens += token != NULL;
        return PAM_IGNORE;
    }
    if (strcmp(argv[0], "guard") == 0)
        return s->guard_denied ? PAM_PERM_DENIED : PAM_SUCCESS;
    if (strcmp(argv[0], "password") != 0)
        return PAM_SERVICE_ERR;
    ++s->password_calls;
    const char *token = NULL;
    int rc = pam_get_authtok(pamh, PAM_AUTHTOK, &token, NULL);
    if (rc != PAM_SUCCESS)
        return rc;
    if (token == NULL || strcmp(token, s->password) != 0) {
        ++s->password_failures;
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
    s->stale_tokens += token != NULL;
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
    return s->account_denied ? PAM_PERM_DENIED : PAM_SUCCESS;
}
