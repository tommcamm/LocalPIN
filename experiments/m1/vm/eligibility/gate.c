/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Root-private test gate, not a PIN verifier or installable KDE module. */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <string.h>
#include <unistd.h>
#include "state.h"
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc, const char **argv)
{
    (void)flags; (void)argv;
    const void *service = NULL, *conversation = NULL;
    if (getuid() || geteuid() || argc ||
        pam_get_item(handle, PAM_SERVICE, &service) != PAM_SUCCESS || service == NULL ||
        strcmp(service, "localpin-m1-gated") ||
        pam_get_item(handle, PAM_CONV, &conversation) != PAM_SUCCESS || conversation == NULL)
        return PAM_PERM_DENIED;
    struct eligibility_fixture *state = ((const struct pam_conv *)conversation)->appdata_ptr;
    return state && state->marker == ELIGIBILITY_FIXTURE_MARKER && state->eligible
        ? PAM_SUCCESS : PAM_PERM_DENIED;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *handle, int flags, int argc, const char **argv)
{
    (void)handle; (void)flags; (void)argc; (void)argv;
    return PAM_IGNORE;
}
