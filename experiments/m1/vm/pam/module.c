/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* VM TEST ONLY. A deliberately naive PIN success fixture; never install it. */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include "common.h"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags;
    const void *item = NULL;
    if (argc != 1 || argv == NULL || argv[0] == NULL ||
        pam_get_item(pamh, PAM_CONV, &item) != PAM_SUCCESS || item == NULL)
        return PAM_SYSTEM_ERR;
    struct vm_conversation *s = ((const struct pam_conv *)item)->appdata_ptr;
    if (s == NULL)
        return PAM_SYSTEM_ERR;
    ++s->module_calls;
    const char *candidate = NULL;
    int rc = pam_get_authtok(pamh, PAM_AUTHTOK, &candidate, NULL);
    if (rc != PAM_SUCCESS || candidate == NULL)
        return PAM_IGNORE;
    if (strcmp(argv[0], "capture") == 0)
        return PAM_IGNORE;
    if (strcmp(argv[0], "naive") != 0)
        return PAM_SERVICE_ERR;
    if (strlen(candidate) != 6)
        return PAM_IGNORE;
    for (size_t i = 0; i < 6; ++i)
        if (candidate[i] < '0' || candidate[i] > '9')
            return PAM_IGNORE;
    /* Intentionally incomplete: demonstrates the account-policy bypass. */
    ++s->pin_success;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
