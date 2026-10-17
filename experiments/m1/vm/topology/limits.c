/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Clone-only session limits; no authentication entrypoint. */
#include <security/pam_modules.h>
PAM_EXTERN int pam_sm_open_session(pam_handle_t *handle, int flags, int argc, const char **argv)
{
    (void)flags; (void)argv;
    if (argc || pam_set_data(handle, "systemd.runtime_max_sec", (void *)"15min", 0) != PAM_SUCCESS ||
        pam_set_data(handle, "systemd.tasks_max", (void *)"1024", 0) != PAM_SUCCESS ||
        pam_set_data(handle, "systemd.memory_max", (void *)"3G", 0) != PAM_SUCCESS)
        return PAM_SESSION_ERR;
    return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *handle, int flags, int argc, const char **argv)
{
    (void)handle; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
