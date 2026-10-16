/* SPDX-License-Identifier: MIT OR Apache-2.0
 * Private session-only fixture module. No authentication entrypoint exists. */
#include <security/pam_modules.h>
PAM_EXTERN int pam_sm_open_session(pam_handle_t *handle, int flags, int argc, const char **argv)
{
    (void)flags; (void)argv;
    if (argc != 0)
        return PAM_SESSION_ERR;
    /* pam_systemd v259 consumes NUL-terminated strings for these module data.
       pam_set_data is intentionally called here, never from the application. */
    if (pam_set_data(handle, "systemd.runtime_max_sec", (void *)"45s", 0) != PAM_SUCCESS ||
        pam_set_data(handle, "systemd.tasks_max", (void *)"8", 0) != PAM_SUCCESS ||
        pam_set_data(handle, "systemd.memory_max", (void *)"64M", 0) != PAM_SUCCESS)
        return PAM_SESSION_ERR;
    return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *handle, int flags, int argc, const char **argv)
{
    (void)handle; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
