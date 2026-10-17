/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Disposable VM UI experiment. This module NEVER authorizes authentication. */
#ifdef LOCALPIN_M1_CONTACT_FIXTURE
#define _GNU_SOURCE
#else
#define _DEFAULT_SOURCE
#endif
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#ifdef LOCALPIN_M1_CONTACT_FIXTURE
#include "contact.h"
#endif
#ifdef LOCALPIN_M1_ROUTING_FIXTURE
#include "routing.h"
#endif

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags;
    (void)argv;
    const void *service = NULL;
    const void *user = NULL;
    if (argc != 0 || pamh == NULL ||
        pam_get_item(pamh, PAM_SERVICE, &service) != PAM_SUCCESS || service == NULL ||
        strcmp(service, "kde") != 0 ||
        pam_get_item(pamh, PAM_USER, &user) != PAM_SUCCESS || user == NULL ||
        strcmp(user, "localpintest") != 0)
        return PAM_IGNORE;
    struct passwd entry;
    struct passwd *resolved = NULL;
    char account_buffer[16384];
    if (getpwnam_r("localpintest", &entry, account_buffer, sizeof(account_buffer), &resolved) != 0 ||
        resolved == NULL || entry.pw_uid < 1000 || getuid() != entry.pw_uid || geteuid() != entry.pw_uid)
        return PAM_IGNORE;
#ifdef LOCALPIN_M1_ROUTING_FIXTURE
    localpin_m1_routing(pamh);
#endif
#ifdef LOCALPIN_M1_CONTACT_FIXTURE
    int contact_outcome = localpin_m1_contact();
    char observed_type[129];
    localpin_m1_current_type(observed_type);
    pam_syslog(pamh, LOG_NOTICE, "LocalPIN M1 fallback contact outcome=%d selinux_type=%s",
               contact_outcome, observed_type);
#endif
    char *response = NULL;
    int rc = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &response, "%s", "Password: ");
    if (rc == PAM_SUCCESS && response != NULL) {
        int item_result = pam_set_item(pamh, PAM_AUTHTOK, response);
        pam_syslog(pamh, LOG_NOTICE, "LocalPIN M1 fallback capture set_item=%d", item_result);
    }
    if (response != NULL) {
        explicit_bzero(response, strlen(response));
        free(response);
    }
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_IGNORE;
}
