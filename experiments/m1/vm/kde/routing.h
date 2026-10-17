/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Observation only: live sd-login discovery inside the actual stock greeter.
 * No PIN, grant, broker, process-attestation or authentication success path. */
#ifndef LOCALPIN_M1_KDE_ROUTING_H
#define LOCALPIN_M1_KDE_ROUTING_H
#include <errno.h>
#include <strings.h>
#include <systemd/sd-login.h>

static int localpin_m1_session_candidate(const char *session, uid_t uid)
{
    uid_t owner = 0;
    char *seat = NULL, *type = NULL, *clazz = NULL, *state = NULL, *desktop = NULL;
    int eligible = -1;
    if (sd_session_get_uid(session, &owner) < 0) goto done;
    if (owner != uid || uid == 0) { eligible = 0; goto done; }
    if (sd_session_get_class(session, &clazz) < 0 || clazz == NULL) goto done;
    if (strcmp(clazz, "user")) { eligible = 0; goto done; }
    int remote = sd_session_is_remote(session);
    if (remote < 0) goto done;
    if (remote != 0) { eligible = 0; goto done; }
    if (sd_session_get_type(session, &type) < 0 || type == NULL) goto done;
    if (strcmp(type, "wayland") && strcmp(type, "x11")) { eligible = 0; goto done; }
    if (sd_session_get_state(session, &state) < 0 || state == NULL) goto done;
    if (strcmp(state, "online") && strcmp(state, "active")) { eligible = 0; goto done; }
    if (sd_session_get_seat(session, &seat) < 0 || seat == NULL || !*seat) goto done;
    if (sd_session_get_desktop(session, &desktop) < 0 || desktop == NULL) goto done;
    eligible = !strcasecmp(desktop, "kde") || !strcasecmp(desktop, "plasma") || !strcasecmp(desktop, "plasmax11");
done:
    free(seat); free(type); free(clazz); free(state); free(desktop);
    return eligible;
}

static void localpin_m1_routing(pam_handle_t *pamh)
{
    char *direct = NULL, **sessions = NULL;
    uid_t owner = 0, uid = getuid();
    int direct_rc = sd_pid_get_session(0, &direct);
    int owner_rc = sd_pid_get_owner_uid(0, &owner);
    int count = 0, enumerated = sd_uid_get_sessions(uid, 0, &sessions);
    int complete = enumerated >= 0 && enumerated <= 128;
    if (complete) {
        for (int i = 0; i < enumerated; ++i) {
            if (sessions == NULL || sessions[i] == NULL) { complete = 0; break; }
            int candidate = localpin_m1_session_candidate(sessions[i], uid);
            if (candidate < 0) { complete = 0; break; }
            count += candidate;
        }
    }
    /* Fixed numeric decisions: 0 unavailable, 1 direct eligible, 2 unique
     * verified user-manager candidate. They never authorize authentication. */
    int decision = 0;
    if (direct_rc >= 0 && direct != NULL)
        decision = localpin_m1_session_candidate(direct, uid) == 1 ? 1 : 0;
    else if (direct_rc == -ENODATA && owner_rc >= 0 && owner == uid && complete && count == 1)
        decision = 2;
    pam_syslog(pamh, LOG_NOTICE,
        "LocalPIN M1 routing direct_rc=%d owner_rc=%d owner_match=%d enumeration_complete=%d candidates=%d decision=%d",
        direct_rc, owner_rc, owner_rc >= 0 && owner == uid, complete, complete ? count : -1, decision);
    if (sessions != NULL) { for (char **p = sessions; *p != NULL; ++p) free(*p); free(sessions); }
    free(direct);
}
#endif
