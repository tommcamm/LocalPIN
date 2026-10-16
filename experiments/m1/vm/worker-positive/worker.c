/* SPDX-License-Identifier: MIT OR Apache-2.0
 * VM TEST ONLY: fixed public credentials, own-user PAM, no enrollment grant. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CONF_DIR "/etc/localpin-m1-positive-pam"
#define TARGET "localpintest"
#define CORRECT "LocalPIN-M1-worker-public-fixture!"
#define WRONG "wrong-LocalPIN-M1-worker-fixture"

static void fail(const char *reason)
{
    fprintf(stderr, "M1 positive worker failure: %s\n", reason);
    exit(1);
}

static void identity(void)
{
    char context[256] = {0};
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        fail("context unavailable");
    ssize_t length = read(fd, context, sizeof(context) - 1);
    close(fd);
    char *first = strchr(context, ':');
    char *second = first ? strchr(first + 1, ':') : NULL;
    char *third = second ? strchr(second + 1, ':') : NULL;
    static const char expected[] = "localpin_m1_positive_t";
    if (length <= 0 || !second || !third || (size_t)(third - second - 1) != sizeof(expected) - 1 ||
        memcmp(second + 1, expected, sizeof(expected) - 1) != 0)
        fail("wrong confined process domain");
    struct passwd *account = getpwnam(TARGET);
    if (!account || account->pw_uid == 0 || getuid() != account->pw_uid || geteuid() != account->pw_uid)
        fail("worker must run as dedicated ordinary target UID");
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
    struct __user_cap_data_struct data[2] = {{0}};
    if (syscall(SYS_capget, &header, data) != 0 || data[0].effective || data[1].effective ||
        data[0].permitted || data[1].permitted || data[0].inheritable || data[1].inheritable)
        fail("ordinary worker must have no active capabilities");
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 0)
        fail("native setuid-helper baseline requires reviewed NNP setting");
    fd = open("/etc/shadow", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        close(fd);
        fail("worker unexpectedly opened shadow directly");
    }
    if (errno != EACCES && errno != EPERM)
        fail("shadow denial baseline unavailable");
}

struct conversation_state {
    const char *candidate;
    unsigned int prompts;
};

static int converse(int count, const struct pam_message **messages,
                    struct pam_response **responses, void *data)
{
    struct conversation_state *state = data;
    if (count < 1 || count > 16 || !messages || !responses || !state)
        return PAM_CONV_ERR;
    *responses = NULL;
    struct pam_response *result = calloc((size_t)count, sizeof(*result));
    if (!result)
        return PAM_BUF_ERR;
    for (int index = 0; index < count; ++index) {
        if (!messages[index])
            goto error;
        if (messages[index]->msg_style == PAM_PROMPT_ECHO_OFF) {
            if (++state->prompts > 1 || !state->candidate)
                goto error;
            result[index].resp = strdup(state->candidate);
            if (!result[index].resp)
                goto error;
        } else if (messages[index]->msg_style != PAM_TEXT_INFO && messages[index]->msg_style != PAM_ERROR_MSG) {
            goto error;
        }
    }
    *responses = result;
    return PAM_SUCCESS;
error:
    for (int index = 0; index < count; ++index) {
        if (result[index].resp) {
            explicit_bzero(result[index].resp, strlen(result[index].resp));
            free(result[index].resp);
        }
    }
    free(result);
    return PAM_CONV_ERR;
}

int main(int argc, char **argv)
{
    alarm(18);
    if (argc != 2)
        fail("one fixed public test case required");
    const char *name = argv[1];
    const char *service = "worker";
    struct conversation_state state = {.candidate = CORRECT};
    int expected_auth = PAM_SUCCESS, expected_account = PAM_SUCCESS;
    unsigned int expected_prompts = 1;
    if (!strcmp(name, "permit")) {
        service = "permit";
        state.candidate = NULL;
        expected_prompts = 0;
    } else if (!strcmp(name, "deny")) {
        service = "deny";
        state.candidate = NULL;
        expected_auth = PAM_AUTH_ERR;
        expected_account = -1;
        expected_prompts = 0;
    } else if (!strcmp(name, "wrong")) {
        state.candidate = WRONG;
        expected_auth = PAM_AUTH_ERR;
        expected_account = -1;
    } else if (!strcmp(name, "locked")) {
        expected_auth = PAM_AUTH_ERR;
        expected_account = -1;
    } else if (!strcmp(name, "expired-account")) {
        expected_account = PAM_ACCT_EXPIRED;
    } else if (!strcmp(name, "expired-password")) {
        expected_account = PAM_NEW_AUTHTOK_REQD;
    } else if (strcmp(name, "correct") && strcmp(name, "recovery")) {
        fail("unknown public test case");
    }
    identity();
    struct pam_conv conv = {.conv = converse, .appdata_ptr = &state};
    pam_handle_t *handle = NULL;
    if (pam_start_confdir(service, TARGET, &conv, CONF_DIR, &handle) != PAM_SUCCESS)
        fail("private PAM start");
    int auth = pam_authenticate(handle, 0);
    int account = auth == PAM_SUCCESS ? pam_acct_mgmt(handle, 0) : -1;
    int ended = pam_end(handle, auth);
    /* Numeric outcomes and a fixed public case name only; never a candidate. */
    printf("M1 positive result case=%s auth=%d account=%d prompts=%u\n",
           name, auth, account, state.prompts);
    if (auth != expected_auth || account != expected_account || state.prompts != expected_prompts || ended != PAM_SUCCESS)
        fail("PAM result assertion");
    return 0;
}
