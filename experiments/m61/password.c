/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Disposable-VM evidence only. Fixed real PAM services, private stdin candidate. */
#define _DEFAULT_SOURCE
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>

static unsigned char candidate[513];
static size_t length;
static int prompts;

static int conversation(int count, const struct pam_message **messages,
                        struct pam_response **responses, void *data) {
    (void)data;
    if (count < 1 || count > 16 || !messages || !responses)
        return PAM_CONV_ERR;
    struct pam_response *out = calloc((size_t)count, sizeof(*out));
    if (!out) return PAM_BUF_ERR;
    for (int i = 0; i < count; ++i) {
        if (messages[i]->msg_style == PAM_PROMPT_ECHO_OFF && prompts == 0) {
            ++prompts;
            out[i].resp = calloc(length + 1, 1);
            if (!out[i].resp) goto fail;
            memcpy(out[i].resp, candidate, length);
        } else if (messages[i]->msg_style != PAM_TEXT_INFO &&
                   messages[i]->msg_style != PAM_ERROR_MSG) {
            goto fail;
        }
    }
    *responses = out;
    return PAM_SUCCESS;
fail:
    for (int i = 0; i < count; ++i) {
        if (out[i].resp) { explicit_bzero(out[i].resp, strlen(out[i].resp)); free(out[i].resp); }
    }
    free(out);
    return PAM_CONV_ERR;
}

int main(int argc, char **argv) {
    const struct rlimit core = {0, 0};
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) || setrlimit(RLIMIT_CORE, &core)) return 2;
    if (argc != 3 || (strcmp(argv[1], "original") && strcmp(argv[1], "enroll"))) return 2;
    length = fread(candidate, 1, sizeof(candidate), stdin);
    if (!length || length > 512 || memchr(candidate, 0, length)) return 2;
    struct pam_conv conv = {conversation, NULL};
    pam_handle_t *handle = NULL;
    int start = pam_start(!strcmp(argv[1], "original") ? "kde" : "localpin-enroll",
                         argv[2], &conv, &handle);
    int auth = start;
    int account = -1;
    int ended = -1;
    if (start == PAM_SUCCESS) {
        auth = pam_authenticate(handle, PAM_DISALLOW_NULL_AUTHTOK);
        if (auth == PAM_SUCCESS) account = pam_acct_mgmt(handle, 0);
        ended = pam_end(handle, auth == PAM_SUCCESS ? account : auth);
    }
    explicit_bzero(candidate, sizeof(candidate));
    printf("{\"start\":%d,\"auth\":%d,\"account\":%d,\"end\":%d,\"prompts\":%d}\n",
           start, auth, account, ended, prompts);
    return 0;
}
