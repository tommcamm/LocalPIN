/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Disposable M7 VM only: actual kde PAM stack, repeated handle, private stdin. */
#define _DEFAULT_SOURCE
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

static unsigned char candidate[513];
static size_t length;
static int prompts;

static int conversation(int count, const struct pam_message **messages,
                        struct pam_response **responses, void *data)
{
    (void)data;
    if (count < 1 || count > 16 || !messages || !responses) return PAM_CONV_ERR;
    *responses = NULL;
    struct pam_response *out = calloc((size_t)count, sizeof(*out));
    if (!out) return PAM_BUF_ERR;
    for (int i = 0; i < count; ++i) {
        if (!messages[i]) goto fail;
        if (messages[i]->msg_style == PAM_PROMPT_ECHO_OFF && prompts == 0) {
            ++prompts;
            out[i].resp = calloc(length + 1, 1);
            if (!out[i].resp) goto fail;
            memcpy(out[i].resp, candidate, length);
        } else if (messages[i]->msg_style != PAM_TEXT_INFO &&
                   messages[i]->msg_style != PAM_ERROR_MSG) goto fail;
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

int main(void)
{
    const struct rlimit core = {0, 0};
    if (getuid() != 21061 || geteuid() != 21061 ||
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) || setrlimit(RLIMIT_CORE, &core)) return 2;
    struct pam_conv conv = {conversation, NULL};
    pam_handle_t *handle = NULL;
    if (pam_start("kde", "lp61test", &conv, &handle) != PAM_SUCCESS) return 77;
    unsigned calls = 0;
    for (;;) {
        unsigned char header[2];
        size_t n = fread(header, 1, sizeof(header), stdin);
        if (!n && feof(stdin)) break;
        if (n != 2 || ++calls > 32) return 2;
        length = (size_t)header[0] * 256 + header[1];
        if (length > 512 || fread(candidate, 1, length, stdin) != length ||
            memchr(candidate, 0, length)) return 2;
        prompts = 0;
        struct timespec before, after;
        if (clock_gettime(CLOCK_BOOTTIME, &before)) return 2;
        int auth = pam_authenticate(handle, 0);
        int cred = pam_setcred(handle, PAM_REFRESH_CRED);
        if (clock_gettime(CLOCK_BOOTTIME, &after)) return 2;
        long elapsed_ms = (after.tv_sec - before.tv_sec) * 1000 +
                          (after.tv_nsec - before.tv_nsec) / 1000000;
        explicit_bzero(candidate, sizeof(candidate));
        printf("{\"auth\":%d,\"setcred\":%d,\"prompts\":%d,\"elapsed_ms\":%ld}\n",
               auth, cred, prompts, elapsed_ms);
        fflush(stdout);
    }
    return pam_end(handle, PAM_SUCCESS) == PAM_SUCCESS ? 0 : 2;
}
