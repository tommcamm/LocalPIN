/* SPDX-License-Identifier: MIT OR Apache-2.0 */
#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "fixture.h"

static int conversation(int n, const struct pam_message **messages,
                        struct pam_response **responses, void *data)
{
    struct fixture *s = data;
    if (n <= 0 || n > 32 || messages == NULL || responses == NULL || s == NULL)
        return PAM_CONV_ERR;
    *responses = NULL;
    struct pam_response *r = calloc((size_t)n, sizeof(*r));
    if (r == NULL)
        return PAM_BUF_ERR;
    for (int i = 0; i < n; ++i) {
        if (messages[i] == NULL)
            goto fail;
        switch (messages[i]->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
            ++s->prompts;
            if (s->cancel == 1 || s->prompts > 1)
                goto fail;
            r[i].resp = strdup(s->candidate);
            if (r[i].resp == NULL)
                goto fail;
            if (s->cancel == 3)
                r[i].resp_retcode = 1;
            if (s->cancel == 4) {
                explicit_bzero(r[i].resp, strlen(r[i].resp));
                free(r[i].resp);
                r[i].resp = NULL;
            }
            break;
        case PAM_TEXT_INFO:
        case PAM_ERROR_MSG:
            break;
        default:
            goto fail;
        }
    }
    if (s->mutation != 0 && pam_set_item(s->pamh,
            s->mutation == 1 ? PAM_USER : PAM_SERVICE,
            s->mutation == 1 ? "other" : "login") != PAM_SUCCESS)
        goto fail;
    *responses = r;
    if (s->cancel == 2) {
        /* pam_conv(3) leaves resource cleanup with the application on error.
         * It does not promise a NULL output pointer. Leave the freed pointer
         * in *responses: a module must check the error before inspecting it. */
        for (int i = 0; i < n; ++i) {
            if (r[i].resp != NULL) {
                explicit_bzero(r[i].resp, strlen(r[i].resp));
                free(r[i].resp);
            }
        }
        free(r);
        return PAM_CONV_ERR;
    }
    return PAM_SUCCESS;
fail:
    for (int i = 0; i < n; ++i) {
        if (r[i].resp != NULL) {
            explicit_bzero(r[i].resp, strlen(r[i].resp));
            free(r[i].resp);
        }
    }
    free(r);
    return PAM_CONV_ERR;
}

static char *decode(const char *hex)
{
    if (strcmp(hex, "-") == 0)
        return strdup("");
    size_t size = strlen(hex);
    if (size % 2 != 0 || size > 65536)
        exit(77);
    char *result = calloc(size / 2 + 1, 1);
    if (result == NULL)
        exit(77);
    for (size_t i = 0; i < size; i += 2) {
        unsigned int value;
        if (sscanf(hex + i, "%2x", &value) != 1 || value == 0)
            exit(77);
        result[i / 2] = (char)value;
    }
    return result;
}

int main(int argc, char **argv)
{
    if (argc != 4)
        return 77;
    /* Exercise the rejection of real/effective UID mismatch without host root. */
    if (strcmp(argv[3], "mixed") == 0 && setresuid(1000, 0, 0) != 0)
        return 77;
    struct fixture s = {0};
    struct pam_conv conv = {conversation, &s};
    pam_handle_t *pamh = NULL;
    int rc = pam_start(argv[1], argv[2], &conv, &pamh);
    if (rc != PAM_SUCCESS)
        return 77;
    s.pamh = pamh;
    char *line = NULL;
    size_t capacity = 0;
    while (getline(&line, &capacity, stdin) > 0) {
        char candidate[65537], password[65537];
        if (sscanf(line, "%65536s %65536s %d %d %d %d", candidate, password,
                   &s.cancel, &s.guard_denied, &s.account_denied, &s.mutation) != 6)
            return 77;
        s.candidate = decode(candidate);
        s.password = decode(password);
        s.prompts = s.password_calls = s.setcred_calls = 0;
        s.account_calls = s.stale_tokens = 0;
        int before = s.password_failures;
        rc = pam_authenticate(pamh, 0);
        int cred = pam_setcred(pamh, PAM_REFRESH_CRED);
        int account = pam_acct_mgmt(pamh, 0);
        printf("{\"rc\":%d,\"cred\":%d,\"account\":%d,\"prompts\":%d,"
               "\"password_calls\":%d,\"password_failures\":%d,"
               "\"new_password_failures\":%d,\"setcred_calls\":%d,"
               "\"account_calls\":%d,\"stale_tokens\":%d}\n",
               rc, cred, account, s.prompts, s.password_calls,
               s.password_failures, s.password_failures - before,
               s.setcred_calls, s.account_calls, s.stale_tokens);
        fflush(stdout);
        explicit_bzero(s.candidate, strlen(s.candidate));
        explicit_bzero(s.password, strlen(s.password));
        free(s.candidate);
        free(s.password);
    }
    free(line);
    return pam_end(pamh, rc) == PAM_SUCCESS ? 0 : 77;
}
