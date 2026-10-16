/* SPDX-License-Identifier: MIT OR Apache-2.0 */
#define _DEFAULT_SOURCE
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "fixture.h"

static unsigned checks;
static unsigned failures;

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
            if (s->cancel || s->prompts > 1)
                goto fail;
            r[i].resp = strdup(s->candidate);
            if (r[i].resp == NULL)
                goto fail;
            break;
        case PAM_TEXT_INFO:
        case PAM_ERROR_MSG:
            break;
        default:
            goto fail;
        }
    }
    *responses = r;
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

static void check(int passed, const char *name)
{
    ++checks;
    if (!passed)
        ++failures;
    printf("%s %s\n", passed ? "PASS" : "FAIL", name);
}

static void config(const char *dir, const char *service, const char *text)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, service) >= (int)sizeof(path))
        exit(77);
    FILE *f = fopen(path, "wx");
    if (f == NULL) {
        perror("INFRA config");
        exit(77);
    }
    if (fputs(text, f) == EOF || fclose(f) != 0) {
        perror("INFRA config write");
        exit(77);
    }
}

static pam_handle_t *start(const char *dir, const char *service, struct fixture *s)
{
    struct pam_conv conv = {conversation, s};
    pam_handle_t *pamh = NULL;
    int rc = pam_start_confdir(service, s->user == NULL ? "localpin_synthetic" : s->user, &conv, dir, &pamh);
    if (rc != PAM_SUCCESS) {
        fprintf(stderr, "INFRA pam_start_confdir: %d\n", rc);
        exit(77);
    }
    return pamh;
}

static void finish(pam_handle_t *pamh, int status)
{
    if (pam_end(pamh, status) != PAM_SUCCESS) {
        fprintf(stderr, "INFRA pam_end failed\n");
        exit(77);
    }
}

static void attempt(pam_handle_t *pamh, struct fixture *s, const char *name,
                    int wanted, int prompts, int password_calls, int pin_attempts)
{
    s->prompts = s->password_calls = s->pin_attempts = s->stale_token = 0;
    int rc = pam_authenticate(pamh, 0);
    /* Linux-PAM denies application access to PAM_AUTHTOK; inspect in module. */
    int before_setcred = s->setcred_calls;
    int cred = pam_setcred(pamh, PAM_REFRESH_CRED);
    int ok = (wanted == PAM_SUCCESS ? rc == PAM_SUCCESS : rc != PAM_SUCCESS)
        && s->prompts == prompts && s->password_calls == password_calls
        && s->pin_attempts == pin_attempts && s->stale_token == 0
        && s->setcred_calls > before_setcred
        && (rc == PAM_SUCCESS ? cred == PAM_SUCCESS : cred != PAM_SUCCESS);
    check(ok, name);
    if (!ok)
        fprintf(stderr, "  rc=%d prompts=%d password_calls=%d pin_attempts=%d stale=%d setcred=%d\n",
                rc, s->prompts, s->password_calls, s->pin_attempts, s->stale_token, cred);
}

int main(int argc, char **argv)
{
    if ((argc != 3 && argc != 4) || argv[1][0] != '/' || argv[2][0] != '/') {
        fprintf(stderr, "INFRA expected absolute private directory and PAM module directory\n");
        return 77;
    }
    const char *dir = argv[1];
    char text[PATH_MAX * 5];
    char module[PATH_MAX];
    if (snprintf(module, sizeof(module), "%s/pam_m1_fixture.so", dir) >= (int)sizeof(module))
        return 77;
    snprintf(text, sizeof(text), "auth required %s/pam_permit.so\n", argv[2]);
    config(dir, "permit", text);
    snprintf(text, sizeof(text), "auth required %s/pam_deny.so\n", argv[2]);
    config(dir, "deny", text);
    struct fixture s = {.candidate = "synthetic-password", .password = "synthetic-password"};
    pam_handle_t *pamh = start(dir, "permit", &s);
    int rc = pam_authenticate(pamh, 0);
    finish(pamh, rc);
    if (rc != PAM_SUCCESS || s.prompts != 0) {
        fprintf(stderr, "INFRA permit baseline failed: %d\n", rc);
        return 77;
    }
    pamh = start(dir, "deny", &s);
    rc = pam_authenticate(pamh, 0);
    finish(pamh, rc);
    if (rc != PAM_AUTH_ERR || s.prompts != 0) {
        fprintf(stderr, "INFRA deny baseline failed: %d\n", rc);
        return 77;
    }
    puts("BASELINE permit=success deny=PAM_AUTH_ERR prompts=0");
    if (argc == 4) {
        if (strcmp(argv[3], "--unix") != 0)
            return 77;
        snprintf(text, sizeof(text), "auth required %s/pam_unix.so nodelay\n", argv[2]);
        config(dir, "unix-baseline", text);
        s = (struct fixture){.candidate = "481516"};
        pamh = start(dir, "unix-baseline", &s);
        rc = pam_authenticate(pamh, 0);
        finish(pamh, rc);
        if (rc != PAM_SUCCESS || s.prompts != 1) {
            fprintf(stderr, "INFRA synthetic pam_unix positive baseline failed: %d prompts=%d\n", rc, s.prompts);
            return 77;
        }
        s = (struct fixture){.candidate = "wrong-synthetic-password"};
        pamh = start(dir, "unix-baseline", &s);
        rc = pam_authenticate(pamh, 0);
        finish(pamh, rc);
        if (rc != PAM_AUTH_ERR || s.prompts != 1) {
            fprintf(stderr, "INFRA synthetic pam_unix negative baseline failed: %d prompts=%d\n", rc, s.prompts);
            return 77;
        }
        puts("BASELINE synthetic pam_unix correct=success wrong=PAM_AUTH_ERR prompts=1");
        snprintf(text, sizeof(text),
                 "auth [success=done default=ignore] %s capture\n"
                 "auth required %s/pam_unix.so nodelay try_first_pass\n", module, argv[2]);
        config(dir, "unix-candidate", text);
        s = (struct fixture){.candidate = "481516", .mode = FIXTURE_PIN_WRONG};
        pamh = start(dir, "unix-candidate", &s);
        attempt(pamh, &s, "pam_unix reuses six-digit password after PIN mismatch", PAM_SUCCESS, 1, 0, 1);
        s.candidate = "wrong-synthetic-password";
        attempt(pamh, &s, "pam_unix reused handle rejects fresh wrong password", PAM_AUTH_ERR, 1, 0, 0);
        s.candidate = "481516";
        attempt(pamh, &s, "pam_unix reused handle accepts fresh correct password", PAM_SUCCESS, 1, 0, 1);
        finish(pamh, PAM_SUCCESS);
        s = (struct fixture){.user = "localpin_ordinary", .candidate = "synthetic-password", .mode = FIXTURE_PIN_WRONG};
        pamh = start(dir, "unix-candidate", &s);
        attempt(pamh, &s, "pam_unix reuses ordinary password", PAM_SUCCESS, 1, 0, 0);
        finish(pamh, PAM_SUCCESS);
        s = (struct fixture){.user = "localpin_bytes", .candidate = "\x80\xff\xc3\xa9 \t", .mode = FIXTURE_PIN_WRONG};
        pamh = start(dir, "unix-candidate", &s);
        attempt(pamh, &s, "pam_unix reuses non-UTF-8 and whitespace password bytes", PAM_SUCCESS, 1, 0, 0);
        finish(pamh, PAM_SUCCESS);
        printf("RESULT pam_unix checks=%u failed=%u; synthetic namespace accounts only\n", checks, failures);
        return failures == 0 ? 0 : 1;
    }
    /* Mirrors a narrow proposed control rule, not a Fedora service fixture. */
    snprintf(text, sizeof(text),
             "auth [success=done default=ignore] %s capture\n"
             "auth required %s password\n"
             "account required %s account\n", module, module, module);
    config(dir, "candidate", text);
    snprintf(text, sizeof(text),
             "auth requisite %s guard\n"
             "auth [success=done default=ignore] %s capture\n"
             "auth required %s password\n", module, module, module);
    config(dir, "guarded", text);
    snprintf(text, sizeof(text),
             "auth required %s guard\n"
             "auth [success=done default=ignore] %s capture\n"
             "auth required %s password\n", module, module, module);
    config(dir, "required-before", text);
    snprintf(text, sizeof(text),
             "auth [success=done default=ignore] %s/missing.so\n"
             "auth required %s password\n", dir, module);
    config(dir, "missing", text);

    const struct {
        const char *name;
        const char *candidate;
        int mode;
        int pin_attempts;
    } cases[] = {
        {"ordinary password uses one candidate", "synthetic-password", FIXTURE_PIN_WRONG, 0},
        {"six-digit account password after PIN mismatch", "481516", FIXTURE_PIN_WRONG, 1},
        {"leading-zero password preserved", "001122", FIXTURE_PIN_WRONG, 1},
        {"empty input reaches password policy", "", FIXTURE_PIN_WRONG, 0},
        {"unicode digit lookalikes bypass PIN", "\xef\xbc\x91\xef\xbc\x92\xef\xbc\x93\xef\xbc\x94\xef\xbc\x95\xef\xbc\x96", FIXTURE_PIN_WRONG, 0},
        {"non-UTF-8/control/space bytes preserved", " \x80\xff\t\nA ", FIXTURE_PIN_WRONG, 0},
        {"five digits bypass PIN", "12345", FIXTURE_PIN_WRONG, 0},
        {"seven digits bypass PIN", "1234567", FIXTURE_PIN_WRONG, 0},
        {"cooldown preserves six-digit password", "481516", FIXTURE_COOLDOWN, 0},
        {"disabled preserves password", "481516", FIXTURE_DISABLED, 0},
        {"not enrolled preserves password", "481516", FIXTURE_NOT_ENROLLED, 0},
        {"broker unavailable preserves password", "481516", FIXTURE_BROKER_DOWN, 0},
        {"timeout outcome preserves password", "481516", FIXTURE_TIMEOUT, 0},
        {"corrupt state outcome preserves password", "481516", FIXTURE_CORRUPT, 0},
        {"identity refusal cannot authorize PIN", "481516", FIXTURE_IDENTITY_MISMATCH, 0},
        {"service refusal cannot authorize PIN", "481516", FIXTURE_UNSUPPORTED_SERVICE, 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        s = (struct fixture){.candidate = cases[i].candidate, .password = cases[i].candidate,
                             .mode = cases[i].mode};
        pamh = start(dir, "candidate", &s);
        attempt(pamh, &s, cases[i].name, PAM_SUCCESS, 1, 1, cases[i].pin_attempts);
        finish(pamh, PAM_SUCCESS);
    }
    char all_bytes[256];
    for (size_t i = 0; i < 255; ++i)
        all_bytes[i] = (char)(i + 1);
    all_bytes[255] = '\0';
    s = (struct fixture){.candidate = all_bytes, .password = all_bytes, .mode = FIXTURE_PIN_WRONG};
    pamh = start(dir, "candidate", &s);
    attempt(pamh, &s, "all 255 non-NUL byte values preserved", PAM_SUCCESS, 1, 1, 0);
    finish(pamh, PAM_SUCCESS);
    char long_candidate[512];
    memset(long_candidate, 'A', sizeof(long_candidate) - 1);
    long_candidate[sizeof(long_candidate) - 1] = '\0';
    s = (struct fixture){.candidate = long_candidate, .password = long_candidate, .mode = FIXTURE_PIN_WRONG};
    pamh = start(dir, "candidate", &s);
    attempt(pamh, &s, "511-byte candidate preserved", PAM_SUCCESS, 1, 1, 0);
    finish(pamh, PAM_SUCCESS);
    s = (struct fixture){.candidate = "001122", .password = "synthetic-password", .mode = FIXTURE_PIN_OK};
    pamh = start(dir, "candidate", &s);
    attempt(pamh, &s, "PIN success short circuits password", PAM_SUCCESS, 1, 0, 1);
    s.candidate = "481516";
    s.password = "481516";
    s.mode = FIXTURE_PIN_WRONG;
    attempt(pamh, &s, "reused handle PIN success then six-digit password", PAM_SUCCESS, 1, 1, 1);
    s.candidate = "bad-password";
    attempt(pamh, &s, "reused handle prior success cannot authorize wrong password", PAM_AUTH_ERR, 1, 1, 0);
    s.candidate = "481516";
    attempt(pamh, &s, "reused handle failure then correct password", PAM_SUCCESS, 1, 1, 1);
    s.cancel = 1;
    attempt(pamh, &s, "cancel conversation cannot authorize", PAM_AUTH_ERR, 2, 1, 0);
    s.cancel = 0;
    attempt(pamh, &s, "reused handle cancellation then fresh password", PAM_SUCCESS, 1, 1, 1);
    finish(pamh, PAM_SUCCESS);

    s = (struct fixture){.candidate = "001122", .password = "wrong", .mode = FIXTURE_PIN_OK,
                         .guard_denied = 1};
    pamh = start(dir, "guarded", &s);
    attempt(pamh, &s, "preceding requisite check denies before PIN", PAM_AUTH_ERR, 0, 0, 0);
    finish(pamh, PAM_PERM_DENIED);
    /* A later successful PIN must not erase an earlier required failure. */
    s = (struct fixture){.candidate = "001122", .password = "001122", .mode = FIXTURE_PIN_OK,
                         .guard_denied = 1};
    pamh = start(dir, "required-before", &s);
    attempt(pamh, &s, "preceding required failure survives later PIN success", PAM_AUTH_ERR, 1, 1, 1);
    finish(pamh, PAM_PERM_DENIED);
    s.guard_denied = 0;
    s.eligibility_denied = 1;
    pamh = start(dir, "candidate", &s);
    attempt(pamh, &s, "adapter eligibility refusal continues original password policy", PAM_SUCCESS, 1, 1, 0);
    check(s.account_calls == 0, "pam_authenticate does not execute account phase");
    check(pam_acct_mgmt(pamh, 0) != PAM_SUCCESS && s.account_calls == 1,
          "explicit account phase can deny after auth success");
    finish(pamh, PAM_PERM_DENIED);
    s = (struct fixture){.candidate = "synthetic-password", .password = "synthetic-password"};
    pamh = start(dir, "missing", &s);
    attempt(pamh, &s, "missing optional adapter reaches one password prompt", PAM_SUCCESS, 1, 1, 0);
    finish(pamh, PAM_SUCCESS);
    printf("RESULT checks=%u failed=%u; mock-only, no host accounts or PAM configuration used\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
