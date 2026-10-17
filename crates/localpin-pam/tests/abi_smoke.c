/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Native ABI smoke only: no PAM handle, authentication stack or account lookup. */
#include <dlfcn.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <security/pam_modules.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error "this smoke test covers only the reviewed Linux x86_64 PAM ABI"
#endif

_Static_assert(CHAR_BIT == 8 && sizeof(int) == 4 && sizeof(void *) == 8,
               "the reviewed module ABI requires x86_64 integer/pointer sizes");
_Static_assert(sizeof(struct pam_message) == 16 &&
               offsetof(struct pam_message, msg_style) == 0 &&
               offsetof(struct pam_message, msg) == 8,
               "unexpected Linux-PAM message layout");
_Static_assert(sizeof(struct pam_response) == 16 &&
               offsetof(struct pam_response, resp) == 0 &&
               offsetof(struct pam_response, resp_retcode) == 8,
               "unexpected Linux-PAM response layout");
_Static_assert(sizeof(struct pam_conv) == 16 &&
               offsetof(struct pam_conv, conv) == 0 &&
               offsetof(struct pam_conv, appdata_ptr) == 8,
               "unexpected Linux-PAM conversation layout");
_Static_assert(PAM_SUCCESS == 0 && PAM_IGNORE == 25 && PAM_PROMPT_ECHO_OFF == 1 &&
               PAM_SERVICE == 1 && PAM_USER == 2 && PAM_CONV == 5 && PAM_AUTHTOK == 6,
               "unexpected Linux-PAM constants");

typedef int (*pam_operation)(pam_handle_t *, int, int, const char **);
_Static_assert(sizeof(pam_operation) == sizeof(void *),
               "POSIX dynamic symbols require the reviewed function-pointer ABI");

static int check_export(void *library, const char *name)
{
    (void)dlerror();
    void *symbol = dlsym(library, name);
    if (dlerror() != NULL || symbol == NULL)
        return 1;
    /* POSIX dlsym returns the named function's address. Copy its representation
     * instead of relying on an ISO C object/function pointer cast extension. */
    pam_operation operation = NULL;
    memcpy(&operation, &symbol, sizeof(operation));
    const char *arguments[] = {"unsupported", NULL};
    const int counts[] = {-1, 0, 1, INT_MAX};
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); ++i) {
        if (operation(NULL, 0, counts[i], NULL) != PAM_IGNORE ||
            operation(NULL, PAM_SILENT, counts[i], arguments) != PAM_IGNORE)
            return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2 || argv[1][0] != '/') {
        fputs("usage: abi-smoke /absolute/path/to/liblocalpin_pam.so\n", stderr);
        return 2;
    }
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) {
        fputs("ABI smoke: module load failed\n", stderr);
        return 1;
    }
    const int failed = check_export(library, "pam_sm_authenticate") ||
                       check_export(library, "pam_sm_setcred");
    if (dlclose(library) != 0 || failed) {
        fputs("ABI smoke: exported module contract failed\n", stderr);
        return 1;
    }
    puts("PASS native x86_64 PAM layouts, exports and null-handle rejection; no authentication performed");
    return 0;
}
