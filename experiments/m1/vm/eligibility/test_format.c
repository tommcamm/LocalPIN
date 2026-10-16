/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Test only pure hash-format rejection; never call the embedded checker main. */
#define main unused_guarded_checker_entrypoint
#include "check.c"
#undef main
int main(void)
{
    char valid[128] = "$6$synthetic$";
    memset(valid + strlen(valid), '.', 86);
    valid[sizeof("$6$synthetic$") - 1 + 86] = '\0';
    if (!sha512_fixture_hash(valid) || sha512_fixture_hash("$6$malformed") ||
        sha512_fixture_hash("$y$unsupported") || sha512_fixture_hash("") || sha512_fixture_hash("!")) return 1;
    valid[strlen(valid) - 1] = 'z';
    if (sha512_fixture_hash(valid)) return 1;
    puts("Pure strict fixture hash-format checks PASS; no PAM/account operation");
    return 0;
}
