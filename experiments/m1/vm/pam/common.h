/* SPDX-License-Identifier: MIT OR Apache-2.0 */
#ifndef LOCALPIN_M1_VM_PAM_COMMON_H
#define LOCALPIN_M1_VM_PAM_COMMON_H
struct vm_conversation {
    const char *candidate;
    int prompts;
    int module_calls;
    int pin_success;
};
#endif
