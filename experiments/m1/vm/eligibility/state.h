/* SPDX-License-Identifier: MIT OR Apache-2.0 */
#ifndef LOCALPIN_M1_ELIGIBILITY_STATE_H
#define LOCALPIN_M1_ELIGIBILITY_STATE_H
struct eligibility_fixture {
    unsigned long marker;
    int eligible;
    int conversation_calls;
};
#define ELIGIBILITY_FIXTURE_MARKER 0x4d31454cUL
#endif
