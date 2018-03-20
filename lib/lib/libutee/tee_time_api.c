/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_ta_interface.h>
#include <tee_common_uapi.h>
#include <trusty_std.h>
#include <stdlib.h>
#include <string.h>

struct ta_persistent_time_t {
    uint64_t ref_time;
    TEE_Time ta_ptime;
    bool initialized;
};

static struct ta_persistent_time_t *ta_persistent_time = NULL;

void TEE_GetSystemTime(TEE_Time *time)
{
    int64_t local_time;
    long res;

    res = gettime(0, 0, &local_time);
    if (res < 0)
        TEE_Panic(err_to_tee_err(res));
    /* gettime() returns time in nsec */
    local_time /= 1000000;
    time->seconds = local_time / 1000;
    time->millis = local_time - time->seconds * 1000;
}

TEE_Result TEE_Wait(uint32_t timeout)
{
    return tee_wait(timeout);
}

TEE_Result TEE_GetTAPersistentTime(TEE_Time *time)
{
    int64_t local_time, delta;
    long res;
    TEE_Time delta_tee_time;
    uint32_t msec_carry = 0;

    if (ta_persistent_time == NULL || ta_persistent_time->initialized == false)
        return TEE_ERROR_TIME_NOT_SET;

    res = gettime(0, 0, &local_time);
    if (res < 0)
        TEE_Panic(err_to_tee_err(res));
    delta = local_time - ta_persistent_time->ref_time;
    delta /= 1000000;
    delta_tee_time.seconds = delta / 1000;
    delta_tee_time.millis = delta - delta_tee_time.seconds * 1000;
    time->millis = ta_persistent_time->ta_ptime.millis + delta_tee_time.millis;
    if (time->millis > 999) {
        time->millis -= 1000;
        msec_carry = 1;
    }
    if ((uint64_t)ta_persistent_time->ta_ptime.seconds +
        delta_tee_time.seconds + msec_carry > UINT32_MAX) {
        time->seconds = 0;
        return TEE_ERROR_OVERFLOW;
    }
    time->seconds = ta_persistent_time->ta_ptime.seconds +
                    delta_tee_time.seconds + msec_carry;
    return TEE_SUCCESS;
}

TEE_Result TEE_SetTAPersistentTime(const TEE_Time *time)
{
    int64_t local_time;
    long res;

    /* Default implementation; persistent time needs TEE Trusted Storage */
    ta_persistent_time = malloc(sizeof(struct ta_persistent_time_t));
    if (ta_persistent_time == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    memcpy(&ta_persistent_time->ta_ptime, time, sizeof(TEE_Time));
    ta_persistent_time->initialized = true;
    res = gettime(0, 0, &local_time);
    if (res < 0)
        TEE_Panic(err_to_tee_err(res));
    ta_persistent_time->ref_time = local_time;
    return TEE_SUCCESS;
}

void TEE_GetREETime(TEE_Time *time)
{
    // return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result libutee_reset_persistent_time(void)
{
    if (ta_persistent_time != NULL)
        ta_persistent_time->initialized = false;
    return TEE_SUCCESS;
}
