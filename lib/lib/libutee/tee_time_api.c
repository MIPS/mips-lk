/*
 * Copyright (C) 2016 Imagination Technologies Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
        delta_tee_time.seconds + msec_carry > TEE_MAX_32BIT) {
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

TEE_Result libutee_reset_persistent_time(void) {
    if (ta_persistent_time != NULL)
        ta_persistent_time->initialized = false;
    return TEE_SUCCESS;
}
