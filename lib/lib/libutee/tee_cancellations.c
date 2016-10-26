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

/*
 * The TEE_GetCancellationFlag function determines whether the current task’s
 * Cancellation Flag is set.
 * If cancellations are masked, this function MUST return false . This function
 * cannot panic.
 *
 * Return Value:
 *  - false if the Cancellation Flag is not set or if cancellations are masked
 *  - true if the Cancellation Flag is set and cancellations are not masked
 */
bool TEE_GetCancellationFlag(void)
{
    return false;
}

/*
 * The TEE_UnmaskCancellation function unmasks the effects of cancellation for
 * the current task.
 * When cancellation requests are unmasked, the Cancellation Flag interrupts
 * cancellable functions such as TEE_Wait and requests the cancellation of
 * operations started with TEE_OpenTASession or TEE_InvokeTACommand.
 * By default, tasks created to handle a TA entry point have cancellation
 * masked, so that a TA does not have to cope with the effects of cancellation
 * requests.
 *
 * Return Value:
 *  - true if cancellations were masked prior to calling this function
 *  - false otherwise
 */
bool TEE_UnmaskCancellation(void)
{
    return false;
}

bool TEE_MaskCancellation(void)
{
    return false;
}


