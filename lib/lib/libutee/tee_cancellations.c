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
#include <trusty_std.h>

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
    return get_cancel_flag();
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
    return unmask_cancel_flag();
}

bool TEE_MaskCancellation(void)
{
    return mask_cancel_flag();
}


