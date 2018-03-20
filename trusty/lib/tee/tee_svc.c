/*
 * Copyright (c) 2017-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#include <string.h>
#include <lib/tee/tee_svc.h>
#include <lib/tee/tee_api.h>
#include <tee_common_uapi.h>

vaddr_t tee_svc_uref_base = KERNEL_ASPACE_BASE;

TEE_Result tee_svc_copy_from_user(void *kaddr, const void *uaddr, size_t len)
{
	status_t res;

	res = tee_copy_from_user(kaddr, (user_addr_t)uaddr, len);
	if (res)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

TEE_Result tee_svc_copy_to_user(void *uaddr, const void *kaddr, size_t len)
{
	status_t res;

	res = tee_copy_to_user((user_addr_t)uaddr, kaddr, len);
	if (res)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

TEE_Result tee_svc_copy_kaddr_to_uref(uint32_t *uref, void *kaddr)
{
	uint32_t ref = tee_svc_kaddr_to_uref(kaddr);

	return tee_svc_copy_to_user(uref, &ref, sizeof(ref));
}
