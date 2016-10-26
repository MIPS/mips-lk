/*
 * Copyright (c) 2016 Imagination Technologies Ltd.
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

#if WITH_GP_API

#include <stdlib.h>
#include <uthread.h>
#include <tee_api_types.h>
#include <lib/tee/tee_api.h>
#include <tee_api_defines.h>

#define hidden_copy_from_user(x...) (copy_from_user)(x)
#define hidden_copy_to_user(x...) (copy_to_user)(x)

status_t tee_mmu_check_access_rights(const struct uthread *utc,
			       uint32_t flags, user_addr_t uaddr, size_t len)
{
	user_addr_t a;
	size_t addr_incr = PAGE_SIZE;

	/* Address wrap */
	if ((uaddr + len) < uaddr)
		return ERR_ACCESS_DENIED;

	/* Protect against increment wrap */
	if ((uaddr + addr_incr) < uaddr)
		addr_incr = len;

	for (a = uaddr; a < (uaddr + len); a += addr_incr) {
		paddr_t pa;
		u_int uflags;
		int res;

		res = uthread_virt_to_phys_flags((uthread_t*)utc, (vaddr_t)a,
				&pa, &uflags);
		if (res != NO_ERROR)
			return ERR_ACCESS_DENIED;

		if (!(flags & TEE_MEMORY_ACCESS_ANY_OWNER)) {
#if 1 // MIPS_OPTEE_NOT_YET
			// TODO secure shared mem not implemented for mips
			return ERR_ACCESS_DENIED;
#else // MIPS_OPTEE_NOT_YET
			/*
			 * Strict check that no one else (wich equal or
			 * less trust) may can access this memory.
			 *
			 * Parameters are shared with normal world if they
			 * aren't in secure DDR.
			 *
			 * If the parameters are in secure DDR it's because one
			 * TA is invoking another TA and in that case there's
			 * new memory allocated privately for the paramters to
			 * this TA.
			 *
			 * If we do this check for an address on TA
			 * internal memory it's harmless as it will always
			 * be in secure DDR.
			 */
			if (!tee_mm_addr_is_within_range(&tee_mm_sec_ddr, pa))
				return ERR_ACCESS_DENIED;

#endif // MIPS_OPTEE_NOT_YET
		}

		if ((flags & TEE_MEMORY_ACCESS_WRITE) && !(uflags & UTM_W))
			return ERR_ACCESS_DENIED;
		if ((flags & TEE_MEMORY_ACCESS_READ) && !(uflags & UTM_R))
			return ERR_ACCESS_DENIED;
	}

	return NO_ERROR;
}

#include <lib/syscall.h>

long __SYSCALL sys_check_access_rights(unsigned long flags, const void *buf,
				       size_t len)
{
	uthread_t *ut;
	long res;

	ut = uthread_get_current();
	if (!ut)
		return TEE_ERROR_BAD_STATE;

	res = tee_mmu_check_access_rights(ut, flags, (user_addr_t)buf, len);
	if (res)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

static status_t tee_check_user_param_r(user_addr_t usrc, size_t len)
{
	uthread_t *ut;
	uint32_t flags = TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER;

	ut = uthread_get_current();
	if (!ut)
		return ERR_NOT_VALID;

	return tee_mmu_check_access_rights(ut, flags, usrc, len);
}

static status_t tee_check_user_param_w(user_addr_t usrc, size_t len)
{
	uthread_t *ut;
	uint32_t flags = TEE_MEMORY_ACCESS_WRITE | TEE_MEMORY_ACCESS_ANY_OWNER;

	ut = uthread_get_current();
	if (!ut)
		return ERR_NOT_VALID;

	return tee_mmu_check_access_rights(ut, flags, usrc, len);
}

status_t tee_copy_from_user(void *kdest, user_addr_t usrc, size_t len)
{
	status_t res;

	res = tee_check_user_param_r(usrc, len);
	if (res)
		return ERR_ACCESS_DENIED;

	res = hidden_copy_from_user(kdest, usrc, len);
	if (res)
		return ERR_ACCESS_DENIED;

	return NO_ERROR;
}

status_t tee_copy_to_user(user_addr_t udest, const void *ksrc, size_t len)
{
	status_t res;

	res = tee_check_user_param_w(udest, len);
	if (res)
		return ERR_ACCESS_DENIED;

	res = hidden_copy_to_user(udest, ksrc, len);
	if (res)
		return ERR_ACCESS_DENIED;

	return NO_ERROR;
}
#endif /* WITH_GP_API */
