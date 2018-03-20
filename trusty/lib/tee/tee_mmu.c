/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
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

#include <stdlib.h>
#include <uthread.h>
#include <lib/syscall.h>
#include <tee_api_types.h>
#include <lib/tee/tee_api.h>
#include <tee_api_defines.h>
#ifdef WITH_TRUSTY_TIPC_DEV
#include <lib/trusty/tipc_dev.h>
#endif

#define hidden_copy_from_user(x...) (copy_from_user)(x)
#define hidden_copy_to_user(x...) (copy_to_user)(x)

/* TODO: 12/25/2017 remove this code if regression is not detected */
#if 0
static bool tee_mmu_is_ns_addr_range(paddr_t pa, size_t len)
{
#ifdef WITH_TRUSTY_TIPC_DEV
	/* shared memory region is accessible by non-secure side */
	return tipc_shm_paddr_within_range(pa, len);
#else
	return false;
#endif
}
#endif

status_t mmu_check_access_rights(const struct uthread *ut,
		uint32_t flags, user_addr_t uaddr, size_t len)
{
	u_int offset, npages;

	if (ut == NULL)
		goto err_exit;

	/* Address wrap */
	if ((uaddr + len) < uaddr)
		goto err_exit;

	offset = uaddr & (PAGE_SIZE - 1);
	npages = ROUNDUP((len + offset), PAGE_SIZE) / PAGE_SIZE;
	if (npages == 0)
		npages = 1;

	for (uaddr = ROUNDDOWN(uaddr, PAGE_SIZE); npages > 0;
	     --npages, uaddr += PAGE_SIZE) {
		paddr_t pa;
		u_int uflags;
		int res;

		res = uthread_virt_to_phys_flags((uthread_t *)ut,
				(vaddr_t)uaddr, &pa, &uflags);
		if (res != NO_ERROR)
			goto err_exit;

		if (!(flags & TEE_MEMORY_ACCESS_ANY_OWNER)) {
			/*
			 * Check that no one else with less trust can access
			 * this memory.
			 */
			if (uflags & UTM_NS_MEM)
				goto err_exit;
		}

		if ((flags & TEE_MEMORY_ACCESS_WRITE) && !(uflags & UTM_W))
			goto err_exit;
		if ((flags & TEE_MEMORY_ACCESS_READ) && !(uflags & UTM_R))
			goto err_exit;
	}

	return NO_ERROR;

err_exit:
	return ERR_ACCESS_DENIED;
}

TEE_Result tee_mmu_check_access_rights(const struct uthread *ut,
		uint32_t flags, user_addr_t uaddr, size_t len)
{
	TEE_Result res;

	res = mmu_check_access_rights(ut, flags, uaddr, len);
	if (res)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

TEE_Result __SYSCALL sys_check_access_rights(unsigned long flags,
		const void *buf, uint32_t len)
{
	uthread_t *ut = uthread_get_current();

	return tee_mmu_check_access_rights(ut, flags, (user_addr_t)buf, len);
}

TEE_Result tee_check_user_param_r(user_addr_t usrc, size_t len)
{
	TEE_Result res;
	uthread_t *ut = uthread_get_current();
	uint32_t flags = TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER;

	res = mmu_check_access_rights(ut, flags, usrc, len);
	if (res)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;

}

TEE_Result tee_check_user_param_w(user_addr_t usrc, size_t len)
{
	TEE_Result res;
	uthread_t *ut = uthread_get_current();
	uint32_t flags = TEE_MEMORY_ACCESS_WRITE | TEE_MEMORY_ACCESS_ANY_OWNER;

	res = mmu_check_access_rights(ut, flags, usrc, len);
	if (res)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

TEE_Result tee_check_user_param_rw(user_addr_t usrc, size_t len)
{
	TEE_Result res;
	uthread_t *ut = uthread_get_current();
	uint32_t flags = TEE_MEMORY_ACCESS_READ |
		TEE_MEMORY_ACCESS_WRITE |
		TEE_MEMORY_ACCESS_ANY_OWNER;

	res = mmu_check_access_rights(ut, flags, usrc, len);
	if (res)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

TEE_Result tee_copy_from_user(void *kdest, user_addr_t usrc, size_t len)
{
	TEE_Result res;

	res = tee_check_user_param_r(usrc, len);
	if (res)
		return TEE_ERROR_ACCESS_DENIED;

	res = hidden_copy_from_user(kdest, usrc, len);
	if (res)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

TEE_Result tee_copy_to_user(user_addr_t udest, const void *ksrc, size_t len)
{
	TEE_Result res;

	res = tee_check_user_param_w(udest, len);
	if (res)
		return TEE_ERROR_ACCESS_DENIED;

	res = hidden_copy_to_user(udest, ksrc, len);
	if (res)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}
