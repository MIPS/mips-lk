/*
 * Copyright (c) 2012-2013, NVIDIA CORPORATION. All rights reserved
 * Copyright (c) 2013, Google, Inc. All rights reserved
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#define DEBUG_LOAD_TRUSTY_APP 0

#include <arch.h>
#include <assert.h>
#include <compiler.h>
#include <debug.h>
#include "elf.h"
#include <err.h>
#include <kernel/mutex.h>
#include <kernel/thread.h>
#include <malloc.h>
#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <uthread.h>
#include <lk/init.h>

#include <lib/trusty/trusty_app.h>

/*
 * Layout of .trusty_app.manifest section in the trusted application is the
 * required UUID followed by an abitrary number of configuration options.
 *
 * Note: Ensure that the manifest definition is kept in sync with the
 * one userspace uses to build the trusty apps.
 */

enum {
	TRUSTY_APP_CONFIG_KEY_MIN_STACK_SIZE	= 1,
	TRUSTY_APP_CONFIG_KEY_MIN_HEAP_SIZE	= 2,
	TRUSTY_APP_CONFIG_KEY_MAP_MEM		= 3,
	TRUSTY_APP_CONFIG_KEY_AUTO_START	= 4,
	TRUSTY_APP_CONFIG_KEY_EXTERN		= 5,
	TRUSTY_APP_CONFIG_KEY_PRIVILEGES	= 6,
};

typedef struct trusty_app_manifest {
	uuid_t		uuid;
	uint32_t	config_options[];
} trusty_app_manifest_t;

#define TRUSTY_APP_CFG_ITERATOR(_blob, _cnt, _key, _val) \
	/* initialization */ \
	uint32_t _i = 0, *_itr = (_blob), \
	_sz = _itr[0], _key = _itr[1], *_val = &_itr[2]; \
	/* condition */ \
	(_i < (_cnt)) && (_i + _sz <= (_cnt)); \
	/* iteration expression */ \
	_i += _sz, _itr += _sz, \
	_sz = _itr[0], (_key) = _itr[1], (_val) = &_itr[2]

#define TRUSTY_APP_START_ADDR	0x8000
#define TRUSTY_APP_STACK_TOP	0x1000000 /* 16MB */

#define PAGE_MASK		(PAGE_SIZE - 1)

static u_int trusty_app_count;
static struct list_node trusty_app_list = LIST_INITIAL_VALUE(trusty_app_list);

static char *trusty_app_image_start;
static char *trusty_app_image_end;
static u_int trusty_app_image_size;

extern intptr_t __trusty_app_start;
extern intptr_t __trusty_app_end;

static bool apps_registration_closed;
static mutex_t apps_lock = MUTEX_INITIAL_VALUE(apps_lock);
static struct list_node app_notifier_list = LIST_INITIAL_VALUE(app_notifier_list);
uint als_slot_cnt;
static struct list_node started_app_list = LIST_INITIAL_VALUE(started_app_list);

#define PRINT_TRUSTY_APP_UUID(tid,u)					\
	dprintf(SPEW,							\
		"trusty_app %d uuid: 0x%x 0x%x 0x%x 0x%x%x 0x%x%x%x%x%x%x\n",\
		tid,							\
		(u)->time_low, (u)->time_mid,				\
		(u)->time_hi_and_version,				\
		(u)->clock_seq_and_node[0],				\
		(u)->clock_seq_and_node[1],				\
		(u)->clock_seq_and_node[2],				\
		(u)->clock_seq_and_node[3],				\
		(u)->clock_seq_and_node[4],				\
		(u)->clock_seq_and_node[5],				\
		(u)->clock_seq_and_node[6],				\
		(u)->clock_seq_and_node[7]);

static status_t trusty_app_init_one(const char *name, trusty_app_t *trusty_app);

static void finalize_registration(void)
{
	mutex_acquire(&apps_lock);
	apps_registration_closed = true;
	mutex_release(&apps_lock);
}

status_t trusty_register_app_notifier(trusty_app_notifier_t *n)
{
	status_t ret = NO_ERROR;

	mutex_acquire(&apps_lock);
	if (!apps_registration_closed)
		list_add_tail(&app_notifier_list, &n->node);
	else
		ret = ERR_ALREADY_STARTED;
	mutex_release(&apps_lock);
	return ret;
}

int trusty_als_alloc_slot(void)
{
	int ret;

	mutex_acquire(&apps_lock);
	if (!apps_registration_closed)
		ret = ++als_slot_cnt;
	else
		ret = ERR_ALREADY_STARTED;
	mutex_release(&apps_lock);
	return ret;
}

static inline u_int trusty_app_index(trusty_app_t *trusty_app)
{
	return trusty_app->trusty_app_index;
}

static trusty_app_t *app_alloc(bool is_parent)
{
	trusty_app_t *trusty_app = calloc(1, sizeof(*trusty_app));
	if (!trusty_app)
		return NULL;

	trusty_app->is_parent = is_parent;
	list_initialize(&trusty_app->cloned_child_list);

	// keep an index for logging purposes, it is not a list index
	trusty_app->trusty_app_index = trusty_app_count++;
	list_initialize(&trusty_app->free_map_list);

	THREAD_LOCK(state);
	list_add_tail(&trusty_app_list, &trusty_app->trusty_app_node);
	THREAD_UNLOCK(state);

	return trusty_app;
}

static trusty_app_t *trusty_app_alloc_parent(void)
{
	return app_alloc(true);
}

static trusty_app_t *trusty_app_alloc_child(void)
{
	return app_alloc(false);
}

static void trusty_app_free(trusty_app_t *trusty_app)
{
	THREAD_LOCK(state);
	list_delete(&trusty_app->trusty_app_node);
	if (!trusty_app->is_parent)
		list_delete(&trusty_app->cloned_node);
	free(trusty_app);
	THREAD_UNLOCK(state);
}

__NO_INLINE static void dump_trusty_app_list(void)
{
	printf("dump_trusty_app_list:\n");
	struct trusty_app *trusty_app;

	THREAD_LOCK(state);
	list_for_every_entry(&trusty_app_list, trusty_app, struct trusty_app,
			trusty_app_node)
	{
		PRINT_TRUSTY_APP_UUID(trusty_app_index(trusty_app), &trusty_app->props.uuid);
	}
	THREAD_UNLOCK(state);
}

static void load_app_config_options(intptr_t trusty_app_image_addr,
		trusty_app_t *trusty_app, Elf32_Shdr *shdr)
{
	char  *manifest_data;
	u_int config_blob_size;
	uint32_t *config_blob;
	uint32_t config_cnt;
	u_int trusty_app_idx;

	/* have to at least have a valid UUID */
	ASSERT(shdr->sh_size >= sizeof(uuid_t));

	/* init default config options before parsing manifest */
	trusty_app->props.min_heap_size = 4 * PAGE_SIZE;
	trusty_app->props.min_stack_size = DEFAULT_STACK_SIZE;
	trusty_app->props.auto_start = true;
	trusty_app->props.custom_cfg_ptr = NULL;
	trusty_app->props.custom_cfg_size = NULL;

	trusty_app_idx = trusty_app_index(trusty_app);

	manifest_data = (char *)(trusty_app_image_addr + shdr->sh_offset);

	memcpy(&trusty_app->props.uuid,
	       (uuid_t *)manifest_data,
	       sizeof(uuid_t));

	PRINT_TRUSTY_APP_UUID(trusty_app_idx, &trusty_app->props.uuid);

	manifest_data += sizeof(trusty_app->props.uuid);

	config_blob = (uint32_t *)manifest_data;
	config_blob_size = (shdr->sh_size - sizeof(uuid_t));

	trusty_app->props.config_entry_cnt = config_blob_size / sizeof (u_int);

	/* if no config options we're done */
	if (trusty_app->props.config_entry_cnt == 0) {
		return;
	}

	/* save off configuration blob start so it can be accessed later */
	trusty_app->props.config_blob = config_blob;

	/*
	 * Step thru configuration blob.
	 *
	 * Save off some configuration data while we are here but
	 * defer processing of other data until it is needed later.
	 */
	config_cnt = trusty_app->props.config_entry_cnt;
	for (TRUSTY_APP_CFG_ITERATOR(config_blob, config_cnt, key, val)) {
		switch (key) {
		case TRUSTY_APP_CONFIG_KEY_MIN_STACK_SIZE:
			/* MIN_STACK_SIZE takes 1 data value */
			trusty_app->props.min_stack_size =
				ROUNDUP(val[0], PAGE_SIZE);
			ASSERT(trusty_app->props.min_stack_size > 0);
			break;
		case TRUSTY_APP_CONFIG_KEY_MIN_HEAP_SIZE:
			/* MIN_HEAP_SIZE takes 1 data value */
			trusty_app->props.min_heap_size =
				ROUNDUP(val[0], PAGE_SIZE);
			ASSERT(trusty_app->props.min_heap_size > 0);
			break;
		case TRUSTY_APP_CONFIG_KEY_MAP_MEM:
			/* MAP_MEM takes 3 data values */
			trusty_app->props.map_io_mem_cnt++;
			break;
		case TRUSTY_APP_CONFIG_KEY_AUTO_START:
			/* AUTO_START takes 1 data value */
			trusty_app->props.auto_start = (bool)val[0];
			break;
		case TRUSTY_APP_CONFIG_KEY_EXTERN:
			/* EXTERN config takes 2 data values */
			trusty_app->props.custom_cfg_ptr = (void*)val[0];
			trusty_app->props.custom_cfg_size = (uint32_t*)val[1];
			break;
		case TRUSTY_APP_CONFIG_KEY_PRIVILEGES:
			/* PRIVILEGES takes 1 data value */
			trusty_app->props.privileges = val[0];
			break;
		default:
			dprintf(CRITICAL, "Unknown manifest config key: %d\n",
					key);
			ASSERT(0 && "Unknown manifest config key");
			break;
		}
	}

#if DEBUG_LOAD_TRUSTY_APP
	dprintf(SPEW, "trusty_app %p: stack_sz=0x%x\n", trusty_app,
		trusty_app->props.min_stack_size);
	dprintf(SPEW, "trusty_app %p: heap_sz=0x%x\n", trusty_app,
		trusty_app->props.min_heap_size);
	dprintf(SPEW, "trusty_app %p: num_io_mem=%d\n", trusty_app,
		trusty_app->props.map_io_mem_cnt);
#endif
}

static status_t free_map_list_insert(trusty_app_t *trusty_app, void* ptr)
{
	struct free_map_node *node = malloc(sizeof(struct free_map_node));
	if (!node)
		return ERR_NO_MEMORY;

	node->ptr = ptr;
	THREAD_LOCK(state);
	list_add_tail(&trusty_app->free_map_list, &node->node);
	THREAD_UNLOCK(state);

	return NO_ERROR;
}

static status_t init_brk(trusty_app_t *trusty_app)
{
	status_t status;
	vaddr_t vaddr;
	void *heap;

	trusty_app->cur_brk = trusty_app->start_brk;

	/* do we need to increase user mode heap (if not enough remains)? */
	if ((trusty_app->end_brk - trusty_app->start_brk) >=
	    trusty_app->props.min_heap_size)
		return NO_ERROR;

	heap = memalign(PAGE_SIZE, trusty_app->props.min_heap_size);
	if (heap == 0)
		return ERR_NO_MEMORY;
	memset(heap, 0, trusty_app->props.min_heap_size);

	vaddr = trusty_app->end_brk;
	status = uthread_map_contig(trusty_app->ut, &vaddr,
			     vaddr_to_paddr(heap),
			     trusty_app->props.min_heap_size,
			     UTM_W | UTM_R | UTM_FIXED,
			     UT_MAP_ALIGN_DEFAULT);
	if (status != NO_ERROR || vaddr != trusty_app->end_brk) {
		dprintf(CRITICAL, "cannot map brk\n");
		free(heap);
		return ERR_NO_MEMORY;
	}

	if (free_map_list_insert(trusty_app, heap)) {
		free(heap);
		return ERR_NO_MEMORY;
	}

	trusty_app->end_brk += trusty_app->props.min_heap_size;
	return NO_ERROR;
}

static status_t alloc_address_map(trusty_app_t *trusty_app)
{
	Elf32_Ehdr *elf_hdr = trusty_app->app_img;
	void *trusty_app_image;
	Elf32_Phdr *prg_hdr;
	u_int i, trusty_app_idx;
	status_t ret;
	vaddr_t start_code = ~0;
	vaddr_t start_data = 0;
	vaddr_t end_code = 0;
	vaddr_t end_data = 0;

	trusty_app_image = trusty_app->app_img;
	trusty_app_idx = trusty_app_index(trusty_app);

	if (strncmp((char *)elf_hdr->e_ident, ELFMAG, SELFMAG)) {
		dprintf(CRITICAL, "trusty_app alloc_address_map: ELF header not found\n");
		return ERR_NOT_FOUND;
	}

	/* create mappings for PT_LOAD sections */
	for (i = 0; i < elf_hdr->e_phnum; i++) {
		vaddr_t first, last, last_mem;

		prg_hdr = (Elf32_Phdr *)(trusty_app_image + elf_hdr->e_phoff +
				(i * sizeof(Elf32_Phdr)));

#if DEBUG_LOAD_TRUSTY_APP
		dprintf(SPEW,
			"trusty_app %d: ELF type 0x%x, vaddr 0x%08x, paddr 0x%08x"
			" rsize 0x%08x, msize 0x%08x, flags 0x%08x\n",
			trusty_app_idx, prg_hdr->p_type, prg_hdr->p_vaddr,
			prg_hdr->p_paddr, prg_hdr->p_filesz, prg_hdr->p_memsz,
			prg_hdr->p_flags);
#endif

		if (prg_hdr->p_type != PT_LOAD)
			continue;

		/* skip PT_LOAD if it's below trusty_app start or above .bss */
		if ((prg_hdr->p_vaddr < TRUSTY_APP_START_ADDR) ||
		    (prg_hdr->p_vaddr >= trusty_app->end_bss))
			continue;

		/*
		 * We're expecting to be able to execute the trusty_app in-place,
		 * meaning its PT_LOAD segments, should be page-aligned.
		 */
		ASSERT(!(prg_hdr->p_vaddr & PAGE_MASK) &&
		       !(prg_hdr->p_offset & PAGE_MASK));

		size_t size = (prg_hdr->p_memsz + PAGE_MASK) & ~PAGE_MASK;
		void *seg_vaddr = trusty_app_image + prg_hdr->p_offset;
		paddr_t paddr = vaddr_to_paddr(seg_vaddr);
		vaddr_t vaddr = prg_hdr->p_vaddr;
		u_int flags = PF_TO_UTM_FLAGS(prg_hdr->p_flags) | UTM_FIXED;

		// not running in place, duplicate writable pages, share read-only pages
		if (flags & UTM_W) {
			size_t app_size = prg_hdr->p_memsz;
			size_t app_size_pg = size;

			char* clone_app_img = memalign(PAGE_SIZE, app_size_pg);
			if (!clone_app_img)
				return ERR_NO_MEMORY;

			memcpy(clone_app_img, seg_vaddr, app_size);
			// zero fill the memory after the image
			memset(clone_app_img + app_size, 0, app_size_pg - app_size);

			paddr = vaddr_to_paddr(clone_app_img);

			if (free_map_list_insert(trusty_app, clone_app_img)) {
				free(clone_app_img);
				return ERR_NO_MEMORY;
			}
		}

		ret = uthread_map_contig(trusty_app->ut, &vaddr, paddr, size,
				flags, UT_MAP_ALIGN_DEFAULT);
		if (ret) {
			dprintf(CRITICAL, "cannot map the segment\n");
			return ret;
		}

		vaddr_t stack_bot = TRUSTY_APP_STACK_TOP - trusty_app->props.min_stack_size;
		/* check for overlap into user stack range */
		if (stack_bot < vaddr + size) {
			dprintf(CRITICAL,
				"failed to load trusty_app: (overlaps user stack 0x%lx)\n",
				 stack_bot);
			return ERR_TOO_BIG;
		}

#if DEBUG_LOAD_TRUSTY_APP
		dprintf(SPEW,
			"trusty_app %d: load vaddr 0x%08lx, paddr 0x%08lx,"
			" rsize 0x%08lx, msize 0x%08x, access %c%c%c,"
			" flags 0x%x\n",
			trusty_app_idx, vaddr, paddr, size, prg_hdr->p_memsz,
			flags & UTM_R ? 'r' : '-', flags & UTM_W ? 'w' : '-',
			flags & UTM_X ? 'x' : '-', flags);
#endif

		/* start of code/data */
		first = prg_hdr->p_vaddr;
		if (first < start_code)
			start_code = first;
		if (start_data < first)
			start_data = first;

		/* end of code/data */
		last = prg_hdr->p_vaddr + prg_hdr->p_filesz;
		if ((prg_hdr->p_flags & PF_X) && end_code < last)
			end_code = last;
		if (end_data < last)
			end_data = last;

		/* end of brk */
		last_mem = prg_hdr->p_vaddr + prg_hdr->p_memsz;
		if (last_mem > trusty_app->start_brk) {
			void *segment_start = trusty_app_image + prg_hdr->p_offset;

			trusty_app->start_brk = last_mem;
			/* make brk consume the rest of the page */
			trusty_app->end_brk = prg_hdr->p_vaddr + size;

			/* zero fill the remainder of the page for brk.
			 * do it here (instead of init_brk) so we don't
			 * have to keep track of the kernel address of
			 * the mapping where brk starts */
			memset(segment_start + prg_hdr->p_memsz, 0,
			       size - prg_hdr->p_memsz);
		}
	}

	ret = init_brk(trusty_app);
	if (ret != NO_ERROR) {
		dprintf(CRITICAL, "failed to load trusty_app: trusty_app heap creation error\n");
		return ret;
	}

	dprintf(SPEW, "trusty_app %d: code: start 0x%08lx end 0x%08lx\n",
		trusty_app_idx, start_code, end_code);
	dprintf(SPEW, "trusty_app %d: data: start 0x%08lx end 0x%08lx\n",
		trusty_app_idx, start_data, end_data);
	dprintf(SPEW, "trusty_app %d: bss:                end 0x%08lx\n",
		trusty_app_idx, trusty_app->end_bss);
	dprintf(SPEW, "trusty_app %d: brk:  start 0x%08lx end 0x%08lx\n",
		trusty_app_idx, trusty_app->start_brk, trusty_app->end_brk);

	dprintf(SPEW, "trusty_app %d: entry 0x%08lx\n", trusty_app_idx, trusty_app->ut->entry);

	return NO_ERROR;
}

/*
 * Align the next trusty_app to a page boundary, by copying what remains
 * in the trusty_app image to the aligned next trusty_app start. This should be
 * called after we're done with the section headers as the previous
 * trusty_apps .shstrtab section will be clobbered.
 *
 * Note: trusty_app_image_size remains the carved out part in LK to exit
 * the bootloader loop, so still increment by max_extent. Because of
 * the copy down to an aligned next trusty_app addr, trusty_app_image_size is
 * more than what we're actually using.
 */
static char *align_next_app(Elf32_Ehdr *elf_hdr, Elf32_Shdr *pad_hdr,
			    u_int max_extent)
{
	char *next_trusty_app_align_start;
	char *next_trusty_app_fsize_start;
	char *trusty_app_image_addr;
	u_int copy_size;

	ASSERT(ROUNDUP(max_extent, 4) == elf_hdr->e_shoff);
	ASSERT(pad_hdr);

	trusty_app_image_addr = (char *)elf_hdr;
	max_extent = (elf_hdr->e_shoff + (elf_hdr->e_shnum * elf_hdr->e_shentsize)) - 1;
	ASSERT((trusty_app_image_addr + max_extent + 1) <= trusty_app_image_end);

	next_trusty_app_align_start = trusty_app_image_addr + pad_hdr->sh_offset + pad_hdr->sh_size;
	next_trusty_app_fsize_start = trusty_app_image_addr + max_extent + 1;
	ASSERT(next_trusty_app_align_start <= next_trusty_app_fsize_start);

	copy_size = trusty_app_image_end - next_trusty_app_fsize_start;
	if (copy_size) {
		/*
		 * Copy remaining image bytes to aligned start for the next
		 * (and subsequent) trusty_apps. Also decrement trusty_app_image_end, so
		 * we copy less each time we realign for the next trusty_app.
		 */
		memcpy(next_trusty_app_align_start, next_trusty_app_fsize_start, copy_size);
		arch_sync_cache_range((addr_t)next_trusty_app_align_start,
				       copy_size);
		trusty_app_image_end -= (next_trusty_app_fsize_start - next_trusty_app_align_start);
	}

	trusty_app_image_size -= (max_extent + 1);
	return next_trusty_app_align_start;
}

/*
 * Look in the kernel's ELF header for trusty_app sections and
 * carveout memory for their LOAD-able sections.
 */
static void trusty_app_bootloader(void)
{
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr;
	Elf32_Shdr *bss_shdr, *bss_pad_shdr, *manifest_shdr;
	char *shstbl, *trusty_app_image_addr;
	trusty_app_t *trusty_app = 0;

	dprintf(SPEW, "trusty_app: start %p size 0x%08x end %p\n",
		trusty_app_image_start, trusty_app_image_size, trusty_app_image_end);

	trusty_app_image_addr = trusty_app_image_start;

	while (trusty_app_image_size > 0) {
		u_int i, trusty_app_max_extent;

		trusty_app = trusty_app_alloc_parent();
		if (!trusty_app) {
			dprintf(CRITICAL, "trusty_app_bootloader: failed to allocate trusty app\n");
			return;
		}

		ehdr = (Elf32_Ehdr *) trusty_app_image_addr;
		if (strncmp((char *)ehdr->e_ident, ELFMAG, SELFMAG)) {
			dprintf(CRITICAL, "trusty_app_bootloader: ELF header not found\n");
			break;
		}

		shdr = (Elf32_Shdr *) ((intptr_t)ehdr + ehdr->e_shoff);
		shstbl = (char *)((intptr_t)ehdr + shdr[ehdr->e_shstrndx].sh_offset);

		trusty_app_max_extent = 0;
		bss_shdr = bss_pad_shdr = manifest_shdr = NULL;

		/* calculate trusty_app end */
		for (i = 0; i < ehdr->e_shnum; i++) {
			u_int extent;

			if (shdr[i].sh_type == SHT_NULL)
				continue;
#if DEBUG_LOAD_TRUSTY_APP
			dprintf(SPEW, "trusty_app: sect %d, off 0x%08x, size 0x%08x, flags 0x%02x, name %s\n",
				i, shdr[i].sh_offset, shdr[i].sh_size, shdr[i].sh_flags, shstbl + shdr[i].sh_name);
#endif

			/* track bss and manifest sections */
			if (!strcmp((shstbl + shdr[i].sh_name), ".bss")) {
				bss_shdr = shdr + i;
				trusty_app->end_bss = bss_shdr->sh_addr + bss_shdr->sh_size;
			}
			else if (!strcmp((shstbl + shdr[i].sh_name), ".bss-pad")) {
				bss_pad_shdr = shdr + i;
			}
			else if (!strcmp((shstbl + shdr[i].sh_name),
					 ".trusty_app.manifest")) {
				manifest_shdr = shdr + i;
			}

			if (shdr[i].sh_type != SHT_NOBITS) {
				extent = shdr[i].sh_offset + shdr[i].sh_size;
				if (trusty_app_max_extent < extent)
					trusty_app_max_extent = extent;
			}
		}

		/* we need these sections */
		ASSERT(bss_shdr && bss_pad_shdr && manifest_shdr);

		/* clear .bss */
		ASSERT((bss_shdr->sh_offset + bss_shdr->sh_size) <= trusty_app_max_extent);
		memset((uint8_t *)trusty_app_image_addr + bss_shdr->sh_offset, 0, bss_shdr->sh_size);

		load_app_config_options((intptr_t)trusty_app_image_addr, trusty_app, manifest_shdr);
		trusty_app->app_img = ehdr;

		/* align next trusty_app start */
		trusty_app_image_addr = align_next_app(ehdr, bss_pad_shdr, trusty_app_max_extent);
	}
}

status_t trusty_app_setup_mmio(trusty_app_t *trusty_app, u_int mmio_id,
		vaddr_t *vaddr, uint32_t map_size)
{
	uint32_t config_cnt;
	uint32_t *config_blob;
	u_int id, offset, size;

	/* step thru configuration blob looking for I/O mapping requests */
	config_cnt = trusty_app->props.config_entry_cnt;
	config_blob = trusty_app->props.config_blob;
	for (TRUSTY_APP_CFG_ITERATOR(config_blob, config_cnt, key, val)) {
		switch (key) {
		case TRUSTY_APP_CONFIG_KEY_MAP_MEM:
			id = val[0];
			offset = val[1];
			size = ROUNDUP(val[2], PAGE_SIZE);

			if (id != mmio_id)
				continue;

			map_size = ROUNDUP(map_size, PAGE_SIZE);
			if (map_size > size)
				return ERR_INVALID_ARGS;

			return uthread_map_contig(trusty_app->ut, vaddr, offset,
						map_size, UTM_W | UTM_R | UTM_IO,
						UT_MAP_ALIGN_DEFAULT);
			break;
		default:
			break;
		}
	}

	return ERR_NOT_FOUND;
}

static status_t trusty_app_init_one(const char *name, trusty_app_t *trusty_app)
{
	uthread_t *uthread;
	int ret = NO_ERROR;

	/* entry is 0 at this point since we haven't parsed the elf hdrs
	 * yet */
	Elf32_Ehdr *elf_hdr = trusty_app->app_img;
	uthread = uthread_create(name, elf_hdr->e_entry,
				 DEFAULT_PRIORITY, TRUSTY_APP_STACK_TOP,
				 trusty_app->props.min_stack_size, trusty_app);
	if (uthread == NULL) {
		dprintf(CRITICAL, "Trusty app: allocate user thread failed\n");
		ret = ERR_NO_RESOURCES;
		goto done;
	}
	trusty_app->ut = uthread;

	ret = alloc_address_map(trusty_app);
	if (ret != NO_ERROR) {
		dprintf(CRITICAL, "Trusty app: failed to load address map\n");
		goto done;
	}

	/* attach als_cnt */
	trusty_app->als = calloc(1, als_slot_cnt * sizeof(void*));
	if (!trusty_app->als) {
		dprintf(CRITICAL, "Trusty app: allocate app local storage failed\n");
		ret = ERR_NO_MEMORY;
		goto done;
	}

	/* call all registered startup notifiers */
	trusty_app_notifier_t *n;
	list_for_every_entry(&app_notifier_list, n, trusty_app_notifier_t, node) {
		if (n->startup) {
			ret = n->startup(trusty_app);
			if (ret != NO_ERROR) {
				dprintf(CRITICAL, "Trusty app: failed (%d) to invoke startup notifier\n", ret);
				goto done;
			}
		}
	}
done:
	return ret;
}

void trusty_app_init(void)
{
	trusty_app_t *trusty_app;
	u_int i = 0;
	int ret = NO_ERROR;

	trusty_app_image_start = (char *)&__trusty_app_start;
	trusty_app_image_end = (char *)&__trusty_app_end;
	trusty_app_image_size = (trusty_app_image_end - trusty_app_image_start);

	ASSERT(!((uintptr_t)trusty_app_image_start & PAGE_MASK));

	finalize_registration();

	trusty_app_bootloader();

	THREAD_LOCK(state);
	list_for_every_entry(&trusty_app_list, trusty_app, trusty_app_t,
			trusty_app_node)
	{
		char name[THREAD_NAME_LEN];

		snprintf(name, sizeof(name), "trusty_app_%d_%08x-%04x-%04x",
			 i,
			 trusty_app->props.uuid.time_low,
			 trusty_app->props.uuid.time_mid,
			 trusty_app->props.uuid.time_hi_and_version);

		i++;
		ret = trusty_app_init_one(name, trusty_app);
		if (ret)
			trusty_app_exit(trusty_app);
	}
	THREAD_UNLOCK(state);
}

trusty_app_t *trusty_app_find_by_uuid(uuid_t *uuid)
{
	trusty_app_t *ta;

	/* find app for this uuid */
	THREAD_LOCK(state);
	list_for_every_entry(&trusty_app_list, ta, trusty_app_t,
			trusty_app_node)
	{
		// search parent apps; cloned app uuid are duplicates
		if (!ta->is_parent)
			continue;
		if (!memcmp(&ta->props.uuid, uuid, sizeof(uuid_t)))
			return ta;
	}
	THREAD_UNLOCK(state);

	return NULL;
}

/* rather export trusty_app_list?  */
void trusty_app_forall(void (*fn)(trusty_app_t *ta, void *data), void *data)
{
	trusty_app_t *ta;

	if (fn == NULL)
		return;

	THREAD_LOCK(state);
	list_for_every_entry(&trusty_app_list, ta, trusty_app_t,
			trusty_app_node)
	{
		fn(ta, data);
	}
	THREAD_UNLOCK(state);
}

void trusty_app_dead(trusty_app_t *trusty_app)
{
	THREAD_LOCK(state);
	trusty_app->dead = true;
	THREAD_UNLOCK(state);
}

static inline bool trusty_app_is_dead(trusty_app_t *trusty_app)
{
	assert(thread_lock_held());
	return trusty_app->dead;
}

static inline bool trusty_app_is_started(trusty_app_t *trusty_app)
{
	assert(thread_lock_held());
	return trusty_app->started;
}

static status_t trusty_app_start(trusty_app_t *trusty_app)
{
	int ret = NO_ERROR;

	THREAD_LOCK(state);

	if (trusty_app_is_dead(trusty_app)) {
		ret = ERR_ALREADY_STARTED;
		goto release;
	}

	if (trusty_app_is_started(trusty_app)) {
		ret = ERR_ALREADY_STARTED;
		goto release;
	}

	if (!trusty_app->ut || !trusty_app->ut->entry) {
		ret = ERR_INVALID_ARGS;
		goto release;
	}

	trusty_app->kt = trusty_app->ut->thread;
	trusty_app->dead = false;
	trusty_app->started = true;
	list_add_head(&started_app_list, &trusty_app->started_node);

release:
	THREAD_UNLOCK(state);

	if (ret)
		return ret;

	ret = uthread_start(trusty_app->ut);
	if (ret) {
		THREAD_LOCK(state);
		list_delete(&trusty_app->started_node);
		THREAD_UNLOCK(state);
	}

	return ret;
}

static int clone_parent(const trusty_app_t *parent_app, trusty_app_t **child_app)
{
	trusty_app_t *clone_app;

	clone_app = trusty_app_alloc_child();
	if (!clone_app)
		return ERR_NO_RESOURCES;

	clone_app->end_bss = parent_app->end_bss;
	memcpy(&clone_app->props, &parent_app->props, sizeof(clone_app->props));
	clone_app->app_img = parent_app->app_img;

	*child_app = clone_app;
	return NO_ERROR;
}

static status_t trusty_app_clone(trusty_app_t *parent_app, trusty_app_t **ta_clone)
{
	int ret = NO_ERROR;
	char name[THREAD_NAME_LEN];
	trusty_app_t *clone_app = NULL;

	if (!parent_app->is_parent)
		return ERR_INVALID_ARGS;

	ret = clone_parent(parent_app, &clone_app);
	if (ret)
		return ret;

	u_int trusty_app_idx = trusty_app_index(clone_app);
	snprintf(name, sizeof(name), "TA%010d_%08x-%04x-%04x",
		 trusty_app_idx,
		 clone_app->props.uuid.time_low,
		 clone_app->props.uuid.time_mid,
		 clone_app->props.uuid.time_hi_and_version);

	ret = trusty_app_init_one(name, clone_app);
	if (ret) {
		trusty_app_exit(clone_app);
		clone_app = NULL;
	}

	THREAD_LOCK(state);
	list_add_tail(&parent_app->cloned_child_list, &clone_app->cloned_node);
	THREAD_UNLOCK(state);

	*ta_clone = clone_app;

	return ret;
}

// restarts a trusty_app that may already be dead
// output:
// ta_clone is NULL if the parent app was restarted, otherwise
// ta_clone holds the child app which was cloned and started.
static status_t trusty_app_restart(trusty_app_t *parent_app, trusty_app_t **ta_clone)
{
	int ret = NO_ERROR;
	trusty_app_t *ta = parent_app;
	trusty_app_t *clone_app = NULL;
	trusty_app_t *child_app = NULL;

	*ta_clone = NULL;

	if (!parent_app->is_parent)
		return ERR_INVALID_ARGS;

	// lock state because ta state can change in trusty_exit_handler
	THREAD_LOCK(state);

	if (trusty_app_is_dead(ta)) {
		// check if at least one ta instance is started but not dead
		list_for_every_entry( &ta->cloned_child_list, child_app,
				trusty_app_t, cloned_node) {
			if (child_app->started && !child_app->dead) {
				ret = ERR_ALREADY_STARTED;
				goto release;
			}
		}

		// clone new instance of parent app and start it
		ret = trusty_app_clone(ta, &clone_app);
		if (ret == NO_ERROR)
			ta = clone_app;
		else
			goto release;
	}
	ret = trusty_app_start(ta);
	if (ret == NO_ERROR && clone_app)
		*ta_clone = clone_app;

release:
	THREAD_UNLOCK(state);

	return ret;
}

// may be called externally from other thread contexts
status_t trusty_app_start_instance(uuid_t *uuid, trusty_app_t **trusty_app)
{
	int ret = NO_ERROR;
	trusty_app_t *ta;
	trusty_app_t *ta_clone = NULL;

	ta = trusty_app_find_by_uuid(uuid);
	if (!ta) {
		return ERR_NOT_FOUND;
	}

	ret = trusty_app_restart(ta, &ta_clone);
	if (ta_clone)
		*trusty_app = ta_clone;
	else
		*trusty_app = ta;

	return ret;
}

// may be called externally from other thread contexts
status_t trusty_app_start_clone(uuid_t *uuid, trusty_app_t **trusty_app)
{
	int ret = NO_ERROR;
	trusty_app_t *ta;
	trusty_app_t *ta_clone = NULL;

	*trusty_app = NULL;

	ta = trusty_app_find_by_uuid(uuid);
	if (!ta) {
		return ERR_NOT_FOUND;
	}

	ret = trusty_app_clone(ta, &ta_clone);
	if (ret == NO_ERROR) {
		ret = trusty_app_start(ta_clone);
		if (ret == NO_ERROR)
			*trusty_app = ta_clone;
	}

	return ret;
}

static void auto_start_apps(uint level)
{
	trusty_app_t *trusty_app;
	int ret;

	THREAD_LOCK(state);
	list_for_every_entry(&trusty_app_list, trusty_app, trusty_app_t,
			trusty_app_node)
	{
		// search parent apps; cloned apps are not auto started
		if (!trusty_app->is_parent)
			continue;

		if (!trusty_app->props.auto_start)
			continue;

		ret = trusty_app_start(trusty_app);
		if (ret && (ret != ERR_ALREADY_STARTED))
			panic("Cannot auto start Trusty app, ret = %d!\n", ret);
	}
	THREAD_UNLOCK(state);
}

LK_INIT_HOOK(libtrusty_apps, auto_start_apps, LK_INIT_LEVEL_APPS + 1);

static status_t free_address_map(trusty_app_t *trusty_app)
{
	struct free_map_node *node, *next_node;

	// free allocated data and heap pages
	THREAD_LOCK(state);
	if (!list_is_empty(&trusty_app->free_map_list)) {
		list_for_every_entry_safe(&trusty_app->free_map_list, node, next_node,
				struct free_map_node, node) {
			free(node->ptr);
			list_delete(&node->node);
			free(node);
		}
	}
	THREAD_UNLOCK(state);

	return NO_ERROR;
}

// can be called for app cleanup and for exit
status_t trusty_app_exit(trusty_app_t *trusty_app)
{
	status_t ret = NO_ERROR;

	THREAD_LOCK(state);

	trusty_app->dead = true;

	if (trusty_app->ut)
		uthread_kill(trusty_app->ut, ERR_GENERIC);

	trusty_app->ut = NULL;
	trusty_app->kt = NULL;

	free_address_map(trusty_app);

	if (list_in_list(&trusty_app->started_node))
		list_delete(&trusty_app->started_node);

	/* call all registered shutdown notifiers */
	trusty_app_notifier_t *n;
	list_for_every_entry(&app_notifier_list, n, trusty_app_notifier_t, node) {
		if (n->shutdown) {
			ret = n->shutdown(trusty_app);
			if (ret != NO_ERROR)
				dprintf(CRITICAL,
					"Trusty app: failed (%d) to invoke shutdown notifier\n",
					ret);
		}
	}

	if (!trusty_app->is_parent) {
		/* free after calling shutdown notifiers as they may use als slots */
		if (trusty_app->als) {
			free(trusty_app->als);
			trusty_app->als = NULL;
		}
	}

	if (!trusty_app->is_parent)
		trusty_app_free(trusty_app);

	THREAD_UNLOCK(state);

	return ret;
}

__NO_INLINE static void dump_started_app_list(void)
{
	printf("dump_started_app_list:\n");
	struct trusty_app *trusty_app;

	THREAD_LOCK(state);
	list_for_every_entry(&started_app_list, trusty_app, struct trusty_app,
			started_node)
	{
		printf("\t%s\n", trusty_app->kt ? trusty_app->kt->name : "??? dead");
	}
	THREAD_UNLOCK(state);
}

static int trusty_exit_handler(void *arg)
{
	int ret;

        dprintf(SPEW, "starting trusty_exit_handler\n");

	for (;;) {
		struct trusty_app *trusty_app;
		struct trusty_app *temp;

		THREAD_LOCK(state);
		list_for_every_entry_safe(&started_app_list, trusty_app, temp,
				struct trusty_app, started_node) {
			int thread_ret;
			char name[THREAD_NAME_LEN] = {0};
			if (LK_DEBUGLEVEL == SPEW)
				strncpy(name, trusty_app->kt->name, sizeof(name));

			ret = thread_join(trusty_app->kt, &thread_ret, 0);
			switch (ret) {
			case ERR_TIMED_OUT:
				break;
			case ERR_THREAD_DETACHED: // fall through
			case NO_ERROR:
				// not safe to access thread struct beyond thread_join
				trusty_app->kt = NULL;
				trusty_app->ut = NULL;

				dprintf(SPEW,
					"trusty_exit_handler Caught trusty thread exit %s, ret %d\n",
					name, thread_ret);

				// free app resources
				trusty_app_exit(trusty_app);
#if 0 // DEBUG ONLY
				// call dump_started_app_list only after removing from
				// list any apps which have exited and have
				// released the kernel thread pointer.
				dump_started_app_list();
#endif
				break;
			default:
				panic("Trusty app: trusty_exit_handler unexpected exit %d\n", ret);
				break;
			}
		}
		THREAD_UNLOCK(state);
		thread_sleep(100);
	}
}

static void start_exit_handler(uint level)
{
	thread_detach_and_resume(thread_create("trusty_exit_handler",
				&trusty_exit_handler, NULL, DEFAULT_PRIORITY,
				DEFAULT_STACK_SIZE));
}

LK_INIT_HOOK(libtrusty_apps_exit_handler, start_exit_handler, LK_INIT_LEVEL_APPS - 1);
