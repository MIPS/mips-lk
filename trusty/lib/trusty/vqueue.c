/*
 * Copyright (c) 2013-2014, Google, Inc. All rights reserved
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

#include <assert.h>
#include <err.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <trace.h>

#include <arch/arch_ops.h>

#include <lib/trusty/uio.h>

#include <virtio/virtio_ring.h>
#include "vqueue.h"

#define LOCAL_TRACE 0

#define VQ_LOCK_FLAGS SPIN_LOCK_FLAG_INTERRUPTS

int vqueue_init(struct vqueue *vq, uint32_t id,
		void *desc_addr, void *avail_addr, void *used_addr, uint num,
		void *priv, vqueue_cb_t notify_cb, vqueue_cb_t kick_cb)
{
	DEBUG_ASSERT(vq);

	vq->vring_sz = used_addr - desc_addr
                  + sizeof(uint16_t) * 3 + sizeof(struct vring_used_elem) * num;

	vring_init_v1(&vq->vring, num, desc_addr, avail_addr, used_addr);

	vq->id = id;
	vq->priv = priv;
	vq->notify_cb = notify_cb;
	vq->kick_cb = kick_cb;
	// XXX if vrings are placed in kernel virtual memory then vring_addr
	// will be needed to free the allocated memory.
	vq->vring_addr = (vaddr_t) desc_addr;

	event_init(&vq->avail_event, false, 0);

	return NO_ERROR;
}

void vqueue_destroy(struct vqueue *vq)
{
	vaddr_t vring_addr;
	spin_lock_saved_state_t state;

	DEBUG_ASSERT(vq);

	spin_lock_save(&vq->slock, &state, VQ_LOCK_FLAGS);
	vring_addr = vq->vring_addr;
	vq->vring_addr = (vaddr_t)NULL;
	vq->vring_sz = 0;
	spin_unlock_restore(&vq->slock, state, VQ_LOCK_FLAGS);

	vmm_free_region(vmm_get_kernel_aspace(), vring_addr);
}

void vqueue_signal_avail(struct vqueue *vq)
{
	spin_lock_saved_state_t state;

	spin_lock_save(&vq->slock, &state, VQ_LOCK_FLAGS);
	if (vq->vring_addr)
		vq->vring.used->flags |= VRING_USED_F_NO_NOTIFY;
	spin_unlock_restore(&vq->slock, state, VQ_LOCK_FLAGS);
	event_signal(&vq->avail_event, false);
}

/* The other side of virtio pushes buffers into our avail ring, and pulls them
 * off our used ring. We do the reverse. We take buffers off the avail ring,
 * and put them onto the used ring.
 */

static int _vqueue_get_avail_buf_locked(struct vqueue *vq,
					struct vqueue_buf *iovbuf)
{
	uint16_t next_idx;
	struct vring_desc *desc;

	DEBUG_ASSERT(vq);
	DEBUG_ASSERT(iovbuf);

	if (!vq->vring_addr) {
		/* there is no vring - return an error */
		return ERR_CHANNEL_CLOSED;
	}

	/* the idx counter is free running, so check that it's no more
	 * than the ring size away from last time we checked... this
	 * should *never* happen, but we should be careful. */
	uint16_t avail_cnt = vq->vring.avail->idx - vq->last_avail_idx;
	if (unlikely(avail_cnt > (uint16_t) vq->vring.num)) {
		/* such state is not recoverable */
		panic("vq %p: new avail idx out of range (old %u new %u)\n",
		       vq, vq->last_avail_idx, vq->vring.avail->idx);
	}

	if (vq->last_avail_idx == vq->vring.avail->idx) {
		event_unsignal(&vq->avail_event);
		vq->vring.used->flags &= ~VRING_USED_F_NO_NOTIFY;
		mb();
		if (vq->last_avail_idx == vq->vring.avail->idx) {
			/* no buffers left */
			return ERR_NOT_ENOUGH_BUFFER;
		}
		vq->vring.used->flags |= VRING_USED_F_NO_NOTIFY;
		event_signal(&vq->avail_event, false);
	}
	rmb();

	next_idx = vq->vring.avail->ring[vq->last_avail_idx % vq->vring.num];
	vq->last_avail_idx++;

	if (unlikely(next_idx >= vq->vring.num)) {
		/* index of the first descriptor in chain is out of range.
		   vring is in non recoverable state: we cannot even return
		   an error to the other side */
		panic("vq %p: head out of x range %u (max %u) index %d\n",
		       vq, next_idx, vq->vring.num, (vq->last_avail_idx - 1) % vq->vring.num);
	}

	iovbuf->head = next_idx;
	iovbuf->in_iovs.used = 0;
	iovbuf->in_iovs.len  = 0;
	iovbuf->out_iovs.used = 0;
	iovbuf->out_iovs.len  = 0;

	do {
		struct vqueue_iovs *iovlist;

		if (unlikely(next_idx >= vq->vring.num)) {
			/* Descriptor chain is in invalid state.
			 * Abort message handling, return an error to the
			 * other side and let it deal with it.
			 */
			LTRACEF("vq %p: head out of y range %u (max %u)\n",
			       vq, next_idx, vq->vring.num);
			return ERR_NOT_VALID;
		}

		desc = &vq->vring.desc[next_idx];
		if (desc->flags & VRING_DESC_F_WRITE)
			iovlist = &iovbuf->out_iovs;
		else
			iovlist = &iovbuf->in_iovs;

		if (iovlist->used < iovlist->cnt) {
			/* .base will be set when we map this iov */
			iovlist->iovs[iovlist->used].len = desc->len;
			iovlist->phys[iovlist->used] = (paddr_t) desc->addr;
			iovlist->used++;
			iovlist->len += desc->len;
		} else {
			return ERR_TOO_BIG;
		}

		/* go to the next entry in the descriptor chain */
		next_idx = desc->next;
	} while (desc->flags & VRING_DESC_F_NEXT);

	return NO_ERROR;
}

int vqueue_get_avail_buf(struct vqueue *vq, struct vqueue_buf *iovbuf)
{
	spin_lock_saved_state_t state;

	spin_lock_save(&vq->slock, &state, VQ_LOCK_FLAGS);
	int ret = _vqueue_get_avail_buf_locked(vq, iovbuf);
	spin_unlock_restore(&vq->slock, state, VQ_LOCK_FLAGS);
	return ret;
}

static int _vqueue_add_buf_locked(struct vqueue *vq, struct vqueue_buf *buf, uint32_t len)
{
	struct vring_used_elem *used;

	DEBUG_ASSERT(vq);
	DEBUG_ASSERT(buf);

	if (!vq->vring_addr) {
		/* there is no vring - return an error */
		return ERR_CHANNEL_CLOSED;
	}

	if (buf->head >= vq->vring.num) {
		/* this would probable mean corrupted vring */
		LTRACEF("vq %p: head (%u) out of range (%u)\n",
		         vq, buf->head, vq->vring.num);
		return ERR_NOT_VALID;
	}

	used = &vq->vring.used->ring[vq->vring.used->idx % vq->vring.num];
	used->id = buf->head;
	used->len = len;
	wmb();
	vq->vring.used->idx++;

	vqueue_kick(vq);
	return NO_ERROR;
}

int vqueue_add_buf(struct vqueue *vq, struct vqueue_buf *buf, uint32_t len)
{
	spin_lock_saved_state_t state;

	spin_lock_save(&vq->slock, &state, VQ_LOCK_FLAGS);
	int ret = _vqueue_add_buf_locked(vq, buf, len);
	spin_unlock_restore(&vq->slock, state, VQ_LOCK_FLAGS);
	return ret;
}

int vqueue_kick(struct vqueue *vq)
{
	if (vq->kick_cb)
		return vq->kick_cb(vq, vq->priv);
	return 0;
}

