/*
 * Copyright (c) 2014-2015, Google, Inc. All rights reserved
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
#include <compiler.h>
#include <err.h>
#include <reflist.h>
#include <kernel/mutex.h>
#include <kernel/thread.h>
#include <platform/interrupts.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <trace.h>

#include <lk/init.h>

#include "vqueue.h"
#include <virtio/virtio_ring.h>
#include <virtio/virtio_config.h>

#include "l4virtio_priv.h"

#include <lib/trusty/handle.h>
#include <lib/trusty/ipc.h>
#include <lib/trusty/ipc_msg.h>
#include <lib/trusty/tipc_dev.h>

#define LOCAL_TRACE  0


#define MAX_RX_IOVS  1
#define MAX_TX_IOVS  1

/*
 *  Control endpoint address
 */
#define TIPC_CTRL_ADDR			(53)

/*
 * Max number of opned channels supported
 */
#define TIPC_ADDR_MAX_NUM		256

/*
 * Local adresses base
 */
#define TIPC_ADDR_BASE			1000

/*
 * Maximum service name size
 */
#define TIPC_MAX_SRV_NAME_LEN		(256)

/*
 * Timeout for rx thread ipc send retry (msec)
 */
#define TIPC_RX_RETRY_TIMEOUT		5000

enum {
	VDEV_STATE_RESET = 0,
	VDEV_STATE_GOING_ONLINE,
	VDEV_STATE_ACTIVE,
};


struct tipc_ept {
	uint32_t remote;
	handle_t *chan;
};

struct tipc_dev {
	volatile int state;
	const uuid_t		*uuid;
	const void		*descr_ptr;
	size_t			descr_size;

	struct l4virtio_config *cfg;
	struct l4virtio_queue_config *queue_cfg;
	vaddr_t			driver_window;

	struct vqueue		vqs[TIPC_VQ_NUM];
	struct tipc_ept		epts[TIPC_ADDR_MAX_NUM];
	unsigned long		inuse[BITMAP_NUM_WORDS(TIPC_ADDR_MAX_NUM)];

	event_t			rx_retry;
	event_t			have_handles;
	handle_list_t		handle_list;

	mutex_t			ept_lock;

	thread_t		*rx_thread;
	thread_t		*tx_thread;

	bool			tx_stop;
	bool			rx_stop;
};

struct tipc_hdr {
	uint32_t src;
	uint32_t dst;
	uint32_t reserved;
	uint16_t len;
	uint16_t flags;
	uint8_t data[0];
} __PACKED;

enum tipc_ctrl_msg_types {
	TIPC_CTRL_MSGTYPE_GO_ONLINE = 1,
	TIPC_CTRL_MSGTYPE_GO_OFFLINE,
	TIPC_CTRL_MSGTYPE_CONN_REQ,
	TIPC_CTRL_MSGTYPE_CONN_RSP,
	TIPC_CTRL_MSGTYPE_DISC_REQ,
};

/*
 *   TIPC control message consists of common tipc_ctrl_msg_hdr
 *   immediately followed by message specific body which also
 *   could be empty.
 *
 *   struct tipc_ctrl_msg {
 *      struct tipc_ctrl_msg_hdr hdr;
 *      uint8_t  body[0];
 *   } __PACKED;
 *
 */
struct tipc_ctrl_msg_hdr {
	uint32_t type;
	uint32_t body_len;
} __PACKED;

struct tipc_conn_req_body {
	char name[TIPC_MAX_SRV_NAME_LEN];
} __PACKED;

struct tipc_conn_rsp_body {
	uint32_t target;
	uint32_t status;
	uint32_t remote;
	uint32_t max_msg_size;
	uint32_t max_msg_cnt;
} __PACKED;

struct tipc_disc_req_body {
	uint32_t target;
} __PACKED;


typedef int (*tipc_data_cb_t) (uint8_t *dst, size_t sz, void *ctx);

static int
tipc_send_data(struct tipc_dev *dev, uint32_t local, uint32_t remote,
               tipc_data_cb_t cb, void *cb_ctx,  uint16_t data_len,
               bool wait);

static int
tipc_send_buf(struct tipc_dev *dev, uint32_t local, uint32_t remote,
              void *data, uint16_t data_len, bool wait);


static inline uint addr_to_slot(uint32_t addr)
{
	return (uint)(addr - TIPC_ADDR_BASE);
}

static inline uint32_t slot_to_addr(uint slot)
{
	return (uint32_t) (slot + TIPC_ADDR_BASE);
}

static uint32_t alloc_local_addr(struct tipc_dev *dev, uint32_t remote,
                                 handle_t *chan)
{
	int slot = bitmap_ffz(dev->inuse, TIPC_ADDR_MAX_NUM);
	if (slot >= 0) {
		bitmap_set(dev->inuse, slot);
		dev->epts[slot].chan = chan;
		dev->epts[slot].remote = remote;
		return slot_to_addr(slot);
	}
	return 0;
}

static struct tipc_ept *lookup_ept(struct tipc_dev *dev, uint32_t local)
{
	uint slot = addr_to_slot(local);
	if (slot < TIPC_ADDR_MAX_NUM) {
		if (bitmap_test(dev->inuse, slot)) {
			return &dev->epts[slot];
		}
	}
	return NULL;
}

static uint32_t ept_to_addr(struct tipc_dev *dev, struct tipc_ept *ept)
{
	return slot_to_addr(ept - dev->epts);
}

static void free_local_addr(struct tipc_dev *dev, uint32_t local)
{
	uint slot = addr_to_slot(local);

	if (slot < TIPC_ADDR_MAX_NUM) {
		bitmap_clear(dev->inuse, slot);
		dev->epts[slot].chan = NULL;
		dev->epts[slot].remote = 0;
	}
}

static int virtio_dev_to_kvaddr(struct tipc_dev *dev, paddr_t da, size_t size,
		void **va)
{
	struct tipc_vdev_descr *desc = (struct tipc_vdev_descr *) dev->descr_ptr;

	if (size > desc->driver_mem_size || da > desc->driver_mem_size - size)
		return ERR_NO_RESOURCES;

	*va = (void *)(dev->driver_window + da);

	return NO_ERROR;
}

int virtio_dev_to_phys(struct tipc_dev *dev, paddr_t da, size_t size,
		paddr_t *pa)
{
	void *va;
	status_t ret;

	ret = virtio_dev_to_kvaddr(dev, da, size, &va);
	if (ret)
		return ret;

	*pa = vaddr_to_paddr(va);
	if (*pa == (paddr_t)NULL)
		return ERR_NO_RESOURCES;

	return NO_ERROR;
}

static int virtio_map_iovs(struct tipc_dev *dev, struct vqueue_iovs *vqiovs, u_int flags)
{
	uint  i;
	int ret = NO_ERROR;

	for (i = 0; i < vqiovs->used; i++) {
		void *va;

		ret = virtio_dev_to_kvaddr(dev, vqiovs->phys[i],
				vqiovs->iovs[i].len, &va);
		if (ret)
			break;

		vqiovs->iovs[i].base = va;
	}

	return ret;
}

static void virtio_unmap_iovs(struct vqueue_iovs *vqiovs)
{
	for (uint i = 0; i < vqiovs->used; i++) {
		/* base is expected to be set */
		DEBUG_ASSERT(vqiovs->iovs[i].base);
		/* don't do anything at the moment, the memory is fixed */
		vqiovs->iovs[i].base = NULL;
	}
}



static int _go_online(struct tipc_dev *dev)
{
	struct {
		struct tipc_ctrl_msg_hdr hdr;
		/* body is empty */
	} msg;

	msg.hdr.type = TIPC_CTRL_MSGTYPE_GO_ONLINE;
	msg.hdr.body_len  = 0;

	dev->state = VDEV_STATE_GOING_ONLINE;

	return tipc_send_buf(dev, TIPC_CTRL_ADDR, TIPC_CTRL_ADDR,
	                     &msg, sizeof(msg), true);
}

/*
 * When getting a notify for the TX vq, it is the other side telling us
 * that buffers are now available
 */
static int tipc_tx_vq_notify_cb(struct vqueue *vq, void *priv)
{
	vqueue_signal_avail(vq);
	return 0;
}

static int tipc_rx_vq_notify_cb(struct vqueue *vq, void *priv)
{
	vqueue_signal_avail(vq);
	return 0;
}

static const vqueue_cb_t notify_cbs[TIPC_VQ_NUM] = {
	[TIPC_VQ_TX] = tipc_tx_vq_notify_cb,
	[TIPC_VQ_RX] = tipc_rx_vq_notify_cb,
};


static int send_conn_rsp(struct tipc_dev *dev, uint32_t local,
                         uint32_t remote, uint32_t status,
                         uint32_t msg_sz, uint32_t msg_cnt)
{
	struct {
		struct tipc_ctrl_msg_hdr  hdr;
		struct tipc_conn_rsp_body body;
	} msg;

	msg.hdr.type = TIPC_CTRL_MSGTYPE_CONN_RSP;
	msg.hdr.body_len = sizeof(msg.body);

	msg.body.target = remote;
	msg.body.status = status;
	msg.body.remote = local;
	msg.body.max_msg_size = msg_sz;
	msg.body.max_msg_cnt = msg_cnt;

	return tipc_send_buf(dev, TIPC_CTRL_ADDR, TIPC_CTRL_ADDR,
	                     &msg, sizeof(msg), true);
}

static int send_disc_req(struct tipc_dev *dev, uint32_t local, uint32_t remote)
{
	struct {
		struct tipc_ctrl_msg_hdr  hdr;
		struct tipc_disc_req_body body;
	} msg;

	msg.hdr.type = TIPC_CTRL_MSGTYPE_DISC_REQ;
	msg.hdr.body_len = sizeof(msg.body);

	msg.body.target = remote;

	return tipc_send_buf(dev, local, TIPC_CTRL_ADDR,
	                     &msg,  sizeof(msg), true);
}

static int handle_conn_req(struct tipc_dev *dev, uint32_t remote,
                           const volatile struct tipc_conn_req_body *ns_req)
{
	int err;
	uint32_t local = 0;
	handle_t *chan = NULL;
	struct tipc_conn_req_body req;

	LTRACEF("remote %u\n", remote);

	strncpy(req.name, (const char *)ns_req->name, sizeof(req.name));

	/* open ipc channel */
	err = ipc_port_connect_async(dev->uuid, req.name, sizeof(req.name),
				     0, &chan);
	if (err == NO_ERROR) {
		mutex_acquire(&dev->ept_lock);
		local = alloc_local_addr(dev, remote, chan);
		if (local == 0) {
			LTRACEF("failed to alloc local address\n");
			handle_close(chan);
			chan = NULL;
		}
		mutex_release(&dev->ept_lock);
	}

	if (chan) {
		LTRACEF("new handle: local = 0x%x remote = 0x%x\n",
			 local, remote);
		handle_set_cookie(chan, lookup_ept(dev, local));
		handle_list_add(&dev->handle_list, chan);
		event_signal(&dev->have_handles, false);
		return NO_ERROR;
	}

	err = send_conn_rsp(dev, local, remote, ERR_NO_RESOURCES, 0, 0);
	if (err) {
		TRACEF("failed (%d) to send response\n", err);
	}

	return err;
}

static int handle_disc_req(struct tipc_dev *dev, uint32_t remote,
                           const volatile struct tipc_disc_req_body *ns_req)
{
	struct tipc_ept *ept;
	uint32_t target = ns_req->target;

	LTRACEF("remote %u: target %u\n", remote, target);

	mutex_acquire(&dev->ept_lock);

	/* Ultimately we have to lookup channel by remote address.
	 * Local address is also provided by remote side but there
	 * is a scenario when it might not be valid. Nevertheless,
	 * we can try to use it first before doing full lookup.
	 */
	ept = lookup_ept(dev, target);
	if (!ept || ept->remote != remote) {
		ept = NULL;
		/* do full search: TODO search handle list */
		for (uint slot  = 0; slot < countof(dev->epts); slot++) {
			if (bitmap_test(dev->inuse, slot)) {
				if (dev->epts[slot].remote == remote) {
					ept = &dev->epts[slot];
					break;
				}
			}
		}
	}

	if (ept) {
		handle_t *chan = ept->chan;

		if (chan) {
			/* detach handle from handle list */
			handle_list_del(&dev->handle_list, chan);

			/* detach ept */
			handle_set_cookie(chan, NULL);

			/* close handle */
			handle_close(chan);
		}

		free_local_addr(dev, ept_to_addr(dev, ept));
	}

	mutex_release(&dev->ept_lock);

	return NO_ERROR;
}

static int handle_ctrl_msg(struct tipc_dev *dev, uint32_t remote,
                           const volatile void *ns_data, size_t msg_len)
{
	uint32_t msg_type;
	size_t   msg_body_len;
	const volatile void *ns_msg_body;
	const volatile struct tipc_ctrl_msg_hdr *ns_msg_hdr = ns_data;

	DEBUG_ASSERT(ns_data);

	/* do some sanity checks */
	if (msg_len < sizeof(struct tipc_ctrl_msg_hdr)) {
		LTRACEF("%s: remote=%u: ttl_len=%zu\n",
		        "malformed msg", remote, msg_len);
		return ERR_NOT_VALID;
	}

	msg_type = ns_msg_hdr->type;
	msg_body_len = ns_msg_hdr->body_len;
	ns_msg_body = (const volatile uint8_t *)ns_data + sizeof(struct tipc_ctrl_msg_hdr);

	if (sizeof(struct tipc_ctrl_msg_hdr) + msg_body_len != msg_len)
		goto err_mailformed_msg;

	switch (msg_type) {
	case TIPC_CTRL_MSGTYPE_CONN_REQ:
		if (msg_body_len != sizeof(struct tipc_conn_req_body))
			break;
		return handle_conn_req(dev, remote, ns_msg_body);

	case TIPC_CTRL_MSGTYPE_DISC_REQ:
		if (msg_body_len != sizeof(struct tipc_disc_req_body))
			break;
		return handle_disc_req(dev, remote, ns_msg_body);

	default:
		break;
	}

err_mailformed_msg:
	LTRACEF("%s: remote=%u: ttl_len=%zu msg_type=%u msg_len=%zu\n",
		"malformed msg", remote, msg_len, msg_type, msg_body_len);
	return ERR_NOT_VALID;
}

static void signal_rx_retry(struct tipc_dev *dev)
{
	/* unblock and set reschedule=true for the rx thread */
	LTRACEF("sending rx_retry signal\n");
	event_signal(&dev->rx_retry, true);
}

static int handle_chan_msg(struct tipc_dev *dev, uint32_t remote, uint32_t local,
                           const volatile void *ns_data, size_t len)
{
	struct tipc_ept *ept;
	int ret;
	ipc_msg_kern_t msg = {
		.iov		= (iovec_kern_t []) {
			[0]	= {
				.base	= (void *)ns_data,
				.len	= len,
			},
		},
		.num_iov	= 1,
		.num_handles	= 0,
	};

	event_unsignal(&dev->rx_retry);

retry_send_msg:
	ret = ERR_NOT_FOUND;
	mutex_acquire(&dev->ept_lock);
	ept = lookup_ept(dev, local);
	if (ept && ept->remote == remote) {
		if (ept->chan)
			ret = ipc_send_msg(ept->chan, &msg);
	}
	mutex_release(&dev->ept_lock);

	if (ret == ERR_NOT_ENOUGH_BUFFER) {
		LTRACEF("waiting for rx_retry signal...\n");
		ret = event_wait_timeout(&dev->rx_retry,
				TIPC_RX_RETRY_TIMEOUT);
		if (ret == NO_ERROR) {
			LTRACEF("... retrying ipc_send_msg\n");
			goto retry_send_msg;
		}
		/* timeout not fatal; just not expected and will drop a msg */
		DEBUG_ASSERT(ret != ERR_TIMED_OUT);
	}

	return ret;
}

static int handle_rx_msg(struct tipc_dev *dev, struct vqueue_buf *buf)
{
	const volatile struct tipc_hdr *ns_hdr;
	const volatile void *ns_data;
	size_t ns_data_len;
	uint32_t  src_addr;
	uint32_t  dst_addr;

	DEBUG_ASSERT(dev);
	DEBUG_ASSERT(buf);

	LTRACEF("got RX buf: head %hu buf in %d out %d\n",
	         buf->head,  buf->in_iovs.used, buf->out_iovs.used);

	/* we will need at least 1 iovec */
	if (buf->in_iovs.used == 0) {
		LTRACEF("unexpected in_iovs num %d\n", buf->in_iovs.used);
		return ERR_INVALID_ARGS;
	}

	/* there should be exactly 1 in_iov but it is not fatal if the first
	   one is big enough */
	if (buf->in_iovs.used != 1) {
		LTRACEF("unexpected in_iovs num %d\n", buf->in_iovs.used);
	}

	/* out_iovs are not supported: just log message and ignore it */
	if (buf->out_iovs.used != 0) {
		LTRACEF("unexpected out_iovs num %d\n", buf->in_iovs.used);
	}

	/* map in_iovs, Non-secure, no-execute, cached, read-only */
	uint map_flags = ARCH_MMU_FLAG_NS | ARCH_MMU_FLAG_PERM_NO_EXECUTE |
	                 ARCH_MMU_FLAG_CACHED | ARCH_MMU_FLAG_PERM_RO;
	int ret = virtio_map_iovs(dev, &buf->in_iovs, map_flags);
	if (ret) {
		TRACEF("failed to map iovs %d\n", ret);
		return ret;
	}

	/* check message size */
	if (buf->in_iovs.iovs[0].len < sizeof(struct tipc_hdr)) {
		LTRACEF("msg too short %zu\n", buf->in_iovs.iovs[0].len);
		ret = ERR_INVALID_ARGS;
		goto done;
	}

	ns_hdr  = buf->in_iovs.iovs[0].base;
	ns_data = (uint8_t *)buf->in_iovs.iovs[0].base + sizeof(struct tipc_hdr);
	ns_data_len = ns_hdr->len;
	src_addr = ns_hdr->src;
	dst_addr = ns_hdr->dst;

	if (ns_data_len + sizeof(struct tipc_hdr) != buf->in_iovs.iovs[0].len) {
		LTRACEF("malformed message len %zu msglen %zu\n",
			ns_data_len, buf->in_iovs.iovs[0].len);
		ret = ERR_INVALID_ARGS;
		goto done;
	}

	if (dst_addr == TIPC_CTRL_ADDR)
		ret = handle_ctrl_msg(dev, src_addr, ns_data, ns_data_len);
	else
		ret = handle_chan_msg(dev, src_addr, dst_addr, ns_data, ns_data_len);

done:
	virtio_unmap_iovs(&buf->in_iovs);

	return ret;
}

static int tipc_rx_thread_func(void *arg)
{
	struct tipc_dev *dev = arg;
	paddr_t in_phys[MAX_RX_IOVS];
	iovec_kern_t in_iovs[MAX_RX_IOVS];
	struct vqueue *vq = &dev->vqs[TIPC_VQ_RX];
	struct vqueue_buf buf;
	int ret;

	LTRACEF("enter\n");

	ret = _go_online(dev);
	if (ret == NO_ERROR) {
		dev->state = VDEV_STATE_ACTIVE;
	}

	LTRACEF("Device is online\n");

	memset(&buf, 0, sizeof(buf));

	buf.in_iovs.cnt  = MAX_RX_IOVS;
	buf.in_iovs.phys = in_phys;
	buf.in_iovs.iovs = in_iovs;

	while(!dev->rx_stop) {
		/* wait for next available buffer */
		event_wait(&vq->avail_event);

		ret = vqueue_get_avail_buf(vq, &buf);

		if (ret == ERR_CHANNEL_CLOSED)
			break;  /* need to terminate */

		if (ret == ERR_NOT_ENOUGH_BUFFER)
			continue;  /* no new messages */

		if (likely(ret == NO_ERROR)) {
			ret = handle_rx_msg(dev, &buf);
			if (ret < 0)
				TRACEF("Error (%d) dropping msg!\n", ret);
		}

		ret = vqueue_add_buf(vq, &buf, ret);
		if (ret == ERR_CHANNEL_CLOSED)
			break;  /* need to terminate */

		if (ret != NO_ERROR) {
			/* any other error is only possible if
			 * vqueue is corrupted.
			 */
			panic("Unable (%d) to return buffer to vqueue\n", ret);
		}
	}

	LTRACEF("exit\n");

	return 0;
}

typedef struct data_cb_ctx {
	handle_t      *chan;
	ipc_msg_info_t msg_inf;
} data_cb_ctx_t;

static int tx_data_cb(uint8_t *buf, size_t buf_len, void *ctx)
{
	int rc;
	data_cb_ctx_t *cb_ctx = (data_cb_ctx_t *) ctx;

	DEBUG_ASSERT(buf);
	DEBUG_ASSERT(cb_ctx);

	iovec_kern_t dst_iov = { buf, buf_len };
	ipc_msg_kern_t dst_kern_msg = {
		.iov     = &dst_iov,
		.num_iov = 1,
		.num_handles = 0,
		.handles = NULL,
	};

	/* read data */
	rc = ipc_read_msg(cb_ctx->chan, cb_ctx->msg_inf.id, 0,
		          &dst_kern_msg);

	/* retire msg */
	ipc_put_msg(cb_ctx->chan, cb_ctx->msg_inf.id);
	return rc;
}

static void handle_tx_msg(struct tipc_dev *dev, handle_t *chan)
{
	int ret;
	uint32_t local = 0;
	uint32_t remote = 0;
	struct tipc_ept *ept;
	data_cb_ctx_t cb_ctx = { .chan = chan };

	mutex_acquire(&dev->ept_lock);
	ept = handle_get_cookie(chan);
	if (!ept) {
		mutex_release(&dev->ept_lock);
		return;
	}
	remote = ept->remote;
	mutex_release(&dev->ept_lock);

	/* for all available messages */
	for (;;) {
		/* get next message info */
		ret = ipc_get_msg(chan, &cb_ctx.msg_inf);

		if (ret == ERR_NO_MSG)
			break; /* no new messages */

		if (ret != NO_ERROR) {
			/* should never happen */
			panic ("%s: failed (%d) to get message\n",
			       __func__, ret);
		}

		uint16_t ttl_size = cb_ctx.msg_inf.len;

		LTRACEF("forward message (%d bytes)\n", ttl_size);

		/* send message using data callback */
		ret = tipc_send_data(dev, local, remote,
		                     tx_data_cb, &cb_ctx, ttl_size, true);
		if (ret != NO_ERROR) {
			/* nothing we can do about it: log it */
			TRACEF("tipc_send_data failed (%d)\n", ret);
		}
	}
}

static void handle_hup(struct tipc_dev *dev, handle_t *chan)
{
	uint32_t local = 0;
	uint32_t remote = 0;
	struct tipc_ept *ept;
	bool send_disc = false;

	mutex_acquire(&dev->ept_lock);
	ept = handle_get_cookie(chan);
	if (ept) {
		/* get remote address */
		remote = ept->remote;
		local  = ept_to_addr(dev, ept);
		send_disc = true;

		/* remove handle from handle list */
		handle_list_del(&dev->handle_list, chan);

		/* kill cookie */
		handle_set_cookie(chan, NULL);

		/* close it */
		handle_close(chan);

		/* free_local_address */
		free_local_addr(dev, local);
	}
	mutex_release(&dev->ept_lock);

	if (send_disc) {
		/* send disconnect request */
		(void) send_disc_req(dev, local, remote);
	}

	/* unblock rx thread potentially waiting to retry */
	signal_rx_retry(dev);
}

static void handle_ready(struct tipc_dev *dev, handle_t *chan)
{
	uint32_t local = 0;
	uint32_t remote = 0;
	struct tipc_ept *ept;
	bool send_rsp = false;

	mutex_acquire(&dev->ept_lock);
	ept = handle_get_cookie(chan);
	if (ept) {
		/* get remote address */
		remote = ept->remote;
		local  = ept_to_addr(dev, ept);
		send_rsp = true;
	}
	mutex_release(&dev->ept_lock);

	if (send_rsp) {
		/* send connect response */
		(void) send_conn_rsp(dev, local, remote, 0,
				     IPC_CHAN_MAX_BUF_SIZE, 1);
	}
}

static void handle_tx(struct tipc_dev *dev)
{
	int ret;
	handle_t *chan;
	uint32_t  chan_event;

	DEBUG_ASSERT(dev);

	for (;;) {
		/* wait for incoming messgages */
		ret = handle_list_wait(&dev->handle_list, &chan,
				       &chan_event, INFINITE_TIME);

		if (ret == ERR_NOT_FOUND) {
			/* no handles left */
			return;
		}

		if (ret < 0) {
			/* only possible if somebody else is waiting
			   on the same handle which should never happen */
			panic("%s: couldn't wait for handle events (%d)\n",
			      __func__, ret);
		}

		DEBUG_ASSERT(chan);
		DEBUG_ASSERT(ipc_is_channel(chan));

		if (chan_event & IPC_HANDLE_POLL_READY) {
			handle_ready(dev, chan);
		} else if (chan_event & IPC_HANDLE_POLL_MSG) {
			handle_tx_msg(dev, chan);
		} else if (chan_event & IPC_HANDLE_POLL_HUP) {
			handle_hup(dev, chan);
		} else if (chan_event & IPC_HANDLE_POLL_SEND_UNBLOCKED) {
			signal_rx_retry(dev);
		} else {
			LTRACEF("Unhandled event %x\n", chan_event);
		}
		handle_decref(chan);
	}
}

static int tipc_tx_thread_func(void *arg)
{
	struct tipc_dev *dev = arg;

	LTRACEF("enter\n");
	while (!dev->tx_stop) {
		LTRACEF("waiting for handles\n");

		/* wait forever until we have handles */
		event_wait(&dev->have_handles);

		LTRACEF("have handles\n");

		/* handle messsages */
		handle_tx(dev);

		LTRACEF("no handles\n");
	}

	LTRACEF("exit\n");
	return 0;
}

static status_t tipc_dev_reset(struct tipc_dev *dev)
{
	status_t rc;
	struct tipc_ept *ept;

	if (dev->state == VDEV_STATE_RESET)
		return NO_ERROR;

	/* Shutdown rx thread to block all incomming requests */
	dev->rx_stop = true;
	vqueue_signal_avail(&dev->vqs[TIPC_VQ_RX]);
	rc = thread_join(dev->rx_thread, NULL, 1000);
	LTRACEF("rx thread join: returned %d\n", rc);
	if (rc != NO_ERROR) {
		panic("unable to shutdown rx thread: %d\n", rc);
	}
	dev->rx_thread = NULL;
	dev->rx_stop = false;

	/* Set stop tx thread */
	dev->tx_stop = true;

	/* close all channels */
	mutex_acquire(&dev->ept_lock);
	ept = dev->epts;
	for (uint slot  = 0; slot < countof(dev->epts); slot++, ept++) {
		if (!bitmap_test(dev->inuse, slot))
			continue;

		if (!ept->chan)
			continue;

		handle_list_del(&dev->handle_list, ept->chan);
		handle_set_cookie(ept->chan, NULL);
		handle_close(ept->chan);
		free_local_addr(dev, ept_to_addr(dev, ept));
	}
	mutex_release(&dev->ept_lock);

	/* kick tx thread and tx vq */
	event_signal(&dev->have_handles, false);
	vqueue_signal_avail(&dev->vqs[TIPC_VQ_TX]);

	/* wait it to terminate */
	rc = thread_join(dev->tx_thread, NULL, 1000);
	LTRACEF("tx thread join: returned %d\n", rc);
	if (rc != NO_ERROR) {
		panic("unable to shutdown tx thread: %d\n", rc);
	}
	dev->tx_thread = NULL;
	dev->tx_stop = false;

	/* destroy vqs */
	vqueue_destroy(&dev->vqs[TIPC_VQ_RX]);
	vqueue_destroy(&dev->vqs[TIPC_VQ_TX]);

	/* enter reset state */
	dev->state = VDEV_STATE_RESET;

	return NO_ERROR;
}

static status_t validate_descr(struct tipc_dev *dev,
                               struct tipc_vdev_descr *vdev_descr)
{
	if (vdev_descr->hdr.type != RSC_VDEV) {
		LTRACEF("unexpected type %d\n", vdev_descr->hdr.type);
		return ERR_INVALID_ARGS;
	}

	if (vdev_descr->vdev.id != VIRTIO_ID_L4TRUSTY_IPC) {
		LTRACEF("unexpected vdev id%d\n", vdev_descr->vdev.id);
		return ERR_INVALID_ARGS;
	}

	if (vdev_descr->vdev.num_of_vrings != TIPC_VQ_NUM) {
		LTRACEF("unexpected number of vrings (%d vs. %d)\n",
			vdev_descr->vdev.num_of_vrings, TIPC_VQ_NUM);
		return ERR_INVALID_ARGS;
	}

	/* check if NS driver successfully initilized */
	if (vdev_descr->vdev.status != (VIRTIO_CONFIG_S_ACKNOWLEDGE |
				        VIRTIO_CONFIG_S_DRIVER |
				        VIRTIO_CONFIG_S_DRIVER_OK | VIRTIO_STATUS_FEATURES_OK)) {
		LTRACEF("unexpected status %d\n",
			(int)vdev_descr->vdev.status);
		return ERR_INVALID_ARGS;
	}

	return NO_ERROR;
}

static int virtio_kick_cb(struct vqueue *vq, void *priv)
{
	struct tipc_dev *dev = (struct tipc_dev *)priv;

	// kick other side
	dev->cfg->interrupt_status |= 1;
	wmb();
	dev->cfg->queue_notify =
		dev->queue_cfg[vqueue_id(vq)].device_notify_index;

	return 0;
}

/*
 *  Should be only called once.
 */
static status_t tipc_dev_probe(struct tipc_dev *dev,
                               struct tipc_vdev_descr *dscr)
{
	status_t ret;
	uint vring_cnt;
	char tname[32];

	LTRACEF("%p: descr = %p\n", dev, dscr);

	if (dev->state != VDEV_STATE_RESET)
		return ERR_BAD_STATE;

	ret = validate_descr(dev, dscr);
	if (ret != NO_ERROR)
		return ret;

	/* vring[0] == TX queue (host's RX) */
	/* vring[1] == RX queue (host's TX) */
	for (vring_cnt = 0; vring_cnt < dscr->vdev.num_of_vrings; vring_cnt++) {
		struct fw_rsc_vdev_vring *vring = &dscr->vrings[vring_cnt];
		struct l4virtio_queue_config *qcfg = &dev->queue_cfg[vring_cnt];
		void *daddr;
		void *aaddr;
		void *uaddr;


		if (virtio_dev_to_kvaddr(dev, qcfg->desc_addr, 0, &daddr))
			goto err_vq_init;

		if (virtio_dev_to_kvaddr(dev, qcfg->avail_addr, 0, &aaddr))
			goto err_vq_init;

		if (virtio_dev_to_kvaddr(dev, qcfg->used_addr, 0, &uaddr))
			goto err_vq_init;

		ret = vqueue_init(&dev->vqs[vring_cnt], vring_cnt,
				  daddr, aaddr, uaddr, vring->num, dev,
				  notify_cbs[vring_cnt], &virtio_kick_cb);
		if (ret)
			goto err_vq_init;
	}

	/* create rx thread */
	snprintf(tname, sizeof(tname), "tipc-dev%u-rx", dscr->vdev.notifyid);
	dev->rx_thread =
		thread_create(tname, tipc_rx_thread_func, dev,
			      DEFAULT_PRIORITY, DEFAULT_STACK_SIZE);

	if (dev->rx_thread) {
		thread_resume(dev->rx_thread);
	}

	/* create tx thread */
	snprintf(tname, sizeof(tname), "tipc-dev%u-tx", dscr->vdev.notifyid);
	dev->tx_thread =
		thread_create(tname, tipc_tx_thread_func, dev,
			      DEFAULT_PRIORITY, DEFAULT_STACK_SIZE);
	if (dev->tx_thread) {
		thread_resume(dev->tx_thread);
	}

	return ret;

err_vq_init:
	while (vring_cnt--) {
		vqueue_destroy(&dev->vqs[vring_cnt]);
	}
	return ret;
}

static int
tipc_send_data(struct tipc_dev *dev, uint32_t local, uint32_t remote,
               tipc_data_cb_t cb, void *cb_ctx,  uint16_t data_len,
               bool wait)
{
	paddr_t out_phys[MAX_TX_IOVS];
	iovec_kern_t out_iovs[MAX_TX_IOVS];
	struct vqueue *vq = &dev->vqs[TIPC_VQ_TX];
	struct vqueue_buf buf;
	int ret = 0;

	DEBUG_ASSERT(dev);

	/* check if data callback specified */
	if (!cb)
		return ERR_INVALID_ARGS;

	size_t ttl_len =
	sizeof(struct tipc_hdr) + data_len;

	memset(&buf, 0, sizeof(buf));
	buf.out_iovs.cnt  = MAX_TX_IOVS;
	buf.out_iovs.phys = out_phys;
	buf.out_iovs.iovs = out_iovs;


	/* get buffer or wait if needed */
	do {
		/* get buffer */
		ret = vqueue_get_avail_buf(vq, &buf);
		if (ret == NO_ERROR) {
			/* got it */
			break;
		}

		if (ret != ERR_NOT_ENOUGH_BUFFER || !wait) {
			/* no buffers and no wait */
			goto err;
		}

		/* wait for buffers */
		event_wait(&vq->avail_event);
		if (dev->tx_stop) {
			return ERR_CHANNEL_CLOSED;
		}
	} while (true);

	/* we only support and expect single out_iovec for now */
	if (buf.out_iovs.used == 0) {
		LTRACEF("unexpected iovec cnt in = %d out = %d\n",
		         buf.in_iovs.used, buf.out_iovs.used);
		ret = ERR_NOT_ENOUGH_BUFFER;
		goto done;
	}

	if (buf.out_iovs.used != 1 || buf.in_iovs.used != 0) {
		LTRACEF("unexpected iovec cnt in = %d out = %d\n",
		         buf.in_iovs.used, buf.out_iovs.used);
	}

	/* the first iovec should be large enough to hold header */
	if (sizeof(struct tipc_hdr) > buf.out_iovs.iovs[0].len) {
		/* not enough space to even place header */
		LTRACEF("buf is too small (%zu < %zu)\n",
		         buf.out_iovs.iovs[0].len, ttl_len);
		ret = ERR_NOT_ENOUGH_BUFFER;
		goto done;
	}

	/* map in provided buffers (Non-secure, no-execute, cached, read-write) */
	uint map_flags = ARCH_MMU_FLAG_NS | ARCH_MMU_FLAG_PERM_NO_EXECUTE |
	                 ARCH_MMU_FLAG_CACHED;
	ret = virtio_map_iovs(dev, &buf.out_iovs, map_flags);
	if (ret == NO_ERROR) {
		struct tipc_hdr *hdr = buf.out_iovs.iovs[0].base;

		hdr->src = local;
		hdr->dst = remote;
		hdr->reserved = 0;
		hdr->len = data_len;
		hdr->flags = 0;

		if (ttl_len > buf.out_iovs.iovs[0].len) {
			/* not enough space to put the whole message
			   so it will be truncated */
			LTRACEF("buf is too small (%zu < %zu)\n",
			         buf.out_iovs.iovs[0].len, ttl_len);
			data_len = buf.out_iovs.iovs[0].len -
			           sizeof(struct tipc_hdr);
		}

		/* invoke data_cb to add actual data */
		ret = cb(hdr->data, data_len, cb_ctx);
		if (ret >= 0) {
			/* add header */
			ret += sizeof(struct tipc_hdr);
		}

		virtio_unmap_iovs(&buf.out_iovs);
	}

done:
	ret = vqueue_add_buf(vq, &buf, ret);
err:
	return ret;
}

struct buf_ctx {
	uint8_t  *data;
	size_t    len;
};

static int _send_buf(uint8_t *dst, size_t sz, void *ctx)
{
	struct buf_ctx *buf = (struct buf_ctx *) ctx;

	DEBUG_ASSERT(dst);
	DEBUG_ASSERT(buf);
	DEBUG_ASSERT(buf->data);
	DEBUG_ASSERT(sz <= buf->len);

	memcpy (dst, buf->data,  sz);

	return (int) sz;
}

static int
tipc_send_buf(struct tipc_dev *dev, uint32_t local, uint32_t remote,
              void *data, uint16_t data_len, bool wait)
{
	struct buf_ctx ctx = {data, data_len};

	return tipc_send_data(dev, local, remote,
	                      _send_buf, &ctx, data_len, wait);
}

static void virtio_disable_queues(struct tipc_dev *dev)
{
	uint i;

	for (i = 0; i < TIPC_VQ_NUM; ++i)
		dev->vqs[i].vring_addr = 0;
}

static enum handler_return virtio_handle_irq(void *arg)
{
	struct tipc_dev *dev = (struct tipc_dev *)arg;
	struct tipc_vdev_descr *desc = (struct tipc_vdev_descr *) dev->descr_ptr;
	uint i;
	uint32_t cmd = dev->cfg->cmd;
	uint32_t payload = cmd & ~VIRTIO_L4CMD_MASK;
	u8 *shadow_status = &desc->vdev.status;

	if (cmd) {
		switch (cmd & VIRTIO_L4CMD_MASK) {
			case VIRTIO_L4CMD_SET_STATUS:
				if (payload == 0) {
					/* reset */
					tipc_dev_reset(dev);
					*shadow_status = 0;
				} else if (!(*shadow_status & VIRTIO_STATUS_FAILED)) {
					*shadow_status = payload;
					if (payload & VIRTIO_STATUS_FAILED) {
						/* stop device */
						virtio_disable_queues(dev);
						dev->state = VDEV_STATE_RESET;
					} else if (payload == VIRTIO_STATUS_READY) {
						/* all is well, start up the device */
						if (tipc_dev_probe(dev, desc) != NO_ERROR) {
							virtio_disable_queues(dev);
							*shadow_status |= VIRTIO_STATUS_FAILED;
						}
					}
				}
				dev->cfg->status = *shadow_status;
				break;
			case VIRTIO_L4CMD_CFG_QUEUE:
				/* check that all queues are still ready */
				if (payload < TIPC_VQ_NUM
						&& dev->vqs[payload].vring_addr
						&& !dev->queue_cfg[payload].ready)
					dev->state = VDEV_STATE_RESET;
				break;
			}
	}

	/* always kick the queues when the device is ready */
	if (*shadow_status == VIRTIO_STATUS_READY) {
		if (dev->state == VDEV_STATE_ACTIVE) {
			// don't know which queue, so kick them all
			for (i = 0; i < TIPC_VQ_NUM; ++i)
				vqueue_notify(dev->vqs + i);
		} else if (dev->state == VDEV_STATE_GOING_ONLINE) {
			vqueue_notify(&dev->vqs[TIPC_VQ_TX]);
		}
	}

	/* acknowledge interrupt and mark command as done */
	dev->cfg->cmd = 0;

	return INT_RESCHEDULE;
}

status_t create_tipc_device(const struct tipc_vdev_descr *descr, size_t size,
                            const uuid_t *uuid, struct tipc_dev **dev_ptr)
{
	status_t ret;
	struct tipc_dev *dev;
	uint i;

	DEBUG_ASSERT(uuid);
	DEBUG_ASSERT(descr);
	DEBUG_ASSERT(size);

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return ERR_NO_MEMORY;

	mutex_init(&dev->ept_lock);
	dev->state = VDEV_STATE_RESET;
	dev->uuid = uuid;
	dev->descr_ptr = descr;
	dev->descr_size = size;
	handle_list_init(&dev->handle_list);
	event_init(&dev->have_handles, false, EVENT_FLAG_AUTOUNSIGNAL);
	event_init(&dev->rx_retry, false, EVENT_FLAG_AUTOUNSIGNAL);

	/* init virtio device */
	dev->cfg = (struct l4virtio_config *) (descr->config_base + 0x80000000);
	dev->queue_cfg = (struct l4virtio_queue_config *)
                     &dev->cfg->config[descr->vdev.config_len / 4 + 1];
	dev->driver_window = (vaddr_t)descr->driver_mem_base + 0x80000000;

	dev->cfg->version = 2;
	dev->cfg->device_id = descr->vdev.id;
	dev->cfg->vendor_id = 0x44; // virtio
	dev->cfg->dev_features_map[0] = descr->vdev.dfeatures;
	dev->cfg->queue_num_max = 0x200;
	dev->cfg->num_queues = descr->vdev.num_of_vrings;
	dev->cfg->queues_offset = (char *)dev->queue_cfg - (char *)dev->cfg;

	// setup queues
	for (i = 0; i < descr->vdev.num_of_vrings; ++i) {
		dev->queue_cfg[i].num_max = descr->vrings[i].num;
		dev->queue_cfg[i].device_notify_index = i;
	}

	// setup config space
	// NOT IMPLEMENTED: private tipc dev config space at 0x100;

	// register and enable interrupts
	mask_interrupt(descr->notify_irq);

	register_int_handler(descr->notify_irq, &virtio_handle_irq, dev);

	unmask_interrupt(descr->notify_irq);

	// write magic to signal that we are ready.
	dev->cfg->magic = VIRTIO_MMIO_MAGIC;

	if (dev_ptr)
		*dev_ptr = dev;

	return NO_ERROR;

err_register:
	free(dev);
	return ret;
}


