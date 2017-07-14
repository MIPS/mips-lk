/*
 * Copyright (c) 2017 Kernkonzept GmbH
 */

#include <dev/virtio/console.h>

#include <err.h>
#include <malloc.h>
#include <trace.h>
#include <lib/cbuf.h>
#include <lib/io.h>
#include <kernel/vm.h>
#include <kernel/mutex.h>
#include <kernel/event.h>

#define LOCAL_TRACE 0

struct virtio_console_dev {
    struct virtio_device *dev;

    mutex_t output_lock;
    event_t output_event;

    struct cbuf inbuf;
    void *inqueue_elems;

    uint rcvbuf_size;
    uint sndbuf_size;
};


#define VIRTIO_CONS_MAX_RECEIVE_BUF_SIZE 256
#define VIRTIO_CONS_RECEIVE_ELEM_SIZE 256
#define VIRTIO_CONS_MAX_SEND_BUF_SIZE 256

static uint num_devices;
static struct virtio_device *devices[4];

#ifdef WITH_VIRTIO_ROOT_CONSOLE
static ssize_t __debug_virtio_write(io_handle_t *io, const char *s, size_t len)
{
    struct virtio_device *dev = devices[0];

    uint16_t i;
    struct vring_desc *desc = virtio_alloc_desc_chain(dev, 1, 1, &i);
    struct vring *tx = &dev->ring[1];
    uint16_t last_used;
    uint16_t volatile *used_ptr = &tx->used->idx;
    bool ints_disabled = arch_ints_disabled();

    if (!desc) {
        char const *err = "ERROR: virtio console stuck. Message dropped: ";
        // console is stuck, print via hypcall instead
        while (*err)
            platform_dputc(*(err++));
        for (size_t i = 0; i < len; ++i)
            platform_dputc(s[i]);
        platform_dputc('\n');
        return 0;
    }

    if (!ints_disabled) {
      arch_disable_ints();
    }

    last_used = *used_ptr;

    desc->addr = vaddr_to_paddr((void *)s);
    desc->len = len;
    /* submit the transfer */
    virtio_submit_chain(dev, 1, i);
    /* kick it off */
    virtio_kick(dev, 1);

    /* busy wait for the transfer to complete */
    while (*used_ptr == last_used)
      ;

    /* need to clear out the used blocks to not run out of descriptors */
    uint cur_idx = *used_ptr;
    for (uint i = tx->last_used; i != (cur_idx & tx->num_mask); i = (i + 1) & tx->num_mask) {
        struct vring_used_elem *used_elem = &tx->used->ring[i];

        virtio_free_desc(dev, 1, used_elem->id);

    }
    tx->last_used = cur_idx & tx->num_mask;

    if (!ints_disabled)
      arch_enable_ints();

    return 0;
}

static ssize_t __debug_virtio_read(io_handle_t *io, char *s, size_t len)
{
    size_t ret =  virtio_console_read(devices[0], s, len, true);

    return (ret <= 0) ? 0 : ret;
}

static const io_handle_hooks_t virtio_console_hooks = {
    .write  = __debug_virtio_write,
    .read   = __debug_virtio_read,
};
#endif

static enum handler_return virtio_console_irq_driver_callback(struct virtio_device *dev, uint ring, const struct vring_used_elem *e)
{
    struct virtio_console_dev *cdev = (struct virtio_console_dev *)dev->priv;

    if (ring == 0) {
        /* write input in buffer */
        struct vring_desc *desc = virtio_desc_index_to_desc(dev, ring, e->id);

        void *va = paddr_to_kvaddr(desc->addr);

        /* XXX handle buffer overflows */
        cbuf_write(&cdev->inbuf, va, e->len, false);

        /* immediately put the buffer back for reuse */
        virtio_submit_chain(dev, 0, e->id);

    } else {
        fprintf(stderr, "free used\n");
        virtio_free_desc(dev, ring, e->id);

        /* signal output is done event */
        event_signal(&cdev->output_event, false);
    }

    return INT_RESCHEDULE;
}

struct virtio_device *virtio_get_console(uint idx)
{
    return (idx < num_devices) ? devices[idx] : 0;
}

status_t virtio_console_init(struct virtio_device *dev, uint32_t host_features)
{
    struct virtio_console_dev *cdev;

    LTRACEF("dev %p, host_features 0x%x\n", dev, host_features);

    /* allocate a new block device */
    cdev = malloc(sizeof(struct virtio_console_dev));
    if (!cdev)
        return ERR_NO_MEMORY;

    mutex_init(&cdev->output_lock);
    event_init(&cdev->output_event, false, EVENT_FLAG_AUTOUNSIGNAL);

    cdev->dev = dev;
    dev->priv = cdev;

    cbuf_initialize(&cdev->inbuf, 1024 * 1024);

    /* make sure the device is reset */
    virtio_reset_device(dev);

    /* ack and set the driver status bit */
    virtio_status_acknowledge_driver(dev);

    if (virtio_status_acknowledge_features(dev) != NO_ERROR)
        return ERR_BAD_STATE;

    /* allocate receive queue */
    cdev->rcvbuf_size = virtio_mmio_max_queue_size(dev, 0);
    if (cdev->rcvbuf_size > VIRTIO_CONS_MAX_RECEIVE_BUF_SIZE)
        cdev->rcvbuf_size = VIRTIO_CONS_MAX_RECEIVE_BUF_SIZE;
    virtio_alloc_ring(dev, 0, cdev->rcvbuf_size);
    /* allocate transmit queue */
    cdev->sndbuf_size = virtio_mmio_max_queue_size(dev, 1);
    if (cdev->sndbuf_size > VIRTIO_CONS_MAX_RECEIVE_BUF_SIZE)
        cdev->sndbuf_size = VIRTIO_CONS_MAX_RECEIVE_BUF_SIZE;
    virtio_alloc_ring(dev, 1, cdev->sndbuf_size);

    /* set our irq handler */
    dev->irq_driver_callback = &virtio_console_irq_driver_callback;

    /* set DRIVER_OK */
    virtio_status_driver_ok(dev);

    /* allocate receive buffers and put them into the queue */
    cdev->inqueue_elems = malloc(cdev->rcvbuf_size
                                 * VIRTIO_CONS_RECEIVE_ELEM_SIZE);
    for (unsigned i = 0; i < cdev->rcvbuf_size; ++i) {
        uint16_t i;
        struct vring_desc *desc = virtio_alloc_desc_chain(dev, 0, 1, &i);
        vaddr_t va = (vaddr_t) ((char *) cdev->inqueue_elems
                                + i * VIRTIO_CONS_RECEIVE_ELEM_SIZE);

        desc->addr = vaddr_to_paddr((void *)va);
        desc->len = VIRTIO_CONS_RECEIVE_ELEM_SIZE;
        desc->flags |= VRING_DESC_F_WRITE;
        /* submit the transfer */
        virtio_submit_chain(dev, 0, i);
    }

    /* kick it off */
    virtio_kick(dev, 0);

    if (num_devices < 4) {
        devices[num_devices] = dev;
        ++num_devices;
    }

#ifdef WITH_VIRTIO_ROOT_CONSOLE
    if (num_devices == 1)
        io_handle_init(&console_io, &virtio_console_hooks);
#endif

    return NO_ERROR;
}

ssize_t virtio_console_read(struct virtio_device *dev, void *buf, size_t len, bool wait)
{
    struct virtio_console_dev *cdev = (struct virtio_console_dev *)dev->priv;

    return cbuf_read(&cdev->inbuf, buf, len, wait);
}

ssize_t virtio_console_write(struct virtio_device *dev, const void *buf, size_t len)
{
    uint16_t i;
    struct virtio_console_dev *cdev = (struct virtio_console_dev *)dev->priv;

    mutex_acquire(&cdev->output_lock);

    struct vring_desc *desc = virtio_alloc_desc_chain(dev, 1, 1, &i);

    desc->addr = vaddr_to_paddr((void *)buf);
    desc->len = len;
    /* submit the transfer */
    virtio_submit_chain(dev, 1, i);
    /* kick it off */
    virtio_kick(dev, 1);

    /* wait for the transfer to complete */
    event_wait(&cdev->output_event);

    mutex_release(&cdev->output_lock);

    return 0;
}

void virtio_console_dump(struct virtio_device *dev)
{
  uint i;

  printf("Available queue bitmap: 0x%x\n", dev->active_rings_bitmap);

  for (i = 0; i < 2; ++i) {
      struct vring *vr = dev->ring + i;
      printf("\nQueue %u:\n", i);
      printf("  vring desc address: %p\n", vr->desc);
      printf("  vring avail address: %p\n", vr->avail);
      printf("  vring avail idx: %u\n", vr->avail->idx);
      printf("  vring used address: %p\n", vr->used);
      printf("  vring used idx: %u\n", vr->used->idx);
  }

}
