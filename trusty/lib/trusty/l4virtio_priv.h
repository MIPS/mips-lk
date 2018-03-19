/*
 * Copyright (c) 2014 Travis Geiselbrecht
 * Copyright (c) 2017 Kernkonzept GmbH
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
#pragma once

#include <compiler.h>
#include <stdint.h>

// MMIO virtio structure with L4Re extensions

struct l4virtio_config {
    /* 0x00 */  uint32_t magic;
    uint32_t version;
    uint32_t device_id;
    uint32_t vendor_id;
    /* 0x10 */  uint32_t host_features;
    uint32_t host_features_sel;
    uint32_t __reserved0[2];
    /* 0x20 */  uint32_t guest_features;
    uint32_t guest_features_sel;
    uint32_t num_queues;  // L4virtio
    uint32_t queues_offset; // L4virtio
    /* 0x30 */  uint32_t queue_sel;
    uint32_t queue_num_max;
    uint32_t queue_num;
    uint32_t queue_align;
    /* 0x40 */  uint32_t queue_pfn;
    uint32_t queue_ready;
    uint32_t __reserved2[2];
    /* 0x50 */  uint32_t queue_notify;
    uint32_t __reserved3[3];
    /* 0x60 */  uint32_t interrupt_status;
    uint32_t interrupt_ack;
    uint32_t __reserved4[2];
    /* 0x70 */  uint32_t status;
    uint32_t __reserved5[3];
    /* 0x80 */ uint32_t queue_desc_lo;
    uint32_t queue_desc_hi;
    uint32_t __reserved6[2];
    /* 0x90 */ uint32_t queue_avail_lo;
    uint32_t queue_avail_hi;
    uint32_t __reserved7[2];
    /* 0xa0 */ uint32_t queue_used_lo;
    uint32_t queue_used_hi;
    uint32_t dev_features_map[8]; // L4virtio protocol
    uint32_t driver_features_map[8]; // L4virtio protocol
    uint8_t __reserved8[16];
    uint32_t cmd; // L4virtio protocol
    uint32_t config_generation;
    /* 0x100 */ uint32_t config[0];
};

struct l4virtio_queue_config {
    uint16_t num_max;
    uint16_t num;
    uint16_t ready;
    uint16_t driver_notify_index;
    uint64_t desc_addr;
    uint64_t avail_addr;
    uint64_t used_addr;
    uint16_t device_notify_index;
};

STATIC_ASSERT(sizeof(struct l4virtio_config) == 0x100);

#define VIRTIO_MMIO_MAGIC 0x74726976 // 'virt'

#define VIRTIO_STATUS_ACKNOWLEDGE (1<<0)
#define VIRTIO_STATUS_DRIVER      (1<<1)
#define VIRTIO_STATUS_DRIVER_OK   (1<<2)
#define VIRTIO_STATUS_FEATURES_OK (1<<3)
#define VIRTIO_STATUS_FAILED      (1<<7)
#define VIRTIO_STATUS_READY       0xF

#define VIRTIO_L4CMD_NONE       0x00000000 ///< No command pending
#define VIRTIO_L4CMD_SET_STATUS 0x01000000 ///< Set the status register
#define VIRTIO_L4CMD_CFG_QUEUE  0x02000000 ///< Configure a queue
#define VIRTIO_L4CMD_MASK       0xff000000 ///< Mask to get command bits

