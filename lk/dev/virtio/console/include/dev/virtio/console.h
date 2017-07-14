/*
 * Copyright (c) 2017 Kernkonzept GmbH
 */

#include <compiler.h>
#include <sys/types.h>
#include <dev/virtio.h>

struct virtio_device *virtio_get_console(uint idx);

status_t virtio_console_init(struct virtio_device *dev, uint32_t host_features) __NONNULL();

ssize_t virtio_console_read(struct virtio_device *dev, void *buf, size_t len, bool wait) __NONNULL();

ssize_t virtio_console_write(struct virtio_device *dev, const void *buf, size_t len) __NONNULL();

void virtio_console_dump(struct virtio_device *dev);
