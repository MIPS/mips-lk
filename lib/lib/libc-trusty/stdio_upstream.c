/*
 * Copyright (C) 2013-2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <printf.h>
#include <stdio.h>
#include <string.h>
#include <trusty_std.h>
#include <err.h>

#define LINE_BUFFER_SIZE 128

struct file_buffer {
	char data[LINE_BUFFER_SIZE];
	size_t pos;
};

struct file_context {
	int fd;
	struct file_buffer *buffer;
};

struct file_buffer stdout_buffer = {.pos = 0};
struct file_buffer stderr_buffer = {.pos = 0};
struct file_context fctx[3] = {
	{.fd = 0, .buffer = NULL},
	{.fd = 1, .buffer = &stdout_buffer },
	{.fd = 2, .buffer = &stderr_buffer }
};

static int buffered_put(struct file_buffer *buffer, int fd, char c)
{
	int result = 0;

	buffer->data[buffer->pos++] = c;
	if (buffer->pos == sizeof(buffer->data) || c == '\n') {
		result = write(fd, buffer->data, buffer->pos);
		buffer->pos = 0;
	}
	return result;
}

static int buffered_write(struct file_context *ctx, const char *str, size_t sz)
{
	unsigned i;

	if (!ctx->buffer) {
		return ERR_INVALID_ARGS;
	}

	for (i = 0; i < sz; i++) {
		int result = buffered_put(ctx->buffer, ctx->fd, str[i]);
		if (result < 0) {
			return result;
		}
	}

	return sz;
}

static ssize_t __stdin_write(io_handle_t *io, const char *s, size_t len)
{
	return buffered_write(&fctx[0], s, len);
}

static ssize_t __stdout_write(io_handle_t *io, const char *s, size_t len)
{
	return buffered_write(&fctx[1], s, len);
}

static ssize_t __stderr_write(io_handle_t *io, const char *s, size_t len)
{
	return buffered_write(&fctx[2], s, len);
}

static ssize_t __null_read(io_handle_t *io, char *s, size_t len)
{
	return (unsigned char)0xff;
}

static const io_handle_hooks_t stdin_io_hooks = {
	.write  = __stdin_write,
	.read   = __null_read,
};

static const io_handle_hooks_t stdout_io_hooks = {
	.write  = __stdout_write,
	.read   = __null_read,
};

static const io_handle_hooks_t stderr_io_hooks = {
	.write  = __stderr_write,
	.read   = __null_read,
};

io_handle_t stdin_io = IO_HANDLE_INITIAL_VALUE(&stdin_io_hooks);
io_handle_t stdout_io = IO_HANDLE_INITIAL_VALUE(&stdout_io_hooks);
io_handle_t stderr_io = IO_HANDLE_INITIAL_VALUE(&stderr_io_hooks);

#define DEFINE_STDIO_DESC(id, handle)   \
	[(id)]  = {                 \
		.io = &handle,      \
	}

FILE __stdio_FILEs[3] = {
	DEFINE_STDIO_DESC(0, stdin_io), /* stdin */
	DEFINE_STDIO_DESC(1, stdout_io), /* stdout */
	DEFINE_STDIO_DESC(2, stderr_io), /* stderr */
};
#undef DEFINE_STDIO_DESC
