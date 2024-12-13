/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2017 Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"

#include "spdk/fd.h"
#include "spdk/log.h"
#include "spdk/string.h"

#include "../uring/bdev_uring.h"

#include "bdev_fallocate.h"

struct bdev_fallocate {
	struct spdk_bdev bdev;
	struct spdk_bdev_desc *access_desc;
	struct spdk_thread *access_thread;
	char *filename;
	int fd;
	TAILQ_ENTRY(bdev_fallocate) link;
};
static TAILQ_HEAD(, bdev_fallocate) g_fallocate_bdev_head = TAILQ_HEAD_INITIALIZER(g_fallocate_bdev_head);

struct bdev_fallocate_io {
	struct spdk_io_channel *access_channel;
};



static int bdev_fallocate_initialize(void) { return 0; }
static void bdev_fallocate_finish(void) {}
static int bdev_fallocate_get_ctx_size(void) { return 0; }

static struct spdk_bdev_module fallocate_if = {
	.name			= "fallocate",
	.module_init	= bdev_fallocate_initialize,
	.module_fini	= bdev_fallocate_finish,
	.get_ctx_size	= bdev_fallocate_get_ctx_size,
};
SPDK_BDEV_MODULE_REGISTER(fallocate, &fallocate_if)



static void dummy_bdev_delete_cb(void *cb_arg, int bdeverrno) {}

static int
bdev_fallocate_close(struct bdev_fallocate *fallocate)
{
	if (fallocate->fd == -1) {
		return 0;
	}

	if (close(fallocate->fd) != 0) {
		SPDK_ERRLOG("close() failed (fd=%d), errno %d: %s\n",
				fallocate->fd, errno, spdk_strerror(errno));
		return errno;
	}

	fallocate->fd = -1;

	return 0;
}

static void
bdev_fallocate_access_desc_close(void *ctx)
{
	struct spdk_bdev_desc *desc = ctx;
	char *access_name = strdup(spdk_bdev_desc_get_bdev(desc)->name);

	spdk_bdev_close(desc);
	delete_uring_bdev(access_name, dummy_bdev_delete_cb, NULL);

	free(access_name);
}

static void
bdev_fallocate_io_unregister_cb(void *io_device)
{
	struct bdev_fallocate *fallocate = io_device;

	if (fallocate == NULL) {
		return;
	}
	free(fallocate->filename);
	free(fallocate->bdev.name);
	free(fallocate);
}

static int
bdev_fallocate_destruct(void *ctx)
{
	struct bdev_fallocate *fallocate = ctx;
	int rc = 0;

	TAILQ_REMOVE(&g_fallocate_bdev_head, fallocate, link);

	if (fallocate->access_thread && fallocate->access_thread != spdk_get_thread()) {
		spdk_thread_send_msg(fallocate->access_thread, bdev_fallocate_access_desc_close, fallocate->access_desc);
	} else {
		bdev_fallocate_access_desc_close(fallocate->access_desc);
	}

	rc = bdev_fallocate_close(fallocate);

	spdk_io_device_unregister(fallocate, bdev_fallocate_io_unregister_cb);
	return rc;
}

static void
bdev_fallocate_complete_io_stack(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	assert(bdev_io == cb_arg);
	spdk_bdev_io_stack_pop(bdev_io);
	spdk_bdev_io_complete(bdev_io, success ? SPDK_BDEV_IO_STATUS_SUCCESS : SPDK_BDEV_IO_STATUS_FAILED);
}

static void
bdev_fallocate_submit_request(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	struct bdev_fallocate *fallocate = SPDK_CONTAINEROF(bdev_io->bdev, struct bdev_fallocate, bdev);
	struct bdev_fallocate_io *fallocate_io = spdk_io_channel_get_ctx(ch);
	int rc = 0;

	spdk_bdev_io_stack_push(bdev_io);
	rc = spdk_bdev_io_submit(bdev_io, fallocate->access_desc, fallocate_io->access_channel,
			bdev_fallocate_complete_io_stack, bdev_io);
	if (rc != 0) {
		/* Currently spdk_bdev_io_submit() always returns 0. This path
		* does not need to allocate a bdev_io, so -ENOMEM handling
		* is not required.
		*/
		SPDK_ERRLOG("bdev_io submission failed\n");
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
	}
}

static bool
bdev_fallocate_io_type_supported(void *ctx, enum spdk_bdev_io_type io_type)
{
	struct bdev_fallocate *fallocate = ctx;

	return spdk_bdev_io_type_supported(spdk_bdev_desc_get_bdev(fallocate->access_desc), io_type);
}

static struct spdk_io_channel *
bdev_fallocate_get_io_channel(void *ctx)
{
	struct bdev_fallocate *fallocate = ctx;

	return spdk_get_io_channel(fallocate);
}

static int
bdev_fallocate_dump_info_json(void *ctx, struct spdk_json_write_ctx *w)
{
	struct bdev_fallocate *fallocate = ctx;

	spdk_json_write_name(w, "fallocate");
	spdk_json_write_object_begin(w);
	spdk_json_write_named_string(w, "filename", fallocate->filename);
	spdk_json_write_object_end(w);

	return 0;
}

static void
bdev_fallocate_write_json_config(struct spdk_bdev *bdev, struct spdk_json_write_ctx *w)
{
	struct bdev_fallocate *fallocate = bdev->ctxt;
	char uuid_str[SPDK_UUID_STRING_LEN];

	spdk_json_write_object_begin(w);
	spdk_json_write_named_string(w, "method", "bdev_fallocate_create");

	spdk_json_write_named_object_begin(w, "params");
	spdk_json_write_named_string(w, "name", bdev->name);
	spdk_uuid_fmt_lower(uuid_str, sizeof(uuid_str), &bdev->uuid);
	spdk_json_write_named_string(w, "uuid", uuid_str);
	spdk_json_write_named_string(w, "filename", fallocate->filename);
	spdk_json_write_named_uint64(w, "size", bdev->blockcnt * bdev->blocklen);
	spdk_json_write_object_end(w);

	spdk_json_write_object_end(w);
}

static const struct spdk_bdev_fn_table fallocate_bdev_fn_table = {
	.destruct			= bdev_fallocate_destruct,
	.submit_request		= bdev_fallocate_submit_request,
	.io_type_supported	= bdev_fallocate_io_type_supported,
	.get_io_channel		= bdev_fallocate_get_io_channel,
	.dump_info_json		= bdev_fallocate_dump_info_json,
	.write_config_json	= bdev_fallocate_write_json_config,
};



static int
bdev_fallocate_do_fallocate(struct bdev_fallocate *fallocate, uint64_t size) {
	uint64_t fallocate_size = spdk_fd_get_size(fallocate->fd);
	int rc = 0;

	if (size <= fallocate_size) {
		goto exit;
	}

	SPDK_DEBUGLOG(fallocate, "allocating space (file=%s,fd=%d): old size %ju, new size %ju\n",
			fallocate->filename, fallocate->fd, fallocate_size, size);

	rc = posix_fallocate(fallocate->fd, 0, size);
	if (rc != 0) {
		SPDK_ERRLOG("posix_fallocate() failed (file=%s,fd=%d), errno %d: %s\n",
				fallocate->filename, fallocate->fd, rc, spdk_strerror(rc));
	}

exit:
	fallocate->bdev.blockcnt = spdk_fd_get_size(fallocate->fd) / fallocate->bdev.blocklen;

	rc = bdev_uring_rescan(spdk_bdev_desc_get_bdev(fallocate->access_desc)->name);

	return rc;
}

static int
bdev_fallocate_do_setxattrs(struct bdev_fallocate *fallocate, const struct bdev_fallocate_xattrs *xattrs) {
	size_t i = 0;

	SPDK_DEBUGLOG(fallocate, "setting xattrs (file=%s,fd=%d)\n", fallocate->filename, fallocate->fd);

	for (i = 0; i < xattrs->num_xattrs; i++) {
		if (fsetxattr(fallocate->fd, xattrs->xattrs[i].name, xattrs->xattrs[i].value, strlen(xattrs->xattrs[i].value), 0) != 0) {
			SPDK_ERRLOG("setxattr() failed (file=%s,fd=%d,attr=%s), errno %d: %s\n",
					fallocate->filename, fallocate->fd, xattrs->xattrs[i].name, errno, spdk_strerror(errno));
			return errno;
		}
	}
	return 0;
}

static void
dummy_bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev, void *ctx) {}

static int
bdev_fallocate_create_cb(void *io_device, void *ctx_buf)
{
	struct bdev_fallocate *fallocate = io_device;
	struct bdev_fallocate_io *fallocate_io = ctx_buf;

	fallocate_io->access_channel = spdk_bdev_get_io_channel(fallocate->access_desc);

	return 0;
}

static void
bdev_fallocate_destroy_cb(void *io_device, void *ctx_buf)
{
	struct bdev_fallocate_io *fallocate_io = ctx_buf;

	spdk_put_io_channel(fallocate_io->access_channel);
}

int
bdev_fallocate_create(const struct bdev_fallocate_create_opts *opts, struct spdk_bdev **bdev)
{
	struct bdev_fallocate *fallocate = NULL;
	struct bdev_uring_opts uring_opts = {};
	struct stat statBuf = {};
	int rc = -1;

	fallocate = calloc(1, sizeof(struct bdev_fallocate));
	if (!fallocate) {
		SPDK_ERRLOG("unable to allocate memory for fallocate backend\n");
		return rc;
	}

	fallocate->bdev.product_name = "fallocate bdev";
	fallocate->bdev.module = &fallocate_if;
	fallocate->bdev.fn_table = &fallocate_bdev_fn_table;
	fallocate->bdev.ctxt = fallocate;
	fallocate->bdev.blocklen = 4096;

	if (opts->size % fallocate->bdev.blocklen != 0) {
		SPDK_ERRLOG("size %ju is not a multiple of 4096\n", opts->size);
		goto error;
	}

	fallocate->filename = strdup(opts->filename);
	if (!fallocate->filename) {
		goto error;
	}

	fallocate->bdev.name = strdup(opts->name);
	if (!fallocate->bdev.name) {
		goto error;
	}

	if (!spdk_mem_all_zero(&opts->uuid, sizeof(opts->uuid))) {
		spdk_uuid_copy(&fallocate->bdev.uuid, &opts->uuid);
	}

	if (stat(fallocate->filename, &statBuf) == 0) {
		if (!S_ISREG(statBuf.st_mode)) {
			SPDK_ERRLOG("not S_ISREG() (file=%s), mode %d\n",
					fallocate->filename, statBuf.st_mode);
			goto error;
		}
	} else if (errno != ENOENT) {
		SPDK_ERRLOG("stat() failed (file=%s), errno %d: %s\n",
				fallocate->filename, errno, spdk_strerror(errno));
		rc = errno;
		goto error;
	}

	fallocate->fd = open(fallocate->filename, O_CREAT | O_RDWR, 0640);
	if (fallocate->fd == -1) {
		SPDK_ERRLOG("open() failed (file=%s), errno %d: %s\n",
				fallocate->filename, errno, spdk_strerror(errno));
		rc = errno;
		goto error;
	}

	uring_opts.name = spdk_sprintf_alloc("%s-uring", opts->name);
	rc = spdk_bdev_open_ext(uring_opts.name, true, dummy_bdev_event_cb, NULL, &fallocate->access_desc);
	if (rc == -ENODEV) {
		uring_opts.block_size = fallocate->bdev.blocklen;
		uring_opts.filename = fallocate->filename;
		if (create_uring_bdev(&uring_opts) == NULL) {
			SPDK_ERRLOG("create_uring_bdev() failed\n");
			rc = -1;
			goto error;
		}
		rc = spdk_bdev_open_ext(uring_opts.name, true, dummy_bdev_event_cb, NULL, &fallocate->access_desc);
	}
	if (rc != 0) {
		SPDK_ERRLOG("spdk_bdev_open_ext() failed, rc %d: %s\n",
				rc, spdk_strerror(rc));
		goto claim_error;
	}
	fallocate->access_thread = spdk_get_thread();

	spdk_io_device_register(fallocate, bdev_fallocate_create_cb, bdev_fallocate_destroy_cb,
			sizeof(struct bdev_fallocate_io), fallocate->bdev.name);
	rc = spdk_bdev_register(&fallocate->bdev);
	if (rc != 0) {
		SPDK_ERRLOG("spdk_bdev_register() failed, errno %d: %s\n",
				errno, spdk_strerror(errno));
		goto modify_error;
	}

	rc = bdev_fallocate_do_setxattrs(fallocate, &opts->xattrs);
	if (rc != 0) {
		goto modify_error;
	}

	rc = bdev_fallocate_do_fallocate(fallocate, opts->size);
	if (rc != 0) {
		goto modify_error;
	}

	TAILQ_INSERT_TAIL(&g_fallocate_bdev_head, fallocate, link);
	*bdev = &fallocate->bdev;
	return 0;

modify_error:
	spdk_bdev_close(fallocate->access_desc);
	spdk_io_device_unregister(fallocate, bdev_fallocate_io_unregister_cb);

claim_error:
	delete_uring_bdev(uring_opts.name, dummy_bdev_delete_cb, NULL);

error:
	bdev_fallocate_close(fallocate);
	bdev_fallocate_io_unregister_cb(fallocate);
	return rc;
}

struct bdev_fallocate_unregister_ctx {
	char *filename;
	spdk_bdev_fallocate_delete_complete cb_fn;
	void *cb_arg;
};

static void
bdev_fallocate_bdev_unregister_cb(void *arg, int bdeverrno)
{
	struct bdev_fallocate_unregister_ctx *ctx = arg;

	SPDK_DEBUGLOG(fallocate, "unregister cb, bdeverrno %d\n", bdeverrno);

	if (unlink(ctx->filename) != 0) {
		SPDK_ERRLOG("unlink() failed (file=%s), errno %d: %s\n",
				ctx->filename, errno, spdk_strerror(errno));
	}

	ctx->cb_fn(ctx->cb_arg, bdeverrno);
	free(ctx->filename);
	free(ctx);
}

void
bdev_fallocate_delete(const struct bdev_fallocate_delete_opts *opts, spdk_bdev_fallocate_delete_complete cb_fn, void *cb_arg)
{
	struct bdev_fallocate_unregister_ctx *ctx = NULL;
	struct spdk_bdev_desc *desc = NULL;
	struct spdk_bdev *bdev = NULL;
	struct bdev_fallocate *fallocate = NULL;
	int rc = 0;

	ctx = calloc(1, sizeof(struct bdev_fallocate_unregister_ctx));
	if (ctx == NULL) {
		cb_fn(cb_arg, -ENOMEM);
		return;
	}

	rc = spdk_bdev_open_ext(opts->name, false, dummy_bdev_event_cb, NULL, &desc);
	if (rc != 0) {
		cb_fn(cb_arg, rc);
		return;
	}

	bdev = spdk_bdev_desc_get_bdev(desc);
	if (bdev->module != &fallocate_if) {
		cb_fn(cb_arg, rc);
		goto cleanup;
	}

	fallocate = SPDK_CONTAINEROF(bdev, struct bdev_fallocate, bdev);

	ctx->filename = strdup(fallocate->filename);
	ctx->cb_fn = cb_fn;
	ctx->cb_arg = cb_arg;
	spdk_bdev_unregister(bdev, bdev_fallocate_bdev_unregister_cb, ctx);

cleanup:
	spdk_bdev_close(desc);
}

int
bdev_fallocate_resize(const struct bdev_fallocate_resize_opts *opts)
{
	struct spdk_bdev_desc *desc = NULL;
	struct spdk_bdev *bdev = NULL;
	struct bdev_fallocate *fallocate = NULL;
	int rc = 0;

	rc = spdk_bdev_open_ext(opts->name, false, dummy_bdev_event_cb, NULL, &desc);
	if (rc != 0) {
		return rc;
	}

	bdev = spdk_bdev_desc_get_bdev(desc);
	if (bdev->module != &fallocate_if) {
		rc = -ENODEV;
		goto exit;
	}

	fallocate = SPDK_CONTAINEROF(bdev, struct bdev_fallocate, bdev);

	if (opts->size % fallocate->bdev.blocklen != 0) {
		SPDK_ERRLOG("new size %ju is not a multiple of %d\n", opts->size, fallocate->bdev.blocklen);
		rc = -1;
		goto exit;
	}

	rc = bdev_fallocate_do_fallocate(fallocate, opts->size);

exit:
	spdk_bdev_close(desc);
	return rc;
}

int
bdev_fallocate_set_xattrs(const struct bdev_fallocate_set_xattrs_opts *opts) {
	struct spdk_bdev_desc *desc = NULL;
	struct spdk_bdev *bdev = NULL;
	struct bdev_fallocate *fallocate = NULL;
	int rc = 0;

	rc = spdk_bdev_open_ext(opts->name, false, dummy_bdev_event_cb, NULL, &desc);
	if (rc != 0) {
		return rc;
	}

	bdev = spdk_bdev_desc_get_bdev(desc);
	if (bdev->module != &fallocate_if) {
		rc = -ENODEV;
		goto exit;
	}

	fallocate = SPDK_CONTAINEROF(bdev, struct bdev_fallocate, bdev);

	rc = bdev_fallocate_do_setxattrs(fallocate, &opts->xattrs);

exit:
	spdk_bdev_close(desc);
	return rc;
}

SPDK_LOG_REGISTER_COMPONENT(fallocate)
