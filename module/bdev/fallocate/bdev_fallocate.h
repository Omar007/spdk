/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2016 Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef SPDK_BDEV_FALLOCATE_H
#define SPDK_BDEV_FALLOCATE_H

#include "spdk/stdinc.h"

#include "spdk/bdev_module.h"

#define FALLOCATE_MAX_XATTRS 255

typedef void (*spdk_bdev_fallocate_delete_complete)(void *cb_arg, int bdeverrno);

struct bdev_fallocate_xattr {
	char *name;
	char *value;
};

struct bdev_fallocate_xattrs {
	size_t num_xattrs;
	struct bdev_fallocate_xattr xattrs[FALLOCATE_MAX_XATTRS];
};

struct bdev_fallocate_create_opts {
	char *name;
	struct spdk_uuid uuid;
	char *filename;
	uint64_t size;
	struct bdev_fallocate_xattrs xattrs;
};

struct bdev_fallocate_delete_opts {
	char *name;
};

struct bdev_fallocate_resize_opts {
	char *name;
	uint64_t size;
};

int bdev_fallocate_create(const struct bdev_fallocate_create_opts *opts, struct spdk_bdev **bdev);
void bdev_fallocate_delete(const struct bdev_fallocate_delete_opts *opts, spdk_bdev_fallocate_delete_complete cb_fn, void *cb_arg);
int bdev_fallocate_resize(const struct bdev_fallocate_resize_opts *opts);

#endif /* SPDK_BDEV_FALLOCATE_H */
