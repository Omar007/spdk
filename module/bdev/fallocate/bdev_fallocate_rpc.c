/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2016 Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/log.h"
#include "spdk/rpc.h"
#include "spdk/string.h"

#include "bdev_fallocate.h"

static void
free_rpc_bdev_fallocate_xattrs(struct bdev_fallocate_xattrs *xattrs) {
	size_t i = 0;

	for (i = 0; i < xattrs->num_xattrs; i++) {
		free(xattrs->xattrs[i].name);
		free(xattrs->xattrs[i].value);
	}
}

static const struct spdk_json_object_decoder rpc_bdev_fallocate_xattr_decoders[] = {
	{"name", offsetof(struct bdev_fallocate_xattr, name), spdk_json_decode_string},
	{"value", offsetof(struct bdev_fallocate_xattr, value), spdk_json_decode_string},
};

static int
decode_fallocate_xattr(const struct spdk_json_val *val, void *out) {
	return spdk_json_decode_object(val, rpc_bdev_fallocate_xattr_decoders,
			SPDK_COUNTOF(rpc_bdev_fallocate_xattr_decoders), out);
}

static int
decode_fallocate_xattrs(const struct spdk_json_val *val, void *out) {
	struct bdev_fallocate_xattrs *xattrs = out;

	return spdk_json_decode_array(val, decode_fallocate_xattr, xattrs->xattrs,
			FALLOCATE_MAX_XATTRS, &xattrs->num_xattrs, sizeof(struct bdev_fallocate_xattr));
}

static void
free_rpc_bdev_fallocate_create_opts(struct bdev_fallocate_create_opts *opts)
{
	free(opts->name);
	free(opts->filename);
	free_rpc_bdev_fallocate_xattrs(&opts->xattrs);
}

static const struct spdk_json_object_decoder rpc_bdev_fallocate_create_decoders[] = {
	{"name", offsetof(struct bdev_fallocate_create_opts, name), spdk_json_decode_string},
	{"uuid", offsetof(struct bdev_fallocate_create_opts, uuid), spdk_json_decode_uuid, true},
	{"filename", offsetof(struct bdev_fallocate_create_opts, filename), spdk_json_decode_string},
	{"size", offsetof(struct bdev_fallocate_create_opts, size), spdk_json_decode_uint64},
	{"xattrs", offsetof(struct bdev_fallocate_create_opts, xattrs), decode_fallocate_xattrs,true},
};

static void
rpc_bdev_fallocate_create(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct bdev_fallocate_create_opts opts = {};
	struct spdk_json_write_ctx *w = NULL;
	struct spdk_bdev *bdev = NULL;
	int rc = 0;

	if (spdk_json_decode_object(params, rpc_bdev_fallocate_create_decoders,
			SPDK_COUNTOF(rpc_bdev_fallocate_create_decoders), &opts)) {
		SPDK_DEBUGLOG(bdev_malloc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
				"spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = bdev_fallocate_create(&opts, &bdev);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_string(w, bdev->name);
	spdk_jsonrpc_end_result(request, w);

cleanup:
	free_rpc_bdev_fallocate_create_opts(&opts);
}
SPDK_RPC_REGISTER("bdev_fallocate_create", rpc_bdev_fallocate_create, SPDK_RPC_RUNTIME)



static void
free_rpc_bdev_fallocate_delete_opts(struct bdev_fallocate_delete_opts *opts)
{
	free(opts->name);
}

static const struct spdk_json_object_decoder rpc_bdev_fallocate_delete_decoders[] = {
	{"name", offsetof(struct bdev_fallocate_delete_opts, name), spdk_json_decode_string},
};

static void
rpc_bdev_fallocate_delete_cb(void *cb_arg, int bdeverrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (bdeverrno == 0) {
		spdk_jsonrpc_send_bool_response(request, true);
	} else {
		spdk_jsonrpc_send_error_response(request, bdeverrno, spdk_strerror(-bdeverrno));
	}
}

static void
rpc_bdev_fallocate_delete(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct bdev_fallocate_delete_opts opts = {};

	if (spdk_json_decode_object(params, rpc_bdev_fallocate_delete_decoders,
			SPDK_COUNTOF(rpc_bdev_fallocate_delete_decoders), &opts)) {
		SPDK_DEBUGLOG(bdev_malloc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
				"spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev_fallocate_delete(&opts, rpc_bdev_fallocate_delete_cb, request);

cleanup:
	free_rpc_bdev_fallocate_delete_opts(&opts);
}
SPDK_RPC_REGISTER("bdev_fallocate_delete", rpc_bdev_fallocate_delete, SPDK_RPC_RUNTIME)



static void
free_rpc_bdev_fallocate_resize_opts(struct bdev_fallocate_resize_opts *opts)
{
	free(opts->name);
}

static const struct spdk_json_object_decoder rpc_bdev_fallocate_resize_opts_decoders[] = {
	{"name", offsetof(struct bdev_fallocate_resize_opts, name), spdk_json_decode_string},
	{"size", offsetof(struct bdev_fallocate_resize_opts, size), spdk_json_decode_uint64}
};

static void
rpc_bdev_fallocate_resize(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct bdev_fallocate_resize_opts opts = {};
	int rc = 0;

	if (spdk_json_decode_object(params, rpc_bdev_fallocate_resize_opts_decoders,
			SPDK_COUNTOF(rpc_bdev_fallocate_resize_opts_decoders), &opts)) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
				"spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = bdev_fallocate_resize(&opts);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	spdk_jsonrpc_send_bool_response(request, true);

cleanup:
	free_rpc_bdev_fallocate_resize_opts(&opts);
}
SPDK_RPC_REGISTER("bdev_fallocate_resize", rpc_bdev_fallocate_resize, SPDK_RPC_RUNTIME)



static void
free_rpc_bdev_fallocate_set_xattrs_opts(struct bdev_fallocate_set_xattrs_opts *opts)
{
	free(opts->name);
	free_rpc_bdev_fallocate_xattrs(&opts->xattrs);
}

static const struct spdk_json_object_decoder rpc_bdev_fallocate_set_xattrs_opts_decoders[] = {
	{"name", offsetof(struct bdev_fallocate_set_xattrs_opts, name), spdk_json_decode_string},
	{"xattrs", offsetof(struct bdev_fallocate_set_xattrs_opts, xattrs), decode_fallocate_xattrs},
};

static void
rpc_bdev_fallocate_set_xattrs(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct bdev_fallocate_set_xattrs_opts opts = {};
	int rc = 0;

	if (spdk_json_decode_object(params, rpc_bdev_fallocate_set_xattrs_opts_decoders,
			SPDK_COUNTOF(rpc_bdev_fallocate_set_xattrs_opts_decoders), &opts)) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
				"spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = bdev_fallocate_set_xattrs(&opts);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	spdk_jsonrpc_send_bool_response(request, true);

cleanup:
	free_rpc_bdev_fallocate_set_xattrs_opts(&opts);
}
SPDK_RPC_REGISTER("bdev_fallocate_set_xattrs", rpc_bdev_fallocate_set_xattrs, SPDK_RPC_RUNTIME)