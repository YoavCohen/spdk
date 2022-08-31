/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "vbdev_crypto.h"

#include "spdk/hexlify.h"

/* Reasonable bdev name length + xax driver's name len + max cipher's name len */
#define MAX_KEY_NAME_LEN 128

/* Structure to hold the parameters for this RPC method. */
struct rpc_construct_crypto {
	char *base_bdev_name;
	char *name;
	char *accel_module;
	struct spdk_accel_crypto_key_create_param param;
};

/* Free the allocated memory resource after the RPC handling. */
static void
free_rpc_construct_crypto(struct rpc_construct_crypto *r)
{
	free(r->base_bdev_name);
	free(r->name);
	free(r->accel_module);
	free(r->param.cipher);
	free(r->param.driver_name);
	if (r->param.key1) {
		memset(r->param.key1, 0, strnlen(r->param.key1, SPDK_ACCEL_CRYPTO_KEY_MAX_HEX_LENGTH));
	}
	free(r->param.key1);
	if (r->param.key2) {
		memset(r->param.key2, 0, strnlen(r->param.key2, SPDK_ACCEL_CRYPTO_KEY_MAX_HEX_LENGTH));
	}
	free(r->param.key2);
	free(r->param.key_name);
}

/* Structure to decode the input parameters for this RPC method. */
static const struct spdk_json_object_decoder rpc_construct_crypto_decoders[] = {
	{"base_bdev_name", offsetof(struct rpc_construct_crypto, base_bdev_name), spdk_json_decode_string},
	{"name", offsetof(struct rpc_construct_crypto, name), spdk_json_decode_string},
	{"crypto_pmd", offsetof(struct rpc_construct_crypto, param.driver_name), spdk_json_decode_string, true},
	{"key", offsetof(struct rpc_construct_crypto, param.key1), spdk_json_decode_string, true},
	{"cipher", offsetof(struct rpc_construct_crypto, param.cipher), spdk_json_decode_string, true},
	{"key2", offsetof(struct rpc_construct_crypto, param.key2), spdk_json_decode_string, true},
	{"key_name", offsetof(struct rpc_construct_crypto, param.key_name), spdk_json_decode_string, true},
	{"module", offsetof(struct rpc_construct_crypto, accel_module), spdk_json_decode_string, true},
};

static struct vbdev_crypto_opts *
create_crypto_opts(struct rpc_construct_crypto *rpc, struct spdk_accel_crypto_key *key)
{
	struct vbdev_crypto_opts *opts = calloc(1, sizeof(*opts));
	if (!opts) {
		return NULL;
	}

	opts->bdev_name = strdup(rpc->base_bdev_name);
	if (!opts->bdev_name) {
		free_crypto_opts(opts);
		return NULL;
	}
	opts->vbdev_name = strdup(rpc->name);
	if (!opts->vbdev_name) {
		free_crypto_opts(opts);
		return NULL;
	}

	opts->key = key;

	return opts;
}

/* Decode the parameters for this RPC method and properly construct the crypto
 * device. Error status returned in the failed cases.
 */
static void
rpc_bdev_crypto_create(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_construct_crypto req = {};
	struct vbdev_crypto_opts *crypto_opts = NULL;
	struct spdk_json_write_ctx *w;
	struct spdk_accel_crypto_key *key = NULL;
	int rc;

	if (spdk_json_decode_object(params, rpc_construct_crypto_decoders,
				    SPDK_COUNTOF(rpc_construct_crypto_decoders),
				    &req)) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "Failed to decode crypto disk create parameters.");
		goto cleanup;
	}

	if (!req.name) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "crypto_bdev name is missing");
		goto cleanup;
	}

	if (req.param.key_name) {
		/* New config version */
		key = spdk_accel_crypto_key_get(req.param.key_name);
		if (key) {
			if (req.param.key1 || req.param.cipher || req.param.driver_name) {
				SPDK_NOTICELOG("Key name specified, other parameters are ignored\n");
			}
			SPDK_NOTICELOG("Found key \"%s\"\n", req.param.key_name);
		}
	}

	/* No key_name. Support legacy configuration */
	if (!key) {
		if (req.param.key_name) {
			spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
							 "Key was not found");
			goto cleanup;
		}

		if (req.param.cipher == NULL) {
			req.param.cipher = strdup(BDEV_CRYPTO_DEFAULT_CIPHER);
			if (req.param.cipher == NULL) {
				spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
								 "Unable to allocate memory for req.cipher");
				goto cleanup;
			}
		}

		req.param.key_name = calloc(1, MAX_KEY_NAME_LEN);
		if (!req.param.key_name) {
			/* The new API requires key name. Create it as pmd_name + cipher */
			spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
							 "Unable to allocate memory for key_name");
			goto cleanup;
		}
		snprintf(req.param.key_name, MAX_KEY_NAME_LEN, "%s_%s_%s", req.name, req.param.cipher,
			 req.param.driver_name);

		/* Try to find a key with generated name, we may be loading from a json config where crypto_bdev has no key_name parameter */
		key = spdk_accel_crypto_key_get(req.param.key_name);
		if (key) {
			SPDK_NOTICELOG("Found key \"%s\"\n", req.param.key_name);
		} else {
			rc = spdk_accel_crypto_key_create(req.accel_module, &req.param);
			if (!rc) {
				key = spdk_accel_crypto_key_get(req.param.key_name);
			}
		}
	}

	if (!key) {
		/* We haven't found an existing key or were not able to create a new one */
		SPDK_ERRLOG("No key was found\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "No key was found");
		goto cleanup;
	}

	crypto_opts = create_crypto_opts(&req, key);
	if (!crypto_opts) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "Memory allocation failed");
		goto cleanup;
	}

	rc = create_crypto_disk(crypto_opts);
	if (rc) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		free_crypto_opts(crypto_opts);
		goto cleanup;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_string(w, req.name);
	spdk_jsonrpc_end_result(request, w);

cleanup:
	free_rpc_construct_crypto(&req);
}
SPDK_RPC_REGISTER("bdev_crypto_create", rpc_bdev_crypto_create, SPDK_RPC_RUNTIME)

struct rpc_delete_crypto {
	char *name;
};

static void
free_rpc_delete_crypto(struct rpc_delete_crypto *req)
{
	free(req->name);
}

static const struct spdk_json_object_decoder rpc_delete_crypto_decoders[] = {
	{"name", offsetof(struct rpc_delete_crypto, name), spdk_json_decode_string},
};

static void
rpc_bdev_crypto_delete_cb(void *cb_arg, int bdeverrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (bdeverrno == 0) {
		spdk_jsonrpc_send_bool_response(request, true);
	} else {
		spdk_jsonrpc_send_error_response(request, bdeverrno, spdk_strerror(-bdeverrno));
	}
}

static void
rpc_bdev_crypto_delete(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_delete_crypto req = {NULL};

	if (spdk_json_decode_object(params, rpc_delete_crypto_decoders,
				    SPDK_COUNTOF(rpc_delete_crypto_decoders),
				    &req)) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "Invalid parameters");
		goto cleanup;
	}

	delete_crypto_disk(req.name, rpc_bdev_crypto_delete_cb, request);

	free_rpc_delete_crypto(&req);

	return;

cleanup:
	free_rpc_delete_crypto(&req);
}
SPDK_RPC_REGISTER("bdev_crypto_delete", rpc_bdev_crypto_delete, SPDK_RPC_RUNTIME)
