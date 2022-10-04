/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) Intel Corporation.
 *   Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 */

#include "accel_dpdk_cryptodev.h"

#include "spdk/rpc.h"

static void
rpc_dpdk_cryptodev_accel_enable(struct spdk_jsonrpc_request *request,
				const struct spdk_json_val *params)
{
	if (params != NULL) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "No parameters expected");
		return;
	}

	accel_dpdk_cryptodev_enable();
	spdk_jsonrpc_send_bool_response(request, true);
}
SPDK_RPC_REGISTER("dpdk_cryptodev_accel_enable", rpc_dpdk_cryptodev_accel_enable, SPDK_RPC_STARTUP)
