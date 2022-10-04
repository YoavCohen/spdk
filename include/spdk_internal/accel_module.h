/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES
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

#ifndef SPDK_ACCEL_MODULE_H
#define SPDK_ACCEL_MODULE_H

#include "spdk/stdinc.h"

#include "spdk/accel.h"
#include "spdk/queue.h"
#include "spdk/config.h"

struct spdk_accel_module_if;
struct spdk_accel_task;

void spdk_accel_task_complete(struct spdk_accel_task *task, int status);

/** Some reasonable key length used with strnlen() */
#define SPDK_ACCEL_CRYPTO_KEY_MAX_HEX_LENGTH (1024 + 1)

struct spdk_accel_crypto_key_create_param {
	char *cipher;		/**< Cipher to be used for crypto operations */
	char *key1;		/**< Hexlified key1 */
	char *key2;		/**< Hexlified key2 */
	char *key_name;		/**< Key name */
};

struct spdk_accel_crypto_key {
	void *priv;					/**< Module private data */
	char *key1;					/**< Key1 in binary form */
	size_t key1_size;				/**< Key1 size in bytes */
	char *key2;					/**< Key2 in binary form */
	size_t key2_size;				/**< Key1 size in bytes */
	struct spdk_accel_module_if *module_if;			/**< Accel module the key belongs to */
	struct spdk_accel_crypto_key_create_param param;	/**< User input parameters */
	TAILQ_ENTRY(spdk_accel_crypto_key) link;
};

struct spdk_accel_task {
	struct accel_io_channel		*accel_ch;
	spdk_accel_completion_cb	cb_fn;
	void				*cb_arg;
	union {
		struct {
			struct iovec		*iovs; /* iovs passed by the caller */
			uint32_t		iovcnt; /* iovcnt passed by the caller */
		} s;
		void				*src;
	};
	union {
		struct {
			struct iovec		*iovs; /* iovs passed by the caller */
			uint32_t		iovcnt; /* iovcnt passed by the caller */
		} d;
		void			*dst;
		void			*src2;
	};
	union {
		void				*dst2;
		uint32_t			seed;
		uint64_t			fill_pattern;
		struct spdk_accel_crypto_key	*crypto_key;
	};
	union {
		uint32_t		*crc_dst;
		uint32_t		*output_size;
		uint32_t		block_size; /* for crypto op */
	};
	enum accel_opcode		op_code;
	uint64_t			nbytes;
	union {
		uint64_t		nbytes_dst; /* for compress op */
		uint64_t		iv; /* Initialization vector (tweak) for crypto op */
	};
	int				flags;
	int				status;
	TAILQ_ENTRY(spdk_accel_task)	link;
};

struct spdk_accel_module_if {
	/** Initialization function for the module.  Called by the spdk
	 *   application during startup.
	 *
	 *  Modules are required to define this function.
	 */
	int	(*module_init)(void);

	/** Finish function for the module.  Called by the spdk application
	 *   before the spdk application exits to perform any necessary cleanup.
	 *
	 *  Modules are not required to define this function.
	 */
	void	(*module_fini)(void *ctx);

	/**
	 * Write Acceleration module configuration into provided JSON context.
	 */
	void	(*write_config_json)(struct spdk_json_write_ctx *w);

	/**
	 * Returns the allocation size required for the modules to use for context.
	 */
	size_t	(*get_ctx_size)(void);

	const char *name;
	bool (*supports_opcode)(enum accel_opcode);
	struct spdk_io_channel *(*get_io_channel)(void);
	int (*submit_tasks)(struct spdk_io_channel *ch, struct spdk_accel_task *accel_task);

	/**
	 * Crete crypto key function. Module is repsonsible to fill all necessary parameters in
	 * \b spdk_accel_crypto_key structure
	 */
	int (*crypto_key_init)(struct spdk_accel_crypto_key *key);
	void (*crypto_key_deinit)(struct spdk_accel_crypto_key *key);

	TAILQ_ENTRY(spdk_accel_module_if)	tailq;
};

/**
 * Create a crypto key with given parameters. Accel module copies content of \b param structure
 *
 * \param module_name Accel module used to create a key
 * \param param Key parameters
 * \return 0 on success, negated errno on error
 */
int spdk_accel_crypto_key_create(const char *module_name,
				 const struct spdk_accel_crypto_key_create_param *param);

/**
 * Destroy a creypto key
 *
 * \param key Key to destroy
 * \return 0 on success, negated errno on error
 */
int spdk_accel_crypto_key_destroy(struct spdk_accel_crypto_key *key);

/**
 * Find a crypto key structure by name
 * \param name Key name
 * \return Crypto key structure or NULL
 */
struct spdk_accel_crypto_key *spdk_accel_crypto_key_get(const char *name);

void spdk_accel_module_list_add(struct spdk_accel_module_if *accel_module);

#define SPDK_ACCEL_MODULE_REGISTER(name, module) \
static void __attribute__((constructor)) _spdk_accel_module_register_##name(void) \
{ \
	spdk_accel_module_list_add(module); \
}

/**
 * Called by an accel module when cleanup initiated during .module_fini has completed
 */
void spdk_accel_module_finish(void);

#endif
