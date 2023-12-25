/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef SPDK_FSDEV_MODULE_H
#define SPDK_FSDEV_MODULE_H

#include "spdk/stdinc.h"
#include "spdk/fsdev.h"
#include "spdk/queue.h"
#include "spdk/tree.h"
#include "spdk/util.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Filesystem device I/O
 *
 * This is an I/O that is passed to an spdk_fsdev.
 */
struct spdk_fsdev_io;

/** Filesystem device module */
struct spdk_fsdev_module {
	/**
	 * Initialization function for the module. Called by the fsdev library
	 * during startup.
	 *
	 * Modules are required to define this function.
	 */
	int (*module_init)(void);

	/**
	 * Finish function for the module. Called by the fsdev library
	 * after all fsdevs for all modules have been unregistered.  This allows
	 * the module to do any final cleanup before the fsdev library finishes operation.
	 *
	 * Modules are not required to define this function.
	 */
	void (*module_fini)(void);

	/**
	 * Function called to return a text string representing the module-level
	 * JSON RPCs required to regenerate the current configuration.  This will
	 * include module-level configuration options, or methods to construct
	 * fsdevs when one RPC may generate multiple fsdevs.
	 *
	 * Per-fsdev JSON RPCs (where one "construct" RPC always creates one fsdev)
	 * may be implemented here, or by the fsdev's write_config_json function -
	 * but not both.  Fsdev module implementers may choose which mechanism to
	 * use based on the module's design.
	 *
	 * \return 0 on success or Fsdev specific negative error code.
	 */
	int (*config_json)(struct spdk_json_write_ctx *w);

	/** Name for the module being defined. */
	const char *name;

	/**
	 * Returns the allocation size required for the backend for uses such as local
	 * command structs, local SGL, iovecs, or other user context.
	 */
	int (*get_ctx_size)(void);

	/**
	 * Fields that are used by the internal fsdev subsystem. Fsdev modules
	 *  must not read or write to these fields.
	 */
	struct __fsdev_module_internal_fields {
		TAILQ_ENTRY(spdk_fsdev_module) tailq;
	} internal;
};

typedef void (*spdk_fsdev_unregister_cb)(void *cb_arg, int rc);

/**
 * Function table for a filesystem device backend.
 *
 * The backend filesystem device function table provides a set of APIs to allow
 * communication with a backend.
 */
struct spdk_fsdev_fn_table {
	/** Destroy the backend filesystem device object */
	int (*destruct)(void *ctx);

	/** Process the I/O request. */
	void (*submit_request)(struct spdk_io_channel *ch, struct spdk_fsdev_io *);

	/** Get an I/O channel for the specific fsdev for the calling thread. */
	struct spdk_io_channel *(*get_io_channel)(void *ctx);

	/**
	 * Negotiate fsdev instance options.
	 *
	 * The function validates the desired options and adjust them to reflect it's own capabilities.
	 * The module can only reduce the requested cababilities.
	 *
	 * \return 0 on success or Fsdev specific negative error code.
	 */
	int (*negotiate_opts)(void *ctx, struct spdk_fsdev_instance_opts *opts);

	/**
	 * Output fsdev-specific RPC configuration to a JSON stream. Optional - may be NULL.
	 *
	 * The JSON write context will be initialized with an open object, so the fsdev
	 * driver should write all data necessary to recreate this fsdev by invoking
	 * constructor method. No other data should be written.
	 */
	void (*write_config_json)(struct spdk_fsdev *fsdev, struct spdk_json_write_ctx *w);

	/** Get memory domains used by fsdev. Optional - may be NULL.
	 * Vfsdev module implementation should call \ref spdk_fsdev_get_memory_domains for underlying fsdev.
	 * Vfsdev module must inspect types of memory domains returned by base fsdev and report only those
	 * memory domains that it can work with. */
	int (*get_memory_domains)(void *ctx, struct spdk_memory_domain **domains, int array_size);
};

/**
 * Filesystem device IO completion callback.
 *
 * \param fsdev_io Filesystem device I/O that has completed.
 * \param cb_arg Callback argument specified when fsdev_io was submitted.
 */
typedef void (*spdk_fsdev_io_completion_cb)(struct spdk_fsdev_io *fsdev_io, void *cb_arg);

struct spdk_fsdev_name {
	char *name;
	struct spdk_fsdev *fsdev;
	RB_ENTRY(spdk_fsdev_name) node;
};

typedef TAILQ_HEAD(, spdk_fsdev_io) fsdev_io_tailq_t;
typedef STAILQ_HEAD(, spdk_fsdev_io) fsdev_io_stailq_t;

/** The node ID of the root inode */
#define SPDK_FUSE_ROOT_ID 1 /* Must be the same as FUSE_ROOT_ID in the fuse_kernel.h to avoid translation */

struct spdk_fsdev {
	/** User context passed in by the backend */
	void *ctxt;

	/** Unique name for this filesystem device. */
	char *name;

	/**
	 * Pointer to the fsdev module that registered this fsdev.
	 */
	struct spdk_fsdev_module *module;

	/** function table for all ops */
	const struct spdk_fsdev_fn_table *fn_table;

	/** Negotiable instance ops */
	struct spdk_fsdev_instance_opts opts;

	/** Fields that are used internally by the fsdev subsystem. Fsdev modules
	 *  must not read or write to these fields.
	 */
	struct __fsdev_internal_fields {
		/** Mutex protecting fsdev */
		pthread_mutex_t mutex;

		/** The fsdev status */
		enum spdk_fsdev_status status;

		/** Callback function that will be called after fsdev destruct is completed. */
		spdk_fsdev_unregister_cb unregister_cb;

		/** Unregister call context */
		void *unregister_ctx;

		/** List of open descriptors for this filesystem device. */
		TAILQ_HEAD(, spdk_fsdev_desc) open_descs;

		TAILQ_ENTRY(spdk_fsdev) link;

		/** Fsdev name used for quick lookup */
		struct spdk_fsdev_name fsdev_name;
	} internal;
};

enum spdk_fsdev_op {
	SPDK_FSDEV_OP_LOOKUP,
	SPDK_FSDEV_OP_FORGET,
	SPDK_FSDEV_OP_GETATTR,
	SPDK_FSDEV_OP_SETATTR,
	SPDK_FSDEV_OP_READLINK,
	SPDK_FSDEV_OP_SYMLINK,
	SPDK_FSDEV_OP_MKNOD,
	SPDK_FSDEV_OP_MKDIR,
	SPDK_FSDEV_OP_UNLINK,
	SPDK_FSDEV_OP_RMDIR,
	SPDK_FSDEV_OP_RENAME,
	SPDK_FSDEV_OP_LINK,
	SPDK_FSDEV_OP_OPEN,
	SPDK_FSDEV_OP_READ,
	SPDK_FSDEV_OP_WRITE,
	SPDK_FSDEV_OP_STATFS,
	SPDK_FSDEV_OP_RELEASE,
	SPDK_FSDEV_OP_FSYNC,
	SPDK_FSDEV_OP_SETXATTR,
	SPDK_FSDEV_OP_GETXATTR,
	SPDK_FSDEV_OP_LISTXATTR,
	SPDK_FSDEV_OP_REMOVEXATTR,
	SPDK_FSDEV_OP_FLUSH,
	SPDK_FSDEV_OP_OPENDIR,
	SPDK_FSDEV_OP_READDIR,
	SPDK_FSDEV_OP_RELEASEDIR,
	SPDK_FSDEV_OP_FSYNCDIR,
	SPDK_FSDEV_OP_FLOCK,
	SPDK_FSDEV_OP_CREATE,
	SPDK_FSDEV_OP_ABORT,
	SPDK_FSDEV_OP_FALLOCATE,
	SPDK_FSDEV_OP_COPY_FILE_RANGE,
	__SPDK_FSDEV_OP_LAST
};

struct spdk_fsdev_io {
	/** The filesystem device that this I/O belongs to. */
	struct spdk_fsdev *fsdev;

	/** Enumerated value representing the I/O type. */
	uint8_t type;

	/** A single iovec element for use by this fsdev_io. */
	struct iovec iov;

	union {
		struct {
			spdk_ino_t parent_ino;
			char *name;
		} lookup;
		struct {
			spdk_ino_t ino;
			uint64_t nlookup;
		} forget;
		struct {
			spdk_ino_t ino;
			uint64_t fh;
		} getattr;
		struct {
			spdk_ino_t ino;
			struct stat attr;
			uint32_t to_set;
			uint64_t fh;
		} setattr;
		struct {
			spdk_ino_t ino;
		} readlink;
		struct {
			spdk_ino_t parent_ino;
			char *target;
			char *linkpath;
			uid_t euid;
			gid_t egid;
		} symlink;
		struct {
			spdk_ino_t parent_ino;
			char *name;
			mode_t mode;
			dev_t rdev;
			uid_t euid;
			gid_t egid;
		} mknod;
		struct {
			spdk_ino_t parent_ino;
			char *name;
			mode_t mode;
			uid_t euid;
			gid_t egid;
		} mkdir;
		struct {
			spdk_ino_t parent_ino;
			char *name;
		} unlink;
		struct {
			spdk_ino_t parent_ino;
			char *name;
		} rmdir;
		struct {
			spdk_ino_t parent_ino;
			char *name;
			spdk_ino_t new_parent_ino;
			char *new_name;
			uint32_t flags;
		} rename;
		struct {
			spdk_ino_t ino;
			spdk_ino_t new_parent_ino;
			char *name;
		} link;
		struct {
			spdk_ino_t ino;
			uint32_t flags;
		} open;
		struct {
			spdk_ino_t ino;
			uint64_t fh;
			size_t size;
			uint64_t offs;
			uint32_t flags;
			struct iovec *iov;
			uint32_t iovcnt;
			struct spdk_fsdev_ext_op_opts *opts;
		} read;
		struct {
			spdk_ino_t ino;
			uint64_t fh;
			size_t size;
			uint64_t offs;
			uint64_t flags;
			const struct iovec *iov;
			uint32_t iovcnt;
			struct spdk_fsdev_ext_op_opts *opts;
		} write;
		struct {
			spdk_ino_t ino;
		} statfs;
		struct {
			spdk_ino_t ino;
			uint64_t fh;
		} release;
		struct {
			spdk_ino_t ino;
			uint64_t fh;
			bool datasync;
		} fsync;
		struct {
			spdk_ino_t ino;
			char *name;
			char *value;
			size_t size;
			uint32_t flags;
		} setxattr;
		struct {
			spdk_ino_t ino;
			char *name;
			char *buffer;
			size_t size;
		} getxattr;
		struct {
			spdk_ino_t ino;
			char *buffer;
			size_t size;
		} listxattr;
		struct {
			spdk_ino_t ino;
			char *name;
		} removexattr;
		struct {
			spdk_ino_t ino;
			uint64_t fh;
		} flush;
		struct {
			spdk_ino_t ino;
			uint32_t flags;
		} opendir;
		struct {
			spdk_ino_t ino;
			uint64_t fh;
			uint64_t offset;
			int (*entry_clb)(struct spdk_fsdev_io *fsdev_io, void *cb_arg);
			spdk_fsdev_op_readdir_entry_cb *usr_entry_clb;
		} readdir;
		struct {
			spdk_ino_t ino;
			uint64_t fh;
		} releasedir;
		struct {
			spdk_ino_t ino;
			uint64_t fh;
			bool datasync;
		} fsyncdir;
		struct {
			spdk_ino_t ino;
			uint64_t fh;
			int operation; /* see man flock */
		} flock;
		struct {
			spdk_ino_t parent_ino;
			char *name;
			mode_t mode;
			uint32_t flags;
			mode_t umask;
			uid_t euid;
			gid_t egid;
		} create;
		struct {
			uint64_t unique_to_abort;
		} abort;
		struct {
			spdk_ino_t ino;
			uint64_t fh;
			int mode;
			off_t offset;
			off_t length;
		} fallocate;
		struct {
			spdk_ino_t ino_in;
			uint64_t fh_in;
			off_t off_in;
			spdk_ino_t ino_out;
			uint64_t fh_out;
			off_t off_out;
			size_t len;
			uint32_t flags;
		} copy_file_range;
	} u_in;

	union {
		struct {
			struct spdk_fsdev_entry entry;
		} lookup;
		struct {
			struct stat attr;
			uint64_t attr_timeout_ms;
		} getattr;
		struct {
			struct stat attr;
			uint64_t attr_timeout_ms;
		} setattr;
		struct {
			char *linkname; /* will be freed by the fsdev layer */
		} readlink;
		struct {
			struct spdk_fsdev_entry entry;
		} symlink;
		struct {
			struct spdk_fsdev_entry entry;
		} mknod;
		struct {
			struct spdk_fsdev_entry entry;
		} mkdir;
		struct {
			struct spdk_fsdev_entry entry;
		} link;
		struct {
			uint64_t fh;
		} open;
		struct {
			uint32_t data_size;
		} read;
		struct {
			uint32_t data_size;
		} write;
		struct {
			struct statvfs stbuf;
		} statfs;
		struct {
			size_t value_size;
		} getxattr;
		struct {
			size_t data_size;
			bool size_only;
		} listxattr;
		struct {
			ssize_t fh;
		} opendir;
		struct {
			const char *name;
			struct spdk_fsdev_entry entry;
			off_t offset;
		} readdir;
		struct {
			struct spdk_fsdev_entry entry;
			uint64_t fh;
		} create;
		struct {
			size_t data_size;
		} copy_file_range;
	} u_out;

	/** It may be used by modules to put the fsdev_io into its own list. */
	TAILQ_ENTRY(spdk_fsdev_io) module_link;

	/**
	 *  Fields that are used internally by the fsdev subsystem. Fsdev modules
	 *  must not read or write to these fields.
	 */
	struct __fsdev_io_internal_fields {
		/** The fsdev I/O channel that this was handled on. */
		struct spdk_fsdev_channel *ch;

		/** The fsdev descriptor that was used when submitting this I/O. */
		struct spdk_fsdev_desc *desc;

		/** User function that will be called when this completes */
		spdk_fsdev_io_completion_cb cb;

		/** Context that will be passed to the completion callback */
		void *caller_ctx;

		/**
		 * Set to true while the fsdev module submit_request function is in progress.
		 *
		 * This is used to decide whether spdk_fsdev_io_complete() can complete the I/O directly
		 * or if completion must be deferred via an event.
		 */
		bool in_submit_request;

		/** IO operation */
		enum spdk_fsdev_op op;

		/** IO unique ID */
		uint64_t unique;

		/** User callback */
		void *usr_cpl_clb;

		/** The context for the user callback */
		void *usr_cpl_ctx;

		/** Status for the IO */
		int status;

		/** Member used for linking child I/Os together. */
		TAILQ_ENTRY(spdk_fsdev_io) link;

		/** Entry to the list per_thread_cache of struct spdk_fsdev_mgmt_channel. */
		STAILQ_ENTRY(spdk_fsdev_io) buf_link;

		/** Entry to the list io_submitted of struct spdk_fsdev_channel */
		TAILQ_ENTRY(spdk_fsdev_io) ch_link;
	} internal;

	/**
	 * Per I/O context for use by the fsdev module.
	 */
	uint8_t driver_ctx[0];

	/* No members may be added after driver_ctx! */
};

/**
 * Register a new fsdev.
 *
 * \param fsdev Filesystem device to register.
 *
 * \return 0 on success.
 * \return -EINVAL if the fsdev name is NULL.
 * \return -EEXIST if a fsdev with the same name already exists.
 */
int spdk_fsdev_register(struct spdk_fsdev *fsdev);

/**
 * Start unregistering a fsdev. This will notify each currently open descriptor
 * on this fsdev of the hotremoval to request the upper layers to stop using this fsdev
 * and manually close all the descriptors with spdk_fsdev_close().
 * The actual fsdev unregistration may be deferred until all descriptors are closed.
 *
 * Note: spdk_fsdev_unregister() can be unsafe unless the fsdev is not opened before and
 * closed after unregistration. It is recommended to use spdk_fsdev_unregister_by_name().
 *
 * \param fsdev Filesystem device to unregister.
 * \param cb_fn Callback function to be called when the unregister is complete.
 * \param cb_arg Argument to be supplied to cb_fn
 */
void spdk_fsdev_unregister(struct spdk_fsdev *fsdev, spdk_fsdev_unregister_cb cb_fn, void *cb_arg);

/**
 * Start unregistering a fsdev. This will notify each currently open descriptor
 * on this fsdev of the hotremoval to request the upper layer to stop using this fsdev
 * and manually close all the descriptors with spdk_fsdev_close().
 * The actual fsdev unregistration may be deferred until all descriptors are closed.
 *
 * \param fsdev_name Filesystem device name to unregister.
 * \param module Module by which the filesystem device was registered.
 * \param cb_fn Callback function to be called when the unregister is complete.
 * \param cb_arg Argument to be supplied to cb_fn
 *
 * \return 0 on success, or suitable errno value otherwise
 */
int spdk_fsdev_unregister_by_name(const char *fsdev_name, struct spdk_fsdev_module *module,
				  spdk_fsdev_unregister_cb cb_fn, void *cb_arg);

/**
 * Invokes the unregister callback of a fsdev backing a virtual fsdev.
 *
 * A Fsdev with an asynchronous destruct path should return 1 from its
 * destruct function and call this function at the conclusion of that path.
 * Fsdevs with synchronous destruct paths should return 0 from their destruct
 * path.
 *
 * \param fsdev Filesystem device that was destroyed.
 * \param fsdeverrno Error code returned from fsdev's destruct callback.
 */
void spdk_fsdev_destruct_done(struct spdk_fsdev *fsdev, int fsdeverrno);

/**
 * Indicate to the fsdev layer that the module is done initializing.
 *
 * To be called once during module_init or asynchronously after
 * an asynchronous operation required for module initialization is completed.
 *
 * \param module Pointer to the module completing the initialization.
 */
void spdk_fsdev_module_init_done(struct spdk_fsdev_module *module);

/**
 * Complete a fsdev_io
 *
 * \param fsdev_io I/O to complete.
 * \param status The I/O completion status.
 */
void spdk_fsdev_io_complete(struct spdk_fsdev_io *fsdev_io, int status);


/**
 * Get I/O operation
 *
 * \param fsdev_io I/O to complete.
 *
 * \return operation code assosiated with the I/O
 */
static inline enum spdk_fsdev_op
spdk_fsdev_io_get_op(struct spdk_fsdev_io *fsdev_io)
{
	return fsdev_io->internal.op;
}

/**
 * Get I/O unique id
 *
 * \param fsdev_io I/O to complete.
 *
 * \return I/O unique id
 */
static inline uint64_t
spdk_fsdev_io_get_unuqie(struct spdk_fsdev_io *fsdev_io)
{
	return fsdev_io->internal.unique;
}

/**
 * Free an I/O request. This should only be called after the completion callback
 * for the I/O has been called and notifies the fsdev layer that memory may now
 * be released.
 *
 * \param fsdev_io I/O request.
 */
void spdk_fsdev_free_io(struct spdk_fsdev_io *fsdev_io);


/**
 * Get a thread that given fsdev_io was submitted on.
 *
 * \param fsdev_io I/O
 * \return thread that submitted the I/O
 */
struct spdk_thread *spdk_fsdev_io_get_thread(struct spdk_fsdev_io *fsdev_io);

/**
 * Get the fsdev module's I/O channel that the given fsdev_io was submitted on.
 *
 * \param fsdev_io I/O
 * \return the fsdev module's I/O channel that the given fsdev_io was submitted on.
 */
struct spdk_io_channel *spdk_fsdev_io_get_io_channel(struct spdk_fsdev_io *fsdev_io);

/**
 * Add the given module to the list of registered modules.
 * This function should be invoked by referencing the macro
 * SPDK_FSDEV_MODULE_REGISTER in the module c file.
 *
 * \param fsdev_module Module to be added.
 */
void spdk_fsdev_module_list_add(struct spdk_fsdev_module *fsdev_module);

/**
 * Find registered module with name pointed by \c name.
 *
 * \param name name of module to be searched for.
 * \return pointer to module or NULL if no module with \c name exist
 */
struct spdk_fsdev_module *spdk_fsdev_module_list_find(const char *name);

static inline struct spdk_fsdev_io *
spdk_fsdev_io_from_ctx(void *ctx)
{
	return SPDK_CONTAINEROF(ctx, struct spdk_fsdev_io, driver_ctx);
}

/*
 *  Macro used to register module for later initialization.
 */
#define SPDK_FSDEV_MODULE_REGISTER(name, module) \
static void __attribute__((constructor)) _spdk_fsdev_module_register_##name(void) \
{ \
	spdk_fsdev_module_list_add(module); \
}

#ifdef __cplusplus
}
#endif

#endif /* SPDK_FSDEV_MODULE_H */
