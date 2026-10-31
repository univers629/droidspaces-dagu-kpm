/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * mqueue filesystem type for a kernel built without CONFIG_POSIX_MQUEUE.
 *
 * A kernel without the option has no "mqueue" entry in /proc/filesystems, so
 * mount -t mqueue fails with ENODEV. Container runtimes mount that type at
 * /dev/mqueue during container setup and treat the failure as fatal, which
 * stops any container from starting.
 *
 * The type is constructed the same way as the devtmpfs type in devtmpfs.c:
 * copy the live shmem_fs_type and patch only the fields that must differ. The
 * shmem mount callback, kill_sb, fs_flags and lock keys carry over unchanged,
 * so the mount succeeds and yields an empty directory.
 *
 *   name      +0x00   replaced with "mqueue"
 *   next      +0x38   cleared; register_filesystem rejects a non-null value
 *   fs_supers +0x40   cleared; the source already has mounted instances
 *
 * The mount is a plain tmpfs. The mq_open/mq_send/mq_receive syscalls remain
 * absent, because they live in ipc/mqueue.c which the option also gates; a
 * caller that uses them still receives ENOSYS. Mounting is what the container
 * runtime needs, and that is what this type provides.
 */

#include "mqueue.h"

#include <kallsyms.h>
#include <log.h>

/* Offsets verified against register_filesystem on the target image, which
 * loads fs->name from +0x00 and fs->next from +0x38. The instance occupies
 * 0x68 bytes: the distance from shmem_fs_type to the symbol that follows it. */
#define DAGU_MQ_FST_NAME	0x00UL
#define DAGU_MQ_FST_NEXT	0x38UL
#define DAGU_MQ_FST_FS_SUPERS	0x40UL
#define DAGU_MQ_FST_SIZE	0x68UL

#define DAGU_MQ_GFP_KERNEL	0x006000c0U

static const char mqueue_name[] = "mqueue";

typedef void *(*mq_kmalloc_fn)(unsigned long size, unsigned int flags);
typedef void (*mq_kfree_fn)(const void *pointer);
typedef int (*mq_register_fs_fn)(void *fs_type);
typedef int (*mq_unregister_fs_fn)(void *fs_type);

static mq_kmalloc_fn mq_kmalloc_ptr;
static mq_kfree_fn mq_kfree_ptr;
static mq_register_fs_fn mq_register_ptr;
static mq_unregister_fs_fn mq_unregister_ptr;

static void *mq_registered_type;
static unsigned int mq_installed;

static void mq_copy_bytes(void *dst, const void *src, unsigned long size)
{
	unsigned char *d = (unsigned char *)dst;
	const unsigned char *s = (const unsigned char *)src;
	unsigned long i;

	for (i = 0; i < size; ++i)
		d[i] = s[i];
}

static void mq_store_qword(void *base, unsigned long offset, unsigned long value)
{
	*(volatile unsigned long *)((unsigned char *)base + offset) = value;
}

int dagu_mqueue_install(void)
{
	unsigned long shmem_type;
	void *copy;
	int rc;

	if (mq_installed)
		return -22;

	mq_kmalloc_ptr = (mq_kmalloc_fn)kallsyms_lookup_name("__kmalloc");
	mq_kfree_ptr = (mq_kfree_fn)kallsyms_lookup_name("kfree");
	mq_register_ptr = (mq_register_fs_fn)kallsyms_lookup_name("register_filesystem");
	mq_unregister_ptr =
		(mq_unregister_fs_fn)kallsyms_lookup_name("unregister_filesystem");
	if (!mq_kmalloc_ptr || !mq_kfree_ptr || !mq_register_ptr ||
	    !mq_unregister_ptr)
		return -2;

	/* shmem_fs_type backs tmpfs; the copied mount callback accepts the
	 * bare mount mqueue performs. */
	shmem_type = kallsyms_lookup_name("shmem_fs_type");
	if (!shmem_type) {
		logke("ds-dagu-mqueue: shmem_fs_type not found\n");
		return -2;
	}

	copy = mq_kmalloc_ptr(DAGU_MQ_FST_SIZE, DAGU_MQ_GFP_KERNEL);
	if (!copy)
		return -12;

	mq_copy_bytes(copy, (const void *)shmem_type, DAGU_MQ_FST_SIZE);
	mq_store_qword(copy, DAGU_MQ_FST_NAME, (unsigned long)mqueue_name);
	mq_store_qword(copy, DAGU_MQ_FST_NEXT, 0UL);
	mq_store_qword(copy, DAGU_MQ_FST_FS_SUPERS, 0UL);

	rc = mq_register_ptr(copy);
	if (rc) {
		logke("ds-dagu-mqueue: register failed rc=%d\n", rc);
		mq_kfree_ptr(copy);
		return rc;
	}

	mq_registered_type = copy;
	mq_installed = 1U;
	logki("ds-dagu-mqueue: registered 'mqueue' from shmem_fs_type=0x%lx\n",
	      shmem_type);
	return 0;
}

void dagu_mqueue_uninstall(void)
{
	if (!mq_installed)
		return;
	if (mq_registered_type && mq_unregister_ptr)
		mq_unregister_ptr(mq_registered_type);
	if (mq_registered_type && mq_kfree_ptr)
		mq_kfree_ptr(mq_registered_type);
	mq_registered_type = 0;
	mq_installed = 0U;
}
