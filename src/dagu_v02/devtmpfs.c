/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * devtmpfs filesystem type for a kernel built without CONFIG_DEVTMPFS.
 *
 * The kernel has no devtmpfs entry in /proc/filesystems, so mounting with
 * -t devtmpfs fails with ENODEV and consumers that expect the type are
 * unable to set up their /dev.
 *
 * devtmpfs is a tmpfs instance with a distinctive name: drivers/base/devtmpfs.c
 * mounts tmpfs and registers a separate file_system_type whose mount callback
 * is the tmpfs one. That makes registration possible without the driver-core
 * node maintenance, which is compiled out when CONFIG_DEVTMPFS is unset.
 *
 * Construction copies the live shmem_fs_type rather than rebuilding it, so the
 * mount callback, kill_sb, fs_flags and lock keys carry over unchanged. Only
 * the fields that must differ are patched:
 *
 *   name      +0x00   replaced with "devtmpfs"
 *   next      +0x38   cleared; register_filesystem rejects a non-null value
 *   fs_supers +0x40   cleared; the source already has mounted instances
 *
 * The name offset follows register_filesystem, which loads fs->name from
 * offset zero. The next offset follows the same function, which loads
 * fs->next from +0x38 to reject duplicates and stores the link there.
 *
 * The resulting filesystem is empty at mount time. Node population depends on
 * the driver-core hooks that CONFIG_DEVTMPFS would compile in, so consumers
 * build their own nodes from sysfs.
 */

#include "devtmpfs.h"

#include <kallsyms.h>
#include <log.h>

/*
 * Offsets verified against register_filesystem on the target image, which
 * loads fs->name from +0x00 and fs->next from +0x38.
 *
 * The instance occupies 0x68 bytes on this image: the distance from
 * shmem_fs_type to the symbol that follows it. Copying within that bound
 * keeps the lock keys coherent and stays inside the source object.
 */
#define DAGU_FST_NAME		0x00UL
#define DAGU_FST_NEXT		0x38UL
#define DAGU_FST_FS_SUPERS	0x40UL
#define DAGU_FST_SIZE		0x68UL

#define DAGU_GFP_KERNEL		0x006000c0U

static const char devtmpfs_name[] = "devtmpfs";

typedef void *(*kmalloc_fn)(unsigned long size, unsigned int flags);
typedef void (*kfree_fn)(const void *pointer);
typedef int (*register_fs_fn)(void *fs_type);
typedef int (*unregister_fs_fn)(void *fs_type);

static kmalloc_fn kmalloc_ptr;
static kfree_fn kfree_ptr;
static register_fs_fn register_ptr;
static unregister_fs_fn unregister_ptr;

static void *registered_type;
static unsigned int installed;

static void copy_bytes(void *dst, const void *src, unsigned long size)
{
	unsigned char *d = (unsigned char *)dst;
	const unsigned char *s = (const unsigned char *)src;
	unsigned long i;

	for (i = 0; i < size; ++i)
		d[i] = s[i];
}

static void store_qword(void *base, unsigned long offset, unsigned long value)
{
	*(volatile unsigned long *)((unsigned char *)base + offset) = value;
}

int dagu_devtmpfs_install(void)
{
	unsigned long shmem_type;
	void *copy;

	if (installed)
		return -22;

	kmalloc_ptr = (kmalloc_fn)kallsyms_lookup_name("__kmalloc");
	kfree_ptr = (kfree_fn)kallsyms_lookup_name("kfree");
	register_ptr = (register_fs_fn)kallsyms_lookup_name("register_filesystem");
	unregister_ptr = (unregister_fs_fn)kallsyms_lookup_name("unregister_filesystem");
	if (!kmalloc_ptr || !kfree_ptr || !register_ptr || !unregister_ptr)
		return -2;

	/*
	 * shmem_fs_type backs tmpfs. Its mount callback accepts mode=0755,
	 * which is the option devtmpfs passes.
	 */
	shmem_type = kallsyms_lookup_name("shmem_fs_type");
	if (!shmem_type) {
		logke("ds-dagu-devtmpfs: shmem_fs_type not found\n");
		return -2;
	}

	copy = kmalloc_ptr(DAGU_FST_SIZE, DAGU_GFP_KERNEL);
	if (!copy)
		return -12;

	copy_bytes(copy, (const void *)shmem_type, DAGU_FST_SIZE);
	store_qword(copy, DAGU_FST_NAME, (unsigned long)devtmpfs_name);
	store_qword(copy, DAGU_FST_NEXT, 0UL);
	store_qword(copy, DAGU_FST_FS_SUPERS, 0UL);

	{
		int rc = register_ptr(copy);

		if (rc) {
			logke("ds-dagu-devtmpfs: register failed rc=%d\n", rc);
			kfree_ptr(copy);
			return rc;
		}
	}

	registered_type = copy;
	installed = 1U;
	logki("ds-dagu-devtmpfs: registered from shmem_fs_type=0x%lx\n", shmem_type);
	return 0;
}

void dagu_devtmpfs_uninstall(void)
{
	if (!installed)
		return;
	if (registered_type && unregister_ptr)
		unregister_ptr(registered_type);
	if (registered_type && kfree_ptr)
		kfree_ptr(registered_type);
	registered_type = 0;
	installed = 0U;
}
