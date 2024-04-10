// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * rdpci
 *
 * Copyright (c) 2024 Jan Rusnak <jan@rusnak.sk>
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/cdev.h>
#include <linux/pci.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/xarray.h>
#include <asm/io.h>
#include "logmsg.h"
#include "rdpci_ioctl.h"

MODULE_AUTHOR("Jan Rusnak <jan@rusnak.sk>");
MODULE_DESCRIPTION("rdpci reads PCI memory regions");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

#define DEV_MINOR_NUM 1048576
#define DEV_MINOR_START 256
#define DEV_FILE_MODE 0666

struct bar_remap {
	int bar;
	unsigned long phys_addr;
	unsigned long size;
	void __iomem *kv_addr;
	enum rdpci_read_align read_align;
	struct mutex mtx;
};

struct dev_node {
	dev_t devn;
	struct device *device;
	struct cdev cdev;
};

struct rdpci_ctx {
	int id;
	struct pci_dev *pci_dev;
	struct dev_node dev_node;
	struct bar_remap bar_remap;
};

static int __init rdpci_init(void);
static void __exit rdpci_exit(void);
static int rdpci_probe(struct pci_dev *dev, const struct pci_device_id *id);
static void rdpci_remove(struct pci_dev *dev);
static int open_rdpci(struct inode *inode, struct file *file);
static loff_t llseek_rdpci(struct file *file, loff_t offset, int whence);
static ssize_t read_rdpci(struct file *file, char __user *buf, size_t count, loff_t *pos);
static ssize_t write_rdpci(struct file *file, const char __user *buf, size_t count, loff_t *pos);
static int close_rdpci(struct inode *inode, struct file *file);
static long ioctl_rdpci(struct file *file, unsigned int cmd, unsigned long arg);
static char *devnode_mode(struct device *dev, umode_t *mode);
static int create_dev_node(struct rdpci_ctx *ctx);
static void delete_dev_node(struct rdpci_ctx *ctx);

static DEFINE_XARRAY_ALLOC(ctx_handles);

static struct class *rdpci_class;

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = open_rdpci,
	.llseek = llseek_rdpci,
	.read = read_rdpci,
	.write = write_rdpci,
	.release = close_rdpci,
	.unlocked_ioctl = ioctl_rdpci
};

static struct pci_device_id pci_device_id_table[] = {
	{PCI_DEVICE(0x9710, 0x9835)},
	{0,}
};

MODULE_DEVICE_TABLE(pci, pci_device_id_table);

static struct pci_driver rdpci_driver = {
	.name = "rdpci",
	.id_table = pci_device_id_table,
	.probe = rdpci_probe,
	.remove = rdpci_remove
};

static atomic_t devcnt = ATOMIC_INIT(0);

/**
 * rdpci_init
 */
static int __init rdpci_init(void)
{
	int err;

	rdpci_class = class_create(THIS_MODULE, "rdpci");
	if (IS_ERR(rdpci_class)) {
		logerr("Failed to create rdpci_class\n");
		return PTR_ERR(rdpci_class);
	}
	rdpci_class->devnode = devnode_mode;
	err = pci_register_driver(&rdpci_driver);
	if (err) {
		class_destroy(rdpci_class);
		return err;
	}
	return 0;
}

/**
 * rdpci_exit
 */
static void __exit rdpci_exit(void)
{
	unsigned long index;
	struct rdpci_ctx *ctx;

	pci_unregister_driver(&rdpci_driver);
	class_destroy(rdpci_class);
	xa_for_each(&ctx_handles, index, ctx) {
		mutex_destroy(&ctx->bar_remap.mtx);
		kfree(ctx);
	}
	xa_destroy(&ctx_handles);
}

/**
 * rdpci_probe
 */
static int rdpci_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int err;
	u16 vendor, device;
	int dom, bus, slot, func;
	struct rdpci_ctx *ctx;
	u32 idx;

	err = pci_enable_device(dev);
	if (err) {
		logerr("Failed to enable PCI device\n");
		return err;
	}
	pci_read_config_word(dev, PCI_VENDOR_ID, &vendor);
	pci_read_config_word(dev, PCI_DEVICE_ID, &device);
	dom = pci_domain_nr(dev->bus);
	bus = dev->bus->number;
	slot = PCI_SLOT(dev->devfn);
	func = PCI_FUNC(dev->devfn);
	loginfo("Vendor ID: 0x%04X Device ID: 0x%04X Bus address: [%04X:%02X:%02X.%X]\n", vendor, device, dom, bus, slot, func);
	ctx = kzalloc(sizeof(struct rdpci_ctx), GFP_KERNEL);
	if (unlikely(!ctx)) {
		pci_disable_device(dev);
		return -ENOMEM;
	}
	ctx->id = atomic_add_return(1, &devcnt) - 1;
	ctx->pci_dev = dev;
	mutex_init(&ctx->bar_remap.mtx);
	pci_set_drvdata(dev, ctx);
	err = create_dev_node(ctx);
	if (err)
		goto pci_disable;
	err = xa_alloc(&ctx_handles, &idx, (void *) ctx,  XA_LIMIT(0, 255), GFP_KERNEL);
	if (err)
		goto delete_dev_node;
	return 0;
delete_dev_node:
	delete_dev_node(ctx);
pci_disable:
	pci_disable_device(dev);
	mutex_destroy(&ctx->bar_remap.mtx);
	kfree(ctx);
	return err;
}

/**
 * rdpci_remove
 */
static void rdpci_remove(struct pci_dev *dev)
{
	static struct rdpci_ctx *ctx;

	ctx = pci_get_drvdata(dev);
	delete_dev_node(ctx);
	mutex_lock(&ctx->bar_remap.mtx);
	if (ctx->bar_remap.kv_addr) {
		pci_iounmap(ctx->pci_dev, ctx->bar_remap.kv_addr);
		pci_release_region(ctx->pci_dev, ctx->bar_remap.bar);
		ctx->bar_remap.kv_addr = NULL;
	}
	mutex_unlock(&ctx->bar_remap.mtx);
	pci_disable_device(dev);
	loginfo("PCI device disabled\n");
}

/**
 * open_rdpci
 */
static int open_rdpci(struct inode *inode, struct file *file)
{
	struct dev_node *dn;
	struct rdpci_ctx *ctx;

	dn = container_of(inode->i_cdev, struct dev_node, cdev);
	ctx = container_of(dn, struct rdpci_ctx, dev_node);
	file->private_data = ctx;
	file->f_pos = 0;
	return 0;
}

/**
 * llseek_rdpci
 */
static loff_t llseek_rdpci(struct file *file, loff_t offset, int whence)
{
	static struct rdpci_ctx *ctx;
	int err;

	if (offset < 0 || whence != SEEK_SET)
		return -EINVAL;
	ctx = file->private_data;
	mutex_lock(&ctx->bar_remap.mtx);
	if (ctx->bar_remap.kv_addr) {
		if (ctx->bar_remap.read_align == RDPCI_READ_ALIGN_32) {
			if (offset % 4) {
				err = -EINVAL;
				goto mutex_unlock;
			}
		} else if (ctx->bar_remap.read_align == RDPCI_READ_ALIGN_16) {
			if (offset % 2) {
				err = -EINVAL;
				goto mutex_unlock;
			}
		}
		if (offset >= ctx->bar_remap.size) {
			err = -EINVAL;
			goto mutex_unlock;
		}
		file->f_pos = offset;
		err = 0;
	} else {
		err = -EFAULT;
	}
mutex_unlock:
	mutex_unlock(&ctx->bar_remap.mtx);
	return err;
}

/**
 * read_rdpci
 */
static ssize_t read_rdpci(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	static struct rdpci_ctx *ctx;
	char *kbuf;
	ssize_t ret;
	int cnt, err, offs;
	void *st_offs;

	if (!count)
		return -EINVAL;
	offs = *pos;
	ctx = file->private_data;
	mutex_lock(&ctx->bar_remap.mtx);
	if (!ctx->bar_remap.kv_addr) {
		err = -EFAULT;
		goto mutex_unlock;
	}
	cnt = ctx->bar_remap.size - offs;
	if (cnt <= 0) {
		err = -EINVAL;
		goto mutex_unlock;
	}
	if (count > cnt)
		ret = cnt;
	else
		ret = count;
	switch (ctx->bar_remap.read_align) {
	case RDPCI_READ_ALIGN_32:
		if (ret % 4) {
			ret = -EINVAL;
			goto mutex_unlock;
		}
		cnt = ret / 4;
		break;
	case RDPCI_READ_ALIGN_16:
		if (ret % 2) {
			ret = -EINVAL;
			goto mutex_unlock;
		}
		cnt = ret / 2;
		break;
	case RDPCI_READ_ALIGN_8:
		cnt = ret;
		break;
	}
	kbuf = kzalloc(ret, GFP_KERNEL);
	if (unlikely(!kbuf)) {
		ret = -ENOMEM;
		goto mutex_unlock;
	}
	st_offs = (u8 *) ctx->bar_remap.kv_addr + offs;
	for (int i = 0; i < cnt; i++) {
		if (ctx->bar_remap.read_align == RDPCI_READ_ALIGN_32)
			*((u32 *) kbuf + i) = ioread32((u32 *) st_offs + i);
		else if (ctx->bar_remap.read_align == RDPCI_READ_ALIGN_16)
			*((u16 *) kbuf + i) = ioread16((u16 *) st_offs + i);
		else
			*(kbuf + i) = ioread8((u8 *) st_offs + i);
	}
	err = copy_to_user(buf, kbuf, ret);
	if (err) {
		logerr("copy_to_user() fail\n");
		ret = err;
	} else {
		*pos = offs + ret;
	}
	kfree(kbuf);
mutex_unlock:
	mutex_unlock(&ctx->bar_remap.mtx);
	return ret;
}

/**
 * write_rdpci
 */
static ssize_t write_rdpci(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	return -EINVAL;
}

/**
 * close_rdpci
 */
static int close_rdpci(struct inode *inode, struct file *file)
{
	struct rdpci_ctx *ctx;

	ctx = file->private_data;
	mutex_lock(&ctx->bar_remap.mtx);
	if (ctx->bar_remap.kv_addr) {
		pci_iounmap(ctx->pci_dev, ctx->bar_remap.kv_addr);
		pci_release_region(ctx->pci_dev, ctx->bar_remap.bar);
		ctx->bar_remap.kv_addr = NULL;
	}
	mutex_unlock(&ctx->bar_remap.mtx);
	return 0;
}

/**
 * ioctl_rdpci
 */
static long ioctl_rdpci(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct rdpci_ctx *ctx;
	unsigned int idx, cfg;
	int err;
	struct rdpci_ioctl_bar bar;
	unsigned long bar_start, bar_size, bar_flags;

	ctx = file->private_data;
	if (_IOC_TYPE(cmd) != IOCTL_RDPCI_MAGIC) {
		logerr("Bad magic\n");
		return -ENOTTY;
	}
	if (_IOC_NR(cmd) > IOCTL_RDPCI_MAXIOCTL) {
		logerr("Bad command\n");
		return -ENOTTY;
	}
	if (cmd == IOCTL_RDPCI_CFG_BYTE || cmd == IOCTL_RDPCI_CFG_WORD || cmd == IOCTL_RDPCI_CFG_DWORD) {
		err = __get_user(idx, (unsigned int __user *) arg);
		if (err) {
			logerr("__get_user() error\n");
			return err;
		}
	}
	switch (cmd) {
	case IOCTL_RDPCI_MAP_BAR:
		err = copy_from_user(&bar, (struct rdpci_ioctl_bar __user *) arg, sizeof(struct rdpci_ioctl_bar));
		if (err) {
			logerr("copy_from_user() error\n");
			return err;
		}
		break;
	case IOCTL_RDPCI_CFG_BYTE:
		{
			u8 v;

			err = pci_read_config_byte(ctx->pci_dev, idx, &v);
			if (err) {
				logerr("Read PCI config byte error (index %u)\n", idx);
				return err;
			}
			cfg = v;
		}
		break;
	case IOCTL_RDPCI_CFG_WORD:
		{
			u16 v;

			err = pci_read_config_word(ctx->pci_dev, idx, &v);
			if (err) {
				logerr("Read PCI config word error (index %u)\n", idx);
				return err;
			}
			cfg = v;
		}
		break;
	case IOCTL_RDPCI_CFG_DWORD:
		{
			u32 v;

			err = pci_read_config_dword(ctx->pci_dev, idx, &v);
			if (err) {
				logerr("Read PCI config dword error (index %u)\n", idx);
				return err;
			}
			cfg = v;
		}
		break;
	default:
		return -ENOTTY;
	}
	if (cmd == IOCTL_RDPCI_CFG_BYTE || cmd == IOCTL_RDPCI_CFG_WORD || cmd == IOCTL_RDPCI_CFG_DWORD) {
		err = __put_user(cfg, (unsigned int __user *) arg);
		if (err) {
			logerr("__put_user() error\n");
			return err;
		}
		return 0;
	}
	if (bar.bar < 0)
		return -EINVAL;
	switch (bar.read_align) {
	case RDPCI_READ_ALIGN_32:
	case RDPCI_READ_ALIGN_16:
	case RDPCI_READ_ALIGN_8:
		break;
	default:
		return -EINVAL;
	}
	bar_flags = pci_resource_flags(ctx->pci_dev, bar.bar);
	if (!bar_flags) {
		logerr("BAR%d not implemented\n", bar.bar);
		return -EINVAL;
	}
	bar_start = pci_resource_start(ctx->pci_dev, bar.bar);
	bar_size = pci_resource_len(ctx->pci_dev, bar.bar);
	mutex_lock(&ctx->bar_remap.mtx);
	if (ctx->bar_remap.kv_addr) {
		if (bar.bar == ctx->bar_remap.bar)
			goto nomap;
		pci_iounmap(ctx->pci_dev, ctx->bar_remap.kv_addr);
		pci_release_region(ctx->pci_dev, ctx->bar_remap.bar);
	}
	err = pci_request_region(ctx->pci_dev, bar.bar, "rdpci");
	if (err) {
		logerr("pci_request_region() error\n");
		ctx->bar_remap.kv_addr = NULL;
		goto error;
	}
	ctx->bar_remap.kv_addr = pci_iomap(ctx->pci_dev, bar.bar, 0);
	if (ctx->bar_remap.kv_addr == NULL) {
		pci_release_region(ctx->pci_dev, bar.bar);
		logerr("pci_iomap() error\n");
		err = -ENOMEM;
		goto error;
	}
	ctx->bar_remap.phys_addr = bar_start;
	ctx->bar_remap.size = bar_size;
	ctx->bar_remap.read_align = bar.read_align;
	ctx->bar_remap.bar = bar.bar;
nomap:
	mutex_unlock(&ctx->bar_remap.mtx);
	bar.bar_size = bar_size;
	bar.flags = bar_flags;
	err = copy_to_user((struct rdpci_ioctl_bar __user *) arg, &bar, sizeof(struct rdpci_ioctl_bar));
	if (err) {
		logerr("copy_to_user() error\n");
		return err;
	}
	return 0;
error:
	mutex_unlock(&ctx->bar_remap.mtx);
	return err;
}

/**
 * devnode_mode
 */
static char *devnode_mode(struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = DEV_FILE_MODE;
	return NULL;
}

/**
 * create_dev_node
 */
static int create_dev_node(struct rdpci_ctx *ctx)
{
	int err;

	for (int i = DEV_MINOR_START; i < DEV_MINOR_NUM; i++) {
		ctx->dev_node.devn = MKDEV(10, i);
		if (register_chrdev_region(ctx->dev_node.devn, 1, "rdpci") == 0)
			break;
		if (i == DEV_MINOR_NUM - 1) {
			logerr("Failed to register chrdev_region\n");
			return -EBUSY;
		}
	}
	cdev_init(&ctx->dev_node.cdev, &fops);
	ctx->dev_node.cdev.owner = THIS_MODULE;
	err = cdev_add(&ctx->dev_node.cdev, ctx->dev_node.devn, 1);
	if (err < 0) {
		logerr("Failed to add chrdev\n");
		unregister_chrdev_region(ctx->dev_node.devn, 1);
		return err;
	}
	ctx->dev_node.device = device_create(rdpci_class, NULL, ctx->dev_node.devn, ctx, "rdpci%d", ctx->id);
	if (IS_ERR(ctx->dev_node.device)) {
		logerr("Failed to create dev file\n");
		cdev_del(&ctx->dev_node.cdev);
		unregister_chrdev_region(ctx->dev_node.devn, 1);
		return PTR_ERR(ctx->dev_node.device);
	}
	return 0;
}

/**
 * delete_dev_node
 */
static void delete_dev_node(struct rdpci_ctx *ctx)
{
	device_destroy(rdpci_class, ctx->dev_node.devn);
	cdev_del(&ctx->dev_node.cdev);
	unregister_chrdev_region(ctx->dev_node.devn, 1);
}

module_init(rdpci_init);
module_exit(rdpci_exit);
