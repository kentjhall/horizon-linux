/*
 * Copyright (c) 2017, NVIDIA CORPORATION.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */
#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include "stepper.h"

const struct attribute_group **stepper_get_dev_attribute_groups(void);

static DEFINE_IDA(stepper_ida);
struct class *stepper_class;
static dev_t stepper_devt;

static int stepper_fopen(struct inode *node, struct file *file)
{
	struct cdev *cdev = file->f_path.dentry->d_inode->i_cdev;
	struct stepper_device *stepper = container_of(cdev,
					struct stepper_device, chardev);

	stepper->offset = 0;
	return 0;
}

static loff_t stepper_seek(struct file *file, loff_t offset, int len)
{
	struct cdev *cdev = file->f_path.dentry->d_inode->i_cdev;
	struct stepper_device *stepper = container_of(cdev,
					struct stepper_device, chardev);

	stepper->offset = offset;
	return offset;
}

static long stepper_fioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	int status;
	struct cdev *cdev = file->f_path.dentry->d_inode->i_cdev;
	struct stepper_device *stepper = container_of(cdev,
					struct stepper_device, chardev);

	status = mutex_lock_interruptible(&stepper->ops_lock);
	if (status)
		return status;
	status = stepper->ops->ioctl(&stepper->dev, cmd, arg);
	mutex_unlock(&stepper->ops_lock);

	return status;
}

static ssize_t stepper_fwrite(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	int ret;
	struct cdev *cdev = file->f_path.dentry->d_inode->i_cdev;
	struct stepper_device *stepper = container_of(cdev,
					struct stepper_device, chardev);

	ret = mutex_lock_interruptible(&stepper->ops_lock);
	if (ret)
		return ret;
	ret = stepper->ops->write(&stepper->dev, buf, count);
	mutex_unlock(&stepper->ops_lock);

	return ret;
}

static ssize_t stepper_fread(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
	int ret;
	struct cdev *cdev = file->f_path.dentry->d_inode->i_cdev;
	struct stepper_device *stepper = container_of(cdev,
					struct stepper_device, chardev);

	ret = mutex_lock_interruptible(&stepper->ops_lock);
	if (ret)
		return ret;
	ret = stepper->ops->read(&stepper->dev, buf, count);
	mutex_unlock(&stepper->ops_lock);

	return ret;
}

static const struct file_operations stepper_fops = {
	.owner = THIS_MODULE,
	.open = stepper_fopen,
	.llseek = stepper_seek,
	.unlocked_ioctl = stepper_fioctl,
	.write = stepper_fwrite,
	.read = stepper_fread,
};

static void stepper_device_release(struct device *dev)
{
	struct stepper_device *stepper = container_of(dev,
					struct stepper_device, dev);

	ida_simple_remove(&stepper_ida, stepper->id);
}

struct stepper_device *stepper_device_register(const char *name,
					       struct device *dev,
					       const struct stepper_ops *ops,
					       struct module *owner)
{
	struct stepper_device *stepper;
	int err, of_id = -ENODEV, id = -1;

	if (dev->of_node)
		of_id = of_alias_get_id(dev->of_node, "stepper");

	if (of_id >= 0) {
		id = ida_simple_get(&stepper_ida, of_id, of_id + 1,
				    GFP_KERNEL);
		if (id < 0)
			dev_warn(dev, "aliases ID %d not available\n",
				 of_id);
	}

	if (id < 0) {
		id = ida_simple_get(&stepper_ida, 0, 0, GFP_KERNEL);
		if (id < 0) {
			dev_warn(dev, "alias ID assignment error: %d\n", id);
			return ERR_PTR(id);
		}
	}

	stepper = devm_kzalloc(dev, sizeof(struct stepper_device), GFP_KERNEL);
	if (!stepper) {
		err = -ENOMEM;
		goto err;
	}
	stepper->owner = owner;
	stepper->id = id;
	strlcpy(stepper->name, name, STEPPER_NAME_SIZE);

	if (id > CONFIG_STEPPER_DEV_MAX) {
		dev_warn(dev, "%s:too many stepper devices\n", stepper->name);
		devm_kfree(dev, stepper);
		err = -ENOMEM;
		goto err;
	}
	stepper->ops = ops;
	stepper->dev.parent = dev;
	stepper->dev.class = stepper_class;
	stepper->dev.groups = stepper_get_dev_attribute_groups();
	stepper->dev.release = stepper_device_release;
	stepper->dev.devt = MKDEV(MAJOR(stepper_devt), stepper->id);
	dev_set_name(&stepper->dev, "stepper%d", id);
	mutex_init(&stepper->ops_lock);

	stepper->chardev.ops = &stepper_fops;
	err = device_register(&stepper->dev);
	if (err) {
		put_device(&stepper->dev);
		goto err;
	}
	cdev_init(&stepper->chardev, &stepper_fops);
	stepper->chardev.owner = stepper->owner;
	stepper->chardev.kobj.parent = &stepper->dev.kobj;

	err = cdev_add(&stepper->chardev, stepper->dev.devt, 1);
	if (err) {
		device_unregister(&stepper->dev);
		devm_kfree(dev, stepper);
		goto err;
	}

	return stepper;

err:
	ida_simple_remove(&stepper_ida, id);
	dev_err(dev, "steper core: Error registering device: %s, err = %d",
		name, err);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(stepper_device_register);

static int __stepper_match(struct device *dev, const void *data)
{
	const char *name = data;

	if (strcmp(dev_name(dev), name) == 0)
		return 1;
	return 0;
}

struct stepper_device *stepper_class_open(const char *name)
{
	struct device *dev;
	struct stepper_device *stepper = NULL;

	dev = class_find_device(stepper_class, NULL, name, __stepper_match);
	if (dev)
		stepper = container_of(dev, struct stepper_device, dev);

	if (stepper) {
		if (!try_module_get(stepper->owner)) {
			put_device(dev);
			stepper = NULL;
		}
	}

	return stepper;
}
EXPORT_SYMBOL_GPL(stepper_class_open);

void stepper_class_close(struct stepper_device *stepper)
{
	module_put(stepper->owner);
	put_device(&stepper->dev);
}
EXPORT_SYMBOL_GPL(stepper_class_close);

int stepper_motor_start(struct stepper_device *stepper)
{
	int err = 0;

	if (!stepper->ops || !stepper->ops->start)
		return -ENOTSUPP;
	err = mutex_lock_interruptible(&stepper->ops_lock);
	if (err)
		return err;
	err = stepper->ops->start(&stepper->dev);
	mutex_unlock(&stepper->ops_lock);
	return err;
}
EXPORT_SYMBOL_GPL(stepper_motor_start);

int stepper_motor_restart(struct stepper_device *stepper)
{
	int err = 0;

	if (!stepper->ops || !stepper->ops->restart)
		return -ENOTSUPP;
	err = mutex_lock_interruptible(&stepper->ops_lock);
	if (err)
		return err;
	err = stepper->ops->restart(&stepper->dev);
	mutex_unlock(&stepper->ops_lock);
	return err;
}
EXPORT_SYMBOL_GPL(stepper_motor_restart);

int stepper_motor_stop(struct stepper_device *stepper, bool is_abrupt)
{
	int err = 0;

	if (!stepper->ops || !stepper->ops->stop)
		return -ENOTSUPP;
	err = mutex_lock_interruptible(&stepper->ops_lock);
	if (err)
		return err;
	err = stepper->ops->stop(&stepper->dev);
	mutex_unlock(&stepper->ops_lock);
	return err;
}
EXPORT_SYMBOL_GPL(stepper_motor_stop);

int stepper_motor_direction(struct stepper_device *stepper,
			    enum stepper_direction dir)
{
	int err = 0;

	if (!stepper->ops || !stepper->ops->set_direction)
		return -ENOTSUPP;
	err = mutex_lock_interruptible(&stepper->ops_lock);
	if (err)
		return err;
	err = stepper->ops->set_direction(&stepper->dev, dir);
	mutex_unlock(&stepper->ops_lock);
	return err;
}
EXPORT_SYMBOL_GPL(stepper_motor_direction);

int stepper_motor_setrate(struct stepper_device *stepper, int val,
			  enum stepper_rate_ramp immediate)
{
	int err = 0;

	if (!stepper->ops || !stepper->ops->set_rate)
		return -ENOTSUPP;
	err = mutex_lock_interruptible(&stepper->ops_lock);
	if (err)
		return err;
	err = stepper->ops->set_rate(&stepper->dev, val, immediate);
	mutex_unlock(&stepper->ops_lock);
	return err;
}
EXPORT_SYMBOL_GPL(stepper_motor_setrate);

int stepper_motor_set_ramp(struct stepper_device *stepper, int val,
			   enum stepper_ramp_mode dir)
{
	int err = 0;

	if (!stepper->ops || !stepper->ops->set_ramp_rate)
		return -ENOTSUPP;
	err = mutex_lock_interruptible(&stepper->ops_lock);
	if (err)
		return err;
	err = stepper->ops->set_ramp_rate(&stepper->dev, val, dir);
	mutex_unlock(&stepper->ops_lock);
	return err;
}
EXPORT_SYMBOL_GPL(stepper_motor_set_ramp);

void stepper_device_remove(struct stepper_device *stepper)
{
	int err;

	err = mutex_lock_interruptible(&stepper->ops_lock);
	if (err)
		return;

	cdev_del(&stepper->chardev);
	device_unregister(&stepper->dev);
	stepper->ops = NULL;
	mutex_unlock(&stepper->ops_lock);
}
EXPORT_SYMBOL_GPL(stepper_device_remove);

static int __init stepper_init(void)
{
	int status;

	stepper_class = class_create(THIS_MODULE, "stepper_motor");

	if (IS_ERR(stepper_class))
		goto err;

	status = alloc_chrdev_region(&stepper_devt, 0, CONFIG_STEPPER_DEV_MAX,
				     "stepper");
	return status;
err:
	class_unregister(stepper_class);
	return PTR_ERR(stepper_class);
}

static void __exit stepper_exit(void)
{
	/*Remove memory region allocated*/
	class_destroy(stepper_class);
	if (stepper_devt)
		unregister_chrdev_region(stepper_devt, CONFIG_STEPPER_DEV_MAX);
}
module_init(stepper_init);
module_exit(stepper_exit);

MODULE_AUTHOR("Vishruth Jain <vishruthj@nvidia.com>");
MODULE_DESCRIPTION("Stepper motor class driver");
MODULE_LICENSE("GPL");
