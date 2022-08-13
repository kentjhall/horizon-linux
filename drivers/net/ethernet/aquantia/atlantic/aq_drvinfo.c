/*
 * aQuantia Corporation Network Driver
 * Copyright (C) 2014-2017 aQuantia Corporation. All rights reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

/* File aq_drvinfo.c: Definition of common code for firmware info in sys.*/

#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/hwmon-sysfs.h>
#include <linux/hwmon.h>
#include <linux/uaccess.h>

#include "aq_drvinfo.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
static ssize_t temperature_show(struct device *ndev,
				struct device_attribute *attr, char *buf)
{
	int err;

	struct aq_nic_s *aq_nic = pci_get_drvdata(to_pci_dev(ndev));

	int temp = 0;

	if (!aq_nic->aq_fw_ops->get_temp)
		return -ENXIO;

	err = aq_nic->aq_fw_ops->get_temp(aq_nic->aq_hw, &temp);

	if (err == 0)
		return sprintf(buf, "%d\n", temp * 10);
	return -ENXIO;
}

static ssize_t cable_show(struct device *ndev,
			  struct device_attribute *attr, char *buf)
{
	int err;

	struct aq_nic_s *aq_nic = pci_get_drvdata(to_pci_dev(ndev));

	int cable_len = 0;

	if (!aq_nic->aq_fw_ops->get_cable_len)
		return -ENXIO;

	err = aq_nic->aq_fw_ops->get_cable_len(aq_nic->aq_hw, &cable_len);

	if (err == 0)
		return sprintf(buf, "%d\n", cable_len);
	return -ENXIO;
}

static ssize_t cable_label_show(struct device *ndev,
				struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "Estimated cable length (meters)\n");
}

static ssize_t temperature_label_show(struct device *ndev,
				      struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "PHY temperature\n");
}

static DEVICE_ATTR(temp1_label, S_IWUSR | S_IRUGO, temperature_label_show,
		   NULL);
static SENSOR_DEVICE_ATTR(temp1_input, S_IWUSR | S_IRUGO, temperature_show,
			  NULL, 0);
static DEVICE_ATTR(cable_label, S_IWUSR | S_IRUGO, cable_label_show, NULL);
static SENSOR_DEVICE_ATTR(cable_input, S_IWUSR | S_IRUGO, cable_show, NULL, 1);

static struct attribute *aq_dev_attrs[] = {
	&dev_attr_temp1_label.attr,
	&sensor_dev_attr_temp1_input.dev_attr.attr,
	&dev_attr_cable_label.attr,
	&sensor_dev_attr_cable_input.dev_attr.attr,
	NULL
};

ATTRIBUTE_GROUPS(aq_dev);
#endif

int aq_drvinfo_init(struct net_device *ndev)
{
	int err = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	struct device *dev;

	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct pci_dev *pdev = aq_nic->pdev;

	dev = 
	devm_hwmon_device_register_with_groups(&pdev->dev,
					       ndev->name, 
					       dev_get_drvdata(&pdev->dev),
					       aq_dev_groups);

	if (IS_ERR(dev))
		err = PTR_ERR(dev);
#endif
	return err;
}

void aq_drvinfo_exit(struct net_device *ndev)
{

}

