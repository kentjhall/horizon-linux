/*
 * Copyright (c) 2020, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/sysfs.h>
#include <linux/thermal.h>
#include <linux/err.h>
#include <linux/mlx5/driver.h>

#define MLX5_THERMAL_POLL_INT	1000
#define MLX5_THERMAL_NUM_TRIPS	0
#define DEFAULT_CRIT_TEMP	105000

/* Make sure all trips are writable */
#define MLX5_THERMAL_TRIP_MASK	(BIT(MLX5_THERMAL_NUM_TRIPS) - 1)

struct mlx5_reg_host_mtmp {
	u8 rsvd1[2];
	u8 sensor_id[2];

	u8 rsvd2[2];
	u8 temp[2];

	u8 mt;
	u8 rsvd3;
	u8 max_temp[2];

	u8 tee;
	u8 rsvd4;
	u8 temperature_threshold_hi[2];

	u8 rsvd5[2];
	u8 temperature_threshold_lo[2];

	u8 rsvd6[4];

	u8 sensor_name_hi[4];

	u8 sensor_name_lo[4];
};

static unsigned int mlx5_crit_temp = DEFAULT_CRIT_TEMP;
static bool mlx5_temp_sw_override;
static unsigned int mlx5_debug_temp;

static int mlx5_thermal_get_mtmp_temp(struct mlx5_core_dev *core, int *p_temp)
{
	struct mlx5_reg_host_mtmp mtmp_in;
	struct mlx5_reg_host_mtmp mtmp_out;
	int err;

	if (!mlx5_core_is_pf(core))
		return 0;

	memset(&mtmp_in, 0, sizeof(mtmp_in));
	memset(&mtmp_out, 0, sizeof(mtmp_out));

	mtmp_in.sensor_id[0] = 0;
	mtmp_in.sensor_id[1] = 0;
	mtmp_in.mt = 0x80;
	err = mlx5_core_access_reg(core, &mtmp_in,  sizeof(mtmp_in),
				   &mtmp_out, sizeof(mtmp_out),
				   MLX5_REG_MTMP, 0, 0);
	if (!err)
		/*
		 * The unit of temp returned is in 0.125 C. The thermal
		 * framework expects the value in 0.001 C.
		 */
		*p_temp = (mtmp_out.temp[0] << 8 | mtmp_out.temp[1]) * 125;

	return err;
}

static int mlx5_thermal_get_mode(struct thermal_zone_device *tzdev,
				 enum thermal_device_mode *mode)
{
	struct mlx5_thermal *thermal = tzdev->devdata;

	*mode = thermal->mode;

	return 0;
}

static int mlx5_thermal_set_mode(struct thermal_zone_device *tzdev,
				 enum thermal_device_mode mode)
{
	struct mlx5_thermal *thermal = tzdev->devdata;

	mutex_lock(&tzdev->lock);

	if (mode == THERMAL_DEVICE_ENABLED)
		tzdev->polling_delay = MLX5_THERMAL_POLL_INT;
	else
		tzdev->polling_delay = 0;

	mutex_unlock(&tzdev->lock);

	thermal->mode = mode;
	thermal_zone_device_update(tzdev, THERMAL_EVENT_UNSPECIFIED);

	return 0;
}

static int mlx5_thermal_get_temp(struct thermal_zone_device *tzdev,
				 int *p_temp)
{
	struct mlx5_thermal *thermal = tzdev->devdata;
	struct mlx5_core_dev *core = thermal->core;
	int ret = 0;

	if (mlx5_temp_sw_override) {
		*p_temp = mlx5_debug_temp;
	} else {
		ret = mlx5_thermal_get_mtmp_temp(core, p_temp);
		mlx5_debug_temp = *p_temp;
	}

	/* TODO: Add critical temp trip handling */
	if (*p_temp >= mlx5_crit_temp) {
		pr_err("%s: MLX5 temp reached critical limit.\n", __func__);
	}

	return ret;
}

static int mlx5_thermal_get_crit_temp(struct thermal_zone_device *tzdev,
				      int *temp)
{
	*temp = mlx5_crit_temp;

	return 0;
}

static struct thermal_zone_device_ops mlx5_thermal_ops = {
	.get_mode = mlx5_thermal_get_mode,
	.set_mode = mlx5_thermal_set_mode,
	.get_temp = mlx5_thermal_get_temp,
	.get_crit_temp = mlx5_thermal_get_crit_temp,
};

static ssize_t mlx5_crit_temp_store(struct device *dev,
				    struct device_attribute *da,
				    const char *buf, size_t count)
{
	int temp;

	if (kstrtoint(buf, 0, &temp))
		return -EINVAL;

	mlx5_crit_temp = temp;
	return count;
}

static ssize_t mlx5_crit_temp_show(struct device *dev,
				   struct device_attribute *da,
				   char *buf)
{
	return sprintf(buf, "%d\n", mlx5_crit_temp);
}

static ssize_t mlx5_temp_sw_override_store(struct device *dev,
				    struct device_attribute *da,
				    const char *buf, size_t count)
{
	if (kstrtobool(buf, &mlx5_temp_sw_override))
		return -EINVAL;

	return count;
}

static ssize_t mlx5_temp_sw_override_show(struct device *dev,
				   struct device_attribute *da,
				   char *buf)
{
	return sprintf(buf, "%d\n", mlx5_temp_sw_override);
}

static ssize_t mlx5_temp_store(struct device *dev,
				    struct device_attribute *da,
				    const char *buf, size_t count)
{
	int temp;

	if (kstrtoint(buf, 0, &temp))
		return -EINVAL;

	mlx5_debug_temp = temp;
	return count;
}

static ssize_t mlx5_temp_show(struct device *dev,
				   struct device_attribute *da,
				   char *buf)
{
	return sprintf(buf, "%d\n", mlx5_debug_temp);
}
DEVICE_ATTR_RW(mlx5_crit_temp);
DEVICE_ATTR_RW(mlx5_temp_sw_override);
DEVICE_ATTR_RW(mlx5_temp);

static int mlx5_thermal_match(struct thermal_zone_device *thz, void *data)
{
	/* match for mlx5 */
	return (strncmp((char *)data, thz->type, 4) == 0);
}

int mlx5_thermal_init(struct mlx5_core_dev *core)
{
	struct mlx5_thermal *thermal;
	struct device *dev = &core->pdev->dev;
	const char *data = "mlx5";

	core->thermal = NULL;

	if (thermal_zone_device_find((void *)data, mlx5_thermal_match))
		return 0;

	thermal = devm_kzalloc(dev, sizeof(*thermal), GFP_KERNEL);
	if (!thermal)
		return -ENOMEM;

	thermal->core = core;

	thermal->tzdev = thermal_zone_device_register("mlx5", 0,
			MLX5_THERMAL_TRIP_MASK,
			thermal,
			&mlx5_thermal_ops,
			NULL, 0, MLX5_THERMAL_POLL_INT);
	if (IS_ERR(thermal->tzdev))
		return PTR_ERR(thermal->tzdev);

	device_create_file(dev, &dev_attr_mlx5_crit_temp);
	device_create_file(dev, &dev_attr_mlx5_temp_sw_override);
	device_create_file(dev, &dev_attr_mlx5_temp);

	mlx5_temp_sw_override = false;
	core->thermal = thermal;
	return 0;
}

void mlx5_thermal_deinit(struct mlx5_core_dev *core)
{
	struct device *dev = &core->pdev->dev;

	if (!core->thermal)
		return;

	thermal_zone_device_unregister(core->thermal->tzdev);

	device_remove_file(dev, &dev_attr_mlx5_crit_temp);
	device_remove_file(dev, &dev_attr_mlx5_temp_sw_override);
	device_remove_file(dev, &dev_attr_mlx5_temp);
}
