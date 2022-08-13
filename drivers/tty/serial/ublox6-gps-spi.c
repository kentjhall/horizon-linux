/* u-blox spi GPS driver
 *
 * Driver that enables control of a U-Blox GPS receiver, connected
 * via spi, through the TTY interface.
 *
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
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/spi/spi.h>
#include <linux/workqueue.h>
#include <linux/pm_runtime.h>
#include <linux/interrupt.h>

#define UBLOX_GPS_NUM_PORT 2 /* Number of port */

#define UBLOX_READ_SIZE 1024 /* size of SPI reads */
#define UBLOX_WRITE_ROOM 1024 /* size of tty write room */

/* By default u-blox GPS fill its buffer every 1 second (1000 msecs) */
#define READ_TIME 1000
#define FAST_READ_TIME 100


struct ublox_device {
	struct tty_driver *tty_driver;
	struct tty_port tty_port[UBLOX_GPS_NUM_PORT];
	struct delayed_work dwork;
	bool is_active[UBLOX_GPS_NUM_PORT];
	struct device *device;
	char *read_buf;
};

static void ublox_gps_read_worker(struct work_struct *private);

static void ublox_gps_read_worker(struct work_struct *private)
{
	int bytes_pushed[UBLOX_GPS_NUM_PORT];
	int ret;
	unsigned int gps_buf_size = 0;
	struct ublox_device *ublox_dev = container_of(private,
					struct ublox_device, dwork.work);
	struct spi_device *spi_dev = container_of(ublox_dev->device,
					struct spi_device, dev);

	if (ublox_dev->is_active[0] || ublox_dev->is_active[1]) {
		schedule_delayed_work(&ublox_dev->dwork,
					msecs_to_jiffies(READ_TIME));
		gps_buf_size = UBLOX_READ_SIZE;
	}

	if (gps_buf_size <= 0)
		return;

	do {
		ret = spi_read(spi_dev, ublox_dev->read_buf, gps_buf_size);
		if (ret < 0) {
			dev_dbg(ublox_dev->device,
				"error in spi_read, exitint....\n");
			return;
		}

		dev_dbg(ublox_dev->device, "%d bytes read from spi\n",
			gps_buf_size);

		bytes_pushed[0] = 0;
		if (ublox_dev->is_active[0]) {
			bytes_pushed[0] = tty_insert_flip_string(
			&ublox_dev->tty_port[0], ublox_dev->read_buf,
			gps_buf_size);
			dev_dbg(ublox_dev->device,
				"%d bytes pushed to tty buffer for index 0\n",
				bytes_pushed[0]);
		}

		bytes_pushed[1] = 0;
		if (ublox_dev->is_active[1]) {
			bytes_pushed[1] = tty_insert_flip_string(
			&ublox_dev->tty_port[1], ublox_dev->read_buf,
			gps_buf_size);
			dev_dbg(ublox_dev->device,
				"%d bytes pushed to tty buffer for index 1\n",
				bytes_pushed[1]);
		}

		if (ublox_dev->is_active[0] && ublox_dev->is_active[1] &&
			(bytes_pushed[0] != bytes_pushed[1])) {
			dev_err(ublox_dev->device,
				"bytes pushed to tty are not same\n");
		}

		gps_buf_size -= (bytes_pushed[0] ? bytes_pushed[0] :
							bytes_pushed[1]);

		/*
		 * There is a small chance that we need to split the
		 * data over several buffers. If this is the case we
		 * must loop.
		 */
	} while (gps_buf_size > 0);

	if (ublox_dev->is_active[0])
		tty_flip_buffer_push(&ublox_dev->tty_port[0]);
	if (ublox_dev->is_active[1])
		tty_flip_buffer_push(&ublox_dev->tty_port[1]);
}

static struct ublox_device *ublox_dev_from_tty(struct tty_struct *tty)
{
	return container_of(tty->port, struct ublox_device,
			tty_port[tty->index]);
}

static int ublox_gps_serial_open(struct tty_struct *tty, struct file *filp)
{
	struct ublox_device *ublox_dev = ublox_dev_from_tty(tty);

	return tty_port_open(&ublox_dev->tty_port[tty->index], tty, filp);
}

static void ublox_gps_serial_close(struct tty_struct *tty, struct file *filp)
{
	struct ublox_device *ublox_dev = ublox_dev_from_tty(tty);

	tty_port_close(&ublox_dev->tty_port[tty->index], tty, filp);
}

static int ublox_gps_serial_write(struct tty_struct *tty,
				const unsigned char *buf, int count)
{
	struct ublox_device *ublox_dev = ublox_dev_from_tty(tty);
	int ret;

	/* Block writes from ttyUBLX1 return false count to proceed */
	if (tty->index == 1)
		return count;

	ret = spi_write(container_of(ublox_dev->device, struct spi_device, dev),
			buf, count);
	if (ret < 0) {
		dev_dbg(ublox_dev->device, "error in spi_writing, exiting....\n");
		return ret;
	}
	dev_dbg(ublox_dev->device, "%d bytes written to spi\n", count);

	return count;
}

static int ublox_gps_write_room(struct tty_struct *tty)
{
	/* arbitrary value */
	return UBLOX_WRITE_ROOM;
}

static const struct tty_operations ublox_gps_serial_ops = {
	.open = ublox_gps_serial_open,
	.close = ublox_gps_serial_close,
	.write = ublox_gps_serial_write,
	.write_room = ublox_gps_write_room,
};

static struct ublox_device *ublox_dev_from_tty_port(struct tty_port *port)
{
	return container_of(port, struct ublox_device,
			tty_port[port->tty->index]);
}

static void ublox_gps_shutdown(struct tty_port *port)
{
	struct ublox_device *ublox_dev = ublox_dev_from_tty_port(port);

	dev_dbg(ublox_dev->device, "Shutting down u-blox tty driver\n");

	/* check if the other port is inactive */
	/* if UBLOX_GPS_NUM_PORT is > 2 then this should be modified */
	if (!ublox_dev->is_active[UBLOX_GPS_NUM_PORT - 1 - port->tty->index]) {
		cancel_delayed_work(&ublox_dev->dwork);
		flush_work(&ublox_dev->dwork.work);
	}
	ublox_dev->is_active[port->tty->index] = false;
}

static int ublox_gps_activate(struct tty_port *port, struct tty_struct *tty)
{
	struct ublox_device *ublox_dev = ublox_dev_from_tty_port(port);

	dev_dbg(ublox_dev->device, "Activating u-blox tty driver\n");
	ublox_dev->is_active[port->tty->index] = true;
	if (ublox_dev->is_active[0] || ublox_dev->is_active[1])
		schedule_delayed_work(&ublox_dev->dwork, 0);

	return 0;
}
static const struct tty_port_operations ublox_gps_port_ops = {
	.shutdown = ublox_gps_shutdown,
	.activate = ublox_gps_activate,
};

static int ublox_probe(struct device *dev,
					 int irq, unsigned long flags)
{
	int result = 0;
	struct tty_driver *ublox_gps_tty_driver;
	struct ublox_device *ublox_dev;

	ublox_gps_tty_driver = tty_alloc_driver(UBLOX_GPS_NUM_PORT, 0);
	if (IS_ERR(ublox_gps_tty_driver))
		return PTR_ERR(ublox_gps_tty_driver);

	ublox_dev = devm_kzalloc(dev, sizeof(struct ublox_device),
				GFP_KERNEL);
	if (!ublox_dev) {
		result = -ENOMEM;
		goto err;
	}

	ublox_dev->read_buf = devm_kzalloc(dev, UBLOX_READ_SIZE, GFP_KERNEL);
	if (!ublox_dev->read_buf)
		return -ENOMEM;

	ublox_dev->tty_driver = ublox_gps_tty_driver;

	tty_port_init(&ublox_dev->tty_port[0]);
	tty_port_init(&ublox_dev->tty_port[1]);

	ublox_gps_tty_driver->owner = THIS_MODULE;
	ublox_gps_tty_driver->driver_name = "ublox_gps";
	ublox_gps_tty_driver->name = "ttyUBLX";
	ublox_gps_tty_driver->major = 0; /* dynamically assign */
	ublox_gps_tty_driver->minor_start = 0;
	ublox_gps_tty_driver->type = TTY_DRIVER_TYPE_SERIAL;
	ublox_gps_tty_driver->subtype = SERIAL_TYPE_NORMAL;
	ublox_gps_tty_driver->flags = TTY_DRIVER_REAL_RAW;
	ublox_gps_tty_driver->init_termios = tty_std_termios;
	ublox_gps_tty_driver->init_termios.c_iflag = IGNCR | IXON;
	ublox_gps_tty_driver->init_termios.c_oflag = OPOST;
	ublox_gps_tty_driver->init_termios.c_cflag = B9600 | CS8 | CREAD |
		HUPCL | CLOCAL;
	ublox_gps_tty_driver->init_termios.c_lflag &=
			 ~(ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE);
	ublox_gps_tty_driver->init_termios.c_ispeed = 9600;
	ublox_gps_tty_driver->init_termios.c_ospeed = 9600;
	ublox_gps_tty_driver->num = UBLOX_GPS_NUM_PORT;
	tty_set_operations(ublox_gps_tty_driver, &ublox_gps_serial_ops);
	ublox_dev->tty_port[0].ops = &ublox_gps_port_ops;
	ublox_dev->tty_port[1].ops = &ublox_gps_port_ops;

	tty_port_link_device(&ublox_dev->tty_port[0], ublox_gps_tty_driver, 0);
	tty_port_link_device(&ublox_dev->tty_port[1], ublox_gps_tty_driver, 1);

	result = tty_register_driver(ublox_gps_tty_driver);
	if (result) {
		dev_err(dev, ": %s - tty_register_driver failed\n",
			__func__);
		goto err;
	}


	dev_set_drvdata(dev, ublox_dev);
	INIT_DELAYED_WORK(&ublox_dev->dwork, ublox_gps_read_worker);
	ublox_dev->is_active[0] = false;
	ublox_dev->is_active[1] = false;
	ublox_dev->device = dev;

	return result;

err:
	dev_err(dev, ": %s - returning with error %d\n",
		__func__, result);

	put_tty_driver(ublox_gps_tty_driver);

	return result;
}

static int ublox_gps_probe(struct spi_device *spi)
{
	unsigned long flags = 0;
	int ret;

	/* Setup SPI bus */
	spi->bits_per_word      = 8;
	spi->mode               = SPI_MODE_0;
	spi->max_speed_hz       = 5500000;
	ret = spi_setup(spi);
	if (ret)
		return ret;

	return ublox_probe(&spi->dev, spi->irq, flags);

}

static int ublox_gps_remove(struct spi_device *spi)
{
	struct ublox_device *ublox_dev = (struct ublox_device *)
						dev_get_drvdata(&spi->dev);

	tty_unregister_driver(ublox_dev->tty_driver);
	put_tty_driver(ublox_dev->tty_driver);

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int ublox_suspend(struct device *dev)
{

	struct ublox_device *ublox_dev = dev_get_drvdata(dev);

	cancel_delayed_work(&ublox_dev->dwork);
	flush_work(&ublox_dev->dwork.work);
	dev_dbg(dev, "Suspending u-blox tty driver\n");

	return 0;
}

static int ublox_resume(struct device *dev)
{
	struct ublox_device *ublox_dev = (struct ublox_device *)
						dev_get_drvdata(dev);

	dev_dbg(dev, "Resuming u-blox tty driver\n");
	schedule_delayed_work(&ublox_dev->dwork,
				msecs_to_jiffies(READ_TIME));
	return 0;
}
#endif

static SIMPLE_DEV_PM_OPS(ublox_pm_ops, ublox_suspend, ublox_resume);

static const struct spi_device_id ublox_gps_id[] = {
	{ "ublox_gps", 0 },
	{ }
};
MODULE_DEVICE_TABLE(spi, ublox_gps_id);

static struct spi_driver ublox_gps_spi_driver = {
	.driver = {
		.name  = "ublox_gps",
		.owner = THIS_MODULE,
		.pm = &ublox_pm_ops,
	},
	.id_table  = ublox_gps_id,
	.probe     = ublox_gps_probe,
	.remove    = ublox_gps_remove,
};

module_spi_driver(ublox_gps_spi_driver);

MODULE_DESCRIPTION("u-blox SPI GPS driver");
MODULE_VERSION("v1.0");
MODULE_LICENSE("GPL v2");
