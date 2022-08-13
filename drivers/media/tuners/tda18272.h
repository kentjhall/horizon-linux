/*
 * TDA18272 Silicon tuner driver
 * Copyright (C) Manu Abraham <abraham.manu@gmail.com>

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef __TDA18272_H
#define __TDA18272_H

enum tda18272_mode {
	TDA18272_SINGLE	= 0,
	TDA18272_MASTER,
	TDA18272_SLAVE,
};

struct tda18272_config {
	u8			addr;
	enum tda18272_mode	mode;
};

#if IS_ENABLED(CONFIG_MEDIA_TUNER_TDA18272)

extern struct dvb_frontend *tda18272_attach(
					struct dvb_frontend *fe,
					struct i2c_adapter *i2c,
					const struct tda18272_config *config);

#else
static inline struct dvb_frontend *tda18272_attach(
					struct dvb_frontend *fe,
					struct i2c_adapter *i2c,
					const struct tda18272_config *config)
{
	printk(KERN_WARNING "%s: driver disabled by Kconfig\n", __func__);
	return NULL;
}

#endif /* CONFIG_MEDIA_TUNER_TDA18272 */

#endif /* __TDA18272_H */
