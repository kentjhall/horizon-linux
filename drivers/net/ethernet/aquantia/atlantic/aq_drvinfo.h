/*
 * aQuantia Corporation Network Driver
 * Copyright (C) 2014-2017 aQuantia Corporation. All rights reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

/* File aq_drvinfo.h: Declaration of common code for firmware info in sys.*/

#ifndef AQ_DRVINFO_H
#define AQ_DRVINFO_H

#include "aq_nic.h"
#include "aq_hw.h"
#include "hw_atl/hw_atl_utils.h"


int aq_drvinfo_init(struct net_device *ndev);
void aq_drvinfo_exit(struct net_device *ndev);


#endif /* AQ_DRVINFO_H */

