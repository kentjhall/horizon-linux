/*
 * sysfs for cifs
 *
 * Copyright (c) 2018, NVIDIA Corporation. All Rights Reserved.
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <linux/kobject.h>
#include <linux/slab.h>
#include "cifsglob.h"
#include "sysfs.h"

static struct kset *cifs_sysfs_kset;
static struct kobject *cifs_sysfs_kobj;

static struct kobj_type cifs_uevent_ktype = {

};

void cifs_sysfs_notify_change(const char* source, cifs_event_type event_type) {
	char env_source[30];
	char env_state[30];
	char *envp[3] = { env_source, env_state, NULL };
	sprintf(env_source, "SOURCE=%s", source);
	sprintf(env_state, "STATE=%d", event_type);
	kobject_uevent_env(cifs_sysfs_kobj, KOBJ_CHANGE, envp);
}

int cifs_sysfs_init(void) {
	int ret;
	cifs_sysfs_kset = kset_create_and_add("cifs", NULL, fs_kobj);
	if (!cifs_sysfs_kset) {
		return -ENOMEM;
	}
	cifs_sysfs_kobj = kzalloc(sizeof(*cifs_sysfs_kobj),
		GFP_KERNEL);
	if (!cifs_sysfs_kobj) {
		return -ENOMEM;
	}
	cifs_sysfs_kobj->kset = cifs_sysfs_kset;
	ret = kobject_init_and_add(cifs_sysfs_kobj, &cifs_uevent_ktype, NULL, "uevent");
	if (!ret) {
		kobject_uevent(cifs_sysfs_kobj, KOBJ_ADD);
	} else {
		kfree(cifs_sysfs_kobj);
	}
	return ret;
}

void cifs_sysfs_exit(void) {
	kobject_uevent(cifs_sysfs_kobj, KOBJ_REMOVE);
	kobject_put(cifs_sysfs_kobj);
	kset_unregister(cifs_sysfs_kset);
}
