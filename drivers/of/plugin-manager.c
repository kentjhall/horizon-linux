/*
 * Copyright (c) 2015-2016, NVIDIA CORPORATION.  All rights reserved.
 *
 * Author: Laxman Dewangan<ldewangan@nvidia.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 */

#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include "of_private.h"

#define MAXIMUM_FNAME_LENGTH	300

enum plugin_manager_match_type {
	PLUGIN_MANAGER_MATCH_EXACT,
	PLUGIN_MANAGER_MATCH_PARTIAL,
	PLUGIN_MANAGER_MATCH_GE,
	PLUGIN_MANAGER_MATCH_LT,
};

struct connection_info {
	int level;
	const char *uid_str;
	struct device_node *node;
	struct device_node *org_pm;
	struct device_node *copy_node;
	struct device_node *parent_conn_node;
	struct device_node *child_conn_node;
};

static int link_connection_to_plugin_modules(struct device_node *plmroot,
					     struct device_node *plcroot,
					     struct device_node *ds,
					     struct device_node *connector);

static struct property *__of_copy_property(const struct property *prop,
					   void *new_value, int val_len,
					   gfp_t flags)
{
	struct property *propn;
	int nlen;
	void *nval;

	propn = kzalloc(sizeof(*propn), flags);
	if (!propn)
		return NULL;

	propn->name = kstrdup(prop->name, flags);
	if (!propn->name)
		goto err_fail_name;

	nlen = (new_value) ? val_len : prop->length;
	nval = (new_value) ? new_value : prop->value;
	if (nlen > 0) {
		propn->value = kzalloc(nlen, flags);
		if (!propn->value)
			goto err_fail_value;
		memcpy(propn->value, nval, nlen);
		propn->length = nlen;
	}
	return propn;

err_fail_value:
	kfree(propn->name);
err_fail_name:
	kfree(propn);
	return NULL;
}

static struct property *__of_create_property_by_name(const char *name,
						     void *new_value,
						     int val_len)
{
	struct property *propn;

	if (!name)
		return NULL;

	propn = kzalloc(sizeof(*propn), GFP_KERNEL);
	if (!propn)
		return NULL;

	propn->name = kstrdup(name, GFP_KERNEL);
	if (!propn->name)
		goto err_fail_name;

	if ((val_len > 0) || !new_value) {
		propn->value = kzalloc(val_len, GFP_KERNEL);
		if (!propn->value)
			goto err_fail_value;
		memcpy(propn->value, new_value, val_len);
		propn->length = val_len;
	}

	return propn;

err_fail_value:
	kfree(propn->name);
err_fail_name:
	kfree(propn);

	return NULL;
}

static void free_property(struct property *pp)
{
	if (!pp)
		return;

	kfree(pp->name);
	kfree(pp->value);
	kfree(pp);
}

static struct device_node *of_get_child_by_last_name(struct device_node *node,
						     const char *name)
{
	struct device_node *child;

	for_each_child_of_node(node, child) {
		const char *lname = strrchr(child->full_name, '/');

		if (!strcmp(lname + 1, name))
			return child;
	}

	return NULL;
}

static struct device_node *of_get_nested_child_by_name(struct device_node *node,
						       const char *name)
{
	struct device_node *cnode = node;
	const char *cur_name = name;
	char child_name[100];
	int nlen;
	int len = strlen(name);

	if (!len)
		return NULL;

	while (len) {
		nlen = strcspn(cur_name, "/");
		if (!nlen)
			return NULL;

		memcpy(child_name, cur_name, nlen);
		child_name[nlen] = '\0';

		cnode = of_get_child_by_last_name(cnode, child_name);
		if (!cnode)
			return NULL;
		/* '/' adjustment. */
		nlen++;
		cur_name += nlen;
		if (len <= nlen)
			break;

		len -= nlen;
	}

	return cnode;
}

static void of_add_node_to_parent(struct device_node *parent,
				  struct device_node *child)
{
	struct device_node *last_sibling;

	child->sibling = NULL;
	child->parent = parent;

	if (!parent->child) {
		parent->child = child;
		return;
	}

	last_sibling = parent->child;
	while (last_sibling->sibling)
		last_sibling = last_sibling->sibling;
	last_sibling->sibling = child;
}

static int plugin_module_get_uid(void)
{
	static atomic_t pm_uid = ATOMIC_INIT(-1);

	return atomic_inc_return(&pm_uid);
}

struct device_node *create_simple_device_node(const char *path,
					      const char *add_name,
					      size_t data_size)
{
	struct device_node *new_np;

	new_np = kzalloc(sizeof(*new_np), GFP_KERNEL);
	if (!new_np)
		return NULL;

	new_np->full_name = kasprintf(GFP_KERNEL, "%s/%s", path, add_name);
	new_np->name = kasprintf(GFP_KERNEL, "%s", add_name);

	if (data_size) {
		new_np->data = kzalloc(data_size, GFP_KERNEL);
		if (!new_np->data)
			goto clean;
	}

	return new_np;

clean:
	kfree(new_np->full_name);
	kfree(new_np->name);
	kfree(new_np);
	return NULL;
}

static void free_simple_device_node(struct device_node *np)
{
	if (!np)
		return;

	kfree(np->full_name);
	kfree(np->name);
	kfree(np->data);
	kfree(np);
}

struct device_node *duplicate_single_node(struct device_node *np,
					  const char *base_dir,
					  const char *path,
					  const char *new_name)
{
	struct device_node *dup;
	struct property *pp, *new_pp;
	int ret;
	const char *add_name;
	char fname[MAXIMUM_FNAME_LENGTH + 1] = {};

	dup = kzalloc(sizeof(*dup), GFP_KERNEL);
	if (!dup)
		return NULL;

	if (new_name) {
		add_name = new_name;
	} else {
		add_name = strrchr(np->full_name, '/');
		add_name++;
	}

	if (path) {
		strncpy(fname, path, MAXIMUM_FNAME_LENGTH);
	} else {
		const char *lname = strrchr(np->full_name, '/');
		int llen = strlen(np->full_name) - strlen(lname);

		strncpy(fname, np->full_name, MAXIMUM_FNAME_LENGTH);
		fname[llen] = '\0';
	}

	if (base_dir)
		dup->full_name = kasprintf(GFP_KERNEL, "%s%s/%s",
					   base_dir, fname, add_name);
	else
		dup->full_name = kasprintf(GFP_KERNEL, "%s/%s",
					   fname, add_name);

	of_node_init(dup);

	for_each_property_of_node(np, pp) {
		if (!strcmp(pp->name, "name"))
			new_pp = __of_copy_property(pp, (void *)add_name,
						    strlen(add_name),
						    GFP_KERNEL);
		else
			new_pp = __of_copy_property(pp, NULL, 0, GFP_KERNEL);
		if (!new_pp) {
			kfree(dup->full_name);
			kfree(dup);
			return NULL;
		}

		ret = of_add_property(dup, new_pp);
		if (ret < 0) {
			pr_err("Prop %s can not be added on node %s\n",
			       new_pp->name, dup->full_name);
			free_property(new_pp);
			kfree(dup->full_name);
			kfree(dup);
			return NULL;
		}
	}

	dup->name = __of_get_property(dup, "name", NULL) ? : "<NULL>";
	dup->type = __of_get_property(dup, "device_type", NULL) ? : "<NULL>";

	return dup;
}

struct device_node *get_copy_of_node(struct device_node *np,
				     const char *base_dir,
				     const char *path, const char *new_name)
{
	struct device_node *dup;
	struct device_node *child, *child_dup;
	struct device_node *prev_child = NULL;

	dup = duplicate_single_node(np, base_dir, path, new_name);
	if (!dup)
		return NULL;

	for_each_child_of_node(np, child) {
		child_dup = get_copy_of_node(child, NULL, dup->full_name, NULL);
		if (!child_dup) {
			kfree(dup);
			return NULL;
		}
		child_dup->parent = dup;
		child_dup->sibling = NULL;
		if (!prev_child)
			dup->child = child_dup;
		else
			prev_child->sibling = child_dup;
		prev_child = child_dup;
	}

	return dup;
}

static struct device_node *add_module_connection(struct device_node *parent,
						 struct device_node *pm_node,
						 const char *child_name)
{
	struct device_node *child;
	struct connection_info *cinfo;

	child = create_simple_device_node(parent->full_name, child_name,
					  sizeof(*cinfo));
	if (!child) {
		pr_info("Can not create device node %s\n", child_name);
		return NULL;
	}

	cinfo = child->data;
	cinfo->org_pm = pm_node;
	cinfo->node = child;
	of_add_node_to_parent(parent, child);

	return child;
}

static int of_get_next_phandle(void)
{
	static phandle curr_handle;
	static bool first_time = true;
	struct device_node *np;
	phandle next_handle;
	unsigned long flags;

	raw_spin_lock_irqsave(&devtree_lock, flags);

	if (first_time) {
		for_each_of_allnodes(np) {
			if (np->phandle > curr_handle)
				curr_handle = np->phandle;
		}
		first_time = false;
	}

	next_handle = curr_handle++;
	raw_spin_unlock_irqrestore(&devtree_lock, flags);

	return next_handle;
}

static struct property *__of_string_append(struct device_node *target,
					   struct property *prop)
{
	struct property *new_prop, *tprop;
	const char *tprop_name, *curr_str;
	int slen, tlen, lenp;

	tprop_name = of_prop_next_string(prop, NULL);
	if (!tprop_name)
		return NULL;

	new_prop = kzalloc(sizeof(*new_prop), GFP_KERNEL);
	if (!new_prop)
		return NULL;

	new_prop->name = kstrdup(tprop_name, GFP_KERNEL);
	if (!new_prop->name)
		goto err_fail_name;

	curr_str = of_prop_next_string(prop, tprop_name);
	for (slen = 0; curr_str; curr_str = of_prop_next_string(prop, curr_str))
		slen += strlen(curr_str);

	tprop = of_find_property(target, tprop_name, &lenp);
	tlen = (tprop) ? tprop->length : 0;

	new_prop->value = kmalloc(slen + tlen, GFP_KERNEL);
	if (!new_prop->value)
		goto err_fail_value;

	if (tlen)
		memcpy(new_prop->value, tprop->value, tlen);

	if (slen) {
		curr_str = of_prop_next_string(prop, tprop_name);
		memcpy(new_prop->value + tlen, curr_str, slen);
	}

	new_prop->length = slen + tlen;

	return new_prop;

err_fail_value:
	kfree(new_prop->name);
err_fail_name:
	kfree(new_prop);

	return NULL;
}

static int do_property_override_from_overlay(struct device_node *target,
					     struct device_node *overlay)
{
	struct property *prop;
	struct property *tprop;
	struct property *new_prop;
	const char *pval;
	int lenp = 0;
	int ret;

	pr_debug("Update properties from %s to %s\n", overlay->full_name,
		 target->full_name);

	for_each_property_of_node(overlay, prop) {
		/* Skip those we do not want to proceed */
		if (!strcmp(prop->name, "name") ||
			!strcmp(prop->name, "phandle") ||
			!strcmp(prop->name, "linux,phandle"))
				continue;
		if (!strcmp(prop->name, "delete-target-property")) {
			if (prop->length <= 0)
				continue;
			pval = (const char *)prop->value;
			pr_info("Removing Prop %s from target %s\n",
				pval, target->full_name);
			tprop = of_find_property(target, pval, &lenp);
			if (tprop)
				of_remove_property(target, tprop);
			continue;
		}

		if (!strcmp(prop->name, "append-string-property")) {
			if (prop->length <= 0)
				continue;

			new_prop = __of_string_append(target, prop);
			if (!new_prop) {
				pr_err("Prop %s can not be appended\n",
					of_prop_next_string(prop, NULL));
				return -EINVAL;
			}
			goto add_prop;
		}

		new_prop = __of_copy_property(prop, NULL, 0, GFP_KERNEL);
		if (!new_prop) {
			pr_err("Prop %s can not be duplicated\n",
				prop->name);
			return -EINVAL;
		}

add_prop:
		tprop = of_find_property(target, new_prop->name, &lenp);
		if (!tprop) {
			ret = of_add_property(target, new_prop);
			if (ret < 0) {
				pr_err("Prop %s can not be added on node %s\n",
					new_prop->name, target->full_name);
				goto cleanup;
			}
		} else {
			ret = of_update_property(target, new_prop);
			if (ret < 0) {
				pr_err("Prop %s can not be updated on node %s\n",
					new_prop->name, target->full_name);
				goto cleanup;
			}
		}
	}

	return 0;

cleanup:
	free_property(new_prop);
	return ret;
}

static int plugin_manager_get_fabid(const char *id_str)
{
	int fabid = 0;
	int id;
	int i;

	if (strlen(id_str) < 13)
		return -EINVAL;

	for (i = 0; i < 3; ++i) {
		id = id_str[10 + i];
		switch (id) {
		case 48 ... 57: /* 0 to 9 */
			id = id - 48;
			break;
		case 65 ... 90: /* A to Z */
			id = id - 65 + 10;
			break;
		case 97 ... 122: /* a to z */
			id = id - 97 + 10;
			break;
		default:
			return -EINVAL;
		}

		/* Make digit position to 100x to avoid carry */
		fabid = fabid * 100  + id;
	}

	return fabid;
}

static bool plugin_manager_match_id(struct device_node *np, const char *id_name)
{
	struct property *prop;
	const char *in_str = id_name;
	int match_type = PLUGIN_MANAGER_MATCH_EXACT;
	int valid_str_len = strlen(id_name);
	int fabid = 0, prop_fabid;
	int i;

	if ((valid_str_len > 2) && (in_str[0] == '>') && (in_str[1] == '=')) {
		in_str += 2;
		valid_str_len -= 2;
		match_type = PLUGIN_MANAGER_MATCH_GE;
		goto match_type_done;
	}

	if ((valid_str_len > 1) && (in_str[0] == '<')) {
		in_str += 1;
		valid_str_len -= 1;
		match_type = PLUGIN_MANAGER_MATCH_LT;
		goto match_type_done;
	}

	if ((valid_str_len > 1) && (in_str[0] == '^')) {
		in_str += 1;
		valid_str_len -= 1;
		match_type = PLUGIN_MANAGER_MATCH_PARTIAL;
		goto match_type_done;
	}

	for (i = 0; i < valid_str_len; ++i) {
		if (in_str[i] == '*') {
			valid_str_len = i;
			match_type = PLUGIN_MANAGER_MATCH_PARTIAL;
			break;
		}
	}

match_type_done:
	if ((match_type == PLUGIN_MANAGER_MATCH_GE) ||
		(match_type == PLUGIN_MANAGER_MATCH_LT)) {
		fabid = plugin_manager_get_fabid(in_str);
		if (fabid < 0)
			return false;
	}

	for_each_property_of_node(np, prop) {
		/* Skip those we do not want to proceed */
		if (!strcmp(prop->name, "name") ||
			!strcmp(prop->name, "phandle") ||
			!strcmp(prop->name, "linux,phandle"))
				continue;
		switch (match_type) {
		case PLUGIN_MANAGER_MATCH_EXACT:
			if (strlen(prop->name) != valid_str_len)
				break;
			if (!memcmp(in_str, prop->name, valid_str_len))
				return true;
			break;

		case PLUGIN_MANAGER_MATCH_PARTIAL:
			if (strlen(prop->name) < valid_str_len)
				break;
			if (!memcmp(in_str, prop->name, valid_str_len))
				return true;
			break;

		case PLUGIN_MANAGER_MATCH_GE:
		case PLUGIN_MANAGER_MATCH_LT:
			if (strlen(prop->name) < 13)
				break;
			if (memcmp(in_str, prop->name, 10))
				break;
			prop_fabid = plugin_manager_get_fabid(prop->name);
			if (prop_fabid < 0)
				break;
			if (prop_fabid >= fabid &&
				match_type == PLUGIN_MANAGER_MATCH_GE)
				return true;
			if (prop_fabid < fabid &&
				match_type == PLUGIN_MANAGER_MATCH_LT)
				return true;
			break;
		default:
			break;
		}
	}

	return false;
}

static int do_property_overrides(struct device_node *target,
				 struct device_node *overlay)
{
	struct device_node *tchild, *ochild;
	const char *address_name;
	int ret;

	ret = do_property_override_from_overlay(target, overlay);
	if (ret < 0) {
		pr_err("Target %s update with overlay %s failed: %d\n",
			target->name, overlay->name, ret);
		return ret;
	}

	for_each_child_of_node(overlay, ochild) {
		address_name = strrchr(ochild->full_name, '/');
		tchild = of_get_child_by_last_name(target, address_name + 1);
		if (!tchild) {
			pr_err("Overlay node %s not found in target node %s\n",
				ochild->full_name, target->full_name);
			continue;
		}
		ret = do_property_overrides(tchild, ochild);
		if (ret < 0) {
			pr_err("Target %s update with overlay %s failed: %d\n",
				tchild->name, ochild->name, ret);
			return ret;
		}
	}
	return 0;
}

static int handle_properties_overrides(struct device_node *np,
				       struct device_node *target)
{
	struct device_node *overlay;
	int ret;

	if (!target) {
		target = of_parse_phandle(np, "target", 0);
		if (!target) {
			pr_err("Node %s does not have targer node\n",
				np->name);
			return -EINVAL;
		}
	}

	overlay = of_get_child_by_name(np, "_overlay_");
	if (!overlay) {
		pr_err("Node %s does not have Overlay\n", np->name);
		return -EINVAL;
	}

	ret = do_property_overrides(target, overlay);
	if (ret < 0) {
		pr_err("Target %s update with overlay %s failed: %d\n",
			target->name, overlay->name, ret);
		return -EINVAL;
	}

	return 0;
}

static int __init plugin_manager(struct device_node *np)
{
	struct device_node *board_np, *nct_np, *odm_np, *cnp;
	struct device_node *config_np, *chip_np;
	const char *bname;
	struct property *prop;
	int board_count;
	int odm_count, nct_count, chip_id_count;
	int cname_count, cval_count;
	int nchild;
	bool found = false;
	bool override_on_all_match;
	int ret;

	override_on_all_match = of_property_read_bool(np,
					"enable-override-on-all-matches");

	cname_count = of_property_count_strings(np, "config-names");
	cval_count = of_property_count_u32_elems(np, "configs");
	if (cname_count != cval_count) {
		pr_err("Node %s does not have config-names and configs\n",
			np->name);
		return -EINVAL;
	}

	board_count = of_property_count_strings(np, "ids");
	odm_count = of_property_count_strings(np, "odm-data");
	nct_count = of_property_count_strings(np, "nct-data");
	chip_id_count = of_property_count_strings(np, "chip-id");
	if ((board_count <= 0) && (odm_count <= 0) && (cname_count <= 0) &&
	    (nct_count <= 0) && (chip_id_count <= 0)) {
		pr_err("Node %s does not have property ids, nct and odm data\n",
			np->name);
		return -EINVAL;
	}

	nchild = of_get_child_count(np);
	if (!nchild) {
		pr_err("Node %s does not have Overlay child\n", np->name);
		return -EINVAL;
	}

	/* Match the IDs or odm data */
	board_np = of_find_node_by_path("/chosen/plugin-manager/ids");
	odm_np = of_find_node_by_path("/chosen/plugin-manager/odm-data");
	nct_np = of_find_node_by_path("/chosen/plugin-manager/nct-data");
	chip_np = of_find_node_by_path("/chosen/plugin-manager/chip-id");
	config_np = of_find_node_by_path("/chosen/plugin-manager/configs");
	if (!board_np && !odm_np && !config_np && !nct_np && !chip_np) {
		pr_err("chosen/plugin-manager does'nt have ids, nct and odm-data\n");
		return -EINVAL;
	}

	if ((board_count > 0) && board_np) {
		of_property_for_each_string(np, "ids", prop, bname) {
			found = plugin_manager_match_id(board_np, bname);
			if (found) {
				pr_info("node %s match with board %s\n",
					np->full_name, bname);
				if (override_on_all_match)
					break;
				goto search_done;
			}
		}

		if (override_on_all_match && !found)
			return 0;
	}

	if ((odm_count > 0) && odm_np) {
		bool is_anded_odm_overrides;

		is_anded_odm_overrides = of_property_read_bool(np,
						"odm-anded-override");

		of_property_for_each_string(np, "odm-data", prop, bname) {
			found = of_property_read_bool(odm_np, bname);
			if (found) {
				pr_info("node %s match with odm-data %s\n",
					np->full_name, bname);

				if (is_anded_odm_overrides)
					continue;

				if (override_on_all_match)
					break;
				goto search_done;
			} else {
				if (is_anded_odm_overrides)
					return 0;
			}
		}

		if (override_on_all_match && !found)
			return 0;

		if (!override_on_all_match)
			goto search_done;
	}

	if ((nct_count > 0) && nct_np) {
		of_property_for_each_string(np, "nct-data", prop, bname) {
			found = of_property_read_bool(nct_np, bname);
			if (found) {
				pr_info("node %s match with nct-data %s\n",
					np->full_name, bname);
				if (override_on_all_match)
					break;
				goto search_done;
			}
		}

		if (override_on_all_match && !found)
			return 0;
	}

	if ((chip_id_count > 0) && chip_np) {
		of_property_for_each_string(np, "chip-id", prop, bname) {
			found = of_property_read_bool(chip_np, bname);
			if (found) {
				pr_info("node %s match with chip-id %s\n",
					np->full_name, bname);
				if (override_on_all_match)
					break;
				goto search_done;
			}
		}

		if (override_on_all_match && !found)
			return 0;
	}

	if ((cname_count > 0) && config_np) {
		int index = 0;
		u32 pval = 0, pmv = 0, mask, value;

		of_property_for_each_string(np, "config-names", prop, bname) {
			ret = of_property_read_u32_index(np, "configs",
					index, &pmv);
			if (ret < 0) {
				pr_info("node %s do not have proper configs\n",
					np->name);
				return ret;
			}
			index++;
			ret = of_property_read_u32(config_np, bname, &pval);
			if (ret < 0)
				continue;

			mask = (pmv >> 8) & 0xFF;
			value = pmv & 0xFF;
			pval &= 0xFF;
			found = ((pval & mask) == value);
			if (found) {
				pr_info("node %s match with config %s\n",
					np->full_name, bname);
				if (override_on_all_match)
					break;
				goto search_done;
			}
		}

		if (override_on_all_match && !found)
			return 0;
	}

search_done:
	if (!found)
		return 0;

	for_each_child_of_node(np, cnp)
		handle_properties_overrides(cnp, NULL);

	return 0;
}

static int get_node_address(const struct device_node *np)
{
	char *name = strrchr(np->full_name, '@');
	int addr = 0;

	if (!name)
		return 0;

	name++;
	if (*name == '0')
		addr = memparse(name, &name);

	return addr;
}

static struct device_node *plugin_module_get_node_by_path(
			struct device_node *pm_node, const char *rpath)
{
	struct connection_info *cinfo = pm_node->data;
	const char *end_str, *pdev_str, *dev_path;
	struct device_node *cnode = pm_node;
	char child_name[100];
	char *nfpath;
	int nlen, ret;
	bool uuid;

	if (!((rpath[0] == '.' && rpath[1] == '/')))
		return NULL;

	pdev_str = rpath + 2;
	end_str = pdev_str + strlen(pdev_str);

	while (pdev_str < end_str) {
		uuid = false;
		nlen = strcspn(pdev_str, "/");
		if (!nlen)
			return NULL;

		if (of_property_read_bool(cnode, "make-unique-node-name")) {
			snprintf(child_name, 100, "%s_%s",
				 cinfo->uid_str, pdev_str);
			child_name[strlen(cinfo->uid_str) + nlen + 1] = '\0';
			uuid = true;
		} else {
			memcpy(child_name, pdev_str, nlen);
			child_name[nlen] = '\0';
		}

		pdev_str += nlen + 1;

		cnode = of_get_child_by_name(cnode, child_name);
		if (!cnode)
			break;

		if (!of_property_read_bool(cnode, "PM-RELOCATED"))
			continue;

		if (of_property_read_bool(cnode, "make-unique-node-name"))
			uuid = true;

		ret = of_property_read_string(cnode, "device-path", &dev_path);
		if (ret < 0)
			return NULL;

		if (uuid)
			nfpath = kasprintf(GFP_KERNEL, "%s/%s_%s",
					   dev_path, cinfo->uid_str, pdev_str);
		else
			nfpath = kasprintf(GFP_KERNEL, "%s/%s",
					   dev_path, pdev_str);
		if (!nfpath)
			return NULL;

		cnode = of_find_node_by_path(nfpath);
		kfree(nfpath);
		break;
	}

	return cnode;
}

static struct property *plugin_module_get_property_by_path_name(
		struct device_node *pm_node, const char *pname)
{
	struct property *prop = NULL;
	struct device_node *pnode;
	char *path, *prop_name;
	int len;

	path = kasprintf(GFP_KERNEL, "%s", pname);
	if (!path)
		return NULL;

	prop_name = strrchr(path, '/');
	len = strlen(path) - strlen(prop_name);
	path[len] = '\0';
	prop_name++;

	pnode = plugin_module_get_node_by_path(pm_node, path);
	if (!pnode)
		goto end;

	prop = of_find_property(pnode, prop_name, NULL);
end:
	kfree(path);
	return prop;
}

static struct property *plugin_module_create_property_to_path(
		struct device_node *pm_node, struct property *ref_prop,
		const char *pname)
{
	struct property *prop = NULL;
	struct device_node *pnode;
	char *path, *prop_name;
	void *prop_value = (ref_prop) ? ref_prop->value : NULL;
	int prop_len = (ref_prop) ? ref_prop->length : 0;
	int len;
	int ret;

	path = kasprintf(GFP_KERNEL, "%s", pname);
	if (!path)
		return NULL;

	prop_name = strrchr(path, '/');
	len = strlen(path) - strlen(prop_name);
	path[len] = '\0';
	prop_name++;

	pnode = plugin_module_get_node_by_path(pm_node, path);
	if (!pnode)
		goto end;

	prop = __of_create_property_by_name(prop_name, prop_value, prop_len);
	if (!prop)
		goto end;

	ret = of_add_property(pnode, prop);
	if (ret < 0) {
		pr_err("Prop %s can not be added on node %s\n",
		       prop->name, pnode->full_name);
		free_property(prop);
		prop = NULL;
	}

end:
	kfree(path);
	return prop;
}

static void plugin_module_resolve_uid(struct device_node *cnp)
{
	struct connection_info *cinfo = cnp->data;
	struct device_node *np = cinfo->copy_node;
	struct device_node *funcs, *sub_funcs, *child;
	struct property *name_prop;
	char *lname, *nname, *fname, *nfname;
	const void *ovalue;
	int len;
	int uid;

	funcs = of_get_child_by_name(np, "functions");
	if (!funcs)
		return;

	uid = plugin_module_get_uid();
	cinfo->uid_str = kasprintf(GFP_KERNEL, "PM%03d", uid);
	if (!cinfo->uid_str)
		return;

	fname = kzalloc(MAXIMUM_FNAME_LENGTH + 1, GFP_KERNEL);
	if (!fname)
		return;

	for_each_child_of_node(funcs, sub_funcs) {
		if (!of_property_read_bool(sub_funcs, "make-unique-node-name"))
			continue;

		for_each_child_of_node(sub_funcs, child) {
			ovalue = child->full_name;
			snprintf(fname, MAXIMUM_FNAME_LENGTH, "%s",
				 child->full_name);
			lname = strrchr(fname, '/');
			len = strlen(fname) - strlen(lname);
			fname[len] = '\0';
			nfname = kasprintf(GFP_KERNEL, "%s/%s_%s",
					   fname, cinfo->uid_str, lname + 1);
			if (!nfname) {
				pr_err("Failed to resolve full name\n");
				continue;
			}
			child->full_name = nfname;
			kfree(ovalue);

			name_prop = of_find_property(child, "name", NULL);
			if (!name_prop) {
				child->name = "<NULL>";
				continue;
			}

			ovalue = name_prop->value;
			len = strlen(cinfo->uid_str) + strlen(child->name) + 2;
			nname = kzalloc(len, GFP_KERNEL);
			if (!nname) {
				pr_err("Failed to create UID name\n");
				continue;
			}
			snprintf(nname, len, "%s_%s",
				 cinfo->uid_str, child->name);

			name_prop->value = nname;
			name_prop->length = len;
			kfree(ovalue);

			child->name = nname;
			pr_debug("Resolve the unique ID of node %s\n",
				 child->full_name);
		}
	}

	kfree(fname);
}

static int create_dup_nodes_for_connected_plm(struct device_node *cnp)
{
	struct connection_info *cinfo = cnp->data;
	struct device_node *child;
	struct device_node *np = NULL;
	int ret;

	if (cinfo)
		np = cinfo->org_pm;

	if (np) {
		cinfo->copy_node = get_copy_of_node(np, NULL, NULL, NULL);
		if (!cinfo->copy_node) {
			pr_err("Failed to copy node %s\n", np->full_name);
			return -ENOMEM;
		}

		/* Resolve the UID */
		plugin_module_resolve_uid(cnp);
	}

	for_each_child_of_node(cnp, child) {
		ret = create_dup_nodes_for_connected_plm(child);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int link_module_node_to_connector_node(struct device_node *cnp)
{
	struct connection_info *cinfo = cnp->data;
	struct device_node *connector, *module;
	struct device_node *ds, *us, *ds_con;
	struct connection_info *cdata, *mdata;

	if (!cinfo->copy_node)
		return 0;

	ds = of_get_child_by_name(cinfo->copy_node, "downstream");
	if (!ds) {
		pr_debug("There is no do downstream connectors: %s\n",
			 cinfo->copy_node->full_name);
		return 0;
	}

	for_each_child_of_node(cnp, connector) {
		ds_con = of_get_child_by_name(ds, connector->name);
		if (!ds_con) {
			pr_err("Node %s does not have connector %s\n",
			       ds->full_name, connector->name);
			continue;
		}

		module = connector->child;
		mdata = module->data;
		cdata = connector->data;
		if (!mdata->copy_node) {
			pr_debug("Module %s does not have plug-in node\n",
				 module->name);
			continue;
		}

		us = of_get_child_by_name(mdata->copy_node, "upstream");
		if (!us) {
			pr_err("Module %s does not have upstream node\n",
			       module->name);
			continue;
		}

		mdata->parent_conn_node = ds_con;
		cdata->child_conn_node = us;

		link_module_node_to_connector_node(module);
	}

	return 0;
}

static void update_new_path_node_and_children(struct device_node *np,
					      const char *new_path)
{
	struct device_node *child;
	const char *new_fname, *lname;

	lname = strrchr(np->full_name, '/');
	new_fname = kasprintf(GFP_KERNEL, "%s%s", new_path, lname);
	kfree(np->full_name);
	np->full_name = new_fname;

	__of_attach_node_sysfs(np);

	for_each_child_of_node(np, child)
		update_new_path_node_and_children(child, np->full_name);
}

static int process_sub_devs_copy(struct device_node *pm_node,
				 struct device_node *sub_dev)
{
	struct device_node *us_dev_np, *bus = NULL;
	struct device_node *dev_child, *child, *next_child;
	struct property *nprop;
	const char *dev_str;
	int ret;
	char path[200];
	char prop_name[50];
	const char *sp;
	const char *us_dev;
	unsigned long flags;
	int llen;

	ret = of_property_read_string(sub_dev, "device-path", &dev_str);
	if (ret < 0) {
		pr_err("device-path property not found in node %s\n",
		       sub_dev->full_name);
		return ret;
	}

	memset(path, 0, 200);
	memcpy(path, dev_str, strlen(dev_str));

	if ((dev_str[0] == '.' && dev_str[1] == '/')) {
		sp =  strrchr(dev_str, '/');
		memset(prop_name, 0, 50);
		memcpy(prop_name, sp + 1, strlen(sp));

		llen = strlen(dev_str) - strlen(sp);
		path[llen] = '\0';

		us_dev_np = of_get_nested_child_by_name(pm_node, path + 2);
		if (!us_dev_np) {
			pr_err("Node %s not found at %s\n",
			       path + 2, pm_node->full_name);
			return -EINVAL;
		}

		ret = of_property_read_string(us_dev_np, prop_name, &us_dev);
		if (ret < 0) {
			pr_err("Node %s does not have prop %s\n\n",
			       us_dev_np->full_name, prop_name);
			return ret;
		}

		bus = of_find_node_by_path(us_dev);
	} else if (dev_str[0] == '/') {
		bus = of_find_node_by_path(dev_str);
	} else {
		pr_err("device-path %s (%d) not processed: %s\n",
		       dev_str, (int)strlen(dev_str), sub_dev->full_name);
		return 0;
	}

	if (!bus) {
		pr_err("Node path %s not found\n", us_dev);
		return ret;
	}

	dev_child = sub_dev->child;

	mutex_lock(&of_mutex);
	raw_spin_lock_irqsave(&devtree_lock, flags);

	child = sub_dev->child;
	while (child) {
		next_child = child->sibling;

		of_add_node_to_parent(bus, child);

		pr_debug("Added child %s to bus %s\n",
			 child->full_name, bus->full_name);
		child = next_child;
	}

	raw_spin_unlock_irqrestore(&devtree_lock, flags);

	while (dev_child) {
		update_new_path_node_and_children(dev_child,
						  bus->full_name);
		dev_child = dev_child->sibling;
	}

	mutex_unlock(&of_mutex);

	nprop = __of_create_property_by_name("PM-RELOCATED", NULL, 0);
	if (!nprop)
		return -ENOMEM;

	ret = of_add_property(sub_dev, nprop);
	if (ret < 0) {
		pr_err("Prop %s can not be added on node %s\n",
		       nprop->name, sub_dev->full_name);
		return ret;
	}

	return 0;
}

static int ops_copy_property_value(struct device_node *np,
				   struct device_node *ops)
{
	const char *sprop_str, *tprop_str;
	struct property *sprop, *tprop;
	int ret;

	ret = of_property_read_string(ops, "source-property", &sprop_str);
	if (ret < 0) {
		pr_err("Failed to read source-property @%s\n", ops->full_name);
		return ret;
	}

	ret = of_property_read_string(ops, "target-property", &tprop_str);
	if (ret < 0) {
		pr_err("Failed to read target-property @%s\n", ops->full_name);
		return ret;
	}

	sprop = plugin_module_get_property_by_path_name(np, sprop_str);
	if (!sprop) {
		pr_err("Failed to get property %s:%s\n",
		       sprop_str, ops->full_name);
		return -EINVAL;
	}

	tprop = plugin_module_get_property_by_path_name(np, tprop_str);
	if (!tprop) {
		plugin_module_create_property_to_path(np, sprop, tprop_str);
		return 0;
	}

	if (!sprop->length || !sprop->value) {
		pr_err("No value for source %s\n", sprop_str);
		return -EINVAL;
	}

	if (sprop->length == tprop->length) {
		memcpy(tprop->value, sprop->value, tprop->length);
	} else {
		void *oval = tprop->value;
		void *nval = kzalloc(sprop->length, GFP_KERNEL);

		if (!nval)
			return -ENOMEM;

		tprop->value = nval;
		memcpy(tprop->value, sprop->value, sprop->length);
		tprop->length = sprop->length;
		kfree(oval);
	}

	return 0;
}

static int ops_resolve_property_value(struct device_node *np,
				      struct device_node *ops)
{
	struct device_node *ref_node;
	const char *tprop_str;
	struct property *sprop, *tprop;
	void *oval, *nval;
	int ret, len;

	ret = of_property_read_string(ops, "target-property", &tprop_str);
	if (ret < 0) {
		pr_err("Failed to read target-property @%s\n", ops->full_name);
		return ret;
	}

	tprop = plugin_module_get_property_by_path_name(np, tprop_str);
	if (!tprop) {
		pr_err("Failed to get Property %s at %s\n",
		       tprop_str, np->full_name);
		return -EINVAL;
	}

	ref_node = plugin_module_get_node_by_path(np, tprop->value);
	if (!ref_node) {
		pr_debug("Failed to get node %s @%s\n",
			 (char *)tprop->value, ops->full_name);
		goto try_for_property;
	}

	len = strlen(ref_node->full_name);
	nval = kzalloc(len + 2, GFP_KERNEL);
	if (!nval) {
		pr_err("Memory allocation failed %s\n", ops->full_name);
		return -ENOMEM;
	}

	memcpy(nval, ref_node->full_name, len);
	tprop->length = len + 2;
	goto copy_to_target;

try_for_property:
	sprop = plugin_module_get_property_by_path_name(np, tprop->value);
	if (!sprop) {
		pr_err("Failed to get Property %s at %s\n",
		       (char *)tprop->value, np->full_name);
		return -EINVAL;
	}

	if (sprop->length == tprop->length) {
		memcpy(tprop->value, sprop->value, sprop->length);
		return 0;
	}

	nval = kzalloc(sprop->length, GFP_KERNEL);
	if (!nval)
		return -ENOMEM;

	memcpy(nval, sprop->value, sprop->length);
	tprop->length = sprop->length;

copy_to_target:
	oval = tprop->value;
	tprop->value = nval;
	kfree(oval);

	return 0;
}

static int ops_resolve_property_handle(struct device_node *np,
				       struct device_node *ops)
{
	const char *rnod_str, *tprop_str;
	struct property *tprop;
	struct device_node *ref_node;
	int ret;

	ret = of_property_read_string(ops, "target-property", &tprop_str);
	if (ret < 0) {
		pr_err("Failed to read target-property @%s\n", ops->full_name);
		return ret;
	}

	ret = of_property_read_string(ops, "reference-node", &rnod_str);
	if (ret < 0) {
		pr_err("Failed to read refernce-node @%s\n", ops->full_name);
		return ret;
	}

	ref_node = plugin_module_get_node_by_path(np, rnod_str);
	if (!ref_node) {
		pr_err("Failed to get node %s @%s\n", rnod_str, ops->full_name);
		return ret;
	}

	if (!ref_node->phandle)
		ref_node->phandle = of_get_next_phandle();

	tprop = plugin_module_get_property_by_path_name(np, tprop_str);
	if (!tprop) {
		tprop = plugin_module_create_property_to_path(np, NULL,
							      tprop_str);
		if (!tprop) {
			pr_err("Failed to create property %s\n", tprop_str);
			return -EINVAL;
		}
		tprop->value = kzalloc(8, GFP_KERNEL);
		if (!tprop->value)
			return -ENOMEM;
		tprop->length = 8;
	}

	*(uint32_t *)tprop->value = cpu_to_be32(ref_node->phandle);

	pr_debug("%s: %s and inode %s handle %u\n",
		 __func__, ops->full_name, ref_node->full_name,
		 ref_node->phandle);

	return 0;
}

static int process_sub_functons(struct device_node *pm_node,
				struct device_node *funcs)
{
	struct device_node *ops;

	for_each_child_of_node(funcs, ops) {
		if (of_property_read_bool(ops, "resolve-property-value"))
			ops_resolve_property_value(pm_node, ops);
		else if (of_property_read_bool(ops, "copy-property-value"))
			ops_copy_property_value(pm_node, ops);
		else if (of_property_read_bool(ops, "resolve-property-handle"))
			ops_resolve_property_handle(pm_node, ops);
		else
			pr_err("Unidentified ops at %s\n", ops->full_name);
	}

	return 0;
}

static int copy_all_node_properties(struct device_node *dest,
				    struct device_node *src)
{
	struct property *sprop, *dprop;
	int ret;

	for_each_property_of_node(src, sprop) {
		if (!strcmp(sprop->name, "name") ||
		    !strcmp(sprop->name, "phandle") ||
		    !strcmp(sprop->name, "linux,phandle"))
			continue;

		dprop = of_find_property(dest, sprop->name, NULL);
		/* New property */
		if (!dprop) {
			dprop = __of_copy_property(sprop, NULL, 0, GFP_KERNEL);
			if (!dprop) {
				pr_err("Prop %s can not be duplicated\n",
				       sprop->name);
				continue;
			}

			ret = of_add_property(dest, dprop);
			if (ret < 0) {
				pr_err("Prop %s can not be added on node %s\n",
				       dprop->name, dest->full_name);
				free_property(dprop);
			}
			continue;
		}

		/* Boolean property */
		if (!sprop->length) {
			if (dprop->length) {
				kfree(dprop->value);
				dprop->value = NULL;
				dprop->length = 0;
			}
			continue;
		}

		/* Different length property */
		if (dprop->length != sprop->length) {
			void *old_val = dprop->value;
			void *new_val = kzalloc(sprop->length, GFP_KERNEL);

			memcpy(new_val, sprop->value, sprop->length);
			dprop->value = new_val;
			dprop->length = sprop->length;
			kfree(old_val);
			continue;
		}

		/* Same length */
		memcpy(dprop->value, sprop->value, sprop->length);
	}

	return 0;
}

static void map_module_connector_to_parent(struct device_node *module_us_np,
					   struct device_node *ds_con_np)
{
	struct device_node *ds_pins, *module_pins;
	const char *lname;

	for_each_child_of_node(ds_con_np, ds_pins) {
		lname = strrchr(ds_pins->full_name, '/');
		lname++;

		module_pins = of_get_child_by_last_name(module_us_np, lname);
		if (!module_pins) {
			module_pins = get_copy_of_node(ds_pins, NULL,
						       module_us_np->full_name,
						       lname);
			of_add_node_to_parent(module_us_np, module_pins);
			continue;
		}

		copy_all_node_properties(module_pins, ds_pins);
	}
}

static void process_plugin_module_connections(struct device_node *cnp)
{
	struct connection_info *cinfo = cnp->data;
	struct connection_info *cdata, *mdata;
	struct device_node *connector, *module;
	struct device_node *funcs, *sub_func;

	if (!cinfo->copy_node)
		return;

	if (!cinfo->copy_node->data)
		cinfo->copy_node->data = cinfo;

	/* Perform functons */
	funcs = of_get_child_by_name(cinfo->copy_node, "functions");
	if (!funcs)
		goto handle_ds_connection;

	for_each_child_of_node(funcs, sub_func) {
		if (of_property_read_bool(sub_func, "copy-subdevices"))
			process_sub_devs_copy(cinfo->copy_node, sub_func);
		else
			process_sub_functons(cinfo->copy_node, sub_func);
	}

handle_ds_connection:
	/* Copy Downstream connectors to connected module's upstream */
	for_each_child_of_node(cnp, connector) {
		module = connector->child;
		if (!module)
			continue;

		mdata = module->data;
		cdata = connector->data;
		if (mdata->parent_conn_node) {
			pr_debug("Copying node %s to %s\n",
				 mdata->parent_conn_node->full_name,
				 cdata->child_conn_node->full_name);
			map_module_connector_to_parent(
					cdata->child_conn_node,
					mdata->parent_conn_node);
		}

		process_plugin_module_connections(module);
	}
}

static struct device_node *connect_all_child_modules(
			struct device_node *plmroot,
			struct device_node *plcroot,
			struct device_node *module)
{
	struct connection_info *cinfo;
	struct device_node *nplcroot = plcroot;
	struct device_node *child, *ds;
	struct property *prop;
	const char *module_id = NULL;
	const char *s;
	bool found;

	for_each_property_of_node(module, prop) {
		/* Skip those we do not want to proceed */
		if (!strcmp(prop->name, "name") ||
		    !strcmp(prop->name, "phandle") ||
		    !strcmp(prop->name, "linux,phandle"))
			continue;

		/* Other property is module ID: Support only one module */
		nplcroot = add_module_connection(plcroot, NULL, prop->name);
		if (!nplcroot) {
			pr_info("Not able to create %s\n", prop->name);
			return NULL;
		}
		module_id = prop->name;
		break;
	}

	if (!module_id) {
		pr_info("Module name not found at %s, parent %s\n",
			module->full_name, nplcroot->full_name);
		return NULL;
	}

	/* Get the plugin-module node whose asset-id match with module ID */
	found = false;
	for_each_child_of_node(plmroot, child) {
		of_property_for_each_string(child, "asset-id", prop, s) {
			if (!strcmp(module_id, s)) {
				pr_debug("Asset matched ID %s:%s\n", module_id,
					 child->full_name);
				cinfo = nplcroot->data;
				cinfo->org_pm = child;
				found = true;
				break;
			}
		}
		if (found)
			break;
	}

	if (!found) {
		pr_debug("Plugin module %s not found\n", module->full_name);
		return NULL;
	}

	/* Process for down stream connectors for this module */
	ds = of_get_child_by_name(child, "downstream");
	if (ds) {
		link_connection_to_plugin_modules(plmroot, nplcroot,
						  ds, module);
		return nplcroot;
	}

	for_each_child_of_node(module, child) {
		nplcroot = connect_all_child_modules(plmroot, nplcroot, child);
		if (!nplcroot) {
			pr_info("Deadend found at %s\n", child->full_name);
			return NULL;
		}
	};

	return nplcroot;
}

static int link_connection_to_plugin_modules(struct device_node *plmroot,
					     struct device_node *plcroot,
					     struct device_node *ds,
					     struct device_node *connector)
{
	struct device_node *ds_con, *module, *new_connector;
	struct device_node *nplcroot;
	const char *s, *con_name;
	int ret, naddr, i;
	int mod_add, add;
	bool found;

	for_each_child_of_node(ds, ds_con) {
		/* Match the connection bus with plug-in-module */
		ret = of_property_read_string(ds_con, "identification-bus", &s);
		if (ret)
			continue;

		new_connector = NULL;
		if (*s == '/') {
			con_name = strrchr(connector->full_name, '/');
			if (!strcmp(con_name, s))
				new_connector = connector;
		} else if ((*s == '.') && (*(s + 1) == '/')) {
			new_connector = of_get_nested_child_by_name(connector,
								    s + 2);
		}

		if (!new_connector)
			continue;

		naddr = of_property_count_u32_elems(ds_con,
						    "identification-slave-add");
		if (naddr <= 0) {
			nplcroot = add_module_connection(plcroot, NULL,
							 ds_con->name);
			if (!nplcroot)
				return 0;

			for_each_child_of_node(new_connector, module)
				connect_all_child_modules(plmroot,
							  nplcroot, module);
			continue;
		}

		nplcroot = NULL;
		for_each_child_of_node(new_connector, module) {
			found = false;

			mod_add = get_node_address(module);
			if (mod_add <= 0)
				continue;

			for (i = 0; i < naddr; ++i) {
				u32 pval;

				ret = of_property_read_u32_index(
					ds_con, "identification-slave-add",
					i, &pval);
				if (ret < 0)
					continue;

				add = pval;
				if (add == mod_add)
					found = true;
			}

			if (found) {
				if (!nplcroot)
					nplcroot = add_module_connection(
							plcroot, NULL,
							ds_con->name);
				if (!nplcroot)
					return 0;
				connect_all_child_modules(plmroot, nplcroot,
							  module);
			}
		}
	}

	return 0;
}

static void connection_manager(void)
{
	struct device_node *plmroot, *conroot;
	struct device_node *plmmods, *ds, *connector;
	struct device_node *plcroot;
	struct connection_info *cinfo;

	plmroot = of_find_node_by_path("/plugin-modules");
	if (!plmroot) {
		pr_info("Plugin module not found\n");
		return;
	}

	conroot = of_find_node_by_path("/chosen/plugin-manager/ids/connection");
	if (!conroot) {
		pr_info("chosen/conenction not found\n");
		return;
	}

	plcroot = create_simple_device_node("/", "plugin-connection",
					    sizeof(*cinfo));
	if (!plcroot) {
		pr_info("Failed to create node /plugin-connection\n");
		return;
	}

	for_each_child_of_node(plmroot, plmmods) {
		if (of_property_read_bool(plmmods, "the-root-base-board")) {
			cinfo = plcroot->data;
			cinfo->node = plcroot;
			cinfo->org_pm = plmmods;
			break;
		}
	}

	/* Create connection tree based on module connected */
	for_each_child_of_node(conroot, connector) {
		for_each_child_of_node(plmroot, plmmods) {
			ds = of_get_child_by_name(plmmods, "downstream");
			if (!ds)
				continue;
			link_connection_to_plugin_modules(plmroot, plcroot, ds,
							  connector);
		}
	}

	/* Duplicate plug-in module nodes to each of modules for override */
	create_dup_nodes_for_connected_plm(plcroot);

	/* Link modules node to connector node */
	link_module_node_to_connector_node(plcroot);

	/* Process upstream, device and downstream nodes */
	process_plugin_module_connections(plcroot);

	free_simple_device_node(plcroot);
}

static int __init plugin_manager_init(void)
{
	struct device_node *pm_node;
	struct device_node *child;
	int ret;

	pr_info("Initializing plugin-manager\n");

	connection_manager();

	pm_node = of_find_node_by_path("/plugin-manager");
	if (!pm_node) {
		pr_info("Plugin-manager not available\n");
		return 0;
	}

	if (!of_device_is_available(pm_node)) {
		pr_info("Plugin-manager status disabled\n");
		return 0;
	}

	for_each_available_child_of_node(pm_node, child) {
		ret = plugin_manager(child);
		if (ret < 0)
			pr_err("Error in parsing node %s: %d\n",
				child->full_name, ret);
	}
	return 0;
}
core_initcall(plugin_manager_init);
