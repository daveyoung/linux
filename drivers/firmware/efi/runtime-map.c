/*
 * linux/drivers/efi/runtime-map.c
 * Copyright (C) 2013 Red Hat, Inc., Dave Young <dyoung@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2.0 as published by
 * the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/efi.h>
#include <linux/slab.h>

#include <asm/setup.h>

struct efi_runtime_map_entry {
	efi_memory_desc_t md;
	struct kobject kobj;   /* kobject for each entry */
};

static struct efi_runtime_map_entry **map_entries;
static ssize_t map_attr_show(struct kobject *kobj,
				struct attribute *attr, char *buf);

struct map_attribute {
	struct attribute attr;
	ssize_t (*show)(struct efi_runtime_map_entry *entry, char *buf);
};

static struct map_attribute map_type_attr = __ATTR_RO(type);
static struct map_attribute map_phys_addr_attr   = __ATTR_RO(phys_addr);
static struct map_attribute map_virt_addr_attr  = __ATTR_RO(virt_addr);
static struct map_attribute map_num_pages_attr  = __ATTR_RO(num_pages);
static struct map_attribute map_attribute_attr  = __ATTR_RO(attribute);

/*
 * These are default attributes that are added for every memmap entry.
 */
static struct attribute *def_attrs[] = {
	&map_type_attr.attr,
	&map_phys_addr_attr.attr,
	&map_virt_addr_attr.attr,
	&map_num_pages_attr.attr,
	&map_attribute_attr.attr,
	NULL
};

static const struct sysfs_ops map_attr_ops = {
	.show = map_attr_show,
};

static inline struct efi_runtime_map_entry *to_map_entry(struct kobject *kobj)
{
	return container_of(kobj, struct efi_runtime_map_entry, kobj);
}

static void map_release(struct kobject *kobj)
{
	struct efi_runtime_map_entry *entry;

	entry = to_map_entry(kobj);
	kfree(entry);
}

static struct kobj_type __refdata map_ktype = {
	.sysfs_ops	= &map_attr_ops,
	.default_attrs	= def_attrs,
	.release	= map_release,
};

static ssize_t type_show(struct efi_runtime_map_entry *entry, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "0x%x\n", entry->md.type);
}

#define EFI_RUNTIME_FIELD(var) entry->md.var

#define EFI_RUNTIME_U64_ATTR_SHOW(name) \
static ssize_t name##_show(struct efi_runtime_map_entry *entry, char *buf) \
{ \
	return snprintf(buf, PAGE_SIZE, "0x%llx\n", EFI_RUNTIME_FIELD(name)); \
}

EFI_RUNTIME_U64_ATTR_SHOW(phys_addr);
EFI_RUNTIME_U64_ATTR_SHOW(virt_addr);
EFI_RUNTIME_U64_ATTR_SHOW(num_pages);
EFI_RUNTIME_U64_ATTR_SHOW(attribute);

static inline struct map_attribute *to_map_attr(struct attribute *attr)
{
	return container_of(attr, struct map_attribute, attr);
}

static ssize_t map_attr_show(struct kobject *kobj,
				struct attribute *attr, char *buf)
{
	struct efi_runtime_map_entry *entry = to_map_entry(kobj);
	struct map_attribute *map_attr = to_map_attr(attr);

	return map_attr->show(entry, buf);
}

static struct kset *map_kset;

/*
 * Add map entry on sysfs
 */
static struct efi_runtime_map_entry *add_sysfs_runtime_map_entry(int nr)
{
	int ret;
	unsigned long desc_size;
	struct efi_runtime_map_entry *entry;
	struct efi_info *e = &boot_params.efi_info;

	if (!map_kset) {
		map_kset = kset_create_and_add("runtime-map", NULL,
				efi_kobj);
		if (!map_kset)
			return ERR_PTR(-ENOMEM);
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		kset_unregister(map_kset);
		return entry;
	}

	desc_size = e->efi_memdesc_size;
	memcpy(&entry->md, efi_runtime_map + nr * desc_size,
		sizeof(efi_memory_desc_t));

	kobject_init(&entry->kobj, &map_ktype);
	entry->kobj.kset = map_kset;
	ret = kobject_add(&entry->kobj, NULL, "%d", nr);
	if (ret) {
		kobject_put(&entry->kobj);
		kset_unregister(map_kset);
		return ERR_PTR(ret);
	}

	return entry;
}

static int __init efi_runtime_map_init(void)
{
	int i, j, ret = 0;
	struct efi_runtime_map_entry *entry;

	if (!efi_runtime_map) {
		pr_warn("no efi_runtime_map found\n");
		return -EINVAL;
	}

	map_entries = kzalloc(nr_efi_runtime_map *
		sizeof(struct efi_runtime_map_entry *), GFP_KERNEL);
	if (!map_entries)
		return -ENOMEM;

	for (i = 0; i < nr_efi_runtime_map; i++) {
		entry = add_sysfs_runtime_map_entry(i);
		if (IS_ERR(entry)) {
			for (j = i - 1; j > 0; j--) {
				entry = *(map_entries + j);
				kobject_put(&entry->kobj);
			}
			if (map_kset)
				kset_unregister(map_kset);
			ret = PTR_ERR(entry);
			goto out;
		}
		*(map_entries + i) = entry;
	}

out:
	return ret;
}
late_initcall(efi_runtime_map_init);
