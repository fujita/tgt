/*
 * STGT core sysfs files
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */
#include <stgt_target.h>
#include <stgt_device.h>

/*
 * Target files
 */
#define stgt_target_show_fn(field, format_string)			\
static ssize_t								\
show_##field (struct class_device *cdev, char *buf)			\
{									\
	struct stgt_target *target = cdev_to_stgt_target(cdev);		\
	return snprintf (buf, 20, format_string, target->field);	\
}

#define stgt_target_rd_attr(field, format_string)		\
	stgt_target_show_fn(field, format_string)		\
static CLASS_DEVICE_ATTR(field, S_IRUGO, show_##field, NULL);

stgt_target_rd_attr(queued_cmnds, "%u\n");

static struct class_device_attribute *stgt_target_attrs[] = {
	&class_device_attr_queued_cmnds,
	NULL
};

static void stgt_target_class_release(struct class_device *cdev)
{
	struct stgt_target *target = cdev_to_stgt_target(cdev);
	kfree(target);
}

static struct class stgt_target_class = {
	.name = "stgt_target",
	.release = stgt_target_class_release,
};

static struct class_device_attribute *class_attr_overridden(
				struct class_device_attribute **attrs,
				struct class_device_attribute *attr)
{
	int i;

	if (!attrs)
		return NULL;

	for (i = 0; attrs[i]; i++)
		if (!strcmp(attrs[i]->attr.name, attr->attr.name))
			return attrs[i];
	return NULL;
}

static int class_attr_add(struct class_device *classdev,
			  struct class_device_attribute *attr)
{
	struct class_device_attribute *base_attr;

	/*
	 * Spare the caller from having to copy things it's not interested in.
	*/
	base_attr = class_attr_overridden(stgt_target_attrs, attr);
	if (base_attr) {
		/* extend permissions */
		attr->attr.mode |= base_attr->attr.mode;

		/* override null show/store with default */
		if (!attr->show)
			attr->show = base_attr->show;
		if (!attr->store)
			attr->store = base_attr->store;
	}

	return class_device_create_file(classdev, attr);
}

int stgt_sysfs_register_target(struct stgt_target *target)
{
	struct class_device *cdev = &target->cdev;
	int err, i;

	cdev->class = &stgt_target_class;
	snprintf(cdev->class_id, BUS_ID_SIZE, "target%d", target->tid);

	err = class_device_register(cdev);
	if (err)
		return err;

	if (target->stt->target_attrs) {
		for (i = 0; target->stt->target_attrs[i]; i++) {
			err = class_attr_add(&target->cdev,
					     target->stt->target_attrs[i]);
                        if (err)
                                goto cleanup;
		}
	}

	for (i = 0; stgt_target_attrs[i]; i++) {
		if (!class_attr_overridden(target->stt->target_attrs,
					   stgt_target_attrs[i])) {
			err = class_device_create_file(&target->cdev,
						       stgt_target_attrs[i]);
			if (err)
				goto cleanup;
		}
	}

	return 0;

cleanup:
	class_device_unregister(cdev);
	return err;
}

void stgt_sysfs_unregister_target(struct stgt_target *target)
{
	class_device_unregister(&target->cdev);
}

/*
 * Device files
 */
#define stgt_device_show_fn(field, format_string)			\
static ssize_t								\
show_##field (struct class_device *cdev, char *buf)			\
{									\
	struct stgt_device *device = cdev_to_stgt_device(cdev);		\
	return sprintf(buf, format_string, device->field);	\
}

#define stgt_device_rd_attr(field, format_string)		\
	stgt_device_show_fn(field, format_string)		\
static CLASS_DEVICE_ATTR(field, S_IRUGO, show_##field, NULL);

stgt_device_rd_attr(path, "%s\n");
stgt_device_rd_attr(size, "%llu\n");

static struct class_device_attribute *stgt_device_attrs[] = {
	&class_device_attr_path,
	&class_device_attr_size,
	NULL,
};


static void stgt_device_class_release(struct class_device *cdev)
{
	struct stgt_device *device = cdev_to_stgt_device(cdev);
	struct stgt_target *target = device->target;

	class_device_put(&target->cdev);
	kfree(device->sdt_data);
	kfree(device->path);
	kfree(device);
}

static struct class stgt_device_class = {
	.name = "stgt_device",
	.release = stgt_device_class_release,
};

int stgt_sysfs_register_device(struct stgt_device *device)
{
	struct stgt_target *target = device->target;
	struct class_device *cdev = &device->cdev;
	int err, i;

	cdev->class = &stgt_device_class;
	snprintf(cdev->class_id, BUS_ID_SIZE, "device%d:%llu",
		 target->tid, device->dev_id);
	err = class_device_register(cdev);
	if (err)
		return err;

	/*
	 * get handle to target so our parent is never released before
	 * us
	 */
	if (!class_device_get(&target->cdev))
		return -EINVAL;

	if (device->sdt->device_attrs) {
		for (i = 0; device->sdt->device_attrs[i]; i++) {
			err = class_attr_add(&device->cdev,
					     device->sdt->device_attrs[i]);
                        if (err)
                                goto cleanup;
		}
	}

	for (i = 0; stgt_device_attrs[i]; i++) {
		if (!class_attr_overridden(device->sdt->device_attrs,
					   stgt_device_attrs[i])) {
			err = class_device_create_file(&device->cdev,
						       stgt_device_attrs[i]);
			if (err)
				goto cleanup;
		}
	}

	return 0;

cleanup:
	class_device_put(&target->cdev);
	class_device_unregister(cdev);
	return err;

}

void stgt_sysfs_unregister_device(struct stgt_device *device)
{
	class_device_unregister(&device->cdev);
}

int stgt_sysfs_init(void)
{
	int err;

	err = class_register(&stgt_target_class);
	if (err)
		return err;

	err = class_register(&stgt_device_class);
	if (err)
		class_unregister(&stgt_target_class);
	return err;
}

void stgt_sysfs_exit(void)
{
	class_unregister(&stgt_target_class);
	class_unregister(&stgt_device_class);
}
