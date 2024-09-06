#include <linux/device.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>

#include "ogpu_compute.h"

static long compute_ioctl(struct file *, unsigned int, unsigned long);
static int compute_open(struct inode *, struct file *);
static int compute_release(struct inode *, struct file *);
static int compute_mmap(struct file *, struct vm_area_struct *);

static const char compute_dev_name[] = "ogpu";

static const struct file_operations compute_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = compute_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.open = compute_open,
	.release = compute_release,
	.mmap = compute_mmap,
};

static int compute_char_dev_major = -1;
struct device *compute_device;
static const struct class compute_class = {
	.name = compute_dev_name,
};


int ogpu_chardev_init(void)
{
	int err = 0;
	compute_char_dev_major = register_chrdev(0, compute_dev_name, &compute_fops);
	err = compute_char_dev_major;
	if (err < 0)
		goto err_register_chrdev;

	err = class_register(&compute_class);
	if (err)
		goto err_class_create;

	compute_device = device_create(&compute_class, NULL,
					MKDEV(compute_char_dev_major, 0),
					NULL, compute_dev_name);

	err = PTR_ERR(compute_device);
	if (IS_ERR(compute_device))
		goto err_device_create;

	return 0;

err_device_create:
        class_unregister(&compute_class);
err_class_create:
        unregister_chrdev(compute_char_dev_major, compute_dev_name);
err_register_chrdev:
        return err;

}


void ogpu_chardev_exit(void)
{
        device_destroy(&compute_class, MKDEV(compute_char_dev_major, 0));
        class_unregister(&compute_class);
        unregister_chrdev(compute_char_dev_major, compute_dev_name);
        compute_device = NULL;
}


static int compute_open(struct inode *inode, struct file *filep)
{
	struct compute_process *process;
	bool is_32bit_user_mode;
	if (iminor(inode) != 0)
		return -ENODEV;

	is_32bit_user_mode = in_compat_syscall();

	if (is_32bit_user_mode) {
		dev_warn(compute_device,
                        "Process %d (32-bit) failed to open /dev/ogpu\n"
                        "32-bit processes are not supported by ogpu driver\n",
                        current->pid);
                return -EPERM;
	}

	process = compute_create_process(current);
	  if (IS_ERR(process))
                return PTR_ERR(process);

        /* filep now owns the reference returned by kfd_create_process */
        filep->private_data = process;

        dev_dbg(compute_device, "process %d opened, compat mode (32 bit) - %d\n",
                process->pasid, process->is_32bit_user_mode);

        return 0;

}

static int compute_release(struct inode *inode, struct file *filep)
{
	struct compute_process *process = filep->private_data;

	if (process)
		compute_unref_process(process);

	return 0;
}

static long compute_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct compute_process *process;
	// ogpu_ioctl_t *func;
	return 0;
}


static int compute_mmap(struct file *filep, struct vm_area_struct *vma)
{
	return 0;
}
