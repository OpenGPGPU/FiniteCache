#include "ogpu.h"
#include "ogpu_compute.h"

int ogpu_compute_init() {
	int err;
	err = ogpu_chardev_init();
	if (err < 0)
		goto err_ioctl;

	err = ogpu_topology_init();
	if (err < 0)
		goto err_topology;

	return 0;

err_topology:
	ogpu_chardev_exit();

err_ioctl:
	pr_err("OGPU Compute init error!\n");
	return err;
}


void ogpu_compute_fini(void) {
	// clean processess ...
	ogpu_chardev_exit();
}

