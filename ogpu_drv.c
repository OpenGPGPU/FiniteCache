#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>

#include <drm/drm_gem.h>
#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_drv.h>
#include <drm/drm_fbdev_generic.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_managed.h>
#include <drm/drm_pciids.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_gem_shmem_helper.h>
#include <drm/drm_accel.h>
#include <drm/drm_file.h>
#include <drm/drm_prime.h>

#include <drm/drm_print.h>
#include <drm/drm_debugfs.h>


#include "ogpu.h"
#include "ogpu_drv.h"
#include "ogpu_device.h"
#include "ogpu_compute.h"


const struct pci_device_id pciidlist[] = {
  { PCI_DEVICE(0x8192, 0x0001), },
  { 0, }
};
MODULE_DEVICE_TABLE(pci, pciidlist);


static int ogpu_drm_open(struct drm_device *dev, struct drm_file *file)
{
	return 0;
}

static void ogpu_drm_postclose(struct drm_device *dev, struct drm_file *file)
{
	return;
}



static const struct drm_driver ogpu_accel_driver = {
	.driver_features = DRIVER_COMPUTE_ACCEL | DRIVER_GEM,
	.open = ogpu_drm_open,
	.postclose = ogpu_drm_postclose,
	DRM_GEM_SHMEM_DRIVER_OPS,

	.name = DRIVER_NAME,
	.desc = DRIVER_DESC,

	.major = DRIVER_MAJOR,
	.minor = DRIVER_MINOR,
};

static int ogpu_pci_probe(struct pci_dev *pdev,
                             const struct pci_device_id *ent)
{
	struct drm_device *ddev;
	struct ogpu_device *odev;
	unsigned long flags = ent->driver_data;
	int ret;

	
	odev = devm_drm_dev_alloc(&pdev->dev, &ogpu_accel_driver, typeof(*odev), ddev);
	odev->pdev = pdev;
	odev->dev = &pdev->dev;
	ddev = ogpu_to_drm(odev);

	 pci_set_drvdata(pdev, ddev);

	ret = drm_dev_register(ddev, flags);
	if (ret)
		goto out_devres;

	ogpu_device_init(odev, flags);
	return 0;

out_devres:
	DRM_ERROR("DRM dev register failed!");
	devres_release_group(&pdev->dev, NULL);
	return ret;	
}


static void ogpu_pci_remove(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);
	// struct ogpu_device *odev = drm_to_odev(dev);

	drm_dev_unplug(dev);

	pci_disable_device(pdev);
	pci_wait_for_pending_transaction(pdev);
}

static struct pci_driver  ogpu_pci_driver = {
	.name = DRIVER_NAME, 
	.id_table = pciidlist,
	.probe = ogpu_pci_probe,
	.remove = ogpu_pci_remove,
	// .shutdown = ogpu_pci_shutdown,
	// .driver.pm = 
	// .err_handler = ogpu_pci_err_handler,
	// .dev_groups = ogpu_sysfs_groups,
};

static int __init ogpu_init(void)
{
	int ret;
	ret = ogpu_compute_init();
	if (ret)
		return ret;
	return pci_register_driver(&ogpu_pci_driver);
}

static void __exit ogpu_exit(void)
{
	ogpu_compute_fini();
	pci_unregister_driver(&ogpu_pci_driver);
}


module_init(ogpu_init);
module_exit(ogpu_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL v2");
