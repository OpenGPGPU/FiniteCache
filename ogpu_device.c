#include "ogpu.h"
#include <linux/pci.h>

/**
 * ogpu_device_init - initialize the driver
 *
 * @odev: ogpu_device pointer
 * @flags: driver flags
 *      
 * Initializes the driver info and hw (all asics).
 * Returns 0 for success or an error on failure.
 * Called at driver startup.
 */ 
int ogpu_device_init(struct ogpu_device *odev,
                       uint32_t flags)
{       
	struct drm_device *ddev = ogpu_to_drm(odev);
	struct pci_dev *pdev = odev->pdev;
    
	odev->flags = flags;
    
	odev->usec_timeout = OGPU_MAX_USEC_TIMEOUT;

	odev->mmio_base = pci_resource_start(pdev, 1);
	odev->mmio_size = pci_resource_len(pdev, 1);

	odev->rmmio_base = pci_resource_start(pdev, 0);
	odev->rmmio_size = pci_resource_len(pdev, 0);

	odev->rmmio = ioremap(odev->rmmio_base, odev->rmmio_size);
	if (!odev->rmmio)
		return -ENOMEM;

	return 0;
}
