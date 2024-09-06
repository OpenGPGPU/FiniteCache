#include "ogpu.h"

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

	return 0;
}
