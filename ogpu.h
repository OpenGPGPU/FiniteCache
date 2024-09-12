#ifndef __OGPU_H__
#define __OGPU_H__

#include <drm/drm_file.h>
#include <drm/drm_drv.h>
#include <drm/drm_device.h>
#include <drm/drm_ioctl.h>
#include <linux/swap.h>


#define OGPU_MAX_USEC_TIMEOUT 1000000  /* 1s */

struct ogpu_device {
	struct device *dev;
	struct pci_dev *pdev;
	struct drm_device ddev;

	// enum ogpu_asic_type asic_type;
	uint32_t family;
	uint32_t rev_id;
	unsigned long flags;
	int usec_timeout;

	// const struct ogpu_asic_funcs *asic_funcs;
	
	// Register/doorbell mmio
	resource_size_t rmmio_base;
	resource_size_t rmmio_size;
	void __iomem *rmmio;

	resource_size_t mmio_base;
	resource_size_t mmio_size;

	// protects concurrent MM_INDEX/DATA based register access
	spinlock_t mmio_idx_lock;
	// struct ogpu_mmio_remap rmmio_remap;

	// protects concurrent SMC based register access
	spinlock_t smc_idx_lock;

	// ogpu_rreg_t smc_rreg;
	// ogpu_wreg_t smc_wreg;

	// protects concurrent PCIE register access
	spinlock_t pcie_idx_lock;
	// ...

	// clock/pll info
	//struct ogpu_clock clock;

	// MC
	// struct ogpu_gmc gmc;
	// struct ogpu_gart gart;
	dma_addr_t dummy_page_addr;

	// struct ogpu_vm_manager vm_manager;
	// struct ogpu_vmhub vmhub[OGPU_MAX_VMHUBS];
	// DECLARE_BITMAP(vmhubs_mask, OGPU_MAX_VMHUBS);

	// memory managerment
	// struct ogpu_mman mman;

	// rings
	u64 fence_context;
	unsigned num_rings;
	// struct ogpu_ring *rings[OGPU_MAX_RINGS];
	struct dma_fence __rcu *gang_submit;
	bool b_pool_read;

	// interrupts
	// struct ogpu_irq irq;

};

static inline struct ogpu_device *drm_to_ogpu(struct drm_device *ddev)
{
	return container_of(ddev, struct ogpu_device, ddev);
}

static inline struct drm_device *ogpu_to_drm(struct ogpu_device *odev)
{
	return &odev->ddev;
}

#endif
