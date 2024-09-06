#include "ogpu.h"
#include "ogpu_drv.h"

extern const struct pci_device_id *pciidlist;


/* topology_device_list - Master list of all topology devices */
static struct list_head topology_device_list;

// void ogpu_topology_add_device(struct ogpu_device *odev)
// {
// 	return;
// }
// 
// struct ogpu_topology_device *ogpu_create_topology_device(
// 		struct list_head *device_list)
// {
// 	struct ogpu_topology_device *dev;
// 
// 	dev = ogpu_alloc_struct(dev);
// 	if (!dev) {
// 		pr_err("No memory to allocate a topology device!");
// 		return NULL;
// 	}
// 
// 	INIT_LIST_HEAD(&dev->mem_props);
//         INIT_LIST_HEAD(&dev->cache_props);
//         INIT_LIST_HEAD(&dev->io_link_props);
//         INIT_LIST_HEAD(&dev->p2p_link_props);
//         INIT_LIST_HEAD(&dev->perf_props);
// 
//         list_add_tail(&dev->list, device_list);
// 
//         return dev;
// 
// }

int ogpu_topology_init(void)
{
	const struct pci_device_id *ids = pciidlist;

	 /* topology_device_list - Master list of all topology devices
         */
        
        /* Initialize the head for the both the lists */
        // INIT_LIST_HEAD(&topology_device_list);
        // init_rwsem(&topology_lock);
	return 0;
}
