#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/dmaengine.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/genalloc.h>
#include <linux/hmm.h>
#include <linux/migrate.h>

#include "echodev-cmd.h"

#define DEVNR 64
#define DEVNRNAME "echodev"

#define VID 0x8192
#define DID 0x0001

#define DMA_SRC 0x10
#define DMA_DST 0x18
#define DMA_CNT 0x20
#define DMA_CMD 0x28
#define DMA_RUN 1

struct echodev {
	struct pci_dev *pdev;
	void __iomem *ptr_bar0;
	void __iomem *ptr_bar1;
	uint64_t memory_offset;
	struct gen_pool *dram_pg_pool;
	struct list_head list;
	struct cdev cdev;
	uint32_t ih_ring_rptr;
	dev_t dev_nr;
	struct dev_pagemap pgmap;
	struct mmu_interval_notifier notifier;
};

/* Global Variables */
LIST_HEAD(card_list);
static struct mutex lock;
static int card_count = 0;
static dma_addr_t dma_addr;
static dma_addr_t ih_addr;
static void* ring_buffer;

static const struct dev_pagemap_ops svm_migrate_pgmap_ops = {
	.page_free = svm_migrate_page_free,
	.migrate_to_ram = svm_migrate_to_ram,
};


static bool svm_range_cpu_invalidate_pagetables(struct mmu_interval_notifier *mn,
						const struct mmu_notifier_range *range,
						unsigned long cur_seq)
{
	struct echodev *echo = container_of(mn, struct echodev, notifier);

	if (range->event == MMU_NOTIFY_MIGRATE && range->owner == echo)
		return true;

	mmu_interval_set_seq(mn, cur_seq);
	// invalidate gpu page ...
	return true;
	
}

static const struct mmu_interval_notifier_ops svm_range_mn_ops = {
	.invalidate = svm_range_cpu_invalidate_pagetables,
};

static void mm_init(struct echodev *echo)
{
	struct dev_pagemap *pgmap;
	uint64_t size;
	struct resource *res = NULL;
	void *r;

	echo->memory_offset = 4096;  // first page for pagetable entry
	echo->dram_pg_pool = gen_pool_create(12, -1);
	gen_pool_add(echo->dram_pg_pool, 4096, 64 * 1024 * 1024 - 4096, -1);
	echo->ih_ring_rptr = 0;

	pgmap = &echo->pgmap;
	memset(pgmap, 0, sizeof(*pgmap));

	size = 64 * 1024 * 1024;
	res = devm_request_free_mem_region(&echo->pdev->dev, &iomem_resource, size);
	if (!res)
		printk("devm request failed\n");
	pgmap->range.start = res.start;
	pgmap->range.end = res.end;
	pgmap->type = MEMORY_DEVICE_PRIVATE;
	pgmap->nr_range = 1;
	pgmap->ops = &svm_migrate_pgmap_ops;
	pgmap->owner = echo;
	pgmap->flags = 0;

	devm_memremap_pages(&echo->pdev->dev , pgmap);
	if (!r) {
		printk("devm memremap failed\n");
	}
}


static void echo_page_fault(struct echodev *echo, uint64_t va)
{
	struct mm_struct *mm = echo->notifier.mm;
	struct vm_area_struct *vma;

	vma = vma_lookup(mm, va);
	if (!vma || !(vma->vm_flags & VM_READ)) {
		printk("gpu page fault invalid va %ld\n", va);
		return;
	}
}


static irqreturn_t echo_irq_handler(int irq_nr, void *data)
{
	uint32_t ih_ring_wptr = 0;
	uint64_t va;
	uint64_t *ih_ring = (uint64_t *)(ring_buffer + 4096);
	struct echodev *echo = (struct echodev *) data;
	// visit ih ring
        ih_ring_wptr = ioread32(echo->ptr_bar0 + 0x6C);
        while((ih_ring_wptr - echo->ih_ring_rptr) != 0) {
		va = ih_ring[echo->ih_ring_rptr/8];
		printk("driver ih handle va %ld\n", va);



		echo->ih_ring_rptr += 8;
        }
	
	iowrite32(echo->ih_ring_rptr, echo->ptr_bar0 + 0x68);
	if(ioread32(echo->ptr_bar0 + 8) & 0x1) {
		printk("echodev-drv - Legacy IRQ triggered!\n");
		iowrite32(2, echo->ptr_bar0 + 8);
	}
	return IRQ_HANDLED;
}

static int dma_transfer(struct echodev *echo, void *buffer, int count, dma_addr_t addr, enum dma_data_direction dir)
{
	dma_addr_t buffer_dma_addr = dma_map_single(&echo->pdev->dev, buffer, count, dir);

	/* Setup the DMA controller */
	iowrite32(count, echo->ptr_bar0 + DMA_CNT);

	switch(dir) {
		case DMA_TO_DEVICE: /* 1 */
			iowrite32(buffer_dma_addr, echo->ptr_bar0 + DMA_SRC);
			iowrite32(addr, echo->ptr_bar0 + DMA_DST);
			break;
		case DMA_FROM_DEVICE: /* 2 */
			iowrite32(buffer_dma_addr, echo->ptr_bar0 + DMA_DST);
			iowrite32(addr, echo->ptr_bar0 + DMA_SRC);
			break;
		default:
			return -EFAULT;
	}

	/* Let's fire the dma */
	iowrite32(DMA_RUN | dir, echo->ptr_bar0 + DMA_CMD);

	dma_unmap_single(&echo->pdev->dev, buffer_dma_addr, count, dir);
	return 0;
}

static int echo_open(struct inode *inode, struct file *file)
{
	struct echodev *echo;
	dev_t dev_nr = inode->i_rdev;

	list_for_each_entry(echo, &card_list, list) {
		if(echo->dev_nr == dev_nr) {
			mmu_interval_notifier_insert(echo->nofifier, current->mm,
				0, ULONG_MAX & PAGE_MASK, &svm_range_mn_ops);
			file->private_data = echo;
			return 0;
		}
	}

	return -ENODEV;
}

static ssize_t echo_write(struct file *file, const char __user *user_buffer, size_t count, loff_t *offs)
{
        char *buf;
        int not_copied, to_copy = (count + *offs < 4096) ? count : 4096 - *offs;
        struct echodev *echo = (struct echodev *) file->private_data;

        if(*offs >= pci_resource_len(echo->pdev, 1))
                return 0;

        buf = kmalloc(to_copy, GFP_ATOMIC);
        not_copied = copy_from_user(buf, user_buffer, to_copy);

        dma_transfer(echo, buf, to_copy, *offs, DMA_TO_DEVICE);

        kfree(buf);
        *offs += to_copy - not_copied;
        return to_copy - not_copied;
}

static ssize_t echo_read(struct file *file, char __user *user_buffer, size_t count, loff_t *offs)
{
        char *buf;
        struct echodev *echo = (struct echodev *) file->private_data;
        int not_copied, to_copy = (count + *offs < pci_resource_len(echo->pdev, 1)) ? count : pci_resource_len(echo->pdev, 1) - *offs;

        if(to_copy == 0)
                return 0;

        buf = kmalloc(to_copy, GFP_ATOMIC);

        dma_transfer(echo, buf, to_copy, *offs, DMA_FROM_DEVICE);

        mdelay(5);
        not_copied = copy_to_user(user_buffer, buf, to_copy);

        kfree(buf);
        *offs += to_copy - not_copied;
        return to_copy - not_copied;
}

static int echo_mmap(struct file *file, struct vm_area_struct *vma)
{
	int status;
	unsigned long mmap_offset;
	struct echodev *echo = (struct echodev *) file->private_data;

	// mmap_offset = vma->vm_pgoff << PAGE_SHIFT;

	status = io_remap_pfn_range(vma, vma->vm_start,
				 dma_addr >> PAGE_SHIFT, 8192, vma->vm_page_prot);
	if(status) {
		printk("echodev-drv - Error mmap\n");
		return -status;
	}
	return 0;
}

static long int echo_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	struct echodev *echo = (struct echodev *) file->private_data;
	u32 val;
	struct kern_ring kern_args;
	switch(cmd) {
		case GET_ID:
			val = ioread32(echo->ptr_bar0 + 0x00);
			return copy_to_user((u32 *) arg, &val, sizeof(val));
		case GET_INV:
			val = ioread32(echo->ptr_bar0 + 0x04);
			return copy_to_user((u32 *) arg, &val, sizeof(val));
		case GET_RAND:
			val = ioread32(echo->ptr_bar0 + 0x0C);
			return copy_to_user((u32 *) arg, &val, sizeof(val));
		case SET_INV:
			if(0 != copy_from_user(&val, (u32 *) arg, sizeof(val)))
				return -EFAULT;
			iowrite32(val, echo->ptr_bar0 + 0x4);
			return 0;
		case IRQ:
			iowrite32(1, echo->ptr_bar0 + 0x8);
			return 0;
		case KERN_RING:
			if (0 != copy_from_user(&kern_args, (void *)arg, sizeof(kern_args)))
				return -EFAULT;
			printk("write kern ring\n");
			iowrite32(dma_addr & 0xffffffff, echo->ptr_bar0 + 0x48);
			iowrite32((uint32_t)(dma_addr >> 32), echo->ptr_bar0 + 0x4c);
			iowrite32(kern_args.size, echo->ptr_bar0 + 0x58);
			iowrite32(kern_args.rptr, echo->ptr_bar0 + 0x50);
			iowrite32(kern_args.wptr, echo->ptr_bar0 + 0x54);

			// ih ring
			iowrite32((dma_addr+4096) & 0xffffffff, echo->ptr_bar0 + 0x60);
			iowrite32((uint32_t)(dma_addr >> 32), echo->ptr_bar0 + 0x64);
			iowrite32(127, echo->ptr_bar0 + 0x70);
			iowrite32(0, echo->ptr_bar0 + 0x68);
			iowrite32(0, echo->ptr_bar0 + 0x6c);

			return 0;
		case KERN_WPTR:
			if (0 != copy_from_user(&val, (u32 *)arg, sizeof(val)))
				return -EFAULT;
			printk("write kern wptr %d\n", val);
			iowrite32(val, echo->ptr_bar0 + 0x54);
			return 0;
		default:
			return -EINVAL;
	}
}

static struct file_operations fops = {
	.open = echo_open,
	.mmap = echo_mmap,
	.read = echo_read,
	.write = echo_write,
	.unlocked_ioctl = echo_ioctl,
};

static struct pci_device_id echo_ids[] = {
	{PCI_DEVICE(VID, DID)},
	{},
};
MODULE_DEVICE_TABLE(pci, echo_ids);

static int echo_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int status, irq_nr;
	struct echodev *echo;

	ring_buffer = dma_alloc_coherent(&pdev->dev, 8192, &dma_addr, GFP_KERNEL);
	if (!ring_buffer) {
		printk("alloc ringbuffer failed!\n");
		return -ENOMEM;
	}

	echo = devm_kzalloc(&pdev->dev, sizeof(struct echodev), GFP_KERNEL);
	if(!echo)
		return -ENOMEM;

	mutex_lock(&lock);
	cdev_init(&echo->cdev, &fops);
	echo->cdev.owner = THIS_MODULE;

	echo->dev_nr = MKDEV(DEVNR, card_count++);
	status = cdev_add(&echo->cdev, echo->dev_nr, 1);
	if(status < 0) {
		printk("echodev-drv - Error adding cdev\n");
		return status;
	}

	list_add_tail(&echo->list, &card_list);
	mutex_unlock(&lock);

	echo->pdev = pdev;

	status = pcim_enable_device(pdev);
	if(status != 0) {
		printk("echodev-drv - Error enabling device\n");
		goto fdev;
	}

	pci_set_master(pdev);

	echo->ptr_bar0 = pcim_iomap(pdev, 0, pci_resource_len(pdev, 0));
	if(!echo->ptr_bar0) {
		printk("echodev-drv - Error mapping BAR0\n");
		status = -ENODEV;
		goto fdev;
	}

	echo->ptr_bar1 = pcim_iomap(pdev, 1, pci_resource_len(pdev, 1));
	if(!echo->ptr_bar1) {
		printk("echodev-drv - Error mapping BAR1\n");
		status = -ENODEV;
		goto fdev;
	}

	pci_set_drvdata(pdev, echo);

	status = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_ALL_TYPES);
	if(status != 1) {
		printk("echodev-drv - Error alloc_irq returned %d\n", status);
		status = -ENODEV;
		goto fdev;
	}

	irq_nr = pci_irq_vector(pdev, 0);
	printk("echodev-drv - IRQ Number: %d\n", irq_nr);

	status = devm_request_irq(&pdev->dev, irq_nr, echo_irq_handler, IRQF_SHARED,
	"echodev-irq", echo);
	if(status != 0) {
		printk("echodev-drv - Error requesting interrupt\n");
		goto fdev;
	}

	mm_init(echo);
	return 0;

fdev:
	/* Removing echo from list is missing */
	cdev_del(&echo->cdev);
	return status;

}

static void echo_remove(struct pci_dev *pdev)
{
	struct echodev *echo = (struct echodev *) pci_get_drvdata(pdev);
	printk("echodev-drv - Removing the device with Device Number %d:%d\n",
	MAJOR(echo->dev_nr), MINOR(echo->dev_nr));
	if(echo) {
		mutex_lock(&lock);
		list_del(&echo->list);
		mutex_unlock(&lock);
		cdev_del(&echo->cdev);
	}
	pci_free_irq_vectors(pdev);
}

static struct pci_driver echo_driver = {
	.name = "echodev-driver",
	.probe = echo_probe,
	.remove = echo_remove,
	.id_table = echo_ids,
};

static int __init echo_init(void)
{
	int status;
	dev_t dev_nr = MKDEV(DEVNR, 0);

	status = register_chrdev_region(dev_nr, MINORMASK + 1, DEVNRNAME);
	if(status < 0) {
		printk("echodev-drv - Error registering Device numbers\n");
		return status;
	}

	mutex_init(&lock);

	status = pci_register_driver(&echo_driver);
	if(status < 0) {
		printk("echodev-drv - Error registering driver\n");
		unregister_chrdev_region(dev_nr, MINORMASK + 1);
		return status;
	}
	return 0;
}

static void __exit echo_exit(void)
{
	dev_t dev_nr = MKDEV(DEVNR, 0);
	unregister_chrdev_region(dev_nr, MINORMASK + 1);
	pci_unregister_driver(&echo_driver);
}

module_init(echo_init);
module_exit(echo_exit);

MODULE_INFO(intree, "Y");
MODULE_LICENSE("GPL");
