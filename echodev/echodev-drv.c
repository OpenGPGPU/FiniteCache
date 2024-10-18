#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/dma-fence.h>
#include <linux/dma-direct.h>
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


#define PTE_V (1L << 0)
#define PTE_R (1L << 1)
#define PTE_W (1L << 2)
#define PTE_X (1L << 3)
#define PTE_U (1L << 4)

#define PA2PTE(pa) ((((uint64_t) (pa)) >> 12) << 10)

#define PTE2PA(pte) (((pte) >> 10) << 12)

#define PTE_FLAGS(pte) ((pte) & 0x3FF)


#define PGSHIFT 12
#define PGSIZE 4096
#define PXMASK 0x1FF
#define PXSHIFT(level) (PGSHIFT+(9*(level)))
#define PX(level, va) ((((uint64_t) (va)) >> PXSHIFT(level)) & PXMASK)

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
	struct dma_fence *fence;
	struct mm_struct *mm;
	spinlock_t lock;

};

/* Global Variables */
LIST_HEAD(card_list);
static struct mutex lock;
static int card_count = 0;
static dma_addr_t dma_addr;
// static dma_addr_t ih_addr;
static void* ring_buffer;

static const char *gpu_fence_get_driver_name(struct dma_fence *f)
{
	return "gpu fence";
}

static const char *gpu_fence_get_timeline_name(struct dma_fence *f)
{
	return "gpu fence timeline";
}

static const struct dma_fence_ops fence_ops = {
	.get_driver_name = gpu_fence_get_driver_name,
	.get_timeline_name = gpu_fence_get_timeline_name,
};

static void svm_migrate_page_free(struct page *page)
{
	return;
}

static int dma_transfer2(struct echodev *echo, dma_addr_t buffer, int count, dma_addr_t addr, enum dma_data_direction dir);

static vm_fault_t svm_migrate_to_ram(struct vm_fault *vmf)
{
	// printk("migrate to cpu!!\n");
	struct mm_struct *mm = vmf->vma->vm_mm;
	struct vm_area_struct *vma;
	struct migrate_vma migrate = {0};
	struct echodev *echo;
	void *buf;
	struct page *spage;
	struct page *dpage;
	uint64_t saddr;
	dma_addr_t d_dma_addr;
	uint8_t *kvaddr;

	vma = vma_lookup(mm, vmf->address); 
	echo = vmf->page->zone_device_data;


	printk("migrate to cpu va %lx\n", vmf->address);
	memset(&migrate, 0, sizeof(migrate));
	migrate.vma = vma;
	migrate.start = vmf->address;
	migrate.end = vmf->address + PAGE_SIZE;
	migrate.pgmap_owner = echo; 
	migrate.flags = MIGRATE_VMA_SELECT_DEVICE_PRIVATE;

	buf = kvcalloc(1, 2 * sizeof(*migrate.src) + sizeof(uint64_t) + sizeof(dma_addr_t), GFP_KERNEL);
	migrate.src = buf;
	migrate.dst = migrate.src + 1;
	migrate.fault_page = vmf->page;

	if(!mmget_not_zero(mm))
		pr_err("mm get failed\n");

	mmap_read_lock(mm);
	if(migrate_vma_setup(&migrate)) {
		pr_err("migrate vma setup failed \n");
	}

	if(!migrate.cpages) {
		pr_err("collect migrate page failed\n");
	}
	
	printk("migrate to ram pages %lx\n", migrate.cpages);
	spage = migrate_pfn_to_page(migrate.src[0]);
	saddr = (page_to_pfn(spage) << PAGE_SHIFT) - echo->pgmap.range.start;
	printk("migrate source pfn %lx\n", page_to_pfn(spage));
	printk("migrate to saddr %llx\n", saddr);

	dpage = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, vmf->address);
	if (dpage)
		lock_page(dpage);
	else {
		pr_err("oom!!!\n");
	}
	d_dma_addr = dma_map_page(&echo->pdev->dev, dpage, 0, PAGE_SIZE, DMA_FROM_DEVICE);
	if (dma_mapping_error(&echo->pdev->dev, d_dma_addr))
		pr_err("dma map error!!\n");
	migrate.dst[0] = migrate_pfn(page_to_pfn(dpage));
	printk("migrate dma addr %llx\n", d_dma_addr);
	printk("dpage pfn %lx dma pfn %llx\n",page_to_pfn(dpage), dma_to_phys(&echo->pdev->dev, d_dma_addr) >> PAGE_SHIFT);

	
	printk("migrate source pfn %lx\n", page_to_pfn(spage));
	printk("migrate dst pfn %lx\n", page_to_pfn(dpage));
	kvaddr = kmap(dpage);
	kvaddr[0] = 127;
	kvaddr[1] = 125;
        dma_transfer2(echo, d_dma_addr, 4096, saddr, DMA_FROM_DEVICE);
	dma_fence_wait(echo->fence, true);
	printk("kvaddr data %d %d\n", kvaddr[0], kvaddr[1]);
	// dpage = pfn_to_page(dma_to_phys(&echo->pdev->dev, d_dma_addr) >> PAGE_SHIFT);
	// migrate.dst[0] = migrate_pfn(page_to_pfn(dpage));
	//kvaddr = kmap(dpage);
	// printk("kvaddr dma data %d %d\n", kvaddr[0], kvaddr[1]);

        dma_unmap_page(&echo->pdev->dev, d_dma_addr, PAGE_SIZE, DMA_FROM_DEVICE);
	migrate_vma_pages(&migrate);
	migrate_vma_finalize(&migrate);
	mmap_read_unlock(mm);
	mmput(mm);
	printk("migrate to cpu success\n");
	return 0;
}

static const struct dev_pagemap_ops svm_migrate_pgmap_ops = {
	.page_free = svm_migrate_page_free,
	.migrate_to_ram = svm_migrate_to_ram,
};


static bool svm_range_cpu_invalidate_pagetables(struct mmu_interval_notifier *mn,
						const struct mmu_notifier_range *range,
						unsigned long cur_seq)
{
	printk("svm range invalidate pts \n");

	struct echodev *echo = container_of(mn, struct echodev, notifier);

	if (range->event == MMU_NOTIFY_MIGRATE && range->owner == echo)
		return true;

	//mmu_interval_set_seq(mn, cur_seq);
	// invalidate gpu page ...
	return true;
	
}

static const struct mmu_interval_notifier_ops svm_range_mn_ops = {
	.invalidate = svm_range_cpu_invalidate_pagetables,
};

static int mm_init(struct echodev *echo)
{
	int ret = 0;
	struct dev_pagemap *pgmap;
	uint64_t size;
	struct resource *res = NULL;
	void *r;

	echo->memory_offset = 4096;  // first page for pagetable entry
	echo->dram_pg_pool = gen_pool_create(12, -1);
	if (!echo->dram_pg_pool) {
		pr_err("gen pool create failed\n");
		return -1;
	}
	ret = gen_pool_add(echo->dram_pg_pool, 4096, 64 * 1024 * 1024 - 4096, -1);
	if (IS_ERR(ret)) {
		pr_err("gen pool add failed\n");
		return ret;
	}
	echo->ih_ring_rptr = 0;
	echo->fence = kzalloc(sizeof(*echo->fence), GFP_KERNEL);
	if (!echo->fence) {
		pr_err("fence malloc failed\n");
		return -1;
	}
	spin_lock_init(&echo->lock);
	dma_fence_init(echo->fence, &fence_ops, &echo->lock, 0, 0);

	pgmap = &echo->pgmap;
	memset(pgmap, 0, sizeof(*pgmap));

	size = 64 * 1024 * 1024;
	res = devm_request_free_mem_region(&echo->pdev->dev, &iomem_resource, size);
	if (IS_ERR(res)) {
		printk("devm request failed\n");
		return -1;
	}
	pgmap->range.start = res->start;
	pgmap->range.end = res->end;
	pgmap->type = MEMORY_DEVICE_PRIVATE;
	pgmap->nr_range = 1;
	pgmap->ops = &svm_migrate_pgmap_ops;
	pgmap->owner = echo;
	pgmap->flags = 0;

	r = devm_memremap_pages(&echo->pdev->dev, pgmap);
	if (IS_ERR(r)) {
		printk("devm memremap failed\n");
		return r;
	}

	return 0;
}

static int dma_transfer2(struct echodev *echo, dma_addr_t buffer, int count, dma_addr_t addr, enum dma_data_direction dir)
{

	/* Setup the DMA controller */
	iowrite32(count, echo->ptr_bar0 + DMA_CNT);

	switch(dir) {
		case DMA_TO_DEVICE: /* 1 */
			iowrite32(buffer, echo->ptr_bar0 + DMA_SRC);
			iowrite32(addr, echo->ptr_bar0 + DMA_DST);
			break;
		case DMA_FROM_DEVICE: /* 2 */
			iowrite32(buffer, echo->ptr_bar0 + DMA_DST);
			iowrite32(addr, echo->ptr_bar0 + DMA_SRC);
			break;
		default:
			return -EFAULT;
	}

	/* Let's fire the dma */
	iowrite32(DMA_RUN | dir, echo->ptr_bar0 + DMA_CMD);

	return 0;
}

static void echo_page_fault(struct echodev *echo, uint64_t va)
{
	// struct mm_struct *mm = echo->notifier.mm;
	struct mm_struct *mm = echo->mm;
	struct vm_area_struct *vma;
	struct migrate_vma migrate = {0};
	void *buf;
	struct page *spage;
	dma_addr_t dma_src;
	struct page *tmp_page;
	int level = 2;
	void *pagetable;
	uint64_t pte;

	if (!mmget_not_zero(mm))
		pr_err("gpu page fault mmget failed \n");

	mmap_read_lock(mm);
	vma = vma_lookup(mm, va);
	if (!vma || !(vma->vm_flags & VM_READ)) {
		printk("gpu page fault invalid va %llx\n", va);
		return;
	}

	// printk("gpu page fault va %lx\n", va);
	// migrate vma to vram
	memset(&migrate, 0, sizeof(migrate));
	migrate.vma = vma;
	migrate.start = va;
	migrate.end = va + 4096;
	migrate.flags = MIGRATE_VMA_SELECT_SYSTEM;
	migrate.pgmap_owner = echo; 

	buf = kvcalloc(1,
                       2 * sizeof(*migrate.src) + sizeof(uint64_t) + sizeof(dma_addr_t),
                       GFP_KERNEL);

	if (!buf)
		goto out;

	migrate.src = buf;
	migrate.dst = migrate.src + 1;
	

	if(migrate_vma_setup(&migrate)) {
		pr_err("migrate vma setup failed \n");
	}

	if (!migrate.cpages) {
		printk("failed collect migrate sys pages\n");
		goto out_free;
	}

	// printk("migrate src pfn %lx\n", migrate.src[0]);
	spage = migrate_pfn_to_page(migrate.src[0]);
	dma_src = dma_map_page(&echo->pdev->dev, spage, 0, PAGE_SIZE, DMA_TO_DEVICE);
	if (dma_mapping_error(&echo->pdev->dev, dma_src)) {
		dev_err(&echo->pdev->dev, "fail dma map page\n");
	}

	printk("spage pfn %lx dma pfn %llx\n",page_to_pfn(spage), dma_to_phys(&echo->pdev->dev, dma_src) >> PAGE_SHIFT);
	migrate.dst[0] = (echo->pgmap.range.start+32*1024*1024) >> PAGE_SHIFT;

	tmp_page = pfn_to_page(migrate.dst[0]);
	tmp_page->zone_device_data = echo;
	zone_device_page_init(tmp_page);	
	migrate.dst[0] = migrate_pfn(migrate.dst[0]);

	// copy data to vram
        dma_transfer2(echo, dma_src, 4096, 32*1024*1024, DMA_TO_DEVICE);

	migrate_vma_pages(&migrate);
	migrate_vma_finalize(&migrate);
	// printk("echodev migrate success\n");
        dma_unmap_page(&echo->pdev->dev, dma_src, PAGE_SIZE, DMA_TO_DEVICE);
	mmap_read_unlock(mm);
	mmput(mm);


	// update gpu page table
	// map va to gpu 32*1024*1024
	pagetable = echo->ptr_bar1;
	// printk("pagetable addr %p\n", pagetable);
	for (level = 2; level > 0; level--) {
		uint64_t pgt_addr = 0;
		uint64_t offset = 0;
		offset = PX(level, va) * 8;
		// printk("level %d pagetable addr %p offset %lx\n", level, pagetable, offset);
		pte = ioread32(pagetable + offset + 4);
		pte = pte << 32;
		pte = pte | ioread32(pagetable + offset);
		if (pte & PTE_V) {
			pagetable = PTE2PA(pte) + echo->ptr_bar1;
		} else {
			pgt_addr = gen_pool_alloc(echo->dram_pg_pool, 4096);
			// printk("gpu page table entry addr %lx\n", pgt_addr);
			// update pte	
			pte = PA2PTE(pgt_addr) | PTE_V;
			
			// printk("level %d update pgt %p value %lx\n", level, (void*)(pagetable+offset), pte);
			if (pagetable+offset < echo->ptr_bar1 || pagetable+offset > echo->ptr_bar1 + 64*1024*1024) {
				pr_err("invalid pagetable addr %p\n", (void*)(pagetable+offset));
				return;
			}
			iowrite32(pte, pagetable + offset); 
			iowrite32(pte >> 32, pagetable + offset + 4); 
			// update pagetable addr
			pagetable = pgt_addr + (void *)(echo->ptr_bar1);
		}
		
	}
	if ((pte & PTE_V) != 0)
		printk("!!!!!!!!!!!!!!!!!!!!!!pte valid, page is in map\n");
	pte = PA2PTE(32*1024*1024)|PTE_V;
	// printk("level 0 update pgt %p value %lx\n",(void*)(pagetable+PX(0, va)*8), pte);
	if (pagetable+PX(0, va) < echo->ptr_bar1 || (void*)(pagetable+PX(0, va)*8) > echo->ptr_bar1 + 64*1024*1024) {
		pr_err("invalid pagetable addr %p\n", (void*)(pagetable+PX(0, va)*8));
		return;
	}
	iowrite32(pte, pagetable + PX(0, va) * 8); 
	iowrite32(pte >> 32, pagetable + PX(0, va) * 8 + 4); 

	// printk("echodev update gpu pagetable success \n");
	return;

out_free:
	kvfree(buf);
out:
	return;
}

static irqreturn_t page_fault_irq_handler(int irq_nr, void *data)
{
	uint32_t ih_ring_wptr = 0;
	uint64_t va;
	uint64_t *ih_ring = (uint64_t *)(ring_buffer + 4096);
	struct echodev *echo = (struct echodev *) data;
	// visit ih ring
        ih_ring_wptr = ioread32(echo->ptr_bar0 + 0x6C) & 127;
        while((ih_ring_wptr - echo->ih_ring_rptr) != 0) {
		va = ih_ring[echo->ih_ring_rptr/8];
		printk("echodev driver ih handle va %llx, wptr %d rptr %d\n", va, ih_ring_wptr, echo->ih_ring_rptr);
		echo_page_fault(echo, va);

		echo->ih_ring_rptr += 8;
		echo->ih_ring_rptr = echo->ih_ring_rptr & 127;
        }

	dma_fence_signal(echo->fence);
	iowrite32(echo->ih_ring_rptr, echo->ptr_bar0 + 0x68);
	if(ioread32(echo->ptr_bar0 + 8) & 0x1) {
		printk("echodev-drv - Legacy IRQ triggered!\n");
		iowrite32(2, echo->ptr_bar0 + 8);
	}
	return IRQ_HANDLED;
}

static irqreturn_t echo_irq_handler(int irq_nr, void *data)
{
	return IRQ_WAKE_THREAD;
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
			//mmu_interval_notifier_insert(&echo->notifier, current->mm,
			//	0, ULONG_MAX & PAGE_MASK, &svm_range_mn_ops);
			echo->mm = current->mm;
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
	// unsigned long mmap_offset;
	// struct echodev *echo = (struct echodev *) file->private_data;

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
			printk("write kern ring, dma addr %ld\n", dma_addr);
			iowrite32(dma_addr & 0xffffffff, echo->ptr_bar0 + 0x48);
			iowrite32((uint32_t)(dma_addr >> 32), echo->ptr_bar0 + 0x4c);
			iowrite32(kern_args.size, echo->ptr_bar0 + 0x58);
			iowrite32(kern_args.rptr, echo->ptr_bar0 + 0x50);
			iowrite32(kern_args.wptr, echo->ptr_bar0 + 0x54);

			// ih ring
			iowrite32((dma_addr+4096) & 0xffffffff, echo->ptr_bar0 + 0x60);
			iowrite32((uint32_t)(dma_addr >> 32), echo->ptr_bar0 + 0x64);
			iowrite32(127, echo->ptr_bar0 + 0x70);
			// iowrite32(0, echo->ptr_bar0 + 0x68);
			// iowrite32(0, echo->ptr_bar0 + 0x6c);

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

static int echo_release(struct inode *inode, struct file *file) {
	struct echodev *echo = (struct echodev *) file->private_data;
	//mmu_interval_notifier_remove(&echo->notifier);
	return 0;
}

static struct file_operations fops = {
	.open = echo_open,
	.mmap = echo_mmap,
	.read = echo_read,
	.write = echo_write,
	.release = echo_release,
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

	dma_set_mask(&pdev->dev, DMA_BIT_MASK(32));
	irq_nr = pci_irq_vector(pdev, 0);
	printk("echodev-drv - IRQ Number: %d\n", irq_nr);

	status = devm_request_threaded_irq(&pdev->dev, irq_nr, echo_irq_handler, page_fault_irq_handler, IRQF_SHARED,
	"echodev-irq", echo);
	if(status != 0) {
		printk("echodev-drv - Error requesting interrupt\n");
		goto fdev;
	}

	ring_buffer = dma_alloc_coherent(&pdev->dev, 8192, &dma_addr, GFP_KERNEL);
	if (!ring_buffer) {
		printk("alloc ringbuffer failed!\n");
		return -ENOMEM;
	}

	return mm_init(echo);

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
