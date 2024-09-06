#ifndef __OGPU_COMPUTE_H__
#define __OGPU_COMPUTE_H__

#include <linux/hashtable.h>
#include <linux/mmu_notifier.h>
#include <linux/memremap.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/idr.h>
#include <linux/kfifo.h>
#include <linux/sysfs.h>
#include <drm/drm_file.h>
#include <drm/drm_drv.h>
#include <drm/drm_device.h>
#include <drm/drm_ioctl.h>
#include <linux/swap.h>


#define MAX_GPU_INSTANCE 64

struct compute_process {
	struct hlist_node compute_processes;
	void *mm;
	struct kref ref;
	struct work_struct release_work;

	struct mutex mutex;

	struct task_struct *lead_thread;

	struct mmu_notifier mmu_notifier;

	u32 pasid;

	// struct compute_process_device *pdd[MAX_GPU_INSTANCE];
	uint32_t n_pdds;

	// struct process_queue_manager pqm;

	bool is_32bit_user_mode;

};

#define COMPUTE_PROCESS_TABLE_SIZE 5
extern DECLARE_HASHTABLE(compute_processes_table, COMPUTE_PROCESS_TABLE_SIZE);
extern struct srcu_struct compute_processes_srcu;

int ogpu_compute_init(void);
void ogpu_compute_fini(void);
struct compute_process *compute_create_process(struct task_struct *thread);
void compute_unref_process(struct compute_process *p);
int ogpu_chardev_init(void);
int ogpu_topology_init(void);
void ogpu_chardev_exit(void);



#endif
