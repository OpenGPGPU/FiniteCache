#include "ogpu_compute.h"

/*
 * List of struct compute_process (field compute_process).
 * Unique/indexed by mm_struct*
 */
DEFINE_HASHTABLE(compute_processes_table, 5);
DEFINE_MUTEX(compute_processes_mutex);


DEFINE_SRCU(compute_processes_srcu);


/* For process termination handling */
static struct workqueue_struct *compute_process_wq;


/* Ordered, single-threaded workqueue for restoring evicted
 * processes. Restoring multiple processes concurrently under memory
 * pressure can lead to processes blocking each other from validating
 * their BOs and result in a live-lock situation where processes
 * remain evicted indefinitely.
 */
static struct workqueue_struct * compute_restore_wq;

/* No process locking is needed in this function, because the process
 * is not findable any more. We must assume that no other thread is
 * using it any more, otherwise we couldn't safely free the process
 * structure in the end.
 */
static void compute_process_wq_release(struct work_struct *work)
{
	struct compute_process *p = container_of(work, struct compute_process,
					     release_work);
// struct dma_fence *ef;
// 
// kfd_process_dequeue_from_all_devices(p);
// pqm_uninit(&p->pqm);
// 
// /* Signal the eviction fence after user mode queues are
//  * destroyed. This allows any BOs to be freed without
//  * triggering pointless evictions or waiting for fences.
//  */
// synchronize_rcu();
// ef = rcu_access_pointer(p->ef);
// dma_fence_signal(ef);
// 
// kfd_process_remove_sysfs(p);
// 
// kfd_process_kunmap_signal_bo(p);
// kfd_process_free_outstanding_kfd_bos(p);
// svm_range_list_fini(p);
// 
// kfd_process_destroy_pdds(p);
// dma_fence_put(ef);
// 
// kfd_event_free_process(p);
// 
// kfd_pasid_free(p->pasid);
// mutex_destroy(&p->mutex);
// 
// put_task_struct(p->lead_thread);

	kfree(p);
}



void compute_process_destroy_wq(void)
{
	if (compute_process_wq) {
		destroy_workqueue(compute_process_wq);
		compute_process_wq = NULL;
	}

	if (compute_restore_wq) {
		destroy_workqueue(compute_restore_wq);
		compute_restore_wq = NULL;
	}
}

int compute_process_create_wq(void)
{
	if (!compute_process_wq)
		compute_process_wq = alloc_workqueue("compute_process_wq", 0, 0);
	if (!compute_restore_wq)
		compute_restore_wq = alloc_ordered_workqueue("compute_restore_wq", WQ_FREEZABLE);

	if (!compute_process_wq || !compute_restore_wq) {
		compute_process_destroy_wq();
		return -ENOMEM;
	}

	return 0;
}

static void compute_process_ref_release(struct kref *ref) {
	struct compute_process *p = container_of(ref, struct compute_process, ref);

	INIT_WORK(&p->release_work, compute_process_wq_release);
	queue_work(compute_process_wq, &p->release_work);
}

static struct compute_process *find_process_by_mm(const struct mm_struct *mm)
{
	struct compute_process *process;

	hash_for_each_possible_rcu(compute_processes_table, process, compute_processes, (uintptr_t)mm)
		if (process->mm == mm)
			return process;

	return NULL;
}

static struct compute_process *find_process(const struct task_struct *thread, bool ref)
{
	struct compute_process *p;
	int idx;

	idx = srcu_read_lock(&compute_processes_srcu);
	p = find_process_by_mm(thread->mm);
	if (p && ref)
		kref_get(&p->ref);
	srcu_read_unlock(&compute_processes_srcu, idx);

	return p;
}

void compute_unref_process(struct compute_process *p)
{
	kref_put(&p->ref, compute_process_ref_release);
}

static struct mmu_notifier *compute_process_alloc_notifier(struct mm_struct *mm)
{
	int idx = srcu_read_lock(&compute_processes_srcu);
	struct compute_process *p = find_process_by_mm(mm);

	srcu_read_unlock(&compute_processes_srcu, idx);

	return p ? &p->mmu_notifier : ERR_PTR(-ESRCH);
}

static void compute_process_free_notifier(struct mmu_notifier *mn)
{
	compute_unref_process(container_of(mn, struct compute_process, mmu_notifier));
}

static void compute_process_notifier_release_internal(struct compute_process *p)
{
	int i;

	p->mm = NULL;

	mmu_notifier_put(&p->mmu_notifier);
}


static void compute_process_notifier_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct compute_process *p;

	p = container_of(mn, struct compute_process, mmu_notifier);
	if (WARN_ON(p->mm != mm))
		return;

	mutex_lock(&compute_processes_mutex);

	if (hash_empty(compute_processes_table)) {
		mutex_unlock(&compute_processes_mutex);
		return;
	}
	hash_del_rcu(&p->compute_processes);
	mutex_unlock(&compute_processes_mutex);
	synchronize_srcu(&compute_processes_srcu);

	compute_process_notifier_release_internal(p);
}

static const struct mmu_notifier_ops compute_process_mmu_notifier_ops = {
	.release = compute_process_notifier_release,
	.alloc_notifier = compute_process_alloc_notifier,
	.free_notifier = compute_process_free_notifier,
};

/*
 * On return the compute_process is fully operational and will be freed when the
 * mm is released
 */
static struct compute_process *create_process(const struct task_struct *thread)
{
	struct compute_process *process;
	struct mmu_notifier *mn;
	int err = -ENOMEM;

	process = kzalloc(sizeof(*process), GFP_KERNEL);
	if (!process)
		goto err_alloc_process;

	kref_init(&process->ref);
	mutex_init(&process->mutex);
	process->mm = thread->mm;
	process->lead_thread = thread->group_leader;
	process->n_pdds = 0;

	process->pasid = 1; // compute_pasid_alloc();
	if (process->pasid == 0) {
		err = -ENOSPC;
		goto err_alloc_pasid;
	}

//	err = compute_init_apertures(process);
	if (err != 0)
		goto err_init_apertures;

//	err = svm_range_list_init(process);
	if (err)
		goto err_init_svm_range_list;

	/* alloc_notifier needs to find the process in the hash table */
	hash_add_rcu(compute_processes_table, &process->compute_processes,
			(uintptr_t)process->mm);

	 /* Avoid free_notifier to start kfd_process_wq_release if
         * mmu_notifier_get failed because of pending signal.
         */
	kref_get(&process->ref);

	/* MMU notifier registration must be the last call that can fail
         * because after this point we cannot unwind the process creation.
         * After this point, mmu_notifier_put will trigger the cleanup by
         * dropping the last process reference in the free_notifier.
         */
        mn = mmu_notifier_get(&compute_process_mmu_notifier_ops, process->mm);
        if (IS_ERR(mn)) {
                err = PTR_ERR(mn);
                goto err_register_notifier;
        }
        BUG_ON(mn != &process->mmu_notifier);

	compute_unref_process(process);
        get_task_struct(process->lead_thread);

        // INIT_WORK(&process->debug_event_workarea, debug_event_write_work_handler);
	return process;

err_register_notifier:
        hash_del_rcu(&process->compute_processes);
        // svm_range_list_fini(process);
err_init_svm_range_list:
        // kfd_process_free_outstanding_kfd_bos(process);
        // kfd_process_destroy_pdds(process);
err_init_apertures:
        // pqm_uninit(&process->pqm);
err_process_pqm_init:
        // compute_pasid_free(process->pasid);
err_alloc_pasid:
        // kfd_event_free_process(process);
err_event_init:
        mutex_destroy(&process->mutex);
        kfree(process);
err_alloc_process:
        return ERR_PTR(err);
}


struct compute_process *compute_create_process(struct task_struct *thread)
{
	struct compute_process *process;
	int ret;

	if (!(thread->mm && mmget_not_zero(thread->mm)))
		return ERR_PTR(-EINVAL);

	if (thread->group_leader->mm != thread->mm) {
		mmput(thread->mm);
		return ERR_PTR(-EINVAL);
	}

	mutex_lock(&compute_processes_mutex);

	// if (ogpu_is_locked()) {
	// 	pr_debug("ogpu is locked! Cannot create process!");
	// 	process = ERR_PTR(-EINVAL);
	// 	goto out;
	// }

	process = find_process(thread, false);

	if (process) {
		pr_debug("Process already found\n");
	} else {
		flush_workqueue(compute_process_wq);

		process = create_process(thread);
		if (IS_ERR(process))
			goto out;
	}

out:
	if (!IS_ERR(process))
		kref_get(&process->ref);
	mutex_unlock(&compute_processes_mutex);
	mmput(thread->mm);

	return process;
}
