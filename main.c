#include <linux/hrtimer.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched/task.h>
#include <linux/slab.h>

struct hf_vcpu {
	spinlock_t lock;
	long vm_index;
	long vcpu_index;
	struct task_struct *task;
	struct hrtimer timer;
	bool pending_irq;
};

struct hf_vm {
	long vcpu_count;
	struct hf_vcpu *vcpu;
};

long hf_hvc(size_t arg0, size_t arg1, size_t arg2, size_t arg3);

static struct hf_vm *hf_vms;
static long hf_vm_count;
static struct page *hf_send_page = NULL;
static struct page *hf_recv_page = NULL;

/* TODO: Define constants below according to spec. Include shared header. */
#define HF_VCPU_RUN         0xff00
#define HF_VM_GET_COUNT     0xff01
#define HF_VCPU_GET_COUNT   0xff02
#define HF_VM_CONFIGURE     0xff03
#define HF_RPC_REQUEST      0xff04
#define HF_RPC_READ_REQUEST 0xff05
#define HF_RPC_ACK          0xff06
#define HF_RPC_REPLY        0xff07

/**
 * Wakes up the thread associated with the vcpu that owns the given timer. This
 * is called when the timer the thread is waiting on expires.
 */
static enum hrtimer_restart hf_vcpu_timer_expired(struct hrtimer *timer)
{
	struct hf_vcpu *vcpu = container_of(timer, struct hf_vcpu, timer);
	wake_up_process(vcpu->task);
	return HRTIMER_NORESTART;
}

/**
 * This is the main loop of each vcpu.
 */
static int hf_vcpu_thread(void *data)
{
	struct hf_vcpu *vcpu = data;
	long ret;

	hrtimer_init(&vcpu->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	vcpu->timer.function = &hf_vcpu_timer_expired;

	while (!kthread_should_stop()) {
		unsigned long flags;
		size_t irqs;

		set_current_state(TASK_RUNNING);

		/* Determine if we must interrupt the vcpu. */
		spin_lock_irqsave(&vcpu->lock, flags);
		irqs = vcpu->pending_irq ? 1 : 0;
		vcpu->pending_irq = false;
		spin_unlock_irqrestore(&vcpu->lock, flags);

		/* Call into hafnium to run vcpu. */
		ret = hf_hvc(HF_VCPU_RUN, vcpu->vm_index, vcpu->vcpu_index,
			     irqs);

		/* A negative return value indicates that this vcpu needs to
		 * sleep for the given number of nanoseconds.
		 */
		if (ret < 0) {
			set_current_state(TASK_INTERRUPTIBLE);
			if (kthread_should_stop())
				break;
			hrtimer_start(&vcpu->timer, -ret, HRTIMER_MODE_REL);
			schedule();
			hrtimer_cancel(&vcpu->timer);
			continue;
		}

		/* TODO: Use constants below. */
		switch ((u8)ret) {
		case 0x0: /* Yield (forcibly or voluntarily). */
			break;

		case 0x01: /* WFI. */
			set_current_state(TASK_INTERRUPTIBLE);
			if (kthread_should_stop())
				break;
			schedule();
			break;

		case 0x02: /* Wake up another vcpu. */
			{
				struct hf_vm *vm = hf_vms + vcpu->vm_index;
				long target = ret >> 8;
				if (target < vm->vcpu_count)
					wake_up_process(vm->vcpu[target].task);
			}
			break;

		case 0x03: /* Response available. */
			{
				size_t i, count = ret >> 8;
				const char *buf = page_address(hf_recv_page);
				pr_info("Received response (%zu bytes): ",
					count);
				for (i = 0; i < count; i++)
					printk(KERN_CONT "%c", buf[i]);
				printk(KERN_CONT "\n");
				hf_hvc(HF_RPC_ACK, 0, 0, 0);
			}
			break;
		}
	}

	set_current_state(TASK_RUNNING);

	return 0;
}

/**
 * Frees all resources, including threads, associated with the hafnium driver.
 */
static void hf_free_resources(long vm_count)
{
	long i, j;

	/*
	 * First stop all worker threads. We need to do this before freeing
	 * resources because workers may reference each other, so it is only
	 * safe to free resources after they have all stopped.
	 */
	for (i = 0; i < vm_count; i++) {
		struct hf_vm *vm = hf_vms + i;
		for (j = 0; j < vm->vcpu_count; j++)
			kthread_stop(vm->vcpu[j].task);
	}

	/* Free resources. */
	for (i = 0; i < vm_count; i++) {
		struct hf_vm *vm = hf_vms + i;
		for (j = 0; j < vm->vcpu_count; j++)
			put_task_struct(vm->vcpu[j].task);
		kfree(vm->vcpu);
	}

	kfree(hf_vms);
}

static ssize_t hf_interrupt_store(struct kobject *kobj,
				  struct kobj_attribute *attr, const char *buf,
				  size_t count)
{
	struct hf_vcpu *vcpu;
	unsigned long flags;
	struct task_struct *task;

	/* TODO: Parse input to determine which vcpu to interrupt. */
	/* TODO: Check bounds. */

	vcpu = hf_vms[0].vcpu + 0;

	spin_lock_irqsave(&vcpu->lock, flags);
	vcpu->pending_irq = true;
	/* TODO: Do we need to increment the task's ref count here? */
	task = vcpu->task;
	spin_unlock_irqrestore(&vcpu->lock, flags);

	/* Wake up the task. If it's already running, kick it out. */
	/* TODO: There's a race here: the kick may happen right before we go
	 * to the hypervisor. */
	if (wake_up_process(task) == 0)
		kick_process(task);

	return count;
}

static ssize_t hf_send_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	long ret;
	struct hf_vm *vm;

	/* TODO: Use constant. */
	if (count > 4096)
		count = 4096;

	/* Copy data to send buffer. */
	memcpy(page_address(hf_send_page), buf, count);
	ret = hf_hvc(HF_RPC_REQUEST, 0, count, 0);
	if (ret < 0)
		return -EAGAIN;

	vm = hf_vms + 0;
	if (ret > vm->vcpu_count)
		return -EINVAL;

	if (ret == 0) {
		/*
		 * TODO: We need to interrupt some CPU because none is actually
		 * waiting for data.
		 */
	} else {
		/* Wake up the vcpu that is going to process the data. */
		/* TODO: There's a race where thread may get wake up before it
		 * goes to sleep. Fix this. */
		wake_up_process(vm->vcpu[ret - 1].task);
	}

	return count;
}

static struct kobject *hf_sysfs_obj = NULL;
static struct kobj_attribute interrupt_attr =
	__ATTR(interrupt, 0200, NULL, hf_interrupt_store);
static struct kobj_attribute send_attr =
	__ATTR(send, 0200, NULL, hf_send_store);

/**
 * Initializes the hafnium driver by creating a thread for each vCPU of each
 * virtual machine.
 */
static int __init hf_init(void)
{
	long ret;
	long i, j;

	/* Allocate a page for send and receive buffers. */
	hf_send_page = alloc_page(GFP_KERNEL);
	if (!hf_send_page) {
		pr_err("Unable to allocate send buffer\n");
		return -ENOMEM;
	}

	hf_recv_page = alloc_page(GFP_KERNEL);
	if (!hf_recv_page) {
		__free_page(hf_send_page);
		pr_err("Unable to allocate receive buffer\n");
		return -ENOMEM;
	}

	/*
	 * Configure both addresses. Once configured, we cannot free these pages
	 * because the hypervisor will use them, even if the module is
	 * unloaded.
	 */
	ret = hf_hvc(HF_VM_CONFIGURE, (size_t)page_to_phys(hf_send_page),
		     (size_t)page_to_phys(hf_recv_page), 0);
	if (ret) {
		__free_page(hf_send_page);
		__free_page(hf_recv_page);
		/* TODO: We may want to grab this information from hypervisor
		 * and go from there. */
		pr_err("Unable to configure VM\n");
		return -EIO;
	}

	/* Get the number of VMs and allocate storage for them. */
	ret = hf_hvc(HF_VM_GET_COUNT, 0, 0, 0);
	if (ret < 0) {
		pr_err("Unable to retrieve number of VMs: %ld\n", ret);
		return ret;
	}

	hf_vm_count = ret;
	hf_vms = kmalloc(sizeof(struct hf_vm) * hf_vm_count, GFP_KERNEL);
	if (!hf_vms)
		return -ENOMEM;

	/* Initialize each VM. */
	for (i = 0; i < hf_vm_count; i++) {
		struct hf_vm *vm = hf_vms + i;

		ret = hf_hvc(HF_VCPU_GET_COUNT, i, 0, 0);
		if (ret < 0) {
			pr_err("HF_VCPU_GET_COUNT failed for vm=%ld: %ld", i,
			       ret);
			hf_free_resources(i);
			return ret;
		}

		vm->vcpu_count = ret;
		vm->vcpu = kmalloc(sizeof(struct hf_vcpu) * vm->vcpu_count,
				   GFP_KERNEL);
		if (!vm->vcpu) {
			pr_err("No memory for %ld vcpus for vm %ld",
			       vm->vcpu_count, i);
			hf_free_resources(i);
			return -ENOMEM;
		}

		/* Create a kernel thread for each vcpu. */
		for (j = 0; j < vm->vcpu_count; j++) {
			struct hf_vcpu *vcpu = vm->vcpu + j;
			vcpu->task = kthread_create(hf_vcpu_thread, vcpu,
						    "vcpu_thread_%ld_%ld",
						    i, j);
			if (IS_ERR(vcpu->task)) {
				pr_err("Error creating task (vm=%ld,vcpu=%ld)"
				       ": %ld\n", i, j, PTR_ERR(vcpu->task));
				vm->vcpu_count = j;
				hf_free_resources(i + 1);
				return PTR_ERR(vcpu->task);
			}

			get_task_struct(vcpu->task);
			spin_lock_init(&vcpu->lock);
			vcpu->vm_index = i;
			vcpu->vcpu_index = j;
			vcpu->pending_irq = false;
		}
	}

	/* Start running threads now that all is initialized. */
	for (i = 0; i < hf_vm_count; i++) {
		struct hf_vm *vm = hf_vms + i;
		for (j = 0; j < vm->vcpu_count; j++)
			wake_up_process(vm->vcpu[j].task);
	}

	/* Dump vm/vcpu count info. */
	pr_info("Hafnium successfully loaded with %ld VMs:\n", hf_vm_count);
	for (i = 0; i < hf_vm_count; i++)
		pr_info("\tVM %ld: %ld vCPUS\n", i, hf_vms[i].vcpu_count);

	/* Create the sysfs interface to interrupt vcpus. */
	hf_sysfs_obj = kobject_create_and_add("hafnium", kernel_kobj);
	if (!hf_sysfs_obj) {
		pr_err("Unable to create sysfs object");
	} else {
		ret = sysfs_create_file(hf_sysfs_obj, &interrupt_attr.attr);
		if (ret)
			pr_err("Unable to create 'interrupt' sysfs file");

		ret = sysfs_create_file(hf_sysfs_obj, &send_attr.attr);
		if (ret)
			pr_err("Unable to create 'send' sysfs file");
	}

	return 0;
}

/**
 * Frees up all resources used by the hafnium driver in preparation for
 * unloading it.
 */
static void __exit hf_exit(void)
{
	if (hf_sysfs_obj)
		kobject_put(hf_sysfs_obj);

	pr_info("Preparing to unload hafnium\n");
	hf_free_resources(hf_vm_count);
	pr_info("Hafnium ready to unload\n");
}

MODULE_LICENSE("GPL");

module_init(hf_init);
module_exit(hf_exit);
