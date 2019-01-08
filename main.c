/*
 * Copyright 2018 Google LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <linux/hrtimer.h>
#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <net/sock.h>

#include <hf/call.h>

/* TODO: Reusing AF_ECONET for now as it's otherwise unused. */
#define AF_HF AF_ECONET
#define PF_HF AF_HF

#define MESSAGE_INT_ID 1

#define CONFIG_HAFNIUM_MAX_VMS   16
#define CONFIG_HAFNIUM_MAX_VCPUS 32

struct hf_vcpu {
	struct hf_vm *vm;
	uint32_t vcpu_index;
	struct task_struct *task;
	atomic_t abort_sleep;
	struct hrtimer timer;
};

struct hf_vm {
	uint32_t id;
	uint32_t vcpu_count;
	struct hf_vcpu *vcpu;
};

struct hf_msg_hdr {
	uint64_t src_port;
	uint64_t dst_port;
};

struct hf_sock {
	/* This needs to be the first field. */
	struct sock sk;

	/*
	 * The following fields are immutable after the socket transitions to
	 * SS_CONNECTED state.
	 */
	uint64_t local_port;
	uint64_t remote_port;
	struct hf_vm *peer_vm;
};

struct sockaddr_hf {
	sa_family_t family;
	uint32_t vm_id;
	uint64_t port;
};

static struct proto hf_sock_proto = {
	.name = "hafnium",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct hf_sock),
};

static struct hf_vm *hf_vms;
static uint32_t hf_vm_count;
static struct page *hf_send_page;
static struct page *hf_recv_page;
static atomic64_t hf_next_port = ATOMIC64_INIT(0);
static DEFINE_SPINLOCK(hf_send_lock);
static DEFINE_HASHTABLE(hf_local_port_hash, 7);
static DEFINE_SPINLOCK(hf_local_port_hash_lock);

/**
 * Wakes up the kernel thread responsible for running the given vcpu.
 *
 * Returns 0 if the thread was already running, 1 otherwise.
 */
static int hf_vcpu_wake_up(struct hf_vcpu *vcpu)
{
	/* Set a flag indicating that the thread should not go to sleep. */
	atomic_set(&vcpu->abort_sleep, 1);

	/* Set the thread to running state. */
	return wake_up_process(vcpu->task);
}

/**
 * Puts the current thread to sleep. The current thread must be responsible for
 * running the given vcpu.
 *
 * Going to sleep will fail if hf_vcpu_wake_up() or kthread_stop() was called on
 * this vcpu/thread since the last time it [re]started running.
 */
static void hf_vcpu_sleep(struct hf_vcpu *vcpu)
{
	int abort;

	set_current_state(TASK_INTERRUPTIBLE);

	/* Check the sleep-abort flag after making thread interruptible. */
	abort = atomic_read(&vcpu->abort_sleep);
	if (!abort && !kthread_should_stop())
		schedule();

	/* Set state back to running on the way out. */
	set_current_state(TASK_RUNNING);
}

/**
 * Wakes up the thread associated with the vcpu that owns the given timer. This
 * is called when the timer the thread is waiting on expires.
 */
static enum hrtimer_restart hf_vcpu_timer_expired(struct hrtimer *timer)
{
	struct hf_vcpu *vcpu = container_of(timer, struct hf_vcpu, timer);
	/* TODO: Inject interrupt. */
	hf_vcpu_wake_up(vcpu);
	return HRTIMER_NORESTART;
}

/**
 * Handles a message delivered to this VM by validating that it's well-formed
 * and then queueing it for delivery to the appropriate socket.
 */
static void hf_handle_message(struct hf_vm *sender, const void *ptr, size_t len)
{
	struct hf_sock *hsock;
	const struct hf_msg_hdr *hdr = ptr;
	struct sk_buff *skb;
	int err;

	/* Ignore messages that are too small to hold a header. */
	if (len < sizeof(struct hf_msg_hdr))
		return;

	len -= sizeof(struct hf_msg_hdr);

	/* Go through the colliding sockets. */
	rcu_read_lock();
	hash_for_each_possible_rcu(hf_local_port_hash, hsock, sk.sk_node,
				   hdr->dst_port) {
		if (hsock->peer_vm == sender &&
		    hsock->remote_port == hdr->src_port) {
			sock_hold(&hsock->sk);
			break;
		}
	}
	rcu_read_unlock();

	/* Nothing to do if we couldn't find the target. */
	if (!hsock)
		return;

	/*
	 * TODO: From this point on, there are two failure paths: when we
	 * create the skb below, and when we enqueue it to the socket. What
	 * should we do if they fail? Ideally we would have some form of flow
	 * control to prevent message loss, but how to do it efficiently?
	 *
	 * One option is to have a pre-allocated message that indicates to the
	 * sender that a message was dropped. This way we guarantee that the
	 * sender will be aware of loss and should back-off.
	 */
	/* Create the skb. */
	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		goto exit;

	memcpy(skb_put(skb, len), hdr + 1, len);

	/*
	 * Add the skb to the receive queue of the target socket. On success it
	 * calls sk->sk_data_ready, which is currently set to sock_def_readable,
	 * which wakes up any waiters.
	 */
	err = sock_queue_rcv_skb(&hsock->sk, skb);
	if (err)
		kfree_skb(skb);

exit:
	sock_put(&hsock->sk);
}

/**
 * This function is called when Hafnium requests that the primary VM wake up a
 * vCPU that belongs to a secondary VM.
 *
 * It wakes up the thread if it's sleeping, or kicks it if it's already running.
 *
 * If vCPU is HF_INVALID_VCPU, it injects a MESSAGE_INT_ID interrupt into a vCPU
 * belonging to the specified VM.
 */
static void hf_handle_wake_up_request(uint32_t vm_id, uint16_t vcpu)
{
	struct hf_vm *vm;

	if (vm_id > hf_vm_count) {
		pr_warn("Request to wake up non-existent VM id: %u\n", vm_id);
		return;
	}

	vm = &hf_vms[vm_id - 1];
	if (vcpu >= vm->vcpu_count) {
		int64_t ret;

		if (vcpu != HF_INVALID_VCPU) {
			pr_warn("Request to wake up non-existent vCPU: %u.%u\n",
				vm_id, vcpu);
			return;
		}

		/*
		 * TODO: For now we're picking the first vcpu to interrupt, but
		 * we want to be smarter.
		 */
		vcpu = 0;
		ret = hf_interrupt_inject(vm_id, vcpu, MESSAGE_INT_ID);
		if (ret != 1) {
			/* We don't need to wake up the vcpu. */
			return;
		}
	}

	if (hf_vcpu_wake_up(&vm->vcpu[vcpu]) == 0) {
		/*
		 * The task was already running (presumably on a different
		 * physical CPU); interrupt it. This gives Hafnium a chance to
		 * inject any new interrupts.
		 */
		kick_process(vm->vcpu[vcpu].task);
	}
}

/**
 * This is the main loop of each vcpu.
 */
static int hf_vcpu_thread(void *data)
{
	struct hf_vcpu *vcpu = data;
	struct hf_vcpu_run_return ret;

	hrtimer_init(&vcpu->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	vcpu->timer.function = &hf_vcpu_timer_expired;

	while (!kthread_should_stop()) {
		/*
		 * We're about to run the vcpu, so we can reset the abort-sleep
		 * flag.
		 */
		atomic_set(&vcpu->abort_sleep, 0);

		/* Call into Hafnium to run vcpu. */
		ret = hf_vcpu_run(vcpu->vm->id, vcpu->vcpu_index);

		switch (ret.code) {
		/* Preempted. */
		case HF_VCPU_RUN_PREEMPTED:
			if (need_resched())
				schedule();
			break;

		/* Yield. */
		case HF_VCPU_RUN_YIELD:
			if (!kthread_should_stop())
				schedule();
			break;

		 /* WFI. */
		case HF_VCPU_RUN_WAIT_FOR_INTERRUPT:
			hf_vcpu_sleep(vcpu);
			break;

		/* Wake up another vcpu. */
		case HF_VCPU_RUN_WAKE_UP:
			hf_handle_wake_up_request(ret.wake_up.vm_id,
						  ret.wake_up.vcpu);
			break;

		/* Response available. */
		case HF_VCPU_RUN_MESSAGE:
			hf_handle_message(vcpu->vm, page_address(hf_recv_page),
					  ret.message.size);
			hf_mailbox_clear();
			break;

		case HF_VCPU_RUN_SLEEP:
			hrtimer_start(&vcpu->timer, ret.sleep.ns,
				      HRTIMER_MODE_REL);
			hf_vcpu_sleep(vcpu);
			hrtimer_cancel(&vcpu->timer);
			break;
		}
	}

	return 0;
}

/**
 * Converts a pointer to a struct sock into a pointer to a struct hf_sock. It
 * relies on the fact that the first field of hf_sock is a sock.
 */
static struct hf_sock *hsock_from_sk(struct sock *sk)
{
	return (struct hf_sock *)sk;
}

/**
 * This is called when the last reference to the outer socket is released. For
 * example, if it's a user-space socket, when the last file descriptor pointing
 * to this socket is closed.
 *
 * It begins cleaning up resources, though some can only be cleaned up after all
 * references to the underlying socket are released, which is handled by
 * hf_sock_destruct().
 */
static int hf_sock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct hf_sock *hsock = hsock_from_sk(sk);
	unsigned long flags;

	if (!sk)
		return 0;

	/* Shutdown for both send and receive. */
	lock_sock(sk);
	sk->sk_shutdown |= RCV_SHUTDOWN | SEND_SHUTDOWN;
	sk->sk_state_change(sk);
	release_sock(sk);

	/* Remove from the hash table, so lookups from now on won't find it. */
	spin_lock_irqsave(&hf_local_port_hash_lock, flags);
	hash_del_rcu(&hsock->sk.sk_node);
	spin_unlock_irqrestore(&hf_local_port_hash_lock, flags);

	/*
	 * TODO: When we implement a tx queue, we need to clear it here so that
	 * sk_wmem_alloc will not prevent sk from being freed (sk_free).
	 */

	/*
	 * Wait for in-flight lookups to finish. We need to do this here because
	 * in-flight lookups rely on the reference to the socket we're about to
	 * release.
	 */
	synchronize_rcu();
	sock_put(sk);
	sock->sk = NULL;

	return 0;
}

/**
 * This is called when there are no more references to the socket. It frees all
 * resources that haven't been freed during release.
 */
static void hf_sock_destruct(struct sock *sk)
{
	/*
	 * Clear the receive queue now that the handler cannot add any more
	 * skbs to it.
	 */
	skb_queue_purge(&sk->sk_receive_queue);
}

/**
 * Connects the Hafnium socket to the provided VM and port. After the socket is
 * connected, it can be used to exchange datagrams with the specified peer.
 */
static int hf_sock_connect(struct socket *sock, struct sockaddr *saddr,
			   int len, int connect_flags)
{
	struct sock *sk = sock->sk;
	struct hf_sock *hsock = hsock_from_sk(sk);
	struct hf_vm *vm;
	struct sockaddr_hf *addr;
	int err;
	unsigned long flags;

	/* Basic address validation. */
	if (len < sizeof(struct sockaddr_hf) || saddr->sa_family != AF_HF)
		return -EINVAL;

	addr = (struct sockaddr_hf *)saddr;
	if (addr->vm_id > hf_vm_count)
		return -ENETUNREACH;

	vm = &hf_vms[addr->vm_id - 1];

	/*
	 * TODO: Once we implement access control in Hafnium, check that the
	 * caller is allowed to contact the specified VM. Return -ECONNREFUSED
	 * if access is denied.
	 */

	/* Take lock to make sure state doesn't change as we connect. */
	lock_sock(sk);

	/* Only unconnected sockets are allowed to become connected. */
	if (sock->state != SS_UNCONNECTED) {
		err = -EISCONN;
		goto exit;
	}

	hsock->local_port = atomic64_inc_return(&hf_next_port);
	hsock->remote_port = addr->port;
	hsock->peer_vm = vm;

	sock->state = SS_CONNECTED;

	/* Add socket to hash table now that it's fully initialised. */
	spin_lock_irqsave(&hf_local_port_hash_lock, flags);
	hash_add_rcu(hf_local_port_hash, &sk->sk_node, hsock->local_port);
	spin_unlock_irqrestore(&hf_local_port_hash_lock, flags);

	err = 0;
exit:
	release_sock(sk);
	return err;
}

/**
 * Sends the given skb to the appropriate VM by calling Hafnium. It will also
 * trigger the wake up of a recipient VM.
 *
 * Takes ownership of the skb on success.
 */
static int hf_send_skb(struct sk_buff *skb)
{
	unsigned long flags;
	int64_t ret;
	struct hf_sock *hsock = hsock_from_sk(skb->sk);
	struct hf_vm *vm = hsock->peer_vm;

	/*
	 * Call Hafnium under the send lock so that we serialize the use of the
	 * global send buffer.
	 */
	spin_lock_irqsave(&hf_send_lock, flags);
	memcpy(page_address(hf_send_page), skb->data, skb->len);
	ret = hf_mailbox_send(vm->id, skb->len, false);
	spin_unlock_irqrestore(&hf_send_lock, flags);

	if (ret < 0)
		return -EAGAIN;

	/* Wake some vcpu up to handle the new message. */
	hf_handle_wake_up_request(vm->id, ret);

	kfree_skb(skb);

	return 0;
}

/**
 * Determines if the given socket is in the connected state. It acquires and
 * releases the socket lock.
 */
static bool hf_sock_is_connected(struct socket *sock)
{
	bool ret;

	lock_sock(sock->sk);
	ret = sock->state == SS_CONNECTED;
	release_sock(sock->sk);

	return ret;
}

/**
 * Sends a message to the VM & port the socket is connected to. All variants
 * of write/send/sendto/sendmsg eventually call this function.
 */
static int hf_sock_sendmsg(struct socket *sock, struct msghdr *m, size_t len)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int err;
	struct hf_msg_hdr *hdr;
	struct hf_sock *hsock = hsock_from_sk(sk);

	/* Check length. */
	if (len > HF_MAILBOX_SIZE - sizeof(struct hf_msg_hdr))
		return -EMSGSIZE;

	/* We don't allow the destination address to be specified. */
	if (m->msg_namelen > 0)
		return -EISCONN;

	/* We don't support out of band messages. */
	if (m->msg_flags & MSG_OOB)
		return -EOPNOTSUPP;

	/*
	 * Ensure that the socket is connected. We don't need to hold the socket
	 * lock (acquired and released by hf_sock_is_connected) for the
	 * remainder of the function because the fields we care about are
	 * immutable once the state is SS_CONNECTED.
	 */
	if (!hf_sock_is_connected(sock))
		return -ENOTCONN;

	/*
	 * Allocate an skb for this write. If there isn't enough room in the
	 * socket's send buffer (sk_wmem_alloc >= sk_sndbuf), this will block
	 * (if it's a blocking call). On success, it increments sk_wmem_alloc
	 * and sets up the skb such that sk_wmem_alloc gets decremented when
	 * the skb is freed (sock_wfree gets called).
	 */
	skb = sock_alloc_send_skb(sk, len + sizeof(struct hf_msg_hdr),
				  m->msg_flags & MSG_DONTWAIT, &err);
	if (!skb)
		return err;

	/* Reserve room for the header and initialise it. */
	skb_reserve(skb, sizeof(struct hf_msg_hdr));
	hdr = skb_push(skb, sizeof(struct hf_msg_hdr));
	hdr->src_port = hsock->local_port;
	hdr->dst_port = hsock->remote_port;

	/* Allocate area for the contents, then copy into skb. */
	if (!copy_from_iter_full(skb_put(skb, len), len, &m->msg_iter)) {
		err = -EFAULT;
		goto err_cleanup;
	}

	/*
	 * TODO: We currently do this inline, but when we have support for
	 * readiness notification from Hafnium, we must add this to a per-VM tx
	 * queue that can make progress when the VM becomes writable. This will
	 * fix send buffering and poll readiness notification.
	 */
	err = hf_send_skb(skb);
	if (err)
		goto err_cleanup;

	return 0;

err_cleanup:
	kfree_skb(skb);
	return err;
}

/**
 * Receives a message originated from the VM & port the socket is connected to.
 * All variants of read/recv/recvfrom/recvmsg eventually call this function.
 */
static int hf_sock_recvmsg(struct socket *sock, struct msghdr *m, size_t len,
			   int flags)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int err;
	size_t copy_len;

	if (!hf_sock_is_connected(sock))
		return -ENOTCONN;

	/* Grab the next skb from the receive queue. */
	skb = skb_recv_datagram(sk, flags, flags & MSG_DONTWAIT, &err);
	if (!skb)
		return err;

	/* Make sure we don't copy more than what fits in the output buffer. */
	copy_len = skb->len;
	if (copy_len > len) {
		copy_len = len;
		m->msg_flags |= MSG_TRUNC;
	}

	/* Make sure we don't overflow the return value type. */
	if (copy_len > INT_MAX) {
		copy_len = INT_MAX;
		m->msg_flags |= MSG_TRUNC;
	}

	/* Copy skb to output iterator, then free it. */
	err = skb_copy_datagram_msg(skb, 0, m, copy_len);
	skb_free_datagram(sk, skb);
	if (err)
		return err;

	return copy_len;
}

/**
 * This function is called when a Hafnium socket is created. It initialises all
 * state such that the caller will be able to connect the socket and then send
 * and receive messages through it.
 */
static int hf_sock_create(struct net *net, struct socket *sock, int protocol,
		      int kern)
{
	static const struct proto_ops ops = {
		.family = PF_HF,
		.owner = THIS_MODULE,
		.release = hf_sock_release,
		.bind = sock_no_bind,
		.connect = hf_sock_connect,
		.socketpair = sock_no_socketpair,
		.accept = sock_no_accept,
		.ioctl = sock_no_ioctl,
		.listen = sock_no_listen,
		.shutdown = sock_no_shutdown,
		.setsockopt = sock_no_setsockopt,
		.getsockopt = sock_no_getsockopt,
		.sendmsg = hf_sock_sendmsg,
		.recvmsg = hf_sock_recvmsg,
		.mmap = sock_no_mmap,
		.sendpage = sock_no_sendpage,
		.poll = datagram_poll,
	};
	struct sock *sk;

	if (sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	if (protocol != 0)
		return -EPROTONOSUPPORT;

	/*
	 * For now we only allow callers with sys admin capability to create
	 * Hafnium sockets.
	 */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* Allocate and initialise socket. */
	sk = sk_alloc(net, PF_HF, GFP_KERNEL, &hf_sock_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);

	sk->sk_destruct = hf_sock_destruct;
	sock->ops = &ops;
	sock->state = SS_UNCONNECTED;

	return 0;
}

/**
 * Frees all resources, including threads, associated with the Hafnium driver.
 */
static void hf_free_resources(void)
{
	uint32_t i, j;

	/*
	 * First stop all worker threads. We need to do this before freeing
	 * resources because workers may reference each other, so it is only
	 * safe to free resources after they have all stopped.
	 */
	for (i = 0; i < hf_vm_count; i++) {
		struct hf_vm *vm = &hf_vms[i];

		for (j = 0; j < vm->vcpu_count; j++)
			kthread_stop(vm->vcpu[j].task);
	}

	/* Free resources. */
	for (i = 0; i < hf_vm_count; i++) {
		struct hf_vm *vm = &hf_vms[i];

		for (j = 0; j < vm->vcpu_count; j++)
			put_task_struct(vm->vcpu[j].task);
		kfree(vm->vcpu);
	}

	kfree(hf_vms);
}

/**
 * Initializes the Hafnium driver by creating a thread for each vCPU of each
 * virtual machine.
 */
static int __init hf_init(void)
{
	static const struct net_proto_family proto_family = {
		.family = PF_HF,
		.create = hf_sock_create,
		.owner = THIS_MODULE,
	};
	int64_t ret;
	uint32_t i, j;
	uint32_t total_vm_count;
	uint32_t total_vcpu_count;

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
	ret = hf_vm_configure(page_to_phys(hf_send_page),
			      page_to_phys(hf_recv_page));
	if (ret) {
		__free_page(hf_send_page);
		__free_page(hf_recv_page);
		/*
		 * TODO: We may want to grab this information from hypervisor
		 * and go from there.
		 */
		pr_err("Unable to configure VM\n");
		return -EIO;
	}

	/* Get the number of VMs. */
	ret = hf_vm_get_count();
	if (ret < 0) {
		pr_err("Unable to retrieve number of VMs: %lld\n", ret);
		return -EIO;
	}

	/* Confirm the maximum number of VMs looks sane. */
	BUILD_BUG_ON(CONFIG_HAFNIUM_MAX_VMS < 1);
	BUILD_BUG_ON(CONFIG_HAFNIUM_MAX_VMS > U16_MAX);

	/* Validate the number of VMs. There must at least be the primary. */
	if (ret < 1 || ret > CONFIG_HAFNIUM_MAX_VMS) {
		pr_err("Number of VMs is out of range: %lld\n", ret);
		return -EDQUOT;
	}

	/* Only track the secondary VMs. */
	total_vm_count = ret - 1;
	hf_vms = kmalloc_array(total_vm_count, sizeof(struct hf_vm),
			       GFP_KERNEL);
	if (!hf_vms)
		return -ENOMEM;

	/* Initialize each VM. */
	total_vcpu_count = 0;
	for (i = 0; i < total_vm_count; i++) {
		struct hf_vm *vm = &hf_vms[i];

		/* Adjust the ID as only the secondaries are tracked. */
		vm->id = i + 1;

		ret = hf_vcpu_get_count(vm->id);
		if (ret < 0) {
			pr_err("HF_VCPU_GET_COUNT failed for vm=%u: %lld",
			       vm->id, ret);
			ret = -EIO;
			goto fail_with_cleanup;
		}

		/* Avoid overflowing the vcpu count. */
		if (ret > (U32_MAX - total_vcpu_count)) {
			pr_err("Too many vcpus: %u\n", total_vcpu_count);
			ret = -EDQUOT;
			goto fail_with_cleanup;
		}

		/* Confirm the maximum number of VCPUs looks sane. */
		BUILD_BUG_ON(CONFIG_HAFNIUM_MAX_VCPUS < 1);
		BUILD_BUG_ON(CONFIG_HAFNIUM_MAX_VCPUS > U16_MAX);

		/* Enforce the limit on vcpus. */
		total_vcpu_count += ret;
		if (total_vcpu_count > CONFIG_HAFNIUM_MAX_VCPUS) {
			pr_err("Too many vcpus: %u\n", total_vcpu_count);
			ret = -EDQUOT;
			goto fail_with_cleanup;
		}

		vm->vcpu_count = ret;
		vm->vcpu = kmalloc_array(vm->vcpu_count, sizeof(struct hf_vcpu),
					 GFP_KERNEL);
		if (!vm->vcpu) {
			pr_err("No memory for %u vcpus for vm %u",
			       vm->vcpu_count, vm->id);
			ret = -ENOMEM;
			goto fail_with_cleanup;
		}

		/* Update the number of initialized VMs. */
		hf_vm_count = i + 1;

		/* Create a kernel thread for each vcpu. */
		for (j = 0; j < vm->vcpu_count; j++) {
			struct hf_vcpu *vcpu = &vm->vcpu[j];
			vcpu->task = kthread_create(hf_vcpu_thread, vcpu,
						    "vcpu_thread_%u_%u",
						    vm->id, j);
			if (IS_ERR(vcpu->task)) {
				pr_err("Error creating task (vm=%u,vcpu=%u): %ld\n",
				       vm->id, j, PTR_ERR(vcpu->task));
				vm->vcpu_count = j;
				ret = PTR_ERR(vcpu->task);
				goto fail_with_cleanup;
			}

			get_task_struct(vcpu->task);
			vcpu->vm = vm;
			vcpu->vcpu_index = j;
			atomic_set(&vcpu->abort_sleep, 0);
		}
	}

	/* Register protocol and socket family. */
	ret = proto_register(&hf_sock_proto, 0);
	if (ret) {
		pr_err("Unable to register protocol: %lld\n", ret);
		goto fail_with_cleanup;
	}

	ret = sock_register(&proto_family);
	if (ret) {
		pr_err("Unable to register Hafnium's socket family: %lld\n",
		       ret);
		goto fail_unregister_proto;
	}

	/*
	 * Start running threads now that all is initialized.
	 *
	 * Any failures from this point on must also unregister the socket
	 * family with a call to sock_unregister().
	 */
	for (i = 0; i < hf_vm_count; i++) {
		struct hf_vm *vm = &hf_vms[i];
		for (j = 0; j < vm->vcpu_count; j++)
			wake_up_process(vm->vcpu[j].task);
	}

	/* Dump vm/vcpu count info. */
	pr_info("Hafnium successfully loaded with %u VMs:\n", hf_vm_count);
	for (i = 0; i < hf_vm_count; i++) {
		struct hf_vm *vm = &hf_vms[i];

		pr_info("\tVM %u: %u vCPUS\n", vm->id, vm->vcpu_count);
	}

	return 0;

fail_unregister_proto:
	proto_unregister(&hf_sock_proto);
fail_with_cleanup:
	hf_free_resources();
	return ret;
}

/**
 * Frees up all resources used by the Hafnium driver in preparation for
 * unloading it.
 */
static void __exit hf_exit(void)
{
	pr_info("Preparing to unload Hafnium\n");
	sock_unregister(PF_HF);
	proto_unregister(&hf_sock_proto);
	hf_free_resources();
	pr_info("Hafnium ready to unload\n");
}

MODULE_LICENSE("GPL v2");

module_init(hf_init);
module_exit(hf_exit);
