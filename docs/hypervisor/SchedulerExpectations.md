# Scheduler VM expectations

Hafnium requires there to be a special 'primary' or 'scheduler' VM which is
responsible for scheduling the other VMs. There are some particular expectations
on this VM that are required for the rest of the system to function normally.

## Scheduling

The scheduler VM is responsible for scheduling the vCPUs of all the other VMs.
It should request information about the VMs in the system using the
`FFA_PARTITION_INFO_GET` function, and then schedule their vCPUs as it wishes.
The recommended way of doing this is to create a kernel thread for each vCPU,
which will repeatedly run that vCPU by calling `FFA_RUN`.

`FFA_RUN` will return one of several possible functions, which must be handled
as follows:

### `FFA_INTERRUPT`

The vCPU has been preempted but still has work to do. If the scheduling quantum
has not expired, the scheduler MUST call `FFA_RUN` on the vCPU to allow it to
continue.

If `w1` is non-zero, then Hafnium would like `FFA_RUN` to be called on the vCPU
specified there. The scheduler MUST either wake the vCPU in question up if it is
blocked, or preempt and re-run it if it is already running somewhere. This gives
Hafnium a chance to update any CPU state which might have changed. The scheduler
should call `FFA_RUN` again on the sending VM as usual.

### `FFA_YIELD`

The vCPU has voluntarily yielded the CPU. The scheduler SHOULD take a scheduling
decision to give cycles to those that need them but MUST call `FFA_RUN` on the
vCPU at a later point.

### `FFA_MSG_WAIT`

The vCPU is blocked waiting for a message. The scheduler MUST take it off the
run queue and not call `FFA_RUN` on the vCPU until it has either:

*   injected an interrupt
*   sent it a message
*   received `FFA_INTERRUPT` for it from another vCPU
*   the timeout provided in `w2` is not `FFA_SLEEP_INDEFINITE` and the
    specified duration has expired.

### `FFA_MSG_SEND`

A message has been sent by the vCPU. If the recipient is the scheduler VM itself
then it can handle it as it pleases. Otherwise the scheduler MUST run a vCPU
from the recipient VM and priority SHOULD be given to those vCPUs that are
waiting for a message. The scheduler should call `FFA_RUN` again on the sending
VM as usual.

### `FFA_RX_RELEASE`

The vCPU has made the mailbox writable and there are pending waiters. The
scheduler MUST call `hf_mailbox_waiter_get()` repeatedly and notify all waiters
by injecting an `HF_MAILBOX_WRITABLE_INTID` interrupt. The scheduler should call
`FFA_RUN` again on the sending VM as usual.

### `HF_FFA_RUN_WAIT_FOR_INTERRUPT`

_This is a Hafnium-specific function not part of the FF-A standard._

The vCPU is blocked waiting for an interrupt. The scheduler MUST take it off the
run queue and not call `FFA_RUN` on the vCPU until it has either:

*   injected an interrupt
*   received `FFA_INTERRUPT` for it from another vCPU
*   the timeout provided in `w2` is not `FFA_SLEEP_INDEFINITE` and the
    specified duration has expired.

### `FFA_ERROR`

#### `FFA_ABORTED`

The vCPU has aborted triggering the whole VM to abort. The scheduler MUST treat
this the same as `FFA_INTERRUPT` for all the other vCPUs of the VM. For this
vCPU the scheduler SHOULD either never call `FFA_RUN` on the vCPU again, or treat
it the same as `HF_FFA_RUN_WAIT_FOR_INTERRUPT`.

#### Any other error code

This should not happen if the scheduler VM has called `FFA_RUN` correctly, but
in case there is some other error it should be logged. The scheduler SHOULD
either try again or suspend the vCPU indefinitely.

## Interrupt handling

The scheduler VM is responsible for handling all hardware interrupts. Many of
these will be intended for the scheduler VM itself and it can handle them as
usual. However, it must also:

*   Enable, handle and ignore interrupts for the non-secure hypervisor physical
    timer (PPI 10, IRQ 26).
*   Forward interrupts intended for secondary VMs to an appropriate vCPU of the
    VM by calling `hf_interrupt_inject` and then running the vCPU as usual with
    `FFA_RUN`. (If the vCPU is already running at the time that
    `hf_interrupt_inject` is called then it must be preempted and run again so
    that Hafnium can inject the interrupt.)
