# Running Hafnium under Arm FVP

Arm offers a series of emulators known as Fixed Virtual Platforms (FVPs), which
simulate various processors. They are generally more accurate to the hardware
than QEMU, at the cost of being considerably slower. We support running
[tests](Testing.md) on the FVP as well as QEMU.

## Set up

1.  Download the
    [Armv8-A Base Platform FVP](https://developer.arm.com/products/system-design/fixed-virtual-platforms)
    from Arm.
1.  Unzip it to a directory called `fvp` alongside the root directory of your
    Hafnium checkout.

## Running tests

To run tests with the FVP instead of QEMU, from the root directory of your
Hafnium checkout:

```shell
$ make && kokoro/test.sh --fvp
```

See the `FvpDriver` class in [`hftest.py`](../../test/hftest/hftest.py) for details
on how this works.

## Other resources

When running tests under the FVP we also use a prebuilt version of TF-A, which
is checked in under
[`prebuilts/linux-aarch64/arm-trusted-firmware/`](https://review.trustedfirmware.org/plugins/gitiles/hafnium/prebuilts/+/refs/heads/master/linux-aarch64/arm-trusted-firmware/).
The
[README](https://review.trustedfirmware.org/plugins/gitiles/hafnium/prebuilts/+/refs/heads/master/linux-aarch64/arm-trusted-firmware/README.md)
there has details on how it was built. The source code is available from the
[Arm Trusted Firmware site](https://git.trustedfirmware.org/TF-A/trusted-firmware-a.git).

Documentation of the FVP (including memory maps) is
[available from Arm](https://developer.arm.com/docs/100966/latest).
