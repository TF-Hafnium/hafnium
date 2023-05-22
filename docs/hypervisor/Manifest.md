# Hafnium Manifest

## Format

The format of the manifest is a simple DeviceTree overlay:

```
/dts-v1/;

/ {
	hypervisor {
		compatible = "hafnium,hafnium";

		ffa_tee_enabled;

		vm1 {
			debug_name = "name";
			kernel_filename = "vmlinuz";
			ramdisk_filename = "initrd.img";
		};

		vm2 {
			debug_name = "name";
			kernel_filename = "filename";
			vcpu_count = <N>;
			mem_size = <M>;
		};
		...
	};
};
```

## Example

The following manifest defines a primary VM with two secondary VMs. The first
secondary VM has 1MB of memory, 2 CPUs and kernel image called `kernel0`
(matches filename in Hafnium's [ramdisk](HafniumRamDisk.md)). The second has 2MB
of memory, 4 CPUs and, by omitting the `kernel_filename` property, a kernel
preloaded into memory. The primary VM is given all remaining memory, the same
number of CPUs as the hardware, a kernel image called `vmlinuz` and a ramdisk
`initrd.img`. Secondaries cannot have a ramdisk. FF-A memory sharing with the
TEE is enabled.

```
/dts-v1/;

/ {
	hypervisor {
		compatible = "hafnium,hafnium";

		ffa_tee_enabled;

		vm1 {
			debug_name = "primary VM";
			kernel_filename = "vmlinuz";
			ramdisk_filename = "initrd.img";

			smc_whitelist = <
				0x04000000
				0x3200ffff
				>;
		};

		vm2 {
			debug_name = "secondary VM 1";
			kernel_filename = "kernel0";
			vcpu_count = <2>;
			mem_size = <0x100000>;

			smc_whitelist_permissive;
		};

		vm3 {
			debug_name = "secondary VM 2";
			vcpu_count = <4>;
			mem_size = <0x200000>;
		};
	};
};
```

## FF-A partition
Partitions wishing to follow the FF-A specification must respect the
format specified by the [TF-A binding document](https://trustedfirmware-a.readthedocs.io/en/latest/components/ffa-manifest-binding.html).

## Compiling

Hafnium expects the manifest inside its [RAM disk](HafniumRamDisk.md),
in DeviceTree's binary format (DTB).

Compile the manifest's source file into a DTB with:
```shell
prebuilts/linux-x64/dtc/dtc -I dts -O dtb --out-version 17 -o manifest.dtb <manifest_source_file>
```
