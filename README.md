NetBSD-compatible qemufwcfg device for FreeBSD
==============================================

NetBSD's guest interface to the [QEMU firmware configuration device](https://www.qemu.org/docs/master/specs/fw_cfg.html) is made of two parts:

 - A kernel component that forwards commands to the device from userspace.
 - A FUSE filesystem that exports the read-only virtual filesystem, using the simple kernel interface.

This is a very clean design that minimises the amount of complexity in the kernel.

This repository contains a reimplementation of the NetBSD kernel API (inspired by their code and under the same license) and a copy of the FUSE portion with a Makefile that allows it to build on FreeBSD.

Dependencies
------------

The FUSE filesystem depends on the FUSE libraries to build:

```sh
# pkg ins fusefs-libs
```

Building
--------

Both parts of this build with bmake (the default `make` on FreeBSD / NetBSD).
They are built separately to make it easier to upstream the kernel module to FreeBSD and the FreeBSD-specific changes to NetBSD (and packaging it as a port):

```sh
$ mkdir obj
$ make
$ cd mount_qemufwcfg
$ mkdir obj
$ make
```

You can optionally install by running `make install` in each directory as root:

```sh
# make install
# cd mount_qemufwcfg
# make install BINDIR=/usr/local/sbin
```

Using
-----

The FUSE filesystem depends on both the kernel module from this repository and the fusefs kernel module that is part of the base system.
These can be loaded with `kldload`:

```sh
# kldload fusefs
# kldload ./obj/qemufwcfg.ko
```

You can enable these at boot after installing by putting the following two lines in `/boot/loader.conf`:

```
qemufwcfg_load="YES"
fusefs_load="YES"
```

If the module has loaded correctly then `/dev/qemufwcfg` should exist.
If not, check `dmesg` for errors and file issues against this repository.

Once the module has loaded, you can try running the qemu filesystem:

```sh
# ./mount_qemufwcfg/obj/mount_qemufwcfg /mnt/qemufwcfg/
# ls -R /mnt/qemufwcfg
bios-geometry	bootorder	etc		vgaroms

/mnt/qemufwcfg/etc:
acpi		boot-fail-wait	ramfb		smbios		table-loader	tpm

/mnt/qemufwcfg/etc/acpi:
rsdp	tables

/mnt/qemufwcfg/etc/smbios:
smbios-anchor	smbios-tables

/mnt/qemufwcfg/etc/tpm:
log

/mnt/qemufwcfg/vgaroms:
vgabios-ramfb.bin
```

The exact set of files depends on your qemu configuration but you should see some files here.
You can add additional files using the `-fw_cfg` command-line flag to QEMU.
