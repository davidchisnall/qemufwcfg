NetBSD FUSE driver for qemufwcfg
================================

This is the FUSE driver that talks to the kernel's `qemufwcfg` device and exposes QEMU configuration information into a filesystem.
The files here, with the exception of the Makefile, are taken unmodified from NetBSD git revision 4af3bcc178ac93d46c9a02a2f6d2836a58a4346d.

The Makefile is based on the NetBSD version but with small changes to make it build on FreeBSD.
