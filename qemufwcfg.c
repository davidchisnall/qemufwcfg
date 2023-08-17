/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 David Chisnall <theraven@FreeBSD.org>
 *
 * This file was created using the NetBSD implementation as reference and so
 * may be a derived work of the NetBSD implementation:
 * Copyright (c) 2017 Jared McNeill <jmcneill@invisible.ca>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * This provides a NetBSD-compatible qemufwcfg device.
 *
 * The only intended consumer of this is a FUSE filesystem that exports the
 * firmware configuration to userspace.
 */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/stddef.h>
#include <sys/uio.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <dev/ic/qemufwcfgio.h>

// clang-format off
// Clang-format puts these in the wrong order.
#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/accommon.h>
#include <dev/acpica/acpivar.h>
// clang-format on

// Forward declarations
static int qemufwcfg_probe(device_t);
static int qemufwcfg_attach(device_t);
static int qemufwcfg_detach(device_t);
static int qemufwcfg_open(struct cdev *dev, int oflags, int devtype,
    struct thread *td);
static int qemufwcfg_close(struct cdev *dev, int flags,
    int fmt, struct thread *td);
static int qemufwcfg_ioctl(struct cdev *dev, u_long cmd, caddr_t data,
    int fflag, struct thread *td);
static int qemufwcfg_read(struct cdev *dev, struct uio *uio,
    int ioflag);

/**
 * Device attachment methods.
 */
static device_method_t qemufwcfg_methods[] = {
	/*	Methods	from the device	interface */
	DEVMETHOD(device_probe, qemufwcfg_probe),
	DEVMETHOD(device_attach, qemufwcfg_attach),
	DEVMETHOD(device_detach, qemufwcfg_detach),
	/*	Terminate method list */
	DEVMETHOD_END
};

/**
 * Character device methods.
 */
static struct cdevsw qemufwcfg_cdevsw = {
	.d_version = D_VERSION,
	.d_name = "qemufwcfg",
	.d_open = qemufwcfg_open,
	.d_close = qemufwcfg_close,
	.d_read = qemufwcfg_read,
	.d_ioctl = qemufwcfg_ioctl,
};

/**
 * State for this device.
 */
struct qemufwcfg_softc {
	/// I/O type, MMIO or I/O port
	int io_type;
	/// Resource id, filled in by `bus_alloc_resource_any`.
	int resource_id;
	/// The resource for this device, from ACPI.  May be I/O ports on x86
	/// or MMIO.
	struct resource *res;
	/// Cached copy of the bus space tag from `res`.
	bus_space_tag_t tag;
	/// Cached copy of the bus space handle from `res`.
	bus_space_handle_t handle;
	/// Character device node.
	struct cdev *cdev;
	/// Mutex protecting this structure.  This is used to protect `is_open`.
	struct mtx mutex;
	/// Flag indicating that this is open, protects against concurrent
	/// access.
	bool is_open;
};

/**
 * Driver configuration.
 */
static driver_t qemufwcfg_driver = { "qemufwcfg", qemufwcfg_methods,
	sizeof(struct qemufwcfg_softc) };

DRIVER_MODULE(qemufwcfg, acpi, qemufwcfg_driver, NULL, NULL);

// NOTE: The following two functions assume that all MMIO versions of the
// device will have the same layout.  Currently, QEMU documents an x86 I/O Port
// version and an Arm MMIO version, but it seems reasonable to assume that
// other platforms that use MMIO will not gratuitously change it.

/**
 * Helper.  Writes the specified selector value to the device.
 */
static void
write_selector(struct qemufwcfg_softc *sc, uint16_t index)
{
	// The offset from the base I/O port when using I/O ports
	const int SelectorPortOffset = 0x0;
	// The offset from the base MMIO address, when using MMIO.
	const int SelectorMMIOOffset = 0x8;
	int offset;

	if (sc->io_type == SYS_RES_IOPORT) {
		// I/O port mode uses little endian for the selector
		index = htole16(index);
		offset = SelectorPortOffset;
	} else {
		// MMIO mode uses little endian for the selector
		index = htobe16(index);
		offset = SelectorMMIOOffset;
	}
	// Write the selector value.
	bus_space_write_2(sc->tag, sc->handle, offset, index);
}

/**
 * Helper.  Returns the offset for the selector.
 */
static int
offset_for_data(struct qemufwcfg_softc *sc)
{
	// The offset from the base I/O port when using I/O ports
	const int DataPortOffset = 0x1;
	// The offset from the base MMIO address, when using MMIO.
	const int DataMMIOOffset = 0x0;
	return (
	    (sc->io_type == SYS_RES_IOPORT) ? DataPortOffset : DataMMIOOffset);
}

/**
 * Probe hook.  Checks that the ACPI node exists.
 */
static int
qemufwcfg_probe(device_t dev)
{
	ACPI_HANDLE h;

	if ((h = acpi_get_handle(dev)) == NULL)
		return (ENXIO);

	if (!acpi_MatchHid(h, "QEMU0002"))
		return (ENXIO);

	return 0;
}

/**
 * Attach to the device.  This performs a read on the signature to ensure that
 * this really is the right kind of device.
 */
static int
qemufwcfg_attach(device_t dev)
{
	struct qemufwcfg_softc *sc = device_get_softc(dev);

	// Try to configure the memory space.  The device can use I/O ports on
	// x86, memory elsewhere.
	if (bus_get_resource(dev, SYS_RES_IOPORT, 0, NULL, NULL) == 0) {
		sc->io_type = SYS_RES_IOPORT;
	} else if (bus_get_resource(dev, SYS_RES_MEMORY, 0, NULL, NULL) == 0) {
		sc->io_type = SYS_RES_MEMORY;
	} else {
		device_printf(dev, "Unknown resource type\n");
		return (ENXIO);
	}

	sc->res = bus_alloc_resource_any(dev, sc->io_type, &sc->resource_id,
	    RF_ACTIVE);
	if (sc->res == NULL) {
		device_printf(dev, "Failed to allocate bus resource\n");
		return (ENXIO);
	}

	// Cache the tag and handle so we don't have to keep looking them up.
	sc->tag = rman_get_bustag(sc->res);
	sc->handle = rman_get_bushandle(sc->res);

	// The selector reserved for checking that this is the correct
	// interface.
	const int SignatureSelector = 0;
	write_selector(sc, SignatureSelector);

	// Read 4 bytes from signature.
	int offset = offset_for_data(sc);
	char buf[4];
	bus_space_read_multi_1(sc->tag, sc->handle, offset, buf, sizeof(buf));

	// Check that the signature value is correct.
	static const char expected[] = "QEMU";
	_Static_assert(sizeof(expected) >= sizeof(buf),
	    "Expected value too small!");
	if (strncmp(buf, expected, sizeof(buf)) != 0) {
		bus_release_resource(dev, sc->io_type, sc->resource_id,
		    sc->res);
		sc->res = NULL;
		device_printf(dev,
		    "Failed to attach, got <%c%c%c%c>, expected <QEMU>", buf[0],
		    buf[1], buf[2], buf[3]);
		return (ENXIO);
	}

	mtx_init(&sc->mutex, "qemufwcfg lock", NULL, MTX_DEF);

	// Create the device node.
	struct make_dev_args args;
	make_dev_args_init(&args);
	args.mda_mode = 0400;
	args.mda_devsw = &qemufwcfg_cdevsw;
	args.mda_si_drv1 = sc;
	args.mda_flags = MAKEDEV_WAITOK | MAKEDEV_CHECKNAME;

	make_dev_s(&args, &sc->cdev, "qemufwcfg");

	return (0);
}

/**
 * Detach from the device.  Cleans up resources.
 */
static int
qemufwcfg_detach(device_t dev)
{
	struct qemufwcfg_softc *sc = device_get_softc(dev);
	destroy_dev(sc->cdev);
	bus_release_resource(dev, sc->io_type, sc->resource_id, sc->res);
	mtx_destroy(&sc->mutex);
	return 0;
}

/**
 * Open.  This device doesn't allow concurrent access so this fails if more
 * more than one attempt is made to open the device.
 */
static int
qemufwcfg_open(struct cdev *dev, int oflags __unused, int devtype __unused,
    struct thread *td __unused)
{
	struct qemufwcfg_softc *sc = dev->si_drv1;
	int error = 0;

	mtx_lock(&sc->mutex);
	if (sc->is_open) {
		error = EBUSY;
	} else {
		sc->is_open = true;
	}
	mtx_unlock(&sc->mutex);

	return (error);
}

/**
 * Close the device.  This just marks the device as not open to allow another
 * userspace process to open it, it doesn't do any cleanup.
 */
static int
qemufwcfg_close(struct cdev *dev, int flags __unused, int fmt __unused,
    struct thread *td __unused)
{
	struct qemufwcfg_softc *sc = dev->si_drv1;
	int error = 0;

	mtx_lock(&sc->mutex);
	if (!sc->is_open) {
		error = EINVAL;
	} else {
		sc->is_open = false;
	}
	mtx_unlock(&sc->mutex);

	return (error);
}

/**
 * Ioctl handler.  A single ioctl is supported, to set the selector.
 */
static int
qemufwcfg_ioctl(struct cdev *dev, u_long cmd, caddr_t data,
    int fflag __unused, struct thread *td __unused)
{
	struct qemufwcfg_softc *sc = dev->si_drv1;

	switch (cmd) {
	default:
		return (ENOTTY);
	case FWCFGIO_SET_INDEX: {
		uint16_t index = *(uint16_t *)data;
		write_selector(sc, index);
		return (0);
	}
	}
}

/**
 * Read.  This reads the specified number of bytes from the currently
 * configured selector.  Seek is not supported (here or by the QEMU device),
 * the only way of reading backwards is to reset to the beginning of a 'file'
 * and read forwards.
 *
 * DMA is not currently used.  For small files, the cost of pinning a buffer
 * and passing a physical address out to the host would likely offset any
 * speedup.  We can read 8 bytes at a time and most files that we read are a
 * handful of MMIO reads at this size.
 */
static int
qemufwcfg_read(struct cdev *dev, struct uio *uio, int ioflag __unused)
{
	struct qemufwcfg_softc *sc = dev->si_drv1;

	if (sc == NULL) {
		return (ENXIO);
	}

	int error = 0;
	int offset = offset_for_data(sc);

	// If we're in MMIO mode, try reading 8 bytes at a time.  This reduces
	// the number of VM exits that we need by a factor of 8, which is
	// probably premature optimisation given how rare reads on this device
	// are, but was easy to do.
	if (sc->io_type == SYS_RES_MEMORY) {
		uint64_t buf[8];
		while ((uio->uio_resid > sizeof(buf[0])) && (error == 0)) {
			size_t count = min(sizeof(buf), uio->uio_resid) /
			    sizeof(buf[0]);
			bus_space_read_multi_8(sc->tag, sc->handle, offset, buf,
			    count);
			error = uiomove(buf, count * sizeof(buf[0]), uio);
		}
	}

	while ((uio->uio_resid > 0) && (error == 0)) {
		// Try copying 64 bytes at a time.  If we're on a platform that
		// supports MMIO then we should be copying at most 7 bytes here because
		// we'll have read the rest via 8-byte reads.  If we're using x86 IO
		// Ports then we have to read one byte at at time.
		uint8_t buf[64];
		size_t count = min(sizeof(buf), uio->uio_resid);
		bus_space_read_multi_1(sc->tag, sc->handle, offset, buf, count);
		error = uiomove(buf, count, uio);
	}

	return (error);
}
