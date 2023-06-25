
KMOD   =  qemufwcfg
SRCS   =  qemufwcfg.c device_if.h bus_if.h acpi_if.h opt_acpi.h
CFLAGS+= -I${.CURDIR}/include
.include <bsd.kmod.mk>

