# $NetBSD: Makefile,v 1.5 2021/12/04 06:42:39 pho Exp $

WARNS=	6

PROG=	mount_qemufwcfg
SRCS=	fwcfg.c virtdir.c
MAN=	mount_qemufwcfg.8

# FreeBSD-specific changes here:
CFLAGS+= -I/usr/local/include -D_FILE_OFFSET_BITS=64 -I${.CURDIR}/../include
MK_WERROR=no
LDFLAGS+= -L/usr/local/lib
LDADD=	-lfuse 

.include <bsd.prog.mk>
