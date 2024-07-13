.include <bsd.sysdir.mk>

PROG_CXX=mount_qemufwcfg
SRCS=	mount_qemufwcfg.cc
MAN=	mount_qemufwcfg.8

WARNS?=	5

CXXSTD=	c++20

CXXFLAGS+=-I${SYSDIR}/fs/fuse

NO_SHARED?=NO

.include <bsd.prog.mk>
