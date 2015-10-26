.include <src.opts.mk>
PROG= aslmanager
NO_WERROR=yes

MAN= aslmanager.8

.PATH: .
.PATH: ${.CURDIR}
.PATH: ${.CURDIR}/support
.PATH: ${.CURDIR}/uuid
.PATH: ${.CURDIR}/init


BASE_INCLUDE=  -I. -I${.CURDIR} -I${.CURDIR}/init -I${.CURDIR}/../../include/apple
BASE_INCLUDE+= -I${.CURDIR}/../../include -I${.CURDIR}/../../sys
DEFINES= -D__APPLE__ -fblocks -DLIBC_NO_LIBCRASHREPORTERCLIENT -DPRIVATE
MIG_FLAGS= ${BASE_INCLUDE} 	${DEFINES}
#override default CFLAGS
CFLAGS= ${MIG_FLAGS}  -D__MigTypeCheck
CFLAGS+= -I${.CURDIR}/../../contrib/openbsm -I${.CURDIR}/../../lib/liblaunch -I${.CURDIR}/../../lib/libasl -I${.CURDIR}/../../lib/libdispatch
CFLAGS+= -I${.CURDIR}/../../lib/libxpc -I${.CURDIR}/../../lib/libosxsupport
CFLAGS+= -DHAVE_INTTYPES_H

LDFLAGS+= -pthread

SRCS= aslmanager.c
LDADD+= -lz -lutil -lauditd -lbsm -ldispatch -lmach -lBlocksRuntime -llaunch -losxsupport -lxpc -lnotify -lnv -lsbuf -lasl

.include <bsd.prog.mk>
