#	From: @(#)Makefile	8.1 (Berkeley) 6/10/93
# $FreeBSD$

.include <src.opts.mk>

# The following modules do not describe FreeBSD:
# 14.uucpimpl, 15.uucpnet

# The following modules do not build/install:
# 13.amd (documentation is TeXinfo)
# 16.security 17.password (encumbered)

SUBDIR=	title \
	contents \
	01.setup \
	02.config \
	03.fsck \
	04.quotas \
	05.fastfs \
	06.nfs \
	11.timedop \
	12.timed \
	18.net

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
