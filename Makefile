# ftd — BSD-style makefile. Works with OpenBSD make(1) and GNU make.
#
#   make            build the ftd binary
#   doas make install   install binary, config (kept if present), rc script
#   make clean      remove build output
#
# Override paths as usual: make install PREFIX=/opt DESTDIR=/tmp/stage

PROG=		ftd
PREFIX?=	/usr/local
BINDIR?=	${PREFIX}/bin
SYSCONFDIR?=	/etc
RCDIR?=		${SYSCONFDIR}/rc.d
GO?=		go
INSTALL?=	install

all: ${PROG}

# go build is incremental on its own; always invoke it rather than tracking
# the source list (templates/ and static/ are embedded at build time too).
# First build on a fresh clone fetches dependencies and writes go.sum.
# FRC forces the rule to run every time, portably across BSD and GNU make.
# -buildvcs=false: VCS stamping runs git, which fails when building in a
# checkout owned by another user (e.g. doas make in ~user; git's
# safe.directory check exits 128) or without git installed. We don't need it.
${PROG}: FRC
	@[ -f go.sum ] || ${GO} mod tidy
	${GO} build -trimpath -buildvcs=false -o ${PROG} .

FRC:

install: ${PROG}
	${INSTALL} -d -m 755 ${DESTDIR}${BINDIR}
	${INSTALL} -m 755 ${PROG} ${DESTDIR}${BINDIR}/${PROG}
	@if [ ! -e "${DESTDIR}${SYSCONFDIR}/ftd.conf" ]; then \
		${INSTALL} -d -m 755 "${DESTDIR}${SYSCONFDIR}"; \
		${INSTALL} -m 640 ftd.conf "${DESTDIR}${SYSCONFDIR}/ftd.conf"; \
		echo "installed ${DESTDIR}${SYSCONFDIR}/ftd.conf — edit database_url before starting"; \
	else \
		echo "keeping existing ${DESTDIR}${SYSCONFDIR}/ftd.conf"; \
	fi
	@if [ -d "${DESTDIR}${RCDIR}" ]; then \
		${INSTALL} -m 755 rc.d/ftd "${DESTDIR}${RCDIR}/ftd"; \
		echo "installed ${DESTDIR}${RCDIR}/ftd"; \
	fi

clean:
	rm -f ${PROG}

.PHONY: all install clean
