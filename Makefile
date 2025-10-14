PROG=		ndp-proxy-go
BINDIR=		/usr/local/sbin
RCDIR=		/usr/local/etc/rc.d

all:
	go build -ldflags="-s -w" -o ${PROG} main.go

install: all
	install -m 755 ${PROG} ${BINDIR}/
	install -m 555 files/${PROG}.in ${RCDIR}/${PROG}

clean:
	rm -f ${PROG}

uninstall:
	rm -f ${BINDIR}/${PROG}
	rm -f ${RCDIR}/${PROG}

.PHONY: all install clean uninstall
