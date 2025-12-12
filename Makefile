VERSION=	v0.4.0

PROG=		ndp-proxy-go
BINDIR=		/usr/local/sbin
RCDIR=		/usr/local/etc/rc.d
LDFLAGS=	-s -w -X main.version=$(VERSION)

all:
	go build -ldflags="$(LDFLAGS)" -o $(PROG)

install: all
	install -m 755 $(PROG) $(BINDIR)/
	install -m 555 files/ndp-proxy-go.in $(RCDIR)/ndp-proxy-go

clean:
	rm -f $(PROG)

uninstall:
	rm -f $(BINDIR)/$(PROG)
	rm -f $(RCDIR)/ndp-proxy-go

.PHONY: all install clean uninstall
