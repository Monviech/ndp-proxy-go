VERSION=	0.1.1

PROG=		ndp-proxy-go
BINDIR=		/usr/local/sbin
RCDIR=		/usr/local/etc/rc.d
LDFLAGS=	-s -w -X main.Version=$(VERSION)

all:
	go build -ldflags="$(LDFLAGS)" -o $(PROG)

install: all
	install -m 755 $(PROG) $(BINDIR)/
	install -m 555 files/ndp_proxy_go.in $(RCDIR)/ndp_proxy_go

clean:
	rm -f $(PROG)

uninstall:
	rm -f $(BINDIR)/$(PROG)
	rm -f $(RCDIR)/ndp_proxy_go

.PHONY: all install clean uninstall
