VERSION=	v1.0.0

PROG=		ndp-proxy-go
BINDIR=		/usr/local/sbin
LDFLAGS=	-s -w -X main.version=$(VERSION)

all:
	go build -ldflags="$(LDFLAGS)" -o $(PROG)

install: all
	install -m 755 $(PROG) $(BINDIR)/

clean:
	rm -f $(PROG)

uninstall:
	rm -f $(BINDIR)/$(PROG)

.PHONY: all install clean uninstall
