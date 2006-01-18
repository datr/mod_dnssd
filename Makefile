# $Id$

APXS=/usr/bin/apxs2
APACHECTL=apache2ctl
LIBS=$(shell pkg-config --libs avahi-client)
CFLAGS=$(shell pkg-config --cflags avahi-client)

all: mod_dnssd.la

mod_dnssd.la: mod_dnssd.c
	$(APXS) -c $(CFLAGS) $(LIBS) mod_dnssd.c

install: mod_dnssd.la
	$(APXS) -i -a mod_dnssd.la 

clean:
	rm -rf *.o *.so *.loT .deps/ *.la *.lo *.slo .libs

reload: install restart

start:
	$(APACHECTL) start

restart:
	$(APACHECTL) restart

stop:
	$(APACHECTL) stop

.PHONY: all install clean reload start restart stop
