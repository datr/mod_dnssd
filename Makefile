APXS=/usr/bin/apxs2
APACHECTL=apache2ctl
LIBS=$(shell pkg-config --libs howl)
CFLAGS=$(shell pkg-config --cflags howl)

all: mod_dnssd.so

mod_dnssd.so: mod_dnssd.c
	$(APXS) -c $(CFLAGS) $(LIBS) mod_dnssd.c

install: all
	$(APXS) -i -a -n dnssd mod_dnssd.so

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
