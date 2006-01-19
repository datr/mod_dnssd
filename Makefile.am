# $Id$

# Copyright 2006 Lennart Poettering
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.  You
# may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

EXTRA_DIST=bootstrap.sh LICENSE src/mod_dnssd.c src/Makefile.in
SUBDIRS=src doc

MAINTAINERCLEANFILES = README
noinst_DATA = README LICENSE

README:
	rm -f README
	$(MAKE) -C doc README
	cd $(srcdir) && ln -s doc/README README

homepage: all dist
	test -d $$HOME/homepage/private
	mkdir -p $$HOME/homepage/private/projects/mod_dnssd
	cp *.tar.gz $$HOME/homepage/private/projects/mod_dnssd
	cp doc/README.html doc/style.css $$HOME/homepage/private/projects/mod_dnssd
	ln -sf $$HOME/homepage/private/projects/mod_dnssd/README.html $$HOME/homepage/private/projects/mod_dnssd/index.html

.PHONY: homepage
