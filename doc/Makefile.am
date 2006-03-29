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

noinst_DATA = README.html
EXTRA_DIST = $(noinst_DATA) style.css README.html.in

MAINTAINERCLEANFILES = README.html
CLEANFILES =

if USE_LYNX
noinst_DATA += README
MAINTAINERCLEANFILES += README 
CLEANFILES += README

README: README.html
	lynx --dump $^ | sed 's,file://localhost/.*/doc/README.html,README,' > $@

endif

tidy: README.html
	tidy -e < README.html

.PHONY: tidy
