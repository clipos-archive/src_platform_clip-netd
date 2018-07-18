# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2009-2018 ANSSI. All Rights Reserved.
sbin_PROGRAMS = netd ipsec-updownd
netd_SOURCES = netd.c
netd_CPPFLAGS= -O -Wall -Wextra -Wcast-qual -Wstrict-prototypes -Werror -fno-common -DSTART_SCRIPT=\"@START_SCRIPT@\" -DSTOP_SCRIPT=\"@STOP_SCRIPT@\" -DLIST_SCRIPT=\"@LIST_SCRIPT@\"
ipsec_updownd_SOURCES = ipsec-updownd.c
ipsec_updownd_CPPFLAGS= -O -Wall -Wextra -Wcast-qual -Wstrict-prototypes -Werror -fno-common 
bin_PROGRAMS = netd-client
netd_client_SOURCES = netd-client.c
netd_client_CPPFLAGS= -O -Wall -Wextra -Wcast-qual -Wstrict-prototypes -Werror -fno-common 
