sbin_PROGRAMS = tivobridge
tivobridge_SOURCES = tivobridge.c logger.c cfgfile.c
tivobridge_LDADD = $(LIBOBJS)

AM_CPPFLAGS = -DSYSCONFDIR="\"@sysconfdir@\"" -D_BSD_SOURCE
DISTCLEANFILES = my_stdint.h
