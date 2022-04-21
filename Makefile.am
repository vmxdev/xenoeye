AM_CPPFLAGS = -I$(srcdir)/tkvdb

#bin_PROGRAMS = xenoeye xemkrep
bin_PROGRAMS = xenoeye
xenoeye_SOURCES = xenoeye.c xenoeye.h xe-debug.h \
	utils.h netflow.h netflow.c \
	netflow_templates.c netflow_templates.h \
	tkvdb/tkvdb.c tkvdb/tkvdb.h \
	aajson/aajson.h \
	filter.c filter.h filter_lexer.c filter_parser.c \
	pcapture.c monit-objects.c monit-objects.h \
	monit-objects-fwm.c monit-objects-mavg.c \
	flow_debug.h flow_debug.c \
	devices.h devices.c \
	iplist.h iplist.c

#xemkrep_SOURCES = xemkrep.c \
#	tkvdb/tkvdb.c tkvdb/tkvdb.h

# checks
check_PROGRAMS = test_filters
test_filters_SOURCES = tests/test_filters.c \
	filter.c filter_lexer.c filter_parser.c iplist.c
TESTS = $(check_PROGRAMS)

# config file
dist_sysconf_DATA = xenoeye.conf devices.conf

# data directories
install-data-local:
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/xenoeye/mo"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/xenoeye/exp"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/xenoeye/expfailed"
