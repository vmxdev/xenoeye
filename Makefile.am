AM_CPPFLAGS = -I$(srcdir)/tkvdb

bin_PROGRAMS = xenoeye xemkgeocache
xenoeye_SOURCES = xenoeye.c xenoeye.h xe-debug.h \
	utils.h netflow.h netflow.c \
	netflow-templates.c netflow-templates.h \
	tkvdb/tkvdb.c tkvdb/tkvdb.h \
	aajson/aajson.h \
	filter.c filter.h filter-lexer.c filter-parser.c \
	filter-parser-funcs.c \
	pcapture.c monit-objects.c monit-objects.h \
	monit-objects-fwm.c monit-objects-mavg.c \
	monit-objects-mavg-act.c monit-objects-mavg-dump.c \
	classification.c \
	flow-debug.h flow-debug.c \
	devices.h devices.c \
	iplist.h iplist.c \
	geoip.h geoip.c

xemkgeocache_SOURCES = xemkgeocache.c

# checks
check_PROGRAMS = test_filters
test_filters_SOURCES = tests/test_filters.c \
	filter.c filter-lexer.c filter-parser.c iplist.c filter-parser-funcs.c
TESTS = $(check_PROGRAMS)

# config file
dist_sysconf_DATA = xenoeye.conf devices.conf

# data directories
install-data-local:
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/xenoeye/mo"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/xenoeye/exp"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/xenoeye/expfailed"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/xenoeye/iplists"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/xenoeye/notifications"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/xenoeye/clsf"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/xenoeye/geoip"
