AM_CPPFLAGS = -I$(srcdir)/tkvdb

bin_PROGRAMS = xenoeye xemkgeodb xegeoq xesflow
xenoeye_SOURCES = xenoeye.c xenoeye.h xe-debug.h \
	utils.h utils.c utils-data.inc netflow.h netflow.c \
	netflow-templates.c netflow-templates.h \
	sflow.c sflow.h xe-sni.h xe-dns.h \
	tkvdb/tkvdb.c tkvdb/tkvdb.h \
	aajson/aajson.h \
	filter.c filter.h filter-lexer.c filter-parser.c \
	filter-parser-funcs.c \
	pcapture.c scapture.c \
	monit-objects.c monit-objects.h \
	monit-objects-fwm.c monit-objects-mavg.c \
	monit-objects-mavg-act.c monit-objects-mavg-dump.c \
	monit-objects-mavg-limfile.c \
	monit-objects-mavg-under.c \
	classification.c \
	flow-debug.h flow-debug.c \
	devices.h devices.c \
	iplist.h iplist.c \
	ip-btrie.h \
	geoip.h geoip.c

xemkgeodb_SOURCES = xemkgeodb.c geoip.h ip-btrie.h tkvdb/tkvdb.c tkvdb/tkvdb.h

xegeoq_SOURCES = xegeoq.c geoip.h ip-btrie.h

xesflow_SOURCES = xesflow.c rawparse.h sflow.h sflow-impl.h xe-sni.h xe-dns.h


# checks
check_PROGRAMS = test_filters
test_filters_SOURCES = tests/test_filters.c \
	filter.c filter-lexer.c filter-parser.c \
	iplist.c filter-parser-funcs.c \
	geoip.c utils.c
TESTS = $(check_PROGRAMS)

# config files
configs = xenoeye.conf devices.conf

# DB export script
libexec_SCRIPTS = scripts/xe-dbexport-pg.sh scripts/xe-dbexport-ch.sh

# data directories and config files
install-data-local:
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/xenoeye/mo"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/xenoeye/exp"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/xenoeye/expfailed"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/xenoeye/iplists"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/xenoeye/notifications"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/xenoeye/clsf"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/xenoeye/geoip"
	$(MKDIR_P) "$(DESTDIR)$(sysconfdir)"
	@for cfg in $(configs); do \
		$(INSTALL_DATA) $$cfg "$(DESTDIR)$(sysconfdir)/$$cfg.sample"; \
		if test -f $(DESTDIR)$(sysconfdir)/$$cfg; then \
			echo "$(DESTDIR)$(sysconfdir)/$$cfg already exists; overwrite manually"; \
		else \
			$(INSTALL_DATA) $$cfg "$(DESTDIR)$(sysconfdir)/$$cfg"; \
		fi \
	done
