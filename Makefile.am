AM_CPPFLAGS = -I$(srcdir)/tkvdb

#bin_PROGRAMS = xenoeye xemkrep
bin_PROGRAMS = xenoeye
xenoeye_SOURCES = xenoeye.c xenoeye.h \
	utils.h netflow.h netflow.c \
	netflow_templates.c netflow_templates.h \
	tkvdb/tkvdb.c tkvdb/tkvdb.h \
	aajson/aajson.h \
	filter.c filter.h filter_lexer.c filter_parser.c \
	pcapture.c monit_objects.c

#xemkrep_SOURCES = xemkrep.c \
#	tkvdb/tkvdb.c tkvdb/tkvdb.h

# checks
check_PROGRAMS = test_filters
test_filters_SOURCES = tests/test_filters.c \
	filter.c filter_lexer.c filter_parser.c
TESTS = $(check_PROGRAMS)
