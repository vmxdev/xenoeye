#ifndef utils_h_included
#define utils_h_included

#include <syslog.h>
#include <stdio.h>

#define LOG(...)                                               \
do {                                                           \
	char _buf[2048];                                       \
	snprintf(_buf, sizeof(_buf), __VA_ARGS__);             \
	syslog(LOG_DEBUG | LOG_USER,                           \
		 "%s [%s, line %d, function %s()]",            \
		_buf, __FILE__, __LINE__, __func__);           \
} while (0)


#endif

