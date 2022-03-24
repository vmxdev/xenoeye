#ifndef utils_h_included
#define utils_h_included

#include <syslog.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#define TOKEN_MAX_SIZE 512

#define LOG(...)                                               \
do {                                                           \
	char _buf[4096];                                       \
	int _ret = snprintf(_buf, sizeof(_buf), __VA_ARGS__);  \
	if (_ret >= (int)(sizeof(_buf))) {                     \
		syslog(LOG_DEBUG | LOG_USER,                   \
		"Next line truncated to %d symbols",           \
		_ret);                                         \
	}                                                      \
	syslog(LOG_DEBUG | LOG_USER,                           \
		"%s [%s, line %d, function %s()]",             \
		_buf, __FILE__, __LINE__, __func__);           \
} while (0)

static inline char *
string_trim(char *str)
{
	char *end;

	/* Trim leading space */
	while(isspace((unsigned char)*str)) {
		str++;
	}

	if(*str == 0) {
		/* All spaces? */
		return str;
	}

	/* Trim trailing space */
	end = str + strlen(str) - 1;
	while(end > str && isspace((unsigned char)*end)) {
		end--;
	}

	/* Write new null terminator character */
	end[1] = '\0';

	return str;
}

typedef __int128_t xe_ip;

#endif

