#ifndef utils_h_included
#define utils_h_included

#include <syslog.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <byteswap.h>

#define TOKEN_MAX_SIZE 512

#define TCP_FLAGS_STR_MAX_SIZE 32
#define TCP_UDP_PORT_STR_MAX_SIZE 40
#define TCP_UDP_PP_STR_MAX_SIZE 90

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

#define MAC_ADDR_SIZE 6

struct mac_addr
{
	uint8_t e[MAC_ADDR_SIZE];
} __attribute__((packed));

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

static inline void
csv_next(char **line, char *val)
{
	char *ptr = *line, *end;
	size_t len;

	/* skip spaces */
	while (isspace(*ptr)) {
		ptr++;
	}

	if (*ptr == '\0') {
		/* empty */
		val[0] = '\0';
		return;
	}

	if (*ptr == '\"') {
		/* string */
		ptr++;

		for (;;) {
			if (*ptr == '\0') {
				/* unexpected end, no closing quote */
				*val = '\0';
				*line = ptr;
				return;
			} else if (*ptr == '\"') {
				if (*(ptr + 1) == '\"') {
					*val = '\"';
					val++;
					ptr += 2;
				} else {
					ptr++;
					break;
				}
			} else {
				*val = *ptr;
				val++;
				ptr++;
			}
		}

		end = strchr(ptr, ',');
		if (!end) {
			*line = strchr(ptr, '\0');
			return;
		}
		*line = end + 1;
	} else {
		end = strchr(ptr, ',');
		if (!end) {
			/* no comma */
			strcpy(val, ptr);
			*line = strchr(ptr, '\0');
			return;
		}
		len = end - ptr;
		memcpy(val, ptr, len);
		val[len] = '\0';
		*line = end + 1;
	}
}


char *tcp_flags_to_str(uint8_t tf);
void port_to_str(char *res, uint16_t port);
void ports_pair_to_str(char *res, uint16_t port1, uint16_t port2);
int mac_addr_read(const char *s, struct mac_addr *r);

typedef __int128_t xe_ip;

/* __builtin_bswap128 */
static inline xe_ip
bswap128(xe_ip x)
{
	union _128_as_64 {
		xe_ip v;
		uint64_t q[2];
	} u1, u2;

	u1.v = x;
	u2.q[1] = bswap_64(u1.q[0]);
	u2.q[0] = bswap_64(u1.q[1]);

	return u2.v;
}

#endif

