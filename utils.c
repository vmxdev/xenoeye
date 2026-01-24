/*
 * xenoeye
 *
 * Copyright (c) 2024-2026, Vladimir Misyurov
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "utils.h"
#include "utils-data.inc"

char *
tcp_flags_to_str(uint8_t tf)
{
	return tcp_flags_db[tf];
}

void
port_to_str(char *res, uint16_t port)
{
	char *s = ports_db[port];
	if (s[0]) {
		sprintf(res, "%s (%d)", s, port);
		return;
	}
	sprintf(res, "%d", port);
}

void
ports_pair_to_str(char *res, uint16_t port1, uint16_t port2)
{
	char *s1 = ports_db[port1];
	char *s2 = ports_db[port2];

	if (s1[0] && s2[0]) {
		sprintf(res, "%s(%d) -> %s(%d)", s1, port1, s2, port2);
		return;
	}

	if (port1 == port2) {
		sprintf(res, "%d -> %d", port1, port2);
		return;
	}

	if (port1 < port2) {
		if (!s1[0] && !s2[0]) {
			sprintf(res, "%d ->", port1);
			return;
		} else if (!s1[0] && s2[0]) {
			sprintf(res, "%d -> %s(%d)", port1, s2, port2);
			return;
		} else if (s1[0] && !s2[0]) {
			sprintf(res, "%s(%d) ->", s1, port1);
			return;
		}
	} else {
		if (!s1[0] && !s2[0]) {
			sprintf(res, "-> %d", port2);
			return;
		} else if (!s1[0] && s2[0]) {
			sprintf(res, "-> %s(%d)", s2, port2);
		} else if (s1[0] && !s2[0]) {
			sprintf(res, "%s(%d) -> %d", s1, port1, port2);
			return;
		}
	}
}

static int
mac_hex_to_int(const char c)
{
	if ((c >= 'a') && (c <= 'f')) {
		return c - 'a' + 10;
	}

	if ((c >= 'A') && (c <= 'F')) {
		return c - 'A' + 10;
	}

	if ((c >= '0') && (c <= '9')) {
		return c - '0';
	}

	return 0;
}

int
mac_addr_read(const char *s, struct mac_addr *r)
{
	struct mac_addr mac;
	int i;
	size_t req_len = MAC_ADDR_SIZE * 3 - 1;

	if (strlen(s) != req_len) {
		return 0;
	}

	for (i=0; i<MAC_ADDR_SIZE; i++) {
		int h1, h2;
		char delim = s[i * 3 + 2];
		if ((delim != ':') && (delim != '\0')) {
			return 0;
		}

		h1 = mac_hex_to_int(s[i * 3 + 0]);
		h2 = mac_hex_to_int(s[i * 3 + 1]);
		mac.e[i] = (h1 << 4) | h2;
	}

	memcpy(r, &mac, MAC_ADDR_SIZE);

	return 1;
}

