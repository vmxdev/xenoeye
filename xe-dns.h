#ifndef xe_dns_included
#define xe_dns_included

#include <arpa/nameser.h>

#define PREFIX "\t\t\t\t"

struct dns_ans_data
{
	uint16_t type;
	uint16_t aclass;
	uint32_t ttl;
	uint16_t data_len;
	uint8_t data[1];
} __attribute__((packed));

static inline int
xe_dns(uint8_t *p, uint8_t *end, char *domain, char *ips)
{
	HEADER *dns_h = (HEADER *)p;
	int i;
	char qname[_POSIX_HOST_NAME_MAX + 1];
	char *nptr = qname;
	int count;
	uint8_t *base;
	int first_addr = 1;

	/* check flags */
	if ((dns_h->qr != 1) || (dns_h->opcode != 0) || (dns_h->rcode != 0)) {
		return 0;
	}

	if ((dns_h->qdcount == 0) || (dns_h->ancount == 0)) {
		return 0;
	}

	LOG(PREFIX"Probably DNS response");

	base = p;
	p += sizeof(HEADER);

	count = be16toh(dns_h->qdcount);

	memset(qname, 0, sizeof(qname));
	for (i=0; i<count; i++) {
		/* get name */
		for (;;) {
			int len, j;

			len = *p;

			if (len == 0) {
				break;
			}

			p++;
			if ((p + len) >= end) {
				LOG(PREFIX"DNS packet too short");
				return 0;
			}
			for (j=0; j<len; j++) {
				*nptr = *p;
				nptr++;
				p++;
			}
			*nptr = '.';
			nptr++;
		}
		p += 1 + 4;
		if (p >= end) {
			LOG(PREFIX"DNS packet too short");
			return 0;
		}
	}
	LOG(PREFIX"DNS domain: %s", qname);
	if (domain) {
		strcpy(domain, qname);
	}

	/* answers */
	count = be16toh(dns_h->ancount);
	for (i=0; i<count; i++) {
		char ansname[_POSIX_HOST_NAME_MAX + 1];
		char *aptr = ansname;
		char *aend = ansname + _POSIX_HOST_NAME_MAX;
		uint8_t *p_save = NULL;

		memset(ansname, 0, sizeof(ansname));
		for (;;) {
			int c, j;

			c = *p;
			if (c == 0) {
				break;
			}
			if ((c & 0xc0) == 0xc0) {
				unsigned int offset
					= be16toh(*((uint16_t *)p)) - 0xc000;
				/* save pointer */
				if (!p_save) {
					p_save = p;
				}
				p = base + offset;
				if (p >= end) {
					LOG(PREFIX"DNS packet too short");
					goto end;
				}
				c = *p;
			}
			if ((aptr + c) >= aend) {
				LOG(PREFIX"Malformed DNS packet");
				goto end;
			}

			p++;
			if ((p + c) >= end) {
				LOG(PREFIX"DNS packet too short");
				goto end;
			}

			for (j=0; j<c; j++) {
				*aptr = *p;
				aptr++;
				p++;
			}
			*aptr = '.';
			aptr++;
		}
		if (p_save) {
			p = p_save + 2;
		}
		if ((p + sizeof(struct dns_ans_data) + 3) > end) {
			LOG(PREFIX"DNS packet too short");
			goto end;
		}

		struct dns_ans_data *ad = (struct dns_ans_data *)p;
		unsigned int l_ad = sizeof(struct dns_ans_data) - 1
			+ be16toh(ad->data_len);

		if (ad->type == htobe16(0x0001)) {
			/* type A */
			char addr[INET6_ADDRSTRLEN + 1];
			if (ad->data_len == htobe16(4)) {
				inet_ntop(AF_INET, ad->data, addr,
					INET_ADDRSTRLEN);
				LOG(PREFIX"DNS ip: %s", addr);
				if (ips) {
					if (first_addr) {
						first_addr = 0;
						ips[0] = '{';
						ips[1] = '\0';
					} else {
						strcat(ips, ",");
					}
					strcat(ips, addr);
				}
			}
		} else if (ad->type == htobe16(28)) {
			/* AAAA */
			if ((p + sizeof(struct dns_ans_data) + 15) > end) {
				LOG(PREFIX"DNS packet too short");
				goto end;
			}
			char addr[INET6_ADDRSTRLEN + 1];
			if (ad->data_len == htobe16(16)) {
				inet_ntop(AF_INET6, ad->data, addr,
					INET6_ADDRSTRLEN);
				LOG(PREFIX"DNS ip: %s", addr);
				if (ips) {
					if (first_addr) {
						first_addr = 0;
						ips[0] = '{';
						ips[1] = '\0';
					} else {
						strcat(ips, ",");
					}
					strcat(ips, addr);
				}
			}
		}
		if ((p + l_ad) > end) {
			LOG(PREFIX"DNS packet too short");
			goto end;
		}
		p += l_ad;
	}
end:
	if (first_addr) {
		/* no ips */
		return 0;
	}
	if (ips) {
		strcat(ips, "}");
	}
	return 1;
}

#undef PREFIX

#endif

