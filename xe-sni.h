#ifndef xe_sni_h_included
#define xe_sni_h_included

#define PREFIX "\t\t\t\t"

struct tls_rec
{
	uint8_t type;
	uint16_t version;
	uint16_t len;
} __attribute__((packed));

struct tls_hello
{
	uint8_t type;
	uint8_t len[3];
	uint16_t version;
	uint8_t random[32];
	uint8_t session_id_len;
} __attribute__((packed));

struct tls_ext
{
	uint16_t type;
	uint16_t len;
} __attribute__((packed));

struct tls_sni
{
	uint16_t list_len;
	uint8_t type;
	uint16_t name_len;
	uint8_t name[1];
} __attribute__((packed));

static int
xe_sni(uint8_t *p, uint8_t *end, char *domain)
{
	uint16_t *cipher_suites_len;
	uint8_t *compress_methods_len;
	struct tls_hello *hello;
	struct tls_rec *rec = (struct tls_rec *)p;

	if (rec->type != 0x16) {
		return 0;
	}

	if ((rec->version != be16toh(0x0301))
		&& (rec->version != be16toh(0x0303))) {

		return 0;
	}

	LOG(PREFIX"Probably TLS Handshake");

	p += sizeof(struct tls_rec);
	if (p >= end) {
		LOG(PREFIX"Packet too short");
		return 0;
	}

	hello = (struct tls_hello *)p;
	if (hello->type != 1) {
		return 0;
	}

	LOG(PREFIX"TLS Client Hello");

	p += sizeof(struct tls_hello) + hello->session_id_len;
	if (p >= end) {
		LOG(PREFIX"Packet too short");
		return 0;
	}

	cipher_suites_len = (uint16_t *)p;
	p += sizeof(uint16_t) + be16toh(*cipher_suites_len);
	if (p >= end) {
		LOG(PREFIX"Packet too short");
		return 0;
	}

	compress_methods_len = (uint8_t *)p;
	p += sizeof(uint8_t) + *compress_methods_len;
	if (p >= end) {
		LOG(PREFIX"Packet too short");
		return 0;
	}

	p += sizeof(uint16_t); // ext len
	for (;;) {
		struct tls_ext *e = (struct tls_ext *)p;
		if (e->type == 0x0000) {
			char server_name[100];
			/* sni */
			struct tls_sni *sni = (struct tls_sni *)
				(p + sizeof(struct tls_ext));
			if (sni->type == 0x00) {
				uint16_t name_len = be16toh(sni->name_len);
				memcpy(server_name, sni->name, name_len);
				server_name[name_len] = '\0';
				LOG(PREFIX"SNI: %s", server_name);
				if (domain) {
					strcpy(domain, server_name);
				}
			}
			break;
		}
		p += sizeof(struct tls_ext) + be16toh(e->len);
		if (p >= end) {
			LOG(PREFIX"No SNI in packet");
			return 0;
		}
	}
	return 1;
}

#undef PREFIX

#endif

