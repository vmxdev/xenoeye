#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "xenoeye.h"
#include "sflow.h"

static void sflow_parse_payload(uint8_t *end, uint8_t *p);

#undef LOG
#define LOG(...)                                               \
do {                                                           \
	char _buf[4096];                                       \
	int _ret = snprintf(_buf, sizeof(_buf), __VA_ARGS__);  \
	if (_ret >= (int)(sizeof(_buf))) {                     \
		fprintf(stderr,                                \
		"Next line truncated to %d symbols",           \
		_ret);                                         \
	}                                                      \
	printf("%s [%s, line %d, function %s()]\n",            \
		_buf, __FILE__, __LINE__, __func__);           \
} while (0)

#include "xe-dns.h"
#include "xe-sni.h"

#define USER_TYPE uint8_t *

#define ON_ETH(D, V)                                              \
do {                                                              \
	(void)data;                                               \
	char buf[32];                                             \
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",             \
		V->h_source[0], V->h_source[1], V->h_source[2],   \
		V->h_source[3], V->h_source[4], V->h_source[5]);  \
	LOG("\t\t\tEthernet src: %s", buf);                       \
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",             \
		V->h_dest[0], V->h_dest[1], V->h_dest[2],         \
		V->h_dest[3], V->h_dest[4], V->h_dest[5]);        \
	LOG("\t\t\tEthernet dst: %s", buf);                       \
	LOG("\t\t\tEthernet proto: 0x%x", be16toh(V->h_proto));   \
} while (0)

#define ON_VLAN1(D, V)                                            \
	LOG("\t\t\tVLAN %d", be16toh(V->h_vlan_TCI));

#define ON_VLAN2(D, V)                                            \
	LOG("\t\t\tVLAN2 %d", be16toh(V->h_vlan_TCI));

#define ON_IP(D, V)                                               \
do {                                                              \
	char s[INET_ADDRSTRLEN + 1];                              \
	inet_ntop(AF_INET, &V->saddr, s, INET_ADDRSTRLEN);        \
	LOG("\t\t\tIPv4 src: %s", s);                             \
	inet_ntop(AF_INET, &V->daddr, s, INET_ADDRSTRLEN);        \
	LOG("\t\t\tIPv4 dst: %s", s);                             \
	LOG("\t\t\tTOS: 0x%0x", V->tos);                          \
	LOG("\t\t\tID: %d", be16toh(V->id));                      \
	LOG("\t\t\tTTL: %d", V->ttl);                             \
	LOG("\t\t\tIP protocol: %d", V->protocol);                \
} while (0)

#define ON_IP6(D, V)                                              \
do {                                                              \
	char s[INET6_ADDRSTRLEN + 1];                             \
	inet_ntop(AF_INET6, &V->ip6_src, s, INET6_ADDRSTRLEN);    \
	LOG("\t\t\tIPv6 src: %s", s);                             \
	inet_ntop(AF_INET6, &V->ip6_dst, s, INET6_ADDRSTRLEN);    \
	LOG("\t\t\tIPv6 dst: %s", s);                             \
	LOG("\t\t\tTTL: %d", V->ip6_ctlun.ip6_un1.ip6_un1_hlim);  \
	LOG("\t\t\tIP protocol: %d", (int)nexthdr);               \
} while (0)

#define ON_UDP(D, V)                                              \
do {                                                              \
	LOG("\t\t\tUDP src port: %d", be16toh(V->source));        \
	LOG("\t\t\tUDP dst port: %d", be16toh(V->dest));          \
} while (0)

#define ON_TCP(D, V)                                              \
do {                                                              \
	LOG("\t\t\tTCP src port: %d", be16toh(V->source));        \
	LOG("\t\t\tTCP dst port: %d", be16toh(V->dest));          \
	LOG("\t\t\tTCP flags: 0x%0x", V->th_flags);               \
} while (0)

#define ON_ICMP(D, V)                                             \
do {                                                              \
	LOG("\t\t\tICMP type: %d", V->type);                      \
	LOG("\t\t\tICMP code: %d", V->code);                      \
} while (0)

#define ON_PAYLOAD(D, P) sflow_parse_payload(D, P);

#include "rawparse.h"

#undef ON_ICMP
#undef ON_TCP
#undef ON_UDP
#undef ON_IP
#undef ON_ETH

static void
sflow_parse_payload(uint8_t *end, uint8_t *p)
{
	if (xe_sni(p, end, NULL)) {
		return;
	}
	if (xe_dns(p, end, NULL, NULL)) {
		return;
	}
}

static inline int
sf5_eth(struct sfdata *s, uint8_t *p, enum RP_TYPE t, uint32_t header_len)
{
	(void)s;
	uint8_t *end = p + header_len;

	if (rawpacket_parse(p, end, t, end)
		< RP_PARSER_STATE_NO_IP) {

		/* Skip non-IP samples */
		return 0;
	}

	return 1;
}

#include "sflow-impl.h"

#undef USER_TYPE
#define USER_TYPE uint8_t **

#undef ON_PAYLOAD
#define ON_PAYLOAD(D, P) *D = P;

#define rawpacket_parse rawpacket_parse_sflow

#include "rawparse.h"

static void
print_usage(const char *prog_name)
{
	LOG("Usage: %s -i eth0 [-f \"udp and port 6543\"]", prog_name);
}


int
main(int argc, char *argv[])
{
	int opt;

	char *ifname = NULL;
	char *filter = "";

	pcap_t *p_handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;

	int ret = EXIT_FAILURE;

	while ((opt = getopt(argc, argv, "f:hi:")) != -1) {
		switch (opt) {
			case 'i':
				ifname = optarg;
				break;

			case 'f':
				filter = optarg;
				break;

			case 'h':
			default:
				print_usage(argv[0]);
				return EXIT_FAILURE;
		}
	}

	if (!ifname) {
		LOG("Interface name is required");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	p_handle = pcap_open_live(ifname, BUFSIZ, 1, 1000, errbuf);
	if (p_handle == NULL) {
		LOG("Can't open device '%s': %s", ifname, errbuf);
		return EXIT_FAILURE;
	}

	if (pcap_compile(p_handle, &fp, filter,
		1, PCAP_NETMASK_UNKNOWN) == -1) {

		LOG("Can't parse filter '%s': %s", filter,
			pcap_geterr(p_handle));
		goto fail_filter;
	}

	if (pcap_setfilter(p_handle, &fp) == -1) {
		LOG("Can't set filter '%s': %s", filter,
			pcap_geterr(p_handle));
		goto fail_setfilter;
	}

	for (;;) {
		int rc;
		struct pcap_pkthdr *header;
		const unsigned char *packet;
		struct flow_packet_info fpi;
		uint8_t *sflow_data = NULL;

		rc = pcap_next_ex(p_handle, &header, &packet);
		if (rc == 1) {
			enum RP_PARSER_STATE ps;
			uint8_t *ptr = (uint8_t *)packet;
			int len;

			ps = rawpacket_parse_sflow(ptr, ptr + header->caplen,
				RP_TYPE_ETHER, &sflow_data);
			if (ps != RP_PARSER_STATE_OK) {
				continue;
			}
			if (!sflow_data) {
				continue;
			}
			len = header->caplen - (sflow_data - packet);

			memcpy(fpi.rawpacket, sflow_data, len);
			sflow_process(NULL, 0, &fpi, len);
		} else {
			LOG("Error reading the packets: %s",
				pcap_geterr(p_handle));
		}
	}

	ret = EXIT_SUCCESS;

fail_setfilter:
	pcap_freecode(&fp);
fail_filter:
	pcap_close(p_handle);

	return ret;
}

