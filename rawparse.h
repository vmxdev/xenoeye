#ifndef rawparse_h_included
#define rawparse_h_included

#include <stdint.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#ifndef USER_TYPE
#define USER_TYPE void *
#endif

#ifndef ON_VLAN1
#define ON_VLAN1(D, V)
#endif

#ifndef ON_VLAN2
#define ON_VLAN2(D, V)
#endif

#ifndef ON_IP
#define ON_IP(D, I)
#endif

#ifndef ON_IP6
#define ON_IP6(D, I)
#endif

#ifndef ON_UDP
#define ON_UDP(D, U)
#endif

#ifndef ON_TCP
#define ON_TCP(D, T)
#endif

#ifndef ON_ICMP
#define ON_ICMP(D, I)
#endif

#define	IP_MF 0x2000
#define IP_OFFSET       0x1FFF

struct vlan_hdr
{
	__be16  h_vlan_TCI;
	__be16  h_vlan_encapsulated_proto;
};

enum RP_PARSER_STATE
{
	RP_PARSER_STATE_NO_ETHER,
	RP_PARSER_STATE_NO_VLAN,
	RP_PARSER_STATE_NO_IP,
	RP_PARSER_STATE_NO_IP_PROTO,

	RP_PARSER_STATE_OK
};

static inline enum RP_PARSER_STATE
rawpacket_parse(uint8_t *ptr, uint32_t len, USER_TYPE data)
{
	uint8_t *end = ptr + len;
	uint16_t h_proto;
	struct ethhdr *eth;
	struct udphdr *udp;
	struct tcphdr *tcp;
	struct icmphdr *icmp;

	if ((ptr + sizeof(struct ethhdr)) >= end) {
		return RP_PARSER_STATE_NO_ETHER;
	}
	eth = (struct ethhdr *)ptr;
	ptr += sizeof(struct ethhdr);

	h_proto = eth->h_proto;

	if ((h_proto == htobe16(ETH_P_8021Q)) || (h_proto == htobe16(ETH_P_8021AD))) {
		struct vlan_hdr *vhdr;

		if (ptr + sizeof(struct vlan_hdr) >= end) {
			return RP_PARSER_STATE_NO_VLAN;
		}
		vhdr = (struct vlan_hdr *)ptr;
		ptr += sizeof(struct vlan_hdr);

		ON_VLAN1(data, vhdr);

		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if ((h_proto == htobe16(ETH_P_8021Q)) || (h_proto == htobe16(ETH_P_8021AD))) {
		struct vlan_hdr *vhdr;

		if (ptr + sizeof(struct vlan_hdr) >= end) {
			return RP_PARSER_STATE_NO_VLAN;
		}
		vhdr = (struct vlan_hdr *)ptr;
		ptr += sizeof(struct vlan_hdr);

		ON_VLAN2(data, vhdr);

		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	if (h_proto == htons(ETH_P_IP)) {
		uint64_t ihl_len;
		struct iphdr *iph;

		if (ptr + sizeof(struct iphdr) >= end) {
			return RP_PARSER_STATE_NO_IP;
		}
		iph = (struct iphdr *)ptr;

		/* is fragment? */
		if ((iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0) {
			ON_IP(data, iph);
			return RP_PARSER_STATE_NO_IP_PROTO;
		}

		ihl_len = iph->ihl * 4;
		ptr += ihl_len;

		if (iph->protocol == IPPROTO_IPIP) {
			if (ptr + sizeof(struct iphdr) >= end) {
				return RP_PARSER_STATE_NO_IP;
			}
			iph = (struct iphdr *)ptr;

			ihl_len = iph->ihl * 4;
			ptr += ihl_len;
		}

		ON_IP(data, iph);

		if (iph->protocol == IPPROTO_TCP) {
			goto tcp;
		} else if (iph->protocol == IPPROTO_UDP) {
			goto udp;
		} else if (iph->protocol == IPPROTO_ICMP) {
			goto icmp;
		} else {
			return RP_PARSER_STATE_NO_IP_PROTO;
		}
	} else if (h_proto == htons(ETH_P_IPV6)) {
		uint64_t ihl_len = sizeof(struct ip6_hdr);
		uint64_t nexthdr;
		struct iphdr *iph;
		struct ip6_hdr *ip6h;

		if (ptr + sizeof(struct ip6_hdr) >= end) {
			return RP_PARSER_STATE_NO_IP;
		}
		ip6h = (struct ip6_hdr *)ptr;
		ptr += sizeof(struct ip6_hdr);

		nexthdr = ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt;

		if (nexthdr == IPPROTO_IPIP) {
			if (ptr + sizeof(struct iphdr) >= end) {
				return RP_PARSER_STATE_NO_IP;
			}
			iph = (struct iphdr *)ptr;

			ihl_len += iph->ihl * 4;
			nexthdr = iph->protocol;
			ptr += ihl_len;

			ON_IP(data, iph);
		} else if (nexthdr == IPPROTO_IPV6) {
			if (ptr + sizeof(struct ip6_hdr) >= end) {
				return RP_PARSER_STATE_NO_IP;
			}
			ip6h = (struct ip6_hdr *)ptr;
			ptr += sizeof(struct ip6_hdr);

			ihl_len += sizeof(struct ip6_hdr);
			//nexthdr = ip6h->nexthdr;
			nexthdr = ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt;
		}

		//pm->ip_proto = nexthdr;

		if (nexthdr == IPPROTO_TCP) {
			goto tcp;
		} else if (nexthdr == IPPROTO_UDP) {
			goto udp;
		} else if (nexthdr == IPPROTO_ICMP) {
			goto icmp;
		} else {
			return RP_PARSER_STATE_NO_IP_PROTO;
		}
		//pm.ip_version = 6;
	} else {
		/* non-ip */
		return RP_PARSER_STATE_NO_IP;
	}

tcp:
	if (ptr + sizeof(struct tcphdr) >= end) {
		return RP_PARSER_STATE_NO_IP_PROTO;
	}
	tcp = (struct tcphdr *)ptr;
	ptr += sizeof(struct tcphdr);
	ON_TCP(data, tcp);

	goto payload;

udp:
	if (ptr + sizeof(struct udphdr) >= end) {
		return RP_PARSER_STATE_NO_IP_PROTO;
	}
	udp = (struct udphdr *)ptr;
	ptr += sizeof(struct udphdr);
	ON_UDP(data, udp);

	goto payload;

icmp:
	if (ptr + sizeof(struct icmphdr) >= end) {
		return RP_PARSER_STATE_NO_IP_PROTO;
	}
	icmp = (struct icmphdr *)ptr;
	ptr += sizeof(struct icmphdr);
	ON_ICMP(data, icmp);

	goto payload;

payload:

	return RP_PARSER_STATE_OK;
}

#endif