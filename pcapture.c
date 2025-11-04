/*
 * xenoeye
 *
 * Copyright (c) 2020-2024, Vladimir Misyurov, Michael Kogan
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <endian.h>
#include <alloca.h>

#include "utils.h"
#include "xenoeye.h"
#include "netflow.h"
#include "sflow.h"
#include "flow-info.h"


#define SIZE_UDP        8               /* length of UDP header */

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14


/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
} __attribute__ ((packed));

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */

	/* source and dest address */
	struct in_addr ip_src, ip_dst;
} __attribute__ ((packed));
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
} __attribute__ ((packed));

/* UDP header */

struct sniff_udp
{
         u_short uh_sport;               /* source port */
         u_short uh_dport;               /* destination port */
         u_short uh_ulen;                /* udp length */
         u_short uh_sum;                 /* udp checksum */
} __attribute__ ((packed));


static void
pcap_packet(struct capture_thread_params *params,
	struct pcap_pkthdr *header, const unsigned char *packet)
{
	/*const struct sniff_ethernet *ethernet;*/  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_udp *udp;            /* The UDP header */
	const unsigned char *payload;           /* Packet payload */

	struct flow_packet_info pkt;          /* flow packet */

	int size_ip;
	int size_payload;

	(void)header;
	/* define ethernet header */
	/*ethernet = (struct sniff_ethernet *)(packet);*/
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	if (!packet) {
		return;
	}
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		/*LOG("Invalid IP header length: %u bytes", size_ip);*/
		return;
	}

	/* determine protocol */	
	if (ip->ip_p != IPPROTO_UDP) {
		return;
	}
	
	/*
	 *  OK, this packet is UDP.
	 */

	/* define/compute udp header offset */
	udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);

	pkt.src_addr_ipv4 = ip->ip_src.s_addr;

	/* define/compute udp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_UDP);

	/* compute udp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_UDP);
	if (size_payload > ntohs(udp->uh_ulen)) {
		size_payload = ntohs(udp->uh_ulen);
	}

	memcpy(pkt.rawpacket, payload, size_payload);
	if (params->type == FLOW_TYPE_NETFLOW) {
		if (netflow_process(params->data, params->thread_idx, &pkt,
			size_payload)) {
			/* ok */
			/*data->packets_processed++;*/
		}
	} else {
		/* sflow */
		sflow_process(params->data, params->thread_idx, &pkt,
			size_payload);
	}
}

static void *
pcapture_thread(void *arg)
{
	struct capture_thread_params params, *params_ptr;

	struct pcap_pkthdr *header;
	const unsigned char *packet;
	int rc;
	/*int64_t sec = 0;*/

	params_ptr = (struct capture_thread_params *)arg;
	params = *params_ptr;
	free(params_ptr);

	LOG("Starting collector thread on interface '%s', filter '%s'",
		params.cap->iface, params.cap->filter);

	for (;;) {
		rc = pcap_next_ex(params.cap->pcap_handle, &header, &packet);
		if (rc >= 0) {
			pcap_packet(&params, header, packet);
		} else {
			LOG("Error reading the packets: %s",
				pcap_geterr(params.cap->pcap_handle));
		}

#if 0
		{
			struct timespec ts;
			struct pcap_stat ps;

			clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
			if ((ts.tv_sec / 10) != sec) {
				pcap_stats(params.cap->pcap_handle, &ps);
				LOG("thread: %lu, recv: %u, drop: %u, ifdrop: %u",
					params.thread_idx,
					ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
				sec = ts.tv_sec / 10;
			}
		}
#endif
	}
	return NULL;
}

int
pcapture_start(struct xe_data *data, struct capture *cap, size_t thread_idx,
	enum FLOW_TYPE type)
{
	struct capture_thread_params *params;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	int thread_err;

	params = malloc(sizeof(struct capture_thread_params));
	if (!params) {
		LOG("malloc() failed");
		goto fail_alloc;
	}
	params->data = data;
	params->thread_idx = thread_idx;
	params->cap = cap;
	params->type = type;

	cap->pcap_handle = pcap_open_live(cap->iface, BUFSIZ, 1, 1000, errbuf);
	if (cap->pcap_handle == NULL) {
		LOG("Couldn't open device %s: %s", cap->iface, errbuf);

		goto fail_pcap_open;
	}

	if (pcap_compile(cap->pcap_handle, &fp, cap->filter,
			1, PCAP_NETMASK_UNKNOWN) == -1) {

		LOG("Couldn't parse filter '%s': %s", cap->filter,
			pcap_geterr(cap->pcap_handle));

		goto fail_compile;
	}

	if (pcap_setfilter(cap->pcap_handle, &fp) == -1) {
		LOG("Couldn't install filter %s: %s", cap->filter,
			pcap_geterr(cap->pcap_handle));

		goto fail_setfilter;
	}

	thread_err = pthread_create(&cap->tid, NULL, &pcapture_thread, params);

	if (thread_err) {
		LOG("Can't start thread: %s", strerror(thread_err));
		goto fail_thread;
	}

	return 1;

/* errors */
fail_thread:
fail_setfilter:
fail_compile:
	pcap_close(cap->pcap_handle);
fail_pcap_open:
	free(params);
fail_alloc:
	return 0;
}

