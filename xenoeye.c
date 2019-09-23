/*
 * xenoeye
 *
 * Copyright (c) 2018-2019, Vladimir Misyurov
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

#include "utils.h"
#include "netflow.h"
#include "netflow_templates.h"
#include "xenoeye.h"

#define DEFAULT_NETFLOW_PORT 2055

/* construct template key, used as key in persistent k-v templates storage */
static void
make_template_key(struct template_key *tkey, uint16_t template_id,
	struct nf_packet_info *npi)
{
	uint8_t *tkeyptr;

	/* key: template ID, source IP, source ID and time */
	tkey->size = sizeof(template_id) + sizeof(npi->src_addr_ipv4)
		+ sizeof(npi->source_id) + sizeof(npi->epoch);

	tkeyptr = tkey->data;

	/* template ID */
	memcpy(tkeyptr, &template_id, sizeof(template_id));
	tkeyptr += sizeof(template_id);

	/* source IPv4 address */
	memcpy(tkeyptr, &(npi->src_addr_ipv4), sizeof(npi->src_addr_ipv4));
	tkeyptr += sizeof(npi->src_addr_ipv4);

	/* source ID */
	memcpy(tkeyptr, &(npi->source_id), sizeof(npi->source_id));
	tkeyptr += sizeof(npi->source_id);

	/* time */
	memcpy(tkeyptr, &(npi->epoch), sizeof(npi->epoch));
}

static int
parse_netflow_v9_template(struct nf_packet_info *npi, uint8_t **ptr,
	int length)
{
	struct nf9_template_item *tmplitem, *ptmpl;
	uint16_t template_id, field_count;
	struct template_key tkey;
	int template_size;

	ptmpl = (struct nf9_template_item *)(*ptr);
	template_id = ptmpl->template_id;
	field_count = ntohs(ptmpl->field_count);

	template_size = 4 + field_count * 4;
	if (template_size > length) {
		/* packet too short */
		LOG("Template is too short");
		return 0;
	}
	LOG("Template id %d, field count: %u", ntohs(template_id),
		field_count);

	/* search for template in database */
	make_template_key(&tkey, template_id, npi);
	tmplitem = netflow_template_find(&tkey);

	*ptr += template_size;

	if (!tmplitem) {
		return netflow_template_add(&tkey, ptmpl);
	}

	if (memcmp(ptmpl, tmplitem, template_size) != 0) {
		LOG("Template modified");
		return netflow_template_add(&tkey, ptmpl);
	}

	return 1;
}

static int
parse_netflow_v9_flowset(struct nf_packet_info *npi, uint8_t **ptr,
	int flowset_id, int length, int count)
{
	uint8_t *fptr;
	int cnt, i;
	struct nf9_template_item *tmpl;
	struct template_key tkey;
	int template_field_count;

	LOG("v9 data, flowset: %d, length == %d, count = %d",
		ntohs(flowset_id), length, count);

	make_template_key(&tkey, flowset_id, npi);
	tmpl = netflow_template_find(&tkey);

	if (!tmpl) {
		LOG("Unknown flowset id %d", ntohs(flowset_id));
		return 0;
	}

	template_field_count = ntohs(tmpl->field_count);

	fptr = (*ptr);
	for (cnt=0; cnt<count; cnt++) {
		LOG("Flowset #%d", cnt);
		for (i=0; i<template_field_count; i++) {
			int flength, ftype;

			flength = ntohs(tmpl->typelen[i].length);
			ftype = ntohs(tmpl->typelen[i].type);

			if (ftype == 21) {
				uint32_t last_uptime;

				if (flength != 4) {
					LOG("Incorrect LAST SWITCHED field");
					return 0;
				}
				memcpy(&last_uptime, fptr, flength);
				last_uptime = ntohl(last_uptime);
				LOG("LAST SWITCHED: %u",
					npi->uptime - last_uptime);
			}
			if (ftype == 22) {
				uint32_t first_uptime;

				if (flength != 4) {
					LOG("Incorrect FIRST SWITCHED field");
					return 0;
				}
				memcpy(&first_uptime, fptr, flength);
				first_uptime = ntohl(first_uptime);
				LOG("FIRST SWITCHED: %u",
					npi->uptime - first_uptime);
			}

			npi->flows[npi->nflows].type = ftype;
			npi->flows[npi->nflows].length = flength;
			memcpy(npi->flows[npi->nflows].value, fptr, flength);
			npi->nflows++;

			LOG("Field type: %d, length == %d, first byte == %d",
				ftype, flength, fptr[0]);
			fptr += flength;

			if ((fptr - (*ptr)) >= length) {
				break;
			}
		}
	}
	(*ptr) += length;
	return 1;
}

static int
parse_netflow_v9(struct xe_data *data, struct nf_packet_info *npi, int len)
{
	struct nf9_header *header;
	int flowset_id, flowset_id_host, length, count;
	uint8_t *ptr;

	npi->nflows = 0;
	npi->tmin = 0;
	npi->tmax = 0;

	header = (struct nf9_header *)npi->rawpacket;
	npi->source_id = header->source_id;
	npi->epoch = header->unix_secs;
	npi->uptime = htonl(header->sys_uptime);

	LOG("got v9, package sequence: %u, source id %u, length %d",
		ntohl(header->package_sequence),
		ntohl(npi->source_id),
		len);


	ptr = (uint8_t *)npi->rawpacket + sizeof(struct nf9_header);

	while (ptr < ((uint8_t *)npi->rawpacket + len)) {
		struct nf9_flowset_header *flowset_header;

		flowset_header = (struct nf9_flowset_header *)ptr;

		flowset_id = flowset_header->flowset_id;
		flowset_id_host = ntohs(flowset_id);
		length = ntohs(flowset_header->length);
		count = ntohs(header->count);

		ptr += 4;

		if (flowset_id_host == 0) {
			if (!parse_netflow_v9_template(npi, &ptr, length)) {
				/* something went wrong in template parser */
				return 0;
			}
		} else if (flowset_id_host == 1) {
			LOG("options template");
			break;
		} else {
			if (!parse_netflow_v9_flowset(npi, &ptr, flowset_id,
				length, count)) {

				break;
			}
		}
	}
	LOG("end of v9");
	LOG("========================");
	return 1;
}


static void
print_usage(const char *progname)
{
	fprintf(stderr, "Usage:\n %s [-p port]\n", progname);
	fprintf(stderr, " %s -h\n", progname);
	fprintf(stderr, "    -p UDP port for Netflow datagrams (default %d)\n",
		DEFAULT_NETFLOW_PORT);
	fprintf(stderr, "    -h print this message\n");
}

int
main(int argc, char *argv[])
{
	int sockfd;
	int one = 1;
	int port = DEFAULT_NETFLOW_PORT;
	struct sockaddr_in serveraddr;
	socklen_t clientlen;
	struct xe_data data;
	int stop = 0;
	int opt;

	while ((opt = getopt(argc, argv, "p:")) != -1) {
		switch (opt) {
			case 'p':
				port = atoi(optarg);
				break;

			case 'h':
			default:
				print_usage(argv[0]);
				return EXIT_SUCCESS;
		}
	}

	openlog(NULL, LOG_PERROR, LOG_USER);

	if (!netflow_templates_init()) {
		LOG("Can't init templates storage, exiting");
		return EXIT_FAILURE;
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		LOG("socket() failed: %s", strerror(errno));
		return EXIT_FAILURE;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
		(const void *)&one, sizeof(int)) == -1) {

		LOG("setsockopt() failed: %s", strerror(errno));
		return EXIT_FAILURE;
	}

	bzero((char *)&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons((unsigned short)port);

	if (bind(sockfd, (struct sockaddr *)&serveraddr,
		sizeof(serveraddr)) < 0) {

		LOG("bind() failed: %s", strerror(errno));
		return EXIT_FAILURE;
	}

	clientlen = sizeof(struct sockaddr);

	LOG("Starting collector on port %d", port);

	while (!stop) {
		ssize_t len;
		struct nf_packet_info nfpkt;

		len = recvfrom(sockfd, nfpkt.rawpacket,
			MAX_NF_PACKET_SIZE, 0,
			&(nfpkt.src_addr), &clientlen);

		if (len < 0) {
			LOG("recvfrom() failed: %s", strerror(errno));

			continue;
		}

		if (nfpkt.src_addr.sa_family == AF_INET) {
			struct sockaddr_in *addr;

			addr = (struct sockaddr_in *)&nfpkt.src_addr;
			/* we're supporting only IPv4 */
			LOG("src_addr: %s", inet_ntoa(addr->sin_addr));

			nfpkt.src_addr_ipv4 =
				 *((uint32_t *)&(addr->sin_addr));
		} else {
			nfpkt.src_addr_ipv4 = 0;
		}

		if (parse_netflow_v9(&data, &nfpkt, len)) {
			/* ok */
		}
	}

	close(sockfd);
	netflow_templates_shutdown();

	return EXIT_SUCCESS;
}

