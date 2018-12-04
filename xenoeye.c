/*
 * xenoeye
 *
 * Copyright (c) 2018, Vladimir Misyurov
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

#include "utils.h"
#include "netflow.h"


#define MAX_FLOWS_PER_PACKET 1000
#define MAX_FLOW_VAL_LEN 32

struct nf_flow_info
{
	int type;
	int length;
	uint8_t value[MAX_FLOW_VAL_LEN];
};

struct nf_packet_info
{
	int n;
	time_t tmin, tmax;
	struct nf_flow_info flows[MAX_FLOWS_PER_PACKET];
};

/* template-based flows */
struct netflow_template_item
{
	int type;
	int length;
};

struct netflow_template
{
	int id;

	int nitems;
	struct netflow_template_item *items;
};

/* we hold netflow templates in memory */

/* number of templates */
static size_t ntemplates = 0;
/* templates */
static struct netflow_template *templates = NULL;

static int
parse_netflow_v9_template(uint8_t **ptr, int length, int count)
{
	struct nf9_template_item *tmplitem;
	int template_id, field_count;
	struct netflow_template *tmptmpl;
	int tmpl_found, i;
	size_t ti;

	LOG("template, length == %d, count: %d", length, count);

	tmplitem = (struct nf9_template_item *)(*ptr);

	template_id = ntohs(tmplitem->template_id);
	field_count = ntohs(tmplitem->field_count);

	LOG("template id %d, field count: %d", template_id, field_count);

	tmpl_found = 0;
	for (ti=0; ti<ntemplates; ti++) {
		if (templates[ti].id == template_id) {
			tmpl_found = 1;
			break;
		}
	}

	if (tmpl_found) {
		free(templates[ti].items);
	} else {
		tmptmpl = realloc(templates, (ntemplates + 1)
			*sizeof(struct netflow_template));
		if (!tmptmpl) {
			LOG("Not enough memory");
			return 0;
		}
		templates = tmptmpl;
		ti = ntemplates;
		templates[ti].id = template_id;
		ntemplates++;
	}

	templates[ti].items = malloc(field_count
		* sizeof(struct netflow_template_item));
	if (!templates[ti].items) {
		LOG("Not enough memory");
		return 0;
	}

	for (i=0; i<field_count; i++) {
		templates[ti].items[i].type =
			ntohs(tmplitem->typelen[i].type);
		templates[ti].items[i].length =
			ntohs(tmplitem->typelen[i].length);

		LOG("  %d. type %d, length %d",
			i,
			templates[ti].items[i].type,
			templates[ti].items[i].length);
	}
	templates[ti].nitems = field_count;
	*ptr += 4 + field_count * 4;

	return 1;
}

static int
parse_netflow_v9_flowset(struct nf_packet_info *npi, uint8_t **ptr,
	int flowset_id, int length, int count)
{
	uint8_t *fptr;
	int cnt, tmpl_found, i;
	size_t ti;

	LOG("v9 data, flowset: %d, length == %d, count = %d",
		flowset_id, length, count);

	tmpl_found = 0;
	for (ti=0; ti<ntemplates; ti++) {
		if (templates[ti].id == flowset_id) {
			tmpl_found = 1;
			break;
		}
	}
	if (!tmpl_found) {
		LOG("Unknown flowset id %d", flowset_id);
		return 0;
	}

	fptr = (*ptr);
	for (cnt=0; cnt<count; cnt++) {
		LOG("flowset #%d\n", cnt);

		for (i=0; i<templates[ti].nitems; i++) {
			int flength, ftype;

			flength = templates[ti].items[i].length;
			ftype = templates[ti].items[i].type;

			npi->flows[npi->n].type = ftype;
			npi->flows[npi->n].length = flength;
			memcpy(npi->flows[npi->n].value, fptr, flength);
			npi->n++;

			LOG("field type: %d, length == %d, first byte == %d",
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
parse_netflow_v9(struct nf_packet_info *npi, const uint8_t *packet, int len)
{
	struct nf9_header *header;
	int flowset_id, length, count;
	uint8_t *ptr;

	npi->n = 0;
	npi->tmin = 0;
	npi->tmax = 0;

	header = (struct nf9_header *)packet;
	LOG("got v9, package sequence: %u, source id %u, length %d",
		ntohl(header->package_sequence),
		ntohl(header->source_id),
		len);

	ptr = (uint8_t *)packet + sizeof(struct nf9_header);

	while (ptr < ((uint8_t *)packet + len)) {
		struct nf9_flowset_header *flowset_header;

		flowset_header = (struct nf9_flowset_header *)ptr;

		flowset_id = ntohs(flowset_header->flowset_id);
		length = ntohs(flowset_header->length);
		count = ntohs(header->count);

		ptr += 4;

		if (flowset_id == 0) {
			if (!parse_netflow_v9_template(&ptr,
				length, count)) {
				/* something went wrong in template parser */
				return 0;
			}
		} else if (flowset_id == 1) {
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


int
main(int argc, char *argv[])
{
	int sockfd;
	int one = 1;
	int port;
	struct sockaddr_in serveraddr, clientaddr;
	socklen_t clientlen;
	int stop = 0;

	port = 2055;

	openlog(NULL, LOG_PERROR, LOG_USER);

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

	clientlen = sizeof(clientaddr);

	while (!stop) {
		ssize_t len;
		uint8_t packet[64 * 1024];
		struct nf_packet_info npi;

		len = recvfrom(sockfd, packet, sizeof(packet), 0,
			(struct sockaddr *)&clientaddr, &clientlen);

		if (len < 0) {
			LOG("recvfrom() failed: %s", strerror(errno));
		}

		parse_netflow_v9(&npi, packet, len);
	}

	close(sockfd);

	return EXIT_SUCCESS;
}

