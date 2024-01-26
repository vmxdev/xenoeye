#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include "xenoeye.h"
#include "netflow.h"
#include "sflow.h"
#include "flow-info.h"

static void *
scapture_thread(void *arg)
{
	struct capture_thread_params params, *params_ptr;

	socklen_t clientlen;

	params_ptr = (struct capture_thread_params *)arg;
	params = *params_ptr;
	free(params_ptr);

	clientlen = sizeof(struct sockaddr);

	LOG("Starting collector thread on port %d", params.cap->port);

	for (;;) {
		ssize_t len;
		struct flow_packet_info pkt;

		len = recvfrom(params.cap->sockfd, pkt.rawpacket,
			MAX_NF_PACKET_SIZE, 0,
			&(pkt.src_addr), &clientlen);

		if (len < 0) {
			LOG("recvfrom() failed: %s", strerror(errno));

			continue;
		}

		if (pkt.src_addr.sa_family == AF_INET) {
			struct sockaddr_in *addr;

			addr = (struct sockaddr_in *)&pkt.src_addr;
			/* we're supporting only IPv4 */

			pkt.src_addr_ipv4 =
				 *((uint32_t *)&(addr->sin_addr));
		} else {
			pkt.src_addr_ipv4 = 0;
		}

		if (params.type == FLOW_TYPE_NETFLOW) {
			if (netflow_process(params.data, params.thread_idx,
				&pkt, len)) {
				/* ok */
			}
		} else {
			/* sflow */
			sflow_process(params.data, params.thread_idx, &pkt,
				len);
		}
	}

	close(params.cap->sockfd);

	return NULL;
}

int
scapture_start(struct xe_data *data, struct capture *cap, size_t thread_idx,
	enum FLOW_TYPE type)
{
	int one = 1;
	struct capture_thread_params *params;
	struct sockaddr_in serveraddr;
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

	cap->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (cap->sockfd < 0) {
		LOG("socket() failed: %s", strerror(errno));
		goto fail_socket;
	}

	if (setsockopt(cap->sockfd, SOL_SOCKET, SO_REUSEADDR,
		(const void *)&one, sizeof(int)) == -1) {

		LOG("setsockopt() failed: %s", strerror(errno));
		goto fail_setsockopt;
	}

	bzero((char *)&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;

	/* FIXME: take address from user */
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons(cap->port);

	if (bind(cap->sockfd, (struct sockaddr *)&serveraddr,
		sizeof(serveraddr)) < 0) {

		LOG("bind() failed: %s", strerror(errno));
		goto fail_bind;
	}

	thread_err = pthread_create(&cap->tid, NULL, &scapture_thread, params);

	if (thread_err) {
		LOG("Can't start thread: %s", strerror(thread_err));
		goto fail_thread;
	}

	return 1;

/* errors */
fail_thread:
fail_bind:
fail_setsockopt:
	close(cap->sockfd);
fail_socket:
	free(params);
fail_alloc:
	return 0;
}


