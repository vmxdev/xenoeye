#ifndef xenoeye_h_included
#define xenoeye_h_included

#include <limits.h>
#include <pthread.h>
#include <pcap.h>

struct nf_flow_info;
struct filter_expr;

struct monit_item
{
	char name[PATH_MAX];
	struct filter_expr *expr;
};

enum XENOEYE_CAPTURE_TYPE
{
	XENOEYE_CAPTURE_TYPE_SOCKET,
	XENOEYE_CAPTURE_TYPE_PCAP
};

struct capture
{
	enum XENOEYE_CAPTURE_TYPE type;

	pthread_t tid;

	/* pcap */
	pcap_t *pcap_handle;
	char *iface;
	char *filter;

	/* socket */
	int sockfd;
	char *addr;
	unsigned int port;
};

struct xe_data
{
	size_t nmonit_items;
	struct monit_item *monit_items;

	struct capture *cap;
	size_t ncap;
};

/* helper struct for passing data to capture threads */
struct capture_thread_params
{
	struct xe_data *data;
	size_t idx;                      /* index of capture section */
};


int monit_items_init(struct xe_data *data);
int monit_items_free(struct xe_data *data);

int monit_item_match(struct monit_item *mi, struct nf_flow_info *fi);

int pcapture_start(struct xe_data *data, size_t idx);

#endif

