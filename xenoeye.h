#ifndef xenoeye_h_included
#define xenoeye_h_included

#include <limits.h>
#include <pthread.h>
#include <pcap.h>
#include <stdatomic.h>


typedef __int128_t xe_ip;

struct nf_flow_info;
struct filter_expr;

struct mo_fwm;

/* debug options */
struct xe_debug
{
	int print_flows;
	int print_to_syslog;
	FILE *fout;
};

struct monit_object
{
	char name[PATH_MAX];
	struct filter_expr *expr;

	struct xe_debug debug;

	/* fixed windows in memory */
	size_t nfwm;
	struct mo_fwm *fwms;
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
	size_t nmonit_objects;
	struct monit_object *monit_objects;

	struct capture *cap;
	size_t ncap;

	/* templates */
	int allow_templates_in_future;
	char templates_db[PATH_MAX];

	struct xe_debug debug;
};

/* helper struct for passing data to capture threads */
struct capture_thread_params
{
	struct xe_data *data;
	size_t idx;                      /* index of capture section */
};


int monit_objects_init(struct xe_data *data);
int monit_objects_free(struct xe_data *data);

int monit_object_match(struct monit_object *mi, struct nf_flow_info *fi);

int pcapture_start(struct xe_data *data, size_t idx);


#endif

