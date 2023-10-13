#ifndef xenoeye_h_included
#define xenoeye_h_included

#include <limits.h>
#include <pthread.h>
#include <pcap.h>
#include <stdatomic.h>

#include "utils.h"
#include "xe-debug.h"
#include "monit-objects.h"

/*#define FLOWS_CNT*/

struct nf_flow_info;
struct filter_expr;

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

	/* numer of threads, nthreads == ncap */
	size_t nthreads;

	/* backgriund thread for fixed windows in memory */
	pthread_t fwm_tid;

	/* moving averages */
	pthread_t mavg_dump_tid, mavg_act_tid;
	_Atomic size_t mavg_db_bank_idx;

	/* classification thread */
	pthread_t clsf_tid;

	/* GeoIP/AS databases reload thread */
	pthread_t geoip_tid;

	/* templates */
	int allow_templates_in_future;
	char templates_db[PATH_MAX];

	/* debug settings */
	struct xe_debug debug;

	/* path to devices list */
	char devices[PATH_MAX];

	/* path to monitoring objects */
	char mo_dir[PATH_MAX];

	/* path to export files dir */
	char exp_dir[PATH_MAX];

	/* path to IP lists */
	char iplists_dir[PATH_MAX];

	/* path to notification files */
	char notif_dir[PATH_MAX];

	/* path to dir with classification */
	char clsf_dir[PATH_MAX];

	/* geoip */
	size_t ngeoip_files;
	char *geoip_files;

	/* as */
	size_t nas_files;
	char *as_files;

	/* notify threads about stop */
	atomic_int stop;

#ifdef FLOWS_CNT
	/* flows counter */
	_Atomic uint64_t nflows;
	pthread_t fc_tid;
#endif
};

/* helper struct for passing data to capture threads */
struct capture_thread_params
{
	struct xe_data *data;
	size_t idx; /* thread index */
};

int pcapture_start(struct xe_data *data, size_t idx);

#endif

