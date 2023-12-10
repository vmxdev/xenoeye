#ifndef sflow_h_included
#define sflow_h_included

struct xe_data;
struct flow_packet_info;
struct flow_info;

struct sfdata
{
	struct xe_data *global;
	size_t thread_id;
	struct flow_packet_info *fpi;
	struct flow_info *flow;
};

int
sflow_process(struct xe_data *global, size_t thread_id,
	struct flow_packet_info *fpi, int len);


#endif
