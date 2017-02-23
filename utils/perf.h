#ifndef __UFTRACE_PERF_H__
#define __UFTRACE_PERF_H__

#include <linux/perf_event.h>

#define PERF_MMAP_SIZE  (132 * 1024)  /* 32 + 1 pages */
#define PERF_WATERMARK  (8 * 1024)    /* 2 pages */

struct uftrace_perf_info {
	int			*event_fd;
	void			**page;
	uint64_t		*data_pos;
	FILE			*fp;
	int			nr_event;
};

struct perf_context_switch_event {
	/*
	 * type: PERF_RECORD_SWITCH (14)
	 * misc: PERF_RECORD_MISC_SWITCH_OUT (0x2000)
	 * size: 24
	 */
	struct perf_event_header header;

	struct sample_id {
		uint32_t   pid;
		uint32_t   tid;
		uint64_t   time;
	} sample_id;
};

struct uftrace_ctxsw {
	uint64_t	time;
	int		tid;
	bool		out;
};

/* controls perf_event_attr bits */
#define PERF_CTRL_CTXSW		0x1ULL

#ifndef HAVE_PERF_CTXSW
# define PERF_RECORD_SWITCH           14
# define PERF_RECORD_MISC_SWITCH_OUT  (1 << 13)
#endif

struct ftrace_file_handle;
struct uftrace_record;
struct uftrace_perf;

int setup_perf_record(struct uftrace_perf_info *upi, int nr_cpu, int cpus[],
		      int pid, const char *dirname, int file_idx);
void finish_perf_record(struct uftrace_perf_info *upi);

void record_perf_data(struct uftrace_perf_info *upi, int idx);
int read_perf_data(struct ftrace_file_handle *handle);
struct uftrace_record * get_perf_record(struct uftrace_perf *perf);

#endif /* UFTRACE_PERF_H */
