#ifndef __UFTRACE_PERF_H__
#define __UFTRACE_PERF_H__

#include <linux/perf_event.h>

#define PERF_MMAP_SIZE  (132 * 1024)  /* 32 + 1 pages */
#define PERF_WATERMARK  (8 * 1024)    /* 2 pages */

struct uftrace_perf_info {
	int			*event_fd;
	void			**page;
	uint64_t		*data_pos;
	FILE			**fp;
	int			nr_event;
};

#define PERF_CTRL_CTXSW		0x1ULL

int setup_perf_record(struct uftrace_perf_info *upi, int nr_cpu, int cpus[],
		      int pid, const char *dirname);
void finish_perf_record(struct uftrace_perf_info *upi);

#ifdef HAVE_PERF_CLOCKID
void record_perf_data(struct uftrace_perf_info *upi, int idx);
#else
static inline void record_perf_data(struct uftrace_perf_info *upi, int idx)
{
}
#endif

#endif /* UFTRACE_PERF_H */
