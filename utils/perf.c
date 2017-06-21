#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "uftrace.h"
#include "utils/perf.h"
#include "utils/compiler.h"

/* It needs to synchronize records using monotonic clock */
#ifdef HAVE_PERF_CLOCKID
static bool use_perf = true;
#else
static bool use_perf = false;
#endif

static int __maybe_unused
open_perf_sw_event(int pid, int cpu, uint64_t config, uint64_t control)
{
	/* use dummy events to get scheduling info (Linux v4.3 or later) */
	struct perf_event_attr attr = {
		.size			= sizeof(attr),
		.type			= PERF_TYPE_SOFTWARE,
		.config			= config,
		.sample_type		= PERF_SAMPLE_TIME | PERF_SAMPLE_TID,
		.sample_period		= 1,
		.sample_id_all		= 1,
		.exclude_kernel		= 1,
		.disabled		= 1,
		.enable_on_exec		= 1,
		.inherit		= 1,
		.watermark		= 1,
		.wakeup_watermark	= PERF_WATERMARK,
#ifdef HAVE_PERF_CLOCKID
		.use_clockid		= 1,
		.clockid		= CLOCK_MONOTONIC,
#endif
	};
	unsigned long flag = PERF_FLAG_FD_NO_GROUP;
	int fd;

#ifdef HAVE_PERF_CTXSW
	if (control & PERF_CTRL_CTXSW)
		attr.context_switch = 1;
#endif

	fd = syscall(SYS_perf_event_open, &attr, pid, cpu, -1, flag);
	if (fd < 0)
		pr_dbg("perf event open failed: %m\n");

	return fd;
}

#ifdef HAVE_PERF_CTXSW
static int open_perf_sched_event(int pid, int cpu)
{
	return open_perf_sw_event(pid, cpu, PERF_COUNT_SW_DUMMY, PERF_CTRL_CTXSW);
}
#else
static int open_perf_sched_event(int pid, int cpu)
{
	/* Operation not supported */
	errno = ENOTSUP;
	return -1;
}
#endif

int setup_perf_record(struct uftrace_perf_info *upi, int nr_cpu, int cpus[],
		      int pid, const char *dirname)
{
	char filename[PATH_MAX];
	int fd, i;

	if (!use_perf)
		return 0;

	upi->event_fd = xcalloc(nr_cpu, sizeof(*upi->event_fd));
	upi->data_pos = xcalloc(nr_cpu, sizeof(*upi->data_pos));
	upi->page     = xcalloc(nr_cpu, sizeof(*upi->page));
	upi->fp       = xcalloc(nr_cpu, sizeof(*upi->fp));
	upi->nr_event = nr_cpu;

	memset(upi->event_fd, -1, nr_cpu * sizeof(fd));

	for (i = 0; i < nr_cpu; i++) {
		fd = open_perf_sched_event(pid, cpus[i]);
		if (fd < 0) {
			pr_dbg("failed to open perf event: %m\n");
			use_perf = false;
			break;
		}
		upi->event_fd[i] = fd;

		upi->page[i] = mmap(NULL, PERF_MMAP_SIZE, PROT_READ|PROT_WRITE,
				    MAP_SHARED, fd, 0);
		if (upi->page[i] == MAP_FAILED) {
			pr_dbg("failed to mmap perf event: %m\n");
			use_perf = false;
			break;
		}

		snprintf(filename, sizeof(filename),
			 "%s/perf-cpu%d.dat", dirname, cpus[i]);

		upi->fp[i] = fopen(filename, "w");
		if (upi->fp[i] == NULL) {
			pr_dbg("failed to create perf data file: %m\n");
			use_perf = false;
			break;
		}
	}

	if (!use_perf)
		finish_perf_record(upi);

	return 0;
}

void finish_perf_record(struct uftrace_perf_info *upi)
{
	int i;

	for (i = 0; i < upi->nr_event; i++) {
		close(upi->event_fd[i]);
		munmap(upi->page[i], PERF_MMAP_SIZE);
		fclose(upi->fp[i]);
	}

	free(upi->event_fd);
	free(upi->page);
	free(upi->data_pos);
	free(upi->fp);

	upi->event_fd = NULL;
	upi->page     = NULL;
	upi->data_pos = NULL;
	upi->fp       = NULL;

	upi->nr_event = 0;
}

#ifdef HAVE_PERF_CLOCKID
void record_perf_data(struct uftrace_perf_info *upi, int idx)
{
	struct perf_event_mmap_page *pc = upi->page[idx];
	unsigned char *data = upi->page[idx] + pc->data_offset;
	volatile uint64_t *ptr = (void *)&pc->data_head;
	uint64_t mask = pc->data_size - 1;
	uint64_t old, pos, start, end;
	unsigned long size;
	unsigned char *buf;

	pos = *ptr;
	old = upi->data_pos[idx];

	/* ensure reading the data head first */
	read_memory_barrier();

	if (pos == old)
		return;

	size = pos - old;
	if (size > (unsigned long)(mask) + 1) {
		static bool once = true;

		if (once) {
			pr_log("failed to keep up with mmap data.\n");
			once = false;
		}

		pc->data_tail = pos;
		upi->data_pos[idx] = pos;
		return;
	}

	start = old;
	end   = pos;

	/* handle wrap around */
	if ((start & mask) + size != (end & mask)) {
		buf = &data[start & mask];
		size = mask + 1 - (start & mask);
		start += size;

		if (fwrite(buf, 1, size, upi->fp[idx]) != size) {
			pr_dbg("failed to write perf data: %m\n");
			goto out;
		}
	}

	buf = &data[start & mask];
	size = end - start;
	start += size;

	if (fwrite(buf, 1, size, upi->fp[idx]) != size)
		pr_dbg("failed to write perf data: %m\n");

out:
	/* ensure all reads are done before we write the tail. */
	full_memory_barrier();

	pc->data_tail = pos;
	upi->data_pos[idx] = pos;
}
#endif /* HAVE_PERF_CLOCKID */
