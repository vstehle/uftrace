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

int open_perf_sched_event(int pid, int cpu)
{
#ifdef HAVE_PERF_CTXSW
	return open_perf_sw_event(pid, cpu, PERF_COUNT_SW_DUMMY, PERF_CTRL_CTXSW);
#else
	return -1;
#endif
}

int setup_perf_record(struct uftrace_perf_info *upi, int nr_cpu, int cpus[],
		      int pid, const char *dirname, int file_idx)
{
	bool first = true;
	char *filename = NULL;
	int fd, k;

	if (!use_perf)
		return 0;

	upi->event_fd = xcalloc(nr_cpu, sizeof(*upi->event_fd));
	upi->data_pos = xcalloc(nr_cpu, sizeof(*upi->data_pos));
	upi->page     = xcalloc(nr_cpu, sizeof(*upi->page));
	upi->fp       = NULL;
	upi->nr_event = nr_cpu;

	memset(upi->event_fd, -1, nr_cpu * sizeof(fd));

	for (k = 0; k < nr_cpu; k++) {
		fd = open_perf_sched_event(pid, cpus[k]);
		if (fd < 0) {
			use_perf = false;
			break;
		}
		upi->event_fd[k] = fd;

		upi->page[k] = mmap(NULL, PERF_MMAP_SIZE, PROT_READ|PROT_WRITE,
				    MAP_SHARED, fd, 0);
		if (upi->page[k] == MAP_FAILED) {
			use_perf = false;
			break;
		}

		if (first) {
			if (asprintf(&filename, "%s/perf-idx%d.dat",
				     dirname, file_idx) < 0) {
				pr_err("failed to alloc filename");
			}

			upi->fp = fopen(filename, "w");
			if (upi->fp == NULL)
				pr_err("failed to create perf-idx file");

			free(filename);
			first = false;
		}
	}

	if (!use_perf) {
		/* it failed for some reason */
		for ( ; k >= 0; k--) {
			close(upi->event_fd[k]);
			munmap(upi->page[k], PERF_MMAP_SIZE);
		}
		free(upi->event_fd);
		free(upi->page);
		free(upi->data_pos);
		fclose(upi->fp);

		upi->event_fd = NULL;
		upi->page     = NULL;
		upi->data_pos = NULL;
		upi->fp       = NULL;
	}
	return 0;
}

void finish_perf_record(struct uftrace_perf_info *upi)
{
	int i;

	if (upi->fp == NULL)
		return;

	for (i = 0; i < upi->nr_event; i++) {
		close(upi->event_fd[i]);
		munmap(upi->page[i], PERF_MMAP_SIZE);
	}

	free(upi->event_fd);
	free(upi->page);
	free(upi->data_pos);
	fclose(upi->fp);

	upi->event_fd = NULL;
	upi->page     = NULL;
	upi->data_pos = NULL;
	upi->fp       = NULL;
}

void record_perf_data(struct uftrace_perf_info *upi, int idx)
{
#ifdef HAVE_PERF_CLOCKID
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

		if (fwrite(buf, 1, size, upi->fp) != size) {
			pr_dbg("failed to write perf data: %m\n");
			goto out;
		}
	}

	buf = &data[start & mask];
	size = end - start;
	start += size;

	if (fwrite(buf, 1, size, upi->fp) != size)
		pr_dbg("failed to write perf data: %m\n");

out:
	/* ensure all reads are done before we write the tail. */
	full_memory_barrier();

	pc->data_tail = pos;
	upi->data_pos[idx] = pos;
#endif
}

static int read_perf_event(struct uftrace_perf *perf)
{
	struct perf_context_switch_event ev;

	if (perf->done || perf->fp == NULL)
		return -1;

	if (fread(&ev, sizeof(ev), 1, perf->fp) != 1) {
		perf->done = true;
		return -1;
	}

	if (ev.header.type != PERF_RECORD_SWITCH)
		return -1;

	perf->ctxsw.time = ev.sample_id.time;
	perf->ctxsw.tid  = ev.sample_id.tid;
	perf->ctxsw.out  = ev.header.misc & PERF_RECORD_MISC_SWITCH_OUT;

	perf->valid = true;
	return 0;
}

int read_perf_data(struct ftrace_file_handle *handle)
{
	struct uftrace_perf *perf;
	uint64_t min_time = ~0ULL;
	int best = -1;
	int i;

	for (i = 0; i < handle->nr_perf; i++) {
		perf = &handle->perf[i];

		if (perf->done)
			continue;
		if (!perf->valid) {
			if (read_perf_event(perf) < 0)
				continue;
		}

		if (perf->ctxsw.time < min_time) {
			min_time = perf->ctxsw.time;
			best = i;
		}
	}

	handle->last_perf_idx = best;
	return best;
}

struct uftrace_record * get_perf_record(struct uftrace_perf *perf)
{
	static struct uftrace_record rec;

	rec.type  = UFTRACE_EVENT;
	rec.time  = perf->ctxsw.time;
	rec.magic = RECORD_MAGIC;

	if (perf->ctxsw.out)
		rec.addr = EVENT_ID_PERF_SCHED_OUT;
	else
		rec.addr = EVENT_ID_PERF_SCHED_IN;

	return &rec;
}
