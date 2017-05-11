#include <signal.h>
#include <stdbool.h>
#include <ucontext.h>
#include <assert.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/mcount.h"
#include "utils/filter.h"

#define INVALID_OPCODE  0xce
#define PAGE_SIZE       4096
#define PAGE_ADDR(a)    ((void *)((a) & ~(PAGE_SIZE - 1)))

static int get_ucontext_register(char *reg_name)
{
	static const struct {
		int idx; const char *name;
	} reg_table[] = {
		{ REG_RAX, "rax" }, { REG_RAX, "eax" },
		{ REG_RBX, "rax" }, { REG_RBX, "ebx" },
		{ REG_RCX, "rax" }, { REG_RCX, "ecx" },
		{ REG_RDX, "rax" }, { REG_RDX, "edx" },
		{ REG_RSI, "rax" }, { REG_RSI, "esi" },
		{ REG_RDI, "rax" }, { REG_RDI, "edi" },
		{ REG_RBP, "rax" }, { REG_RBP, "ebp" },
		{ REG_RSP, "rax" }, { REG_RSP, "esp" },
		{ REG_RIP, "rax" }, { REG_RIP, "eip" },
		{ REG_R8,  "r8"  },
		{ REG_R9,  "r9"  },
		{ REG_R10, "r10" },
		{ REG_R11, "r11" },
		{ REG_R12, "r12" },
		{ REG_R13, "r13" },
		{ REG_R14, "r14" },
		{ REG_R15, "r15" },
	};
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(reg_table); i++) {
		if (!strcasecmp(reg_name, reg_table[i].name))
			return reg_table[i].idx;
	}

	return -1;
}

static void sdt_handler(int sig, siginfo_t *info, void *arg)
{
	ucontext_t *ctx = arg;
	unsigned long addr = ctx->uc_mcontext.gregs[REG_RIP];
	struct mcount_event_info * mei;

	mei = mcount_lookup_event(addr);
	assert(mei != NULL);

	mcount_save_event(mei, arg);

	/* skip the invalid insn and continue */
	ctx->uc_mcontext.gregs[REG_RIP] = addr + 1;
}

int mcount_arch_enable_event(struct mcount_event_info *mei)
{
	static bool sdt_handler_set = false;

	if (!sdt_handler_set) {
		struct sigaction act = {
			.sa_flags     = SA_SIGINFO,
			.sa_sigaction = sdt_handler,
		};

		sigemptyset(&act.sa_mask);
		sigaction(SIGILL, &act, NULL);

		sdt_handler_set = true;
	}

	if (mprotect(PAGE_ADDR(mei->addr), PAGE_SIZE, PROT_READ | PROT_WRITE)) {
		pr_dbg("cannot enable event due to protection: %m\n");
		return -1;
	}

	/* replace NOP to an invalid OP so that it can catch SIGILL */
	memset((void *)mei->addr, INVALID_OPCODE, 1);

	if (mprotect(PAGE_ADDR(mei->addr), PAGE_SIZE, PROT_EXEC))
		pr_err("cannot setup event due to protection");

	return 0;
}

int mcount_arch_parse_sdt_argument(struct ftrace_arg_spec *spec,
				   char *arg_str)
{
	char *pos = arg_str;

	/* case 1. simple register: %rdi */
	if (*pos == '%') {
		spec->type = ARG_TYPE_REG;
		spec->reg_idx = get_ucontext_register(pos + 1);
		return 0;
	}

	/* parse (a list of) offsets.. */
	while (isdigit(*pos) || (strchr("+-", *pos) && isdigit(pos[1]))) {
		spec->deref_ofs += strtol(pos, &pos, 10);
	}

	/* case 2. offset + (register): -4(%ebp) */
	if (*pos == '(') {
		char *tmp = strchr(pos, ')');  /* no support for nested deref */

		if (pos[1] != '%' || tmp == NULL)
			return -1;

		*tmp = '\0';

		spec->type = ARG_TYPE_DEREF_REG;
		spec->deref_base = get_ucontext_register(pos + 2);

		if (spec->deref_base >= 0)
			return 0;
	}

	/* case 3. offset + (global) variable + (register): 16+_mp(%rip) */
	/* TODO: it needs an address of the data symbol */
	return -1;
}

void mcount_arch_save_event_arg(struct mcount_event_info *mei,
				struct mcount_event *ev, void *priv)
{
	ucontext_t *ctx = priv;
	struct ftrace_arg_spec *spec;
	int size = 0;

	list_for_each_entry(spec, &mei->args, list) {
		int reg = spec->reg_idx;
		unsigned long val;
		void *ptr;

		if (spec->type == ARG_TYPE_REG) {
			val = ctx->uc_mcontext.gregs[reg];
			ptr = &val;
		}
		else if (spec->type == ARG_TYPE_DEREF_REG) {
			reg = spec->deref_base;
			val = ctx->uc_mcontext.gregs[reg] + spec->deref_ofs;
			ptr = (void *)val;
		}

		memcpy(ev->argbuf + size, ptr, spec->size);
		size += ALIGN(spec->size, 4);
	}

	ev->flags |= EVENT_FL_ARGUMENT;
	ev->arglen = ALIGN(size, 8);
}
