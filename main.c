#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "prog.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static int get_prog_fd(struct prog_bpf *skel, uint32_t index)
{
	switch (index) {
	case 0: return bpf_program__fd(skel->progs.second);
	case 1: return bpf_program__fd(skel->progs.third);
	default:
		fprintf(stderr, "Invalid prog index\n");
		return -1;
	}
}

int main()
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = 1,
			    .attach_point = BPF_TC_INGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	bool hook_created = false;
	struct prog_bpf *skel;
	uint32_t idx;
	int32_t fd;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	skel = prog_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load skeleton\n");
		return 1;
	}

	/* Place tailcall progs into prog array */
	for (idx = 0; idx < 2; idx++) {
		int32_t fd = get_prog_fd(skel, idx);
		if (fd < 0) {
			err = -EINVAL;
			goto cleanup;
		}

		err = bpf_map__update_elem(skel->maps.progs, &idx, sizeof(idx),
					   &fd, sizeof(fd), BPF_ANY);
		if (err < 0) {
			fprintf(stderr, "Failed to update map, idx=%u\n", idx);
			goto cleanup;
		}
	}

	/* The hook (i.e. qdisc) may already exists because:
	 *   1. it is created by other processes or users
	 *   2. or since we are attaching to the TC ingress ONLY,
	 *      bpf_tc_hook_destroy does NOT really remove the qdisc,
	 *      there may be an egress filter on the qdisc
	 */
	err = bpf_tc_hook_create(&tc_hook);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}

	tc_opts.prog_fd = bpf_program__fd(skel->progs.first);
	err = bpf_tc_attach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		goto cleanup;
	}

	printf("Prog is attached!\n");
	printf("Sleeping for 10s...\n");
	sleep(10);

	tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
	err = bpf_tc_detach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}
	printf("Prog is detached.\n");

cleanup:
	if (hook_created)
		bpf_tc_hook_destroy(&tc_hook);
	prog_bpf__destroy(skel);
	return -err;
}
