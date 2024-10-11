#define _GNU_SOURCE

#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "sysctl-write-event.h"
#include "sysctl_monitor_bpf.skel.h"

#define CGROUP_MOUNT_DFLT "/sys/fs/cgroup"

struct ring_buffer *rb;

static void int_exit(int sig)
{
	int cgfd = open(CGROUP_MOUNT_DFLT, O_PATH | O_DIRECTORY | O_CLOEXEC);

	if (cgfd >= 0) {
		bpf_prog_detach(cgfd, BPF_CGROUP_SYSCTL);
		close(cgfd);
	}
}

static int log_sysctl_writes(void *ctx, void *data, size_t data_sz)
{
	struct sysctl_write_event *we = data;

	if (we->errorcode)
		printf("Sysctl monitor BPF returned error: %d\n", we->errorcode);
	else
		printf("%s[%d] tried to update '%s' from '%s' to '%s'\n", we->comm, we->pid, we->path, we->current, we->newvalue);

	return 0;
}

static int attach_bpf(void)
{
	struct sysctl_monitor_bpf *skel;
	int progfd, cgfd;
	int err;

	cgfd = open(CGROUP_MOUNT_DFLT, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (cgfd < 0) {
		printf("failed to open cgroup mount point\n");
		return 1;
	}

	skel = sysctl_monitor_bpf__open_and_load();
	if (!skel) {
		printf("failed to open and load BPF object\n");
		return 1;
	}

	err = sysctl_monitor_bpf__attach(skel);
	if (err) {
		printf("failed to attach BPF program\n");
		return 1;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.written_sysctls), log_sysctl_writes, NULL, NULL);
	if (!rb) {
		printf("failed to create ring buffer\n");
		return 1;
	}

	progfd = bpf_program__fd(skel->progs.sysctl_monitor);

	if (bpf_prog_attach(progfd, cgfd, BPF_CGROUP_SYSCTL, BPF_F_ALLOW_OVERRIDE) < 0) {
		close(progfd);
		return 1;
	}

	close(progfd);

	return 0;
}

int main(int argc, char **argv)
{
	int ret, cgfd;

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGQUIT, int_exit);

	if (attach_bpf())
		return 1;

	// In business
	while (1) {
		ret = ring_buffer__poll(rb, 1000);
		if (ret < 0) {
			if (errno == EINTR)
				break;
			printf("Error polling ring buffer\n");
			break;
		}
	}

	cgfd = open(CGROUP_MOUNT_DFLT, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (cgfd >= 0) {
		bpf_prog_detach(cgfd, BPF_CGROUP_SYSCTL);
		close(cgfd);
	}

	return 0;
}
