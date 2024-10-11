#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "sysctl-write-event.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} written_sysctls SEC(".maps");

static bool my_streq(const char *s1, const char *s2, size_t l)
{
	for (size_t i = 0; i < l; i++) {
		if (s1[i] != s2[i])
			return false;
		if (!s1[i])
			return true;
	}
	return true;
}

struct str {
	char *s;
	size_t l;
};

static long cut_last(u64 i, struct str *str)
{
	char *s;

	// Sanity checks for the preverifier
	if (i >= str->l)
		return 1;

	i = str->l - i - 1;
	s = str->s + i;

	if (*s == 0)
		return 0;

	if (*s == '\n' || *s == '\r' || *s == ' ' || *s == '\t') {
		*s = 0;

		return 0;
	}

	return 1;
}

// Cut off trailing whitespace and newlines
static void chop(char *s, size_t l)
{
	struct str str = { s, l };

	bpf_loop(l, cut_last, &str, 0);
}

SEC("cgroup/sysctl")
int sysctl_monitor(struct bpf_sysctl *ctx)
{
	int r;

	// Allow reads
	if (!ctx->write)
		return 1;

        /* Declare the struct without contextually initializing it.
         * This avoid zero-filling the struct, which would be a waste of
         * resource and code size. Since we're sending an event even on failure,
         * truncate the strings to zero size, in case we don't populate them. */
	struct sysctl_write_event we;
	we.errorcode = 0;
	we.path[0] = 0;
	we.comm[0] = 0;
	we.current[0] = 0;
	we.newvalue[0] = 0;

	/* Set the simple values first */
	we.pid = bpf_get_current_pid_tgid() >> 32;

	// Only monitor net/
	r = bpf_sysctl_get_name(ctx, we.path, sizeof(we.path), 0);
	if (r < 0) {
		we.errorcode = r;
		goto send_event;
	}

        r = bpf_get_current_comm(we.comm, sizeof(we.comm));
        if (r < 0) {
                we.errorcode = r;
                goto send_event;
        }

        r = bpf_sysctl_get_current_value(ctx, we.current, sizeof(we.current));
        if (r < 0) {
                we.errorcode = r;
                goto send_event;
        }

        r = bpf_sysctl_get_new_value(ctx, we.newvalue, sizeof(we.newvalue));
        if (r < 0) {
                we.errorcode = r;
                goto send_event;
        }

	// Both the kernel and userspace applications add a newline at the end,
	// remove it from both strings
	chop(we.current, sizeof(we.current));
	chop(we.newvalue, sizeof(we.newvalue));

send_event:
	// If new value is the same, ignore it
	if (r < 0 || !my_streq(we.current, we.newvalue, sizeof(we.current)))
		bpf_ringbuf_output(&written_sysctls, &we, sizeof(we), 0);

	return 0;
}

char _license[] SEC("license") = "GPL";
