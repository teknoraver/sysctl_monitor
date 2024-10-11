# sysctl monitor

This is a simple tool to monitor sysctl values and dump what is being changed and by whom.
It uses the eBPF CGROUP\_SYSCTL program type to monitor sysctl writes.
Writes are denied by default when the eBPF is attached.

This was the starting point for https://github.com/systemd/systemd/pull/32212
