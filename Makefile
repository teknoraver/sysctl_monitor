LDLIBS += -lbpf
CFLAGS += -O2 -pipe -g -Wall

all:: sysctl_monitor

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

sysctl_monitor_bpf.skel.h: sysctl_monitor.bpf.o
	bpftool gen skeleton $< > $@

sysctl_monitor.bpf.o: sysctl_monitor.bpf.c vmlinux.h
	clang $(CFLAGS) -target bpf -c $< -o $@

sysctl_monitor: sysctl_monitor.c sysctl_monitor_bpf.skel.h

clean::
	$(RM) *.o sysctl_monitor *.skel.h vmlinux.h
