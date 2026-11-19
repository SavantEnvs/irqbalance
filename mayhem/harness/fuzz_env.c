/*
 * fuzz_env.c — see fuzz_env.h. Mocks the kernel-provided environment of the
 * irqbalance daemon (procfs, sysfs, the UNIX control socket) via linker
 * --wrap of libc entry points. No irqbalance function is replaced.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "config.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <ftw.h>

#include "irqbalance.h"
#include "fuzz_env.h"

/* ---- daemon globals not declared in irqbalance.h (defined in irqbalance.c) ---- */
extern volatile int keep_going;
extern int sleep_interval;
extern int last_interval;
extern int foreground_mode;
extern char *cpu_ban_string;
extern char *banned_cpumask_from_ui;
extern GList *cl_banned_modules;
gboolean scan(gpointer data);

/* ---- real libc entry points (resolved by -Wl,--wrap=...) ---- */
FILE *__real_fopen(const char *path, const char *mode);
DIR *__real_opendir(const char *path);
int __real_stat(const char *path, struct stat *st);
ssize_t __real_readlink(const char *path, char *buf, size_t len);

static char fake_root[PATH_MAX];
static int env_ready;

static const char *proc_interrupts;
static size_t proc_interrupts_len;
static const char *proc_stat;
static size_t proc_stat_len;

static const char *client_msg;
static size_t client_msg_len;
static char *reply;

const char fuzz_env_default_interrupts[] =
	"           CPU0       CPU1       CPU2       CPU3\n"
	"  0:         22          0          0          0   IO-APIC   2-edge      timer\n"
	"  8:          0          0          0          1   IO-APIC   8-edge      rtc0\n"
	"  9:          0          4          0          0   IO-APIC   9-fasteoi   acpi\n"
	" 16:        100        200          0          0   IO-APIC  16-fasteoi   ahci[0000:00:1f.2]\n"
	" 24:       1000          0       5000          0   PCI-MSI 1048576-edge      eth0-rx-0\n"
	" 25:          0       3000          0        700   PCI-MSI 1048577-edge      eth0-tx-0\n"
	" 26:          5          0          0          0   PCI-MSI 1048578-edge      eth0\n"
	" 30:         10         10         10         10  xen-dyn    -event     xen-pirq-event\n"
	"NMI:          0          0          0          0   Non-maskable interrupts\n"
	"LOC:       1000       1000       1000       1000   Local timer interrupts\n";

const char fuzz_env_default_stat[] =
	"cpu  400 0 400 4000 40 200 240 0 0 0\n"
	"cpu0 100 0 100 1000 10 50 60 0 0 0\n"
	"cpu1 100 0 100 1000 10 40 70 0 0 0\n"
	"cpu2 100 0 100 1000 10 60 50 0 0 0\n"
	"cpu3 100 0 100 1000 10 50 60 0 0 0\n"
	"intr 12345 22 0 0\n";

/* ------------------------------------------------------------------ */
/* fake /sys + /proc/irq tree                                          */

static int put_file(const char *rel, const char *content)
{
	char path[PATH_MAX];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", fake_root, rel);
	f = __real_fopen(path, "w");
	if (!f)
		return -1;
	fputs(content, f);
	fclose(f);
	return 0;
}

static int put_dir(const char *rel)
{
	char path[PATH_MAX];
	char *p;

	snprintf(path, sizeof(path), "%s/%s", fake_root, rel);
	for (p = path + strlen(fake_root) + 1; *p; p++) {
		if (*p == '/') {
			*p = 0;
			if (mkdir(path, 0755) && errno != EEXIST)
				return -1;
			*p = '/';
		}
	}
	if (mkdir(path, 0755) && errno != EEXIST)
		return -1;
	return 0;
}

static int rm_cb(const char *path, const struct stat *sb, int flag, struct FTW *ftw)
{
	(void)sb; (void)flag; (void)ftw;
	return remove(path);
}

static void remove_fake_root(void)
{
	if (fake_root[0])
		nftw(fake_root, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
}

int fuzz_env_init(void)
{
	const char *tmp;
	char rel[256], val[64];
	int cpu, irq;
	static const int nic_irqs[] = { 24, 25, 26 };
	static const int all_irqs[] = { 16, 24, 25, 26 };

	if (env_ready)
		return 0;

	tmp = getenv("TMPDIR");
	if (!tmp || !*tmp)
		tmp = "/tmp";
	snprintf(fake_root, sizeof(fake_root), "%s/irqbalance-fuzz-XXXXXX", tmp);
	if (!mkdtemp(fake_root)) {
		perror("mkdtemp");
		return -1;
	}
	atexit(remove_fake_root);

	/* CPUs: 0-3 online, one package, L2 shared by {0,1} and {2,3} */
	put_dir("sys/devices/system/cpu");
	put_file("sys/devices/system/cpu/online", "0-3\n");
	put_file("sys/devices/system/cpu/isolated", "\n");
	for (cpu = 0; cpu < 4; cpu++) {
		snprintf(rel, sizeof(rel), "sys/devices/system/cpu/cpu%d/topology", cpu);
		put_dir(rel);
		snprintf(rel, sizeof(rel), "sys/devices/system/cpu/cpu%d/topology/core_siblings", cpu);
		put_file(rel, "f\n");
		snprintf(rel, sizeof(rel), "sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
		put_file(rel, "0\n");
		snprintf(rel, sizeof(rel), "sys/devices/system/cpu/cpu%d/cache/index1", cpu);
		put_dir(rel);
		snprintf(rel, sizeof(rel), "sys/devices/system/cpu/cpu%d/cache/index1/shared_cpu_map", cpu);
		snprintf(val, sizeof(val), "%x\n", 1 << cpu);
		put_file(rel, val);
		snprintf(rel, sizeof(rel), "sys/devices/system/cpu/cpu%d/cache/index2", cpu);
		put_dir(rel);
		snprintf(rel, sizeof(rel), "sys/devices/system/cpu/cpu%d/cache/index2/shared_cpu_map", cpu);
		put_file(rel, cpu < 2 ? "3\n" : "c\n");
		snprintf(rel, sizeof(rel), "sys/devices/system/cpu/cpu%d/node0", cpu);
		put_dir(rel);
	}
	/* a non-cpu entry the cpu scan must skip */
	put_dir("sys/devices/system/cpu/cpufreq");

	/* NUMA node 0 holds every cpu */
	put_dir("sys/devices/system/node/node0");
	put_file("sys/devices/system/node/node0/cpumap", "f\n");

	/* SATA controller on legacy IRQ 16 */
	put_dir("sys/bus/pci/devices/0000:00:1f.2");
	put_file("sys/bus/pci/devices/0000:00:1f.2/irq", "16\n");
	put_file("sys/bus/pci/devices/0000:00:1f.2/vendor", "0x8086\n");
	put_file("sys/bus/pci/devices/0000:00:1f.2/device", "0x2922\n");
	put_file("sys/bus/pci/devices/0000:00:1f.2/subsystem_vendor", "0x8086\n");
	put_file("sys/bus/pci/devices/0000:00:1f.2/subsystem_device", "0x5044\n");
	put_file("sys/bus/pci/devices/0000:00:1f.2/class", "0x010601\n");
	put_file("sys/bus/pci/devices/0000:00:1f.2/numa_node", "0\n");
	put_file("sys/bus/pci/devices/0000:00:1f.2/local_cpus", "f\n");

	/* Ethernet NIC with MSI-X IRQs 24-26, bound to e1000e */
	put_dir("sys/bus/pci/devices/0000:02:00.0/msi_irqs");
	for (irq = 0; irq < 3; irq++) {
		snprintf(rel, sizeof(rel), "sys/bus/pci/devices/0000:02:00.0/msi_irqs/%d", nic_irqs[irq]);
		put_file(rel, "msix\n");
	}
	put_file("sys/bus/pci/devices/0000:02:00.0/vendor", "0x8086\n");
	put_file("sys/bus/pci/devices/0000:02:00.0/device", "0x10d3\n");
	put_file("sys/bus/pci/devices/0000:02:00.0/subsystem_vendor", "0x8086\n");
	put_file("sys/bus/pci/devices/0000:02:00.0/subsystem_device", "0xa01f\n");
	put_file("sys/bus/pci/devices/0000:02:00.0/class", "0x020000\n");
	put_file("sys/bus/pci/devices/0000:02:00.0/numa_node", "0\n");
	put_file("sys/bus/pci/devices/0000:02:00.0/local_cpus", "f\n");
	{
		char path[PATH_MAX];
		snprintf(path, sizeof(path), "%s/sys/bus/pci/devices/0000:02:00.0/driver", fake_root);
		if (symlink("../../../bus/pci/drivers/e1000e", path) && errno != EEXIST)
			return -1;
	}

	/* current affinities, so activate_mappings() has something to change */
	for (irq = 0; irq < 4; irq++) {
		snprintf(rel, sizeof(rel), "proc/irq/%d", all_irqs[irq]);
		put_dir(rel);
		snprintf(rel, sizeof(rel), "proc/irq/%d/smp_affinity", all_irqs[irq]);
		put_file(rel, "f\n");
		snprintf(rel, sizeof(rel), "proc/irq/%d/node", all_irqs[irq]);
		put_file(rel, "0\n");
	}

	fuzz_env_set_proc(fuzz_env_default_interrupts, strlen(fuzz_env_default_interrupts),
			  fuzz_env_default_stat, strlen(fuzz_env_default_stat));
	env_ready = 1;
	return 0;
}

void fuzz_env_set_proc(const char *interrupts, size_t interrupts_len,
		       const char *stat, size_t stat_len)
{
	proc_interrupts = interrupts;
	proc_interrupts_len = interrupts_len;
	proc_stat = stat;
	proc_stat_len = stat_len;
}

/* Map a kernel path into the fake tree. Returns NULL if the path is not ours. */
static const char *redirect(const char *path, char *buf, size_t len)
{
	if (!path)
		return NULL;
	if (strncmp(path, "/sys/devices/", 13) && strncmp(path, "/sys/bus/", 9) &&
	    strncmp(path, "/proc/irq/", 10))
		return NULL;
	snprintf(buf, len, "%s%s", fake_root, path);
	return buf;
}

static FILE *mem_stream(const char *data, size_t len)
{
	if (!data || !len)
		return __real_fopen("/dev/null", "r");
	return fmemopen((void *)data, len, "r");
}

FILE *__wrap_fopen(const char *path, const char *mode)
{
	char buf[PATH_MAX];
	const char *p;

	if (!path || !mode)
		return __real_fopen(path, mode);
	if (env_ready && (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+')) &&
	    (!strncmp(path, "/proc/", 6) || !strncmp(path, "/sys/", 5)))
		return __real_fopen("/dev/null", "w");
	if (env_ready && !strcmp(path, "/proc/interrupts"))
		return mem_stream(proc_interrupts, proc_interrupts_len);
	if (env_ready && !strcmp(path, "/proc/stat"))
		return mem_stream(proc_stat, proc_stat_len);
	if (env_ready && (p = redirect(path, buf, sizeof(buf))))
		return __real_fopen(p, mode);
	return __real_fopen(path, mode);
}

DIR *__wrap_opendir(const char *path)
{
	char buf[PATH_MAX];
	const char *p;

	if (env_ready && (p = redirect(path, buf, sizeof(buf))))
		return __real_opendir(p);
	return __real_opendir(path);
}

int __wrap_stat(const char *path, struct stat *st)
{
	char buf[PATH_MAX];
	const char *p;

	if (env_ready && (p = redirect(path, buf, sizeof(buf))))
		return __real_stat(p, st);
	return __real_stat(path, st);
}

ssize_t __wrap_readlink(const char *path, char *out, size_t len)
{
	char buf[PATH_MAX];
	const char *p;

	if (env_ready && (p = redirect(path, buf, sizeof(buf))))
		return __real_readlink(p, out, len);
	return __real_readlink(path, out, len);
}

/* ------------------------------------------------------------------ */
/* fake control-socket client                                          */

void fuzz_env_set_client_msg(const char *msg, size_t len)
{
	client_msg = msg;
	client_msg_len = len;
}

int __wrap_accept(int fd, struct sockaddr *addr, socklen_t *alen)
{
	(void)fd; (void)addr; (void)alen;
	/* a real descriptor, so the daemon's close() is an ordinary close */
	return open("/dev/null", O_RDWR);
}

/*
 * sock_handle() receives into an uninitialised 16 KiB stack buffer and reads past the
 * received bytes (its prefix checks), so on the real daemon the bytes after a message are
 * whatever the previous message on that frame left there. Model that deterministically:
 * the buffer's image is the previous message of the same input overlaid by this one,
 * all zeros at the start of each input (fuzz_env_daemon_start()).
 */
#define RECV_IMAGE 16384
static char recv_image[RECV_IMAGE];

ssize_t __wrap_recvmsg(int fd, struct msghdr *msg, int flags)
{
	size_t n = 0, i, off = 0;
	struct cmsghdr *cmsg;
	struct ucred cred = { .pid = 1, .uid = 0, .gid = 0 };
	(void)fd; (void)flags;

	n = client_msg_len < RECV_IMAGE ? client_msg_len : RECV_IMAGE;
	memcpy(recv_image, client_msg, n);
	/* SOCK_STREAM semantics: at most what fits in the receive buffer */
	for (i = 0; i < (size_t)msg->msg_iovlen && off < RECV_IMAGE; i++) {
		size_t k = RECV_IMAGE - off;
		if (k > msg->msg_iov[i].iov_len)
			k = msg->msg_iov[i].iov_len;
		memcpy(msg->msg_iov[i].iov_base, recv_image + off, k);
		off += k;
	}
	if (n > off)
		n = off;
	/* the kernel attaches the peer's credentials (SO_PASSCRED); the peer is root */
	if (msg->msg_control && msg->msg_controllen >= CMSG_SPACE(sizeof(cred))) {
		cmsg = CMSG_FIRSTHDR(msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_CREDENTIALS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(cred));
		memcpy(CMSG_DATA(cmsg), &cred, sizeof(cred));
		msg->msg_controllen = CMSG_SPACE(sizeof(cred));
	} else {
		msg->msg_controllen = 0;
	}
	msg->msg_flags = 0;
	return (ssize_t)n;
}

ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags)
{
	char *r;
	(void)fd; (void)flags;

	r = malloc(len + 1);
	if (!r)
		return -1;
	memcpy(r, buf, len);	/* reads every byte the daemon claims to send */
	r[len] = 0;
	free(reply);
	reply = r;
	return (ssize_t)len;
}

const char *fuzz_env_last_reply(void)
{
	return reply ? reply : "";
}

void fuzz_env_clear_reply(void)
{
	free(reply);
	reply = NULL;
}

/* ------------------------------------------------------------------ */
/* daemon lifecycle (mirrors irqbalance.c main())                      */

void fuzz_env_reset_daemon_globals(void)
{
	keep_going = 1;
	one_shot_mode = 0;
	debug_mode = 0;
	foreground_mode = 1;
	journal_logging = 0;
	log_mask = 0;		/* no syslog / console noise */
	log_indent = "    ";
	numa_avail = 1;		/* the fake tree has NUMA node 0 */
	need_rescan = 0;
	need_rebuild = 0;
	cycle_count = 0;
	HZ = 100;
	sleep_interval = SLEEP_INTERVAL;
	last_interval = SLEEP_INTERVAL;
}

void fuzz_env_daemon_start(void)
{
	memset(recv_image, 0, sizeof(recv_image));

	/* build_object_tree() */
	build_numa_node_list();
	parse_cpu_tree();
	rebuild_irq_db();

	for_each_irq(NULL, force_rebalance_irq, NULL);
	parse_proc_interrupts();
	parse_proc_stat();
	clear_slots();
}

void fuzz_env_daemon_stop(void)
{
	/* free_object_tree() */
	free_numa_node_list();
	clear_cpu_tree();
	free_irq_db();

	/* state the control socket / CLI options can change */
	g_list_free_full(cl_banned_irqs, free);
	cl_banned_irqs = NULL;
	free(cpu_ban_string);
	cpu_ban_string = NULL;
	banned_cpumask_from_ui = NULL;
	cpus_clear(banned_cpus);
	fuzz_env_clear_reply();
}
