/*
 * fuzz_env.h — a fixed, synthetic /proc + /sys for driving the irqbalance daemon
 * in-process (fuzz harnesses and the mayhem selftest).
 *
 * irqbalance reads only hard-coded kernel paths (/proc/interrupts, /proc/stat,
 * /sys/devices/system/..., /sys/bus/pci/devices/...) and writes
 * /proc/irq/N/smp_affinity. The daemon objects are linked with
 *   -Wl,--wrap=fopen,--wrap=opendir,--wrap=stat,--wrap=readlink,
 *   -Wl,--wrap=accept,--wrap=recvmsg,--wrap=send
 * so that (environment mock only; no irqbalance code is replaced):
 *   - /proc/interrupts and /proc/stat read from in-memory buffers (the fuzz input),
 *   - other /proc/irq/... and /sys/{devices,bus}/... paths resolve inside a fake
 *     tree created once per process under $TMPDIR (4 CPUs, 2 cache domains,
 *     1 package, NUMA node 0, a SATA controller on legacy IRQ 16 and a NIC with
 *     MSI-X IRQs 24-26),
 *   - every fopen() for writing goes to /dev/null (the host's IRQ affinity is
 *     never touched),
 *   - the control socket's accept()/recvmsg()/send() are a fake client that
 *     delivers one message with root SCM_CREDENTIALS and records the reply.
 */
#ifndef IRQBALANCE_FUZZ_ENV_H
#define IRQBALANCE_FUZZ_ENV_H

#include <stddef.h>

/* Create the fake tree (idempotent). Returns 0 on success. */
int fuzz_env_init(void);

/* Contents served for /proc/interrupts and /proc/stat (not copied: must stay valid). */
void fuzz_env_set_proc(const char *interrupts, size_t interrupts_len,
		       const char *stat, size_t stat_len);

/* A plausible /proc/interrupts and /proc/stat for the fake topology. */
extern const char fuzz_env_default_interrupts[];
extern const char fuzz_env_default_stat[];

/* The message the next accept()ed control-socket client sends. */
void fuzz_env_set_client_msg(const char *msg, size_t len);

/* The last reply the daemon send()s to that client (NUL-terminated, "" if none). */
const char *fuzz_env_last_reply(void);
void fuzz_env_clear_reply(void);

/* Reset the daemon's process-global state to what main() starts with. */
void fuzz_env_reset_daemon_globals(void);

/* main()'s init sequence: build the object tree and take the first samples. */
void fuzz_env_daemon_start(void);
/* free_object_tree() + the socket/CLI state an input can change. */
void fuzz_env_daemon_stop(void);

#endif
