// SPDX-License-Identifier: GPL-2.0-only
// PID-wide opt-in syscall-exit stream, separate from passive monitoring.
typedef unsigned long long u64;
typedef unsigned int u32;
#define SEC(n) __attribute__((section(n), used))
#define UINT(n, v) int(*n)[v]
#define TYPE(n, v) v *n
static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, u64) = (void *)2;
static long (*delete)(void *, const void *) = (void *)3;
static u64 (*pid_tgid)(void) = (void *)14;
static u64 (*now)(void) = (void *)125;
static void *(*task)(void) = (void *)158;
static void *(*regs)(void *) = (void *)175;
static long (*read_kernel)(void *, u32, const void *) = (void *)113;
static long (*signal_thread)(u32) = (void *)117;
static void *(*reserve)(void *, u64, u64) = (void *)131;
static void (*submit)(void *, u64) = (void *)132;
struct config {
  u32 pid, blocked_offset;
  u64 deadline;
};
struct pending {
  u64 entered, requested;
  u32 operation, pad;
};
struct event {
  u32 pid, tid, operation, flags;
  int signal_result;
  u32 pad;
  u64 entered, exited, requested;
  long long result;
  u64 saved[21];
};
struct {
  UINT(type, 2);
  UINT(max_entries, 1);
  TYPE(key, u32);
  TYPE(value, struct config);
} control SEC(".maps");
struct {
  UINT(type, 1);
  UINT(max_entries, 4096);
  TYPE(key, u32);
  TYPE(value, struct pending);
} pending SEC(".maps");
struct {
  UINT(type, 1);
  UINT(max_entries, 4096);
  TYPE(key, u32);
  TYPE(value, u64);
} inflight SEC(".maps");
struct {
  UINT(type, 27);
  UINT(max_entries, 1048576);
} events SEC(".maps");
struct {
  UINT(type, 2);
  UINT(max_entries, 1);
  TYPE(key, u32);
  TYPE(value, u64);
} dropped SEC(".maps");
static void drop(void) {
  u32 k = 0;
  u64 *n = lookup(&dropped, &k);
  if (n) __sync_fetch_and_add(n, 1);
}
static int allowed(u32 op, u64 nr) {
  return op == 1 ? (nr == 1 || nr == 20 || nr == 44 || nr == 46 || nr == 307)
                 : (nr == 0 || nr == 19 || nr == 45 || nr == 47 || nr == 299);
}
static int enter(void *ctx, u32 op) {
  u32 k = 0;
  struct config *c = lookup(&control, &k);
  u64 id = pid_tgid();
  u32 tid = id;
  if (!c || !c->pid || c->pid != (id >> 32) || now() > c->deadline) return 0;
  u64 saved[21];
  if (read_kernel(saved, sizeof(saved), regs(task()))) return 0;
  if (saved[17] != 0x33 || !allowed(op, saved[15])) return 0;
  struct pending p = {.entered = now(), .operation = op};
  read_kernel(&p.requested, 8, (char *)ctx + 12 * 8);  // x86_64 pt_regs.dx: TCP length
  if (update(&pending, &tid, &p, 0)) drop();
  return 0;
}
SEC("kprobe/tcp_sendmsg") int send_entry(void *ctx) { return enter(ctx, 1); }
SEC("kprobe/tcp_recvmsg") int receive_entry(void *ctx) { return enter(ctx, 2); }
struct raw_args {
  u64 args[2];
};
SEC("raw_tracepoint/sys_exit") int io_exit(struct raw_args *ctx) {
  u32 k = 0;
  struct config *c = lookup(&control, &k);
  u64 id = pid_tgid();
  u32 tid = id;
  if (!c || !c->pid || c->pid != (id >> 32)) return 0;
  struct pending *p = lookup(&pending, &tid);
  if (!p) return 0;
  struct pending original = *p;
  delete (&pending, &tid);
  if (now() > c->deadline) return 0;
  struct event e = {.pid = id >> 32,
                    .tid = tid,
                    .operation = original.operation,
                    .entered = original.entered,
                    .requested = original.requested,
                    .exited = now(),
                    .result = ctx->args[1]};
  if (read_kernel(e.saved, sizeof(e.saved), (void *)ctx->args[0])) return 0;
  if (e.saved[17] != 0x33 || !allowed(e.operation, e.saved[15])) return 0;
  // Include readiness/error metadata; do not trigger Java/native unwinding on retry.
  if (e.result == -11 || e.result == -512 || e.result == -513 || e.result == -514 ||
      e.result == -516)
    e.flags = 4;
  else if (lookup(&inflight, &tid))
    e.flags = 2;
  else {
    u64 mask = 0;
    if (read_kernel(&mask, 8, (char *)task() + c->blocked_offset) || mask & (1ULL << 4))
      e.flags = 3;
    else
      e.flags = 1;
  }
  void *slot = reserve(&events, sizeof(e), 0);
  if (!slot) {
    drop();
    return 0;
  }
  if (e.flags == 1) {
    if (update(&inflight, &tid, &e.exited, 1))
      e.flags = 2;
    else {
      e.signal_result = signal_thread(5);
      if (e.signal_result) {
        e.flags = 5;
        delete (&inflight, &tid);
      }
    }
  }
  __builtin_memcpy(slot, &e, sizeof(e));
  submit(slot, 0);
  return 0;
}
char stream_license[] SEC("license") = "GPL";
