// SPDX-License-Identifier: GPL-2.0-only
// Explicit one-shot debug capture; never loaded by the passive collector.
typedef unsigned long long u64;
typedef unsigned int u32;
#define SEC(n) __attribute__((section(n), used))
#define UINT(n, v) int(*n)[v]
#define TYPE(n, v) v *n
static void *(*lookup)(void *, const void *) = (void *)1;
static u64 (*pid_tgid)(void) = (void *)14;
static u64 (*now)(void) = (void *)125;
static void *(*task)(void) = (void *)158;
static void *(*regs)(void *) = (void *)175;
static long (*read_kernel)(void *, u32, const void *) = (void *)113;
static long (*send_thread)(u32) = (void *)117;
struct state {
  u32 pid, tid, operation, armed;
  u32 pending, done;
  int signal_result;
  u32 skipped;
  u64 deadline, entered, exited;
  long long result;
  u64 saved[21];
};
struct {
  UINT(type, 2);
  UINT(max_entries, 1);
  TYPE(key, u32);
  TYPE(value, struct state);
} control SEC(".maps");
static int allowed(u32 op, u64 nr) {
  if (op == 1) return nr == 1 || nr == 20 || nr == 44 || nr == 46 || nr == 307;
  return nr == 0 || nr == 19 || nr == 45 || nr == 47 || nr == 299;
}
static int enter(u32 operation) {
  u32 zero = 0;
  struct state *s = lookup(&control, &zero);
  u64 id = pid_tgid();
  if (!s || !s->armed || s->done || s->pid != (id >> 32) || s->tid != (u32)id ||
      s->operation != operation || now() > s->deadline)
    return 0;
  u64 saved[21];
  if (read_kernel(saved, sizeof(saved), regs(task()))) return 0;
  // Async kernel workers and io_uring completion are not syscall callers.
  if (saved[17] != 0x33 || !allowed(operation, saved[15])) {
    s->skipped++;
    return 0;
  }
  s->pending = 1;
  s->entered = now();
  return 0;
}
SEC("kprobe/tcp_sendmsg") int send_entry(void *ctx) { return enter(1); }
SEC("kprobe/tcp_recvmsg") int receive_entry(void *ctx) { return enter(2); }
struct raw_args {
  u64 args[2];
};
SEC("raw_tracepoint/sys_exit") int io_exit(struct raw_args *ctx) {
  u32 zero = 0;
  struct state *s = lookup(&control, &zero);
  u64 id = pid_tgid();
  if (!s || !s->armed || s->done || !s->pending || s->pid != (id >> 32) || s->tid != (u32)id)
    return 0;
  s->pending = 0;
  if (now() > s->deadline) return 0;
  long long result = ctx->args[1];
  // EAGAIN is readiness, not completed input. Internal restart returns are not final.
  if (result == -11 || result == -512 || result == -513 || result == -514 || result == -516) {
    s->skipped++;
    return 0;
  }
  u64 saved[21];
  if (read_kernel(saved, sizeof(saved), (void *)ctx->args[0])) return 0;
  if (saved[17] != 0x33 || !allowed(s->operation, saved[15])) {
    s->skipped++;
    return 0;
  }
  __builtin_memcpy(s->saved, saved, sizeof(saved));
  s->result = result;
  s->exited = now();
  s->armed = 0;
  s->done = 1;
  s->signal_result = send_thread(5);
  return 0;
}
char frida_license[] SEC("license") = "GPL";
