// SPDX-License-Identifier: GPL-2.0-only
// The loader verifies this tracepoint ABI before attaching. No kernel headers needed.
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef int s32;
#define SEC(name) __attribute__((section(name), used))
#define UINT(name, value) int(*name)[value]
#define TYPE(name, value) value *name
static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, u64) = (void *)2;
static long (*delete)(void *, const void *) = (void *)3;
static u64 (*now_ns)(void) = (void *)125;  // bpf_ktime_get_boot_ns, includes suspend
static u64 (*pid_tgid)(void) = (void *)14;
static u64 (*uid_gid)(void) = (void *)15;
static long (*comm)(void *, u32) = (void *)16;

#ifdef STACK_X86_64
static void *(*current_task_btf)(void) = (void *)158;
static void *(*task_pt_regs)(void *) = (void *)175;
static long (*read_kernel)(void *, u32, const void *) = (void *)113;
static long (*read_user)(void *, u32, const void *) = (void *)112;
#define STACK_BYTES 4096
// Linux x86_64 pt_regs ABI. Do not use this layout for arm64 or compat tasks.
struct user_regs {
  u64 r15, r14, r13, r12, bp, bx, r11, r10, r9, r8;
  u64 ax, cx, dx, si, di, orig_ax, ip, cs, flags, sp, ss;
};
struct origin {
  u64 start_ns;
  u32 pid, tid;
  s32 regs_error, stack_error, instruction_error;
  u32 status, captured, kind;  // 0 connect, 1 TCP send entry, 2 TCP receive entry
  struct user_regs regs;
  u8 instruction[2], padding[6];
  u64 connection_ns, io_requested;
  u8 stack[STACK_BYTES];
};
// Bounded storage: 128 pending snapshots, plus one scratch value per CPU.
// Only stack[0:captured] is valid; scratch tail is never exported by the collector.
struct {
  UINT(type, 1);
  UINT(max_entries, 128);
  TYPE(key, u64);
  TYPE(value, struct origin);
} origins SEC(".maps");
struct {
  UINT(type, 6);
  UINT(max_entries, 1);
  TYPE(key, u32);
  TYPE(value, struct origin);
} origin_scratch SEC(".maps");
struct {
  UINT(type, 2);
  UINT(max_entries, 1);
  TYPE(key, u32);
  TYPE(value, u32);
} origin_enabled SEC(".maps");
struct {
  UINT(type, 2);
  UINT(max_entries, 1);
  TYPE(key, u32);
  TYPE(value, u64);
} origin_drops SEC(".maps");

static __attribute__((noinline)) void capture_origin(u64 id, u64 task, u64 connection, u64 kind,
                                                     u64 requested) {
  u32 zero = 0;
  u32 *enabled = lookup(&origin_enabled, &zero);
  if (!enabled || !(*enabled & (kind ? 2 : 1))) return;
  struct origin *o = lookup(&origin_scratch, &zero);
  if (!o) return;
  __builtin_memset(o, 0, __builtin_offsetof(struct origin, stack));
  o->start_ns = id;
  o->pid = task >> 32;
  o->tid = (u32)task;
  o->connection_ns = connection;
  o->kind = (u32)kind;
  o->io_requested = requested;
  void *regs = task_pt_regs(current_task_btf());
  o->regs_error = read_kernel(&o->regs, sizeof(o->regs), regs);
  if (o->regs_error) {
    o->status = 5;
    goto publish;
  }
  // Only a saved native 64-bit user frame and a matching synchronous syscall.
  // Other execution paths are explicitly unsupported, never attributed by guess.
  if (o->regs.cs != 0x33 || !o->regs.sp || !o->regs.ip) {
    o->status = 3;
    goto publish;
  }
  u64 nr = o->regs.orig_ax;
  if ((!kind && nr != 42) ||
      (kind == 1 && nr != 1 && nr != 20 && nr != 44 && nr != 46 && nr != 307) ||
      (kind == 2 && nr != 0 && nr != 19 && nr != 45 && nr != 47 && nr != 299)) {
    o->status = 4;
    goto publish;
  }
  o->instruction_error = read_user(o->instruction, 2, (void *)(o->regs.ip - 2));
  if (o->instruction_error || o->instruction[0] != 0x0f || o->instruction[1] != 0x05) {
    o->status = 6;
    goto publish;
  }
  o->status = 1;
#pragma clang loop unroll(disable)
  for (u32 i = 0; i < STACK_BYTES / 256; i++) {
    // No page faults are induced. Stop at the first unreadable 256-byte block.
    long err = read_user(o->stack + i * 256, 256, (void *)(o->regs.sp + i * 256));
    if (err) {
      o->stack_error = err;
      o->status = o->captured ? 2 : 7;
      break;
    }
    o->captured += 256;
  }
publish:
  if (update(&origins, &id, o, 1)) {
    u64 *n = lookup(&origin_drops, &zero);
    if (n) __sync_fetch_and_add(n, 1);
  }
}
#endif

struct state_event {
  u64 common;
  u64 socket;
  u32 oldstate, newstate;
  u16 sport, dport, family, protocol;
  u8 saddr[4], daddr[4], saddr6[16], daddr6[16];
};
struct flow {
  u64 start_ns, established_ns, end_ns;
  u32 pid, tid, uid, state;
  u16 sport, dport, family, pad;
  u8 src[16], dst[16], comm[16];
};
struct {
  UINT(type, 1);
  UINT(max_entries, 8192);
  TYPE(key, u64);
  TYPE(value, u64);
} sockets SEC(".maps");
// Keep I/O ownership until destruction: buffered reads can follow TIME_WAIT/CLOSE.
struct {
  UINT(type, 9);
  UINT(max_entries, 8192);
  TYPE(key, u64);
  TYPE(value, u64);
} io_sockets SEC(".maps");
struct {
  UINT(type, 1);
  UINT(max_entries, 8192);
  TYPE(key, u64);
  TYPE(value, struct flow);
} flows SEC(".maps");
struct {
  UINT(type, 2);
  UINT(max_entries, 1);
  TYPE(key, u32);
  TYPE(value, u64);
} drops SEC(".maps");

static void dropped(void) {
  u32 zero = 0;
  u64 *n = lookup(&drops, &zero);
  if (n) __sync_fetch_and_add(n, 1);
}

SEC("tracepoint/sock/inet_sock_set_state")
int trace_state(struct state_event *ctx) {
  if (ctx->protocol != 6 || (ctx->family != 2 && ctx->family != 10)) return 0;
  u64 socket = ctx->socket;
  if (ctx->newstate == 2) {  // TCP_SYN_SENT: synchronous active-open context, not ACK/softirq.
    u64 id = now_ns();
    u64 task = pid_tgid();
    struct flow f = {};
    f.start_ns = id;
    f.pid = task >> 32;
    f.tid = (u32)task;
    f.uid = (u32)uid_gid();
    f.state = 2;
    comm(f.comm, sizeof(f.comm));
    // Invalidate an old pointer association before publishing a new lifetime.
    delete (&sockets, &socket);
    delete (&io_sockets, &socket);
    if (update(&flows, &id, &f, 1)) {
      dropped();
      return 0;
    }
    if (update(&sockets, &socket, &id, 0)) {
      delete (&flows, &id);
      dropped();
      return 0;
    }
#ifdef STACK_X86_64
    if (update(&io_sockets, &socket, &id, 0)) dropped();
    capture_origin(id, task, id, 0, 0);
#endif
    return 0;
  }
  u64 *idp = lookup(&sockets, &socket);
  if (!idp) return 0;  // Ignore passive opens and connections predating attachment.
  u64 id = *idp;
  struct flow *original = lookup(&flows, &id);
  if (!original) return 0;
  struct flow f = *original;
  f.state = ctx->newstate;
  f.sport = ctx->sport;
  f.dport = ctx->dport;
  f.family = ctx->family;
  if (f.family == 2) {
    __builtin_memcpy(f.src, ctx->saddr, 4);
    __builtin_memcpy(f.dst, ctx->daddr, 4);
  } else {
    __builtin_memcpy(f.src, ctx->saddr6, 16);
    __builtin_memcpy(f.dst, ctx->daddr6, 16);
  }
  if (ctx->newstate == 1 && !f.established_ns) f.established_ns = now_ns();
  if (ctx->newstate == 7 || ctx->newstate == 6) {
    f.end_ns = now_ns();
    delete (&sockets, &socket);
  }
  if (update(&flows, &id, &f, 0)) dropped();
  return 0;
}
#ifdef STACK_X86_64
// These are application I/O entry events, NOT packet emission/arrival events.
// Correlate by the actual struct sock pointer and its tracked lifetime, never time proximity.
SEC("kprobe/tcp_sendmsg")
int trace_send(struct user_regs *ctx) {
  u64 socket = ctx->di;
  u64 *id = lookup(&io_sockets, &socket);
  if (id) capture_origin(now_ns(), pid_tgid(), *id, 1, ctx->dx);
  return 0;
}
SEC("kprobe/tcp_recvmsg")
int trace_receive(struct user_regs *ctx) {
  u64 socket = ctx->di;
  u64 *id = lookup(&io_sockets, &socket);
  if (id) capture_origin(now_ns(), pid_tgid(), *id, 2, ctx->dx);
  return 0;
}
SEC("kprobe/inet_sock_destruct")
int trace_destruct(struct user_regs *ctx) {
  u64 socket = ctx->di;
  delete (&io_sockets, &socket);
  return 0;
}
#endif
char LICENSE[] SEC("license") = "GPL";
