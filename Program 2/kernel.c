// kernel.c - tiny RISC-V "OS" skeleton for QEMU virt
// (updated: removed old/unused spawn functions; single generic spawn implementation)

#include <stdint.h>
#include <stddef.h>

/* forward declarations for string helpers */
int kstrcmp(const char *a, const char *b);
int kstrncmp(const char *a, const char *b, int n);
static int katoi(const char *s);
static int kstrlen(const char *s);

/* ------------ Basic types ------------ */

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t  u8;

/* ------------ UART driver (QEMU virt uses ns16550a at 0x10000000) ------------ */

#define UART0_BASE 0x10000000UL
#define UART_RHR   0   /* receive holding (read) */
#define UART_THR   0   /* transmit holding (write) */
#define UART_LSR   5   /* line status register */

static inline u8 mmio_read8(u64 addr) {
    return *(volatile u8 *)addr;
}

static inline void mmio_write8(u64 addr, u8 val) {
    *(volatile u8 *)addr = val;
}

static void uart_putc(char c) {
    /* wait for transmitter holding register empty (THRE, bit 5) */
    while ((mmio_read8(UART0_BASE + UART_LSR) & 0x20) == 0)
        ;
    mmio_write8(UART0_BASE + UART_THR, (u8)c);
}

static char uart_getc(void) {
    /* wait for data ready (bit 0) */
    while ((mmio_read8(UART0_BASE + UART_LSR) & 0x01) == 0)
        ;
    return (char)mmio_read8(UART0_BASE + UART_RHR);
}

static void kputs(const char *s) {
    while (*s) {
        if (*s == '\n') uart_putc('\r');
        uart_putc(*s++);
    }
}

static void kputhex(u64 x) {
    static const char *hex = "0123456789abcdef";
    kputs("0x");
    for (int i = 60; i >= 0; i -= 4) {
        uart_putc(hex[(x >> i) & 0xF]);
    }
}

/* simple line input */
static int kgets(char *buf, int maxlen) {
    int i = 0;
    while (i < maxlen - 1) {
        char c = uart_getc();
        if (c == '\r' || c == '\n') {
            kputs("\r\n");
            break;
        } else if (c == 0x7f || c == '\b') {
            if (i > 0) {
                --i;
                kputs("\b \b");
            }
        } else {
            buf[i++] = c;
            uart_putc(c);
        }
    }
    buf[i] = 0;
    return i;
}

/* ------------ Simple scheduler ------------ */

/* keep this reasonably large so users can spawn many procs */
#define NPROC       12
#define STACK_SIZE  4096

typedef struct context {
    u64 ra;
    u64 sp;
    u64 s0;
    u64 s1;
    u64 s2;
    u64 s3;
    u64 s4;
    u64 s5;
    u64 s6;
    u64 s7;
    u64 s8;
    u64 s9;
    u64 s10;
    u64 s11;
} context_t;

enum proc_state {
    P_UNUSED = 0,
    P_RUNNABLE,
    P_BLOCKED,
};

typedef struct mem_region {
    u64 start;
    u64 end;
} mem_region_t;

/* process name length - reused for file names too */
#define MAX_NAME_LEN    32

typedef struct proc {
    int          pid;
    enum proc_state state;
    context_t    ctx;
    u8           stack[STACK_SIZE];
    mem_region_t region;       /* "memory protection" metadata */
    char         name[MAX_NAME_LEN]; /* persistent copy of process name */
    char         msg[64];      /* optional message for generic spawned tasks */
} proc_t;

static proc_t procs[NPROC];
static int current = -1;
static context_t sched_ctx;
static int next_pid = 1;

extern void context_switch(context_t *old, context_t *new);

static void schedule(void);   /* forward */
static void yield(void);

/* pick next runnable process (round-robin) */
static int pick_next_proc(void) {
    for (int i = 1; i <= NPROC; ++i) {
        int idx = (current + i) % NPROC;
        if (procs[idx].state == P_RUNNABLE)
            return idx;
    }
    return -1;
}

static void yield(void) {
    int me = current;
    if (me < 0) return;
    current = -1;
    context_switch(&procs[me].ctx, &sched_ctx);
}

/* crude sleep: busy-wait for some iterations, then yield */
static void sleep_ticks(int ticks) {
    if (ticks < 0) return;
    for (volatile int i = 0; i < ticks; ++i) {
        /* spin */
    }
    yield();
}

static void schedule(void) {
    for (;;) {
        int n = pick_next_proc();
        if (n < 0) {
            kputs("[scheduler] no runnable tasks, idle...\n");
            for (volatile int i = 0; i < 1000000; ++i) ;
            continue;
        }
        current = n;
        context_switch(&sched_ctx, &procs[n].ctx);
        /* returned from a yield or block */
    }
}

static void proc_init(void) {
    for (int i = 0; i < NPROC; ++i) {
        procs[i].pid   = 0;
        procs[i].state = P_UNUSED;
        procs[i].region.start = 0x0;
        procs[i].region.end   = 0x0;
        procs[i].name[0] = 0;
        procs[i].msg[0] = 0;
    }
}

/* simple user-region allocator stub; just gives each process a unique dummy region */
static void assign_region(proc_t *p, int slot) {
    /* Just for demonstration: disjoint 64KB regions */
    u64 base = 0x40000000UL + (u64)slot * 0x10000UL;
    p->region.start = base;
    p->region.end   = base + 0x10000UL;
}

/* create a new kernel-thread-like process; copies name into proc struct */
static int proc_create(void (*entry)(void), const char *name) {
    for (int i = 0; i < NPROC; ++i) {
        if (procs[i].state == P_UNUSED) {
            proc_t *p = &procs[i];
            p->pid   = next_pid++;
            p->state = P_RUNNABLE;

            /* copy name safely (truncate if needed) */
            int j = 0;
            while (j < MAX_NAME_LEN-1 && name && name[j]) {
                p->name[j] = name[j];
                j++;
            }
            p->name[j] = 0;

            /* setup kernel stack and initial context */
            u64 sp = (u64)(p->stack + STACK_SIZE);
            for (int j2 = 0; j2 < (int)(sizeof(p->ctx)/sizeof(u64)); ++j2) {
                ((u64 *)&p->ctx)[j2] = 0;
            }
            p->ctx.sp = sp;
            p->ctx.ra = (u64)entry;

            p->msg[0] = 0;
            assign_region(p, i);
            return p->pid;
        }
    }
    return -1;
}

/* create a process that prints "<name> working" periodically */
static void proc_generic_worker_entry(void) {
    for (;;) {
        if (current >= 0 && current < NPROC) {
            proc_t *p = &procs[current];
            kputs("[");
            kputs(p->name);
            kputs("] working");
            if (p->msg[0]) {
                kputs(": ");
                kputs(p->msg);
            }
            kputs("\n");
        } else {
            kputs("[worker] invalid current index\n");
        }
        sleep_ticks(2000000);
        yield();
    }
}

/* helper to spawn a generic worker with optional message */
static int proc_create_generic(const char *name, const char *msg) {
    for (int i = 0; i < NPROC; ++i) {
        if (procs[i].state == P_UNUSED) {
            proc_t *p = &procs[i];
            p->pid   = next_pid++;
            p->state = P_RUNNABLE;

            /* copy name */
            int j = 0;
            while (j < MAX_NAME_LEN-1 && name && name[j]) {
                p->name[j] = name[j];
                j++;
            }
            p->name[j] = 0;

            /* copy message if any */
            int k = 0;
            while (k < (int)sizeof(p->msg)-1 && msg && msg[k]) {
                p->msg[k] = msg[k];
                k++;
            }
            p->msg[k] = 0;

            u64 sp = (u64)(p->stack + STACK_SIZE);
            for (int j2 = 0; j2 < (int)(sizeof(p->ctx)/sizeof(u64)); ++j2) {
                ((u64 *)&p->ctx)[j2] = 0;
            }
            p->ctx.sp = sp;
            p->ctx.ra = (u64)proc_generic_worker_entry;

            assign_region(p, i);
            return p->pid;
        }
    }
    return -1;
}

/* ------------ Semaphores (Dijkstra) ------------ */

typedef struct semaphore {
    int value;
    int queue[NPROC];
    int head, tail;
} sem_t;

static void sem_init(sem_t *s, int val) {
    s->value = val;
    s->head = s->tail = 0;
    for (int i = 0; i < NPROC; ++i)
        s->queue[i] = -1;
}

static void sem_wait(sem_t *s) {
    s->value--;
    if (s->value < 0) {
        int me = current;
        if (me < 0) return;
        procs[me].state = P_BLOCKED;
        s->queue[s->tail] = me;
        s->tail = (s->tail + 1) % NPROC;
        yield();
    }
}

static void sem_signal(sem_t *s) {
    s->value++;
    if (s->value <= 0) {
        int pid = s->queue[s->head];
        if (pid >= 0) {
            s->queue[s->head] = -1;
            s->head = (s->head + 1) % NPROC;
            procs[pid].state = P_RUNNABLE;
        }
    }
}

/* ------------ Tiny flat in-memory "file system" ------------ */

#define MAX_FILES       16
#define MAX_FILE_SIZE   512

typedef struct file {
    char name[MAX_NAME_LEN];
    int  used;
    int  size;
    char data[MAX_FILE_SIZE];
} file_t;

static file_t fs[MAX_FILES];

/* find index of file by exact name, or -1 */
static int fs_find_index(const char *name) {
    for (int i = 0; i < MAX_FILES; ++i) {
        if (fs[i].used) {
            const char *n = fs[i].name;
            int j = 0;
            while (n[j] && name[j] && n[j] == name[j]) j++;
            if (n[j] == 0 && name[j] == 0) return i;
        }
    }
    return -1;
}

/* create file with name, empty contents; returns 0 on success, -1 on fail */
static int fs_create(const char *name) {
    if (!name || name[0] == 0) return -1;
    if ((int)kstrlen(name) >= MAX_NAME_LEN) return -1;
    if (fs_find_index(name) >= 0) return -1; /* already exists */

    for (int i = 0; i < MAX_FILES; ++i) {
        if (!fs[i].used) {
            fs[i].used = 1;
            fs[i].size = 0;
            /* copy name */
            int j = 0;
            for (; j < MAX_NAME_LEN-1 && name[j]; ++j) fs[i].name[j] = name[j];
            fs[i].name[j] = 0;
            fs[i].data[0] = 0;
            return 0;
        }
    }
    return -1; /* no space */
}

/* remove file */
static int fs_remove(const char *name) {
    int idx = fs_find_index(name);
    if (idx < 0) return -1;
    fs[idx].used = 0;
    fs[idx].size = 0;
    fs[idx].name[0] = 0;
    fs[idx].data[0] = 0;
    return 0;
}

/* overwrite file (create if doesn't exist) */
static int fs_write(const char *name, const char *data) {
    if (!name || name[0] == 0) return -1;
    int idx = fs_find_index(name);
    if (idx < 0) {
        if (fs_create(name) < 0) return -1;
        idx = fs_find_index(name);
        if (idx < 0) return -1;
    }
    int k = 0;
    for (; k < MAX_FILE_SIZE-1 && data[k]; ++k) fs[idx].data[k] = data[k];
    fs[idx].data[k] = 0;
    fs[idx].size = k;
    return 0;
}

/* append to file (create if doesn't exist) */
static int fs_append(const char *name, const char *data) {
    if (!name || name[0] == 0) return -1;
    int idx = fs_find_index(name);
    if (idx < 0) {
        /* if it doesn't exist, create it and write the data */
        if (fs_create(name) < 0) return -1;
        idx = fs_find_index(name);
        if (idx < 0) return -1;
    }
    int cur = fs[idx].size;
    int k = 0;
    for (; cur < MAX_FILE_SIZE-1 && data[k]; ++k, ++cur) fs[idx].data[cur] = data[k];
    fs[idx].data[cur] = 0;
    fs[idx].size = cur;
    return 0;
}

/* rename a file (exact match required) */
static int fs_rename(const char *old, const char *newname) {
    if (!old || !newname) return -1;
    if ((int)kstrlen(newname) >= MAX_NAME_LEN) return -1;
    int idx_old = fs_find_index(old);
    if (idx_old < 0) return -1;
    if (fs_find_index(newname) >= 0) return -1; /* target exists */
    /* copy new name */
    int j = 0;
    for (; j < MAX_NAME_LEN-1 && newname[j]; ++j) fs[idx_old].name[j] = newname[j];
    fs[idx_old].name[j] = 0;
    return 0;
}

/* helper to get string length (not in original code) */
static int kstrlen(const char *s) {
    int i = 0;
    while (s[i]) i++;
    return i;
}

static void fs_init(void) {
    for (int i = 0; i < MAX_FILES; ++i) {
        fs[i].used = 0;
        fs[i].size = 0;
        fs[i].name[0] = 0;
        fs[i].data[0] = 0;
    }
    /* demo files */
    fs[0].used = 1;
    fs[0].size = 24;
    const char *n0 = "readme.txt";
    for (int i = 0; n0[i] && i < MAX_NAME_LEN-1; ++i) fs[0].name[i] = n0[i];
    fs[0].name[11] = 0;
    const char *d0 = "Hello from tiny RISC-V OS!\n";
    for (int i = 0; d0[i] && i < MAX_FILE_SIZE; ++i) fs[0].data[i] = d0[i];

    fs[1].used = 1;
    fs[1].size = 27;
    const char *n1 = "motd.txt";
    for (int i = 0; n1[i] && i < MAX_NAME_LEN-1; ++i) fs[1].name[i] = n1[i];
    const char *d1 = "Be kind to your page tables.\n";
    for (int i = 0; d1[i] && i < MAX_FILE_SIZE; ++i) fs[1].data[i] = d1[i];
}

static void fs_ls(void) {
    kputs("Files:\n");
    for (int i = 0; i < MAX_FILES; ++i) {
        if (fs[i].used) {
            kputs("  ");
            kputs(fs[i].name);
            kputs(" (");
            /* print decimal size for readability */
            char tmp[16];
            int len = fs[i].size;
            int pos = 0;
            if (len == 0) {
                kputs("0");
            } else {
                int t = len;
                char rev[16];
                int r = 0;
                while (t > 0 && r < 15) {
                    rev[r++] = '0' + (t % 10);
                    t /= 10;
                }
                while (r > 0) tmp[pos++] = rev[--r];
                tmp[pos] = 0;
                kputs(tmp);
            }
            kputs(" bytes)\n");
        }
    }
}

static void fs_cat(const char *name) {
    int idx = fs_find_index(name);
    if (idx < 0) {
        kputs("cat: file not found\n");
        return;
    }
    for (int k = 0; k < fs[idx].size; ++k)
        uart_putc(fs[idx].data[k]);
    if (fs[idx].size == 0 || fs[idx].data[fs[idx].size-1] != '\n')
        kputs("\n");
}

/* ------------ Simple "memory protection" check ------------ */

static int check_user_ptr(proc_t *p, u64 addr, u64 len) {
    if (addr < p->region.start) return 0;
    if (addr + len > p->region.end) return 0;
    return 1;
}

/* ------------ Demo tasks ------------ */

static sem_t demo_sem;

static void worker1(void) {
    for (;;) {
        sem_wait(&demo_sem);
        kputs("[worker1] doing work...\n");
        sleep_ticks(2000000);
        sem_signal(&demo_sem);
        yield();
    }
}

static void worker2(void) {
    for (;;) {
        sem_wait(&demo_sem);
        kputs("[worker2] doing other work...\n");
        sleep_ticks(2000000);
        sem_signal(&demo_sem);
        yield();
    }
}

/* tiny shell-like task */
static const char *extract_token(const char *src, char *dest, int dest_max) {
    while (*src == ' ' || *src == '\t') src++;
    int i = 0;
    while (*src && *src != ' ' && *src != '\t' && i < dest_max - 1) {
        dest[i++] = *src++;
    }
    dest[i] = 0;
    while (*src == ' ' || *src == '\t') src++;
    return src;
}

static void shell_task(void) {
    char buf[256];
    kputs("Welcome to tiny RISC-V OS.\n");
    kputs("Commands: help, ls, cat <name>, ps, kill <pid>, yield\n");
    kputs("          touch <name>, rm <name>, write <name> (adds file)\n");
    kputs("          append <name> <text>, rename <old> <new>\n");
    kputs("          spawn <name> [message]  (creates a worker with that name)\n");
    for (;;) {
        kputs("os> ");
        int n = kgets(buf, sizeof(buf));
        if (n <= 0) { yield(); continue; }

        int end = n-1;
        while (end >= 0 && (buf[end] == ' ' || buf[end] == '\t')) {
            buf[end] = 0;
            end--;
        }

        if (buf[0] == 0) {
            yield();
            continue;
        }
        if (!kstrcmp(buf, "help")) {
            kputs("help            - show this help\n");
            kputs("ls              - list files\n");
            kputs("cat <name>      - show file contents\n");
            kputs("ps              - list processes\n");
            kputs("kill <pid>      - terminate a process\n");
            kputs("yield           - yield CPU\n");
            kputs("touch <name>    - create empty file\n");
            kputs("write <name>    - alias for touch (add file)\n");
            kputs("rm <name>       - remove file\n");
            kputs("append <n> <t>  - append text to file (creates if missing)\n");
            kputs("rename <o> <n>  - rename file (exact match)\n");
            kputs("spawn <name> [message] - create worker with name; optional message\n");
            kputs("spawn print <msg> - special printer process\n");
        } else if (!kstrcmp(buf, "ls")) {
            fs_ls();
        } else if (!kstrcmp(buf, "ps")) {
            kputs("PID   STATE   NAME\n");
            for (int i = 0; i < NPROC; ++i) {
                if (procs[i].state != P_UNUSED) {
                    kputhex(procs[i].pid);
                    kputs("   ");
                    switch (procs[i].state) {
                        case P_RUNNABLE: kputs("RUNN "); break;
                        case P_BLOCKED:  kputs("BLKD "); break;
                        default:         kputs("UNUSED "); break;
                    }
                    kputs("  ");
                    kputs(procs[i].name);
                    if (procs[i].msg[0]) { kputs(" ("); kputs(procs[i].msg); kputs(")"); }
                    kputs("\n");
                }
            }
        } else if (!kstrncmp(buf, "kill ", 5)) {
            const char *arg = buf + 5;
            while (*arg == ' ' || *arg == '\t') arg++;
            if (*arg == 0) {
                kputs("Usage: kill <pid>\n");
            } else {
                int pid = katoi(arg);
                if (pid <= 0) {
                    kputs("kill: invalid pid\n");
                } else {
                    int found = 0;
                    for (int i = 0; i < NPROC; ++i) {
                        if (procs[i].state != P_UNUSED &&
                            procs[i].pid == pid) {

                            found = 1;
                            procs[i].state = P_UNUSED;
                            procs[i].pid   = 0;
                            procs[i].name[0] = 0;
                            procs[i].region.start = 0;
                            procs[i].region.end   = 0;
                            procs[i].msg[0] = 0;
                            break;
                        }
                    }
                    if (!found) {
                        kputs("kill: no such pid\n");
                    }
                }
            }
        } else if (!kstrcmp(buf, "yield")) {
            yield();
        } else if (!kstrncmp(buf, "cat ", 4)) {
            const char *name = buf + 4;
            while (*name == ' ') name++;
            if (*name == 0) {
                kputs("Usage: cat <name>\n");
            } else {
                fs_cat(name);
            }
        } else if (!kstrncmp(buf, "touch ", 6)) {
            const char *namep = buf + 6;
            while (*namep == ' ') namep++;
            char namebuf[MAX_NAME_LEN];
            extract_token(namep, namebuf, MAX_NAME_LEN);
            if (namebuf[0] == 0) {
                kputs("Usage: touch <name>\n");
            } else {
                if (fs_create(namebuf) == 0) kputs("ok\n");
                else kputs("touch: failed (exists or no space)\n");
            }
        } else if (!kstrncmp(buf, "write ", 6)) {
            /* write is alias for touch (create file) */
            const char *namep = buf + 6;
            while (*namep == ' ') namep++;
            char namebuf[MAX_NAME_LEN];
            extract_token(namep, namebuf, MAX_NAME_LEN);
            if (namebuf[0] == 0) {
                kputs("Usage: write <name>\n");
            } else {
                if (fs_create(namebuf) == 0) kputs("ok\n");
                else kputs("write: failed (exists or no space)\n");
            }
        } else if (!kstrncmp(buf, "rm ", 3)) {
            const char *namep = buf + 3;
            while (*namep == ' ') namep++;
            char namebuf[MAX_NAME_LEN];
            extract_token(namep, namebuf, MAX_NAME_LEN);
            if (namebuf[0] == 0) {
                kputs("Usage: rm <name>\n");
            } else {
                if (fs_remove(namebuf) == 0) kputs("ok\n");
                else kputs("rm: failed (not found)\n");
            }
        } else if (!kstrncmp(buf, "append ", 7)) {
            char namebuf[MAX_NAME_LEN];
            const char *p = buf + 7;
            p = extract_token(p, namebuf, MAX_NAME_LEN);
            if (namebuf[0] == 0) {
                kputs("Usage: append <name> <text>\n");
            } else {
                if (*p == 0) {
                    kputs("Usage: append <name> <text>\n");
                } else {
                    if (fs_append(namebuf, p) == 0) kputs("ok\n");
                    else kputs("append: failed\n");
                }
            }
        } else if (!kstrncmp(buf, "rename ", 7)) {
            char oldbuf[MAX_NAME_LEN];
            char newbuf[MAX_NAME_LEN];
            const char *p = buf + 7;
            p = extract_token(p, oldbuf, MAX_NAME_LEN);
            if (oldbuf[0] == 0) {
                kputs("Usage: rename <old> <new>\n");
            } else {
                p = extract_token(p, newbuf, MAX_NAME_LEN);
                if (newbuf[0] == 0) {
                    kputs("Usage: rename <old> <new>\n");
                } else {
                    if (fs_rename(oldbuf, newbuf) == 0) kputs("ok\n");
                    else kputs("rename: failed\n");
                }
            }
        } else if (!kstrncmp(buf, "spawn ", 6)) {
            const char *p = buf + 6;
            while (*p == ' ') p++;
            /* allow: spawn worker1 or spawn <name> [message] or spawn print <message> */
            char namebuf[MAX_NAME_LEN];
            p = extract_token(p, namebuf, MAX_NAME_LEN);
            if (namebuf[0] == 0) {
                kputs("Usage: spawn <name> [message]\n");
            } else {
                /* special-case the original worker1/worker2 entry routines */
                if (!kstrcmp(namebuf, "worker1")) {
                    int pid = proc_create(worker1, "worker1");
                    if (pid > 0) {
                        kputs("spawned worker1 pid=");
                        kputhex(pid);
                        kputs("\n");
                    } else kputs("spawn: failed (no slot)\n");
                } else if (!kstrcmp(namebuf, "worker2")) {
                    int pid = proc_create(worker2, "worker2");
                    if (pid > 0) {
                        kputs("spawned worker2 pid=");
                        kputhex(pid);
                        kputs("\n");
                    } else kputs("spawn: failed (no slot)\n");
                } else if (!kstrcmp(namebuf, "print")) {
                    /* spawn print <message> -> create generic worker named "printer" with message */
                    const char *msg = p;
                    while (*msg == ' ') msg++;
                    if (*msg == 0) {
                        kputs("Usage: spawn print <message>\n");
                    } else {
                        int pid = proc_create_generic("printer", msg);
                        if (pid > 0) {
                            kputs("spawned printer pid=");
                            kputhex(pid);
                            kputs("\n");
                        } else kputs("spawn: failed (no slot)\n");
                    }
                } else {
                    /* generic: spawn <name> [message] */
                    const char *msg = p;
                    while (*msg == ' ') msg++;
                    if (*msg == 0) msg = NULL;
                    int pid = proc_create_generic(namebuf, msg);
                    if (pid > 0) {
                        kputs("spawned ");
                        kputs(namebuf);
                        kputs(" pid=");
                        kputhex(pid);
                        kputs("\n");
                    } else kputs("spawn: failed (no slot)\n");
                }
            }
        } else {
            kputs("Unknown command. Try 'help'.\n");
        }

        yield();
    }
}

/* very tiny replacements for strcmp/strncmp to avoid libc */

static int katoi(const char *s) {
    int neg = 0;
    int val = 0;
    while (*s == ' ' || *s == '\t')
        s++;
    if (*s == '-') {
        neg = 1;
        s++;
    }
    while (*s >= '0' && *s <= '9') {
        val = val * 10 + (*s - '0');
        s++;
    }
    return neg ? -val : val;
}

int kstrcmp(const char *a, const char *b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

int kstrncmp(const char *a, const char *b, int n) {
    if (n <= 0) return 0;
    while (n > 1 && *a && *b && *a == *b) { a++; b++; n--; }
    if (n == 0) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}

/* ------------ kmain (kernel entry from start.S) ------------ */

void kmain(void) {
    kputs("\n--- tiny RISC-V OS starting ---\n");

    proc_init();
    fs_init();
    sem_init(&demo_sem, 1);

    /* create shell only at boot; spawn workers from shell */
    proc_create(shell_task, "shell");

    /* enter scheduler loop (never returns) */
    schedule();
}
