/*
 * dr1zzle Scheduler - Preemptive priority-based scheduler with time slicing
 * Supports cooperative and preemptive tasks, IRQ handlers, sleep/wake, and wait queues
 */

#include "sched.h"
#include "uart.h"
#include "timer.h"
#include "mmio.h"
#include "string.h"
#include "util.h"

/* ========================================================================
 * Internal Data Structures
 * ======================================================================== */

static task_t task_pool[MAX_TASKS];
static uint32_t task_count = 0;
static uint32_t next_pid = 1;

static task_t *current_task = NULL;
static task_t *idle_task = NULL;

/* Run queues per priority level */
static task_t *run_queues[256];
static uint8_t highest_active_prio = 0;

/* Wait queues */
typedef struct {
    task_t *head;
    task_t *tail;
} wait_queue_t;

static wait_queue_t wait_queues[16];  /* Generic wait objects */
static uint32_t wait_queue_count = 0;

/* Sleep queue (sorted by wake_time) */
static task_t *sleep_queue = NULL;

/* Statistics */
static sched_stats_t sched_stats = {0};

/* Scheduler lock (for SMP-safe operations, currently spinlock) */
static volatile uint32_t sched_lock = 0;

/* ========================================================================
 * Low-level primitives
 * ======================================================================== */

static inline void sched_lock_acquire(void) {
    while (__atomic_test_and_set(&sched_lock, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("yield" ::: "memory");
    }
}

static inline void sched_lock_release(void) {
    __atomic_clear(&sched_lock, __ATOMIC_RELEASE);
}

static inline void disable_irq_save(void) {
    __asm__ volatile("msr daifset, #2" ::: "memory");
}

static inline void enable_irq_restore(void) {
    __asm__ volatile("msr daifclr, #2" ::: "memory");
}

/* ========================================================================
 * Run Queue Management
 * ======================================================================== */

static void runq_enqueue(task_t *task) {
    uint8_t prio = task->priority;
    task_t *head = run_queues[prio];
    
    if (!head) {
        task->next = task->prev = task;
        run_queues[prio] = task;
    } else {
        task->next = head;
        task->prev = head->prev;
        head->prev->next = task;
        head->prev = task;
    }
    
    if (prio > highest_active_prio) {
        highest_active_prio = prio;
    }
}

static void runq_dequeue(task_t *task) {
    uint8_t prio = task->priority;
    task_t *head = run_queues[prio];
    
    if (!head) return;
    
    if (task->next == task) {
        /* Only task in queue */
        run_queues[prio] = NULL;
    } else {
        task->prev->next = task->next;
        task->next->prev = task->prev;
        if (head == task) {
            run_queues[prio] = task->next;
        }
    }
    task->next = task->prev = NULL;
    
    /* Update highest_active_prio if needed */
    if (!run_queues[prio] && prio == highest_active_prio) {
        for (int i = 255; i >= 0; i--) {
            if (run_queues[i]) {
                highest_active_prio = i;
                break;
            }
        }
    }
}

static task_t *runq_peek_highest(void) {
    for (int i = 255; i >= 0; i--) {
        if (run_queues[i]) {
            return run_queues[i];
        }
    }
    return idle_task;
}

/* ========================================================================
 * Sleep Queue Management (sorted by wake_time)
 * ======================================================================== */

static void sleepq_enqueue(task_t *task) {
    task_t **pp = &sleep_queue;
    while (*pp && (*pp)->wake_time <= task->wake_time) {
        pp = &(*pp)->next;
    }
    task->next = *pp;
    *pp = task;
}

static task_t *sleepq_dequeue(void) {
    task_t *task = sleep_queue;
    if (task) {
        sleep_queue = task->next;
        task->next = NULL;
    }
    return task;
}

static void sleepq_remove(task_t *task) {
    task_t **pp = &sleep_queue;
    while (*pp) {
        if (*pp == task) {
            *pp = task->next;
            task->next = NULL;
            return;
        }
        pp = &(*pp)->next;
    }
}

/* ========================================================================
 * Context Switch Assembly
 * ======================================================================== */

/* Save current task context, switch to next task */
__attribute__((naked)) void context_switch(task_t *old_task, task_t *new_task) {
    __asm__ volatile(
        /* Save old task registers */
        "stp x0, x1, [%0, #0]     \n"
        "stp x2, x3, [%0, #16]    \n"
        "stp x4, x5, [%0, #32]    \n"
        "stp x6, x7, [%0, #48]    \n"
        "stp x8, x9, [%0, #64]    \n"
        "stp x10, x11, [%0, #80]  \n"
        "stp x12, x13, [%0, #96]  \n"
        "stp x14, x15, [%0, #112] \n"
        "stp x16, x17, [%0, #128] \n"
        "stp x18, x19, [%0, #144] \n"
        "stp x20, x21, [%0, #160] \n"
        "stp x22, x23, [%0, #176] \n"
        "stp x24, x25, [%0, #192] \n"
        "stp x26, x27, [%0, #208] \n"
        "stp x28, x29, [%0, #224] \n"
        "str x30, [%0, #240]      \n"
        "mrs x1, sp               \n"
        "str x1, [%0, #248]       \n"
        "mrs x1, elr_el1          \n"
        "str x1, [%0, #256]       \n"
        "mrs x1, spsr_el1         \n"
        "str x1, [%0, #264]       \n"
        :
        : "r"(&old_task->regs[0])
        : "x1", "memory"
    );
    
    __asm__ volatile(
        /* Load new task registers */
        "ldp x0, x1, [%0, #0]     \n"
        "ldp x2, x3, [%0, #16]    \n"
        "ldp x4, x5, [%0, #32]    \n"
        "ldp x6, x7, [%0, #48]    \n"
        "ldp x8, x9, [%0, #64]    \n"
        "ldp x10, x11, [%0, #80]  \n"
        "ldp x12, x13, [%0, #96]  \n"
        "ldp x14, x15, [%0, #112] \n"
        "ldp x16, x17, [%0, #128] \n"
        "ldp x18, x19, [%0, #144] \n"
        "ldp x20, x21, [%0, #160] \n"
        "ldp x22, x23, [%0, #176] \n"
        "ldp x24, x25, [%0, #192] \n"
        "ldp x26, x27, [%0, #208] \n"
        "ldp x28, x29, [%0, #224] \n"
        "ldr x30, [%0, #240]      \n"
        "ldr x1, [%0, #248]       \n"
        "mov sp, x1               \n"
        "ldr x1, [%0, #256]       \n"
        "msr elr_el1, x1          \n"
        "ldr x1, [%0, #264]       \n"
        "msr spsr_el1, x1         \n"
        :
        : "r"(&new_task->regs[0])
        : "x1", "memory"
    );
    
    __asm__ volatile("ret" ::: "memory");
}

/* ========================================================================
 * Stack Management
 * ======================================================================== */

static uint64_t alloc_stack(size_t size) {
    /* Align to 16 bytes */
    size = (size + 15) & ~15;
    
    /* Use contiguous physical allocation */
    extern void *alloc_contig(uint32_t size);
    void *stack = alloc_contig((uint32_t)size);
    if (!stack) return 0;
    
    /* Return top of stack (high address) */
    return (uint64_t)stack + size;
}

static void free_stack(uint64_t stack_base, size_t size) {
    extern void free_contig(void *base, uint32_t size);
    free_contig((void*)(stack_base - size), (uint32_t)size);
}

/* ========================================================================
 * Task Creation / Destruction
 * ======================================================================== */

task_t *task_create(const char *name, void (*entry)(void *arg), void *arg,
                    uint8_t priority, size_t stack_size, uint16_t flags) {
    
    sched_lock_acquire();
    
    if (task_count >= MAX_TASKS) {
        sched_lock_release();
        return NULL;
    }
    
    if (stack_size < TASK_STACK_MIN) stack_size = TASK_STACK_MIN;
    if (stack_size > TASK_STACK_LARGE) stack_size = TASK_STACK_LARGE;
    
    task_t *task = &task_pool[task_count++];
    memset(task, 0, sizeof(task_t));
    
    task->pid = next_pid++;
    strncpy(task->name, name, sizeof(task->name) - 1);
    task->priority = priority;
    task->state = TASK_STATE_READY;
    task->flags = flags;
    task->entry = entry;
    task->arg = arg;
    
    /* Allocate stack */
    task->stack_size = stack_size;
    task->stack_base = alloc_stack(stack_size);
    if (!task->stack_base) {
        task_count--;
        sched_lock_release();
        return NULL;
    }
    task->stack_limit = task->stack_base - stack_size;
    
    /* Initialize register context for first run */
    task->sp = task->stack_base;
    task->elr = (uint64_t)entry;
    task->spsr = 0x4;  /* EL1h, interrupts enabled */
    
    /* Set up first argument in x0 */
    task->regs[0] = (uint64_t)arg;
    
    /* Add to run queue */
    runq_enqueue(task);
    
    sched_lock_release();
    return task;
}

void task_destroy(task_t *task) {
    sched_lock_acquire();
    
    /* Remove from wherever it might be */
    if (task->state == TASK_STATE_READY || task->state == TASK_STATE_RUNNING) {
        runq_dequeue(task);
    } else if (task->state == TASK_STATE_SLEEPING) {
        sleepq_remove(task);
    } else if (task->state == TASK_STATE_BLOCKED) {
        /* Would need to remove from wait queue */
    }
    
    free_stack(task->stack_base, task->stack_size);
    memset(task, 0, sizeof(task_t));
    task_count--;
    
    sched_lock_release();
}

/* ========================================================================
 * Scheduler Core
 * ======================================================================== */

void sched_init(void) {
    memset(task_pool, 0, sizeof(task_pool));
    memset(run_queues, 0, sizeof(run_queues));
    memset(wait_queues, 0, sizeof(wait_queues));
    task_count = 0;
    next_pid = 1;
    current_task = NULL;
    idle_task = NULL;
    sleep_queue = NULL;
    memset(&sched_stats, 0, sizeof(sched_stats));
    sched_lock = 0;
    
    /* Create idle task */
    idle_task = task_create("idle", (void (*)(void*))sched_idle_loop, NULL,
                           TASK_PRIO_IDLE, TASK_STACK_DEFAULT, TASK_FLAG_SYSTEM);
    if (idle_task) {
        idle_task->state = TASK_STATE_READY;
    }
    
    uart_puts("sched: initialized with ");
    uart_puts(utoa(MAX_TASKS));
    uart_puts(" max tasks\n");
}

static void sched_idle_loop(void *arg) {
    (void)arg;
    while (1) {
        sched_stats.idle_ticks++;
        __asm__ volatile("wfe" ::: "memory");
    }
}

/* Main scheduler tick - called from timer IRQ */
void sched_tick(void) {
    sched_stats.total_ticks++;
    
    if (!current_task) return;
    
    current_task->runtime_ticks++;
    current_task->total_ticks++;
    
    /* Check for sleeping tasks that need waking */
    uint64_t now = timer_now_ms();
    while (sleep_queue && sleep_queue->wake_time <= now) {
        task_t *task = sleepq_dequeue();
        task->state = TASK_STATE_READY;
        runq_enqueue(task);
    }
    
    /* Preemptive scheduling for non-critical tasks */
    if ((current_task->flags & TASK_FLAG_PREEMPT) &&
        !(current_task->flags & TASK_FLAG_CRITICAL) &&
        current_task != idle_task) {
        
        sched_stats.preemptions++;
        sched_yield();
    }
}

void sched_yield(void) {
    sched_lock_acquire();
    disable_irq_save();
    
    task_t *old_task = current_task;
    task_t *new_task = runq_peek_highest();
    
    if (new_task == old_task) {
        enable_irq_restore();
        sched_lock_release();
        return;
    }
    
    if (old_task && old_task->state == TASK_STATE_RUNNING) {
        old_task->state = TASK_STATE_READY;
        runq_enqueue(old_task);
    }
    
    runq_dequeue(new_task);
    new_task->state = TASK_STATE_RUNNING;
    current_task = new_task;
    
    sched_stats.context_switches++;
    
    enable_irq_restore();
    
    context_switch(old_task, new_task);
    
    sched_lock_release();
}

void task_sleep(uint64_t ms) {
    if (!current_task || current_task == idle_task) return;
    
    sched_lock_acquire();
    
    current_task->state = TASK_STATE_SLEEPING;
    current_task->wake_time = timer_now_ms() + ms;
    sleepq_enqueue(current_task);
    
    task_t *new_task = runq_peek_highest();
    if (new_task != current_task) {
        task_t *old_task = current_task;
        runq_dequeue(new_task);
        new_task->state = TASK_STATE_RUNNING;
        current_task = new_task;
        sched_stats.context_switches++;
        
        enable_irq_restore();
        context_switch(old_task, new_task);
    } else {
        enable_irq_restore();
    }
    
    sched_lock_release();
}

/* ========================================================================
 * Wait Queue Operations
 * ======================================================================== */

void task_block(task_t *task, void *wait_object) {
    sched_lock_acquire();
    
    task->state = TASK_STATE_BLOCKED;
    task->wait_object = wait_object;
    runq_dequeue(task);
    
    /* Add to wait queue (simplified - single wait queue for now) */
    if (wait_queue_count < 16) {
        wait_queues[wait_queue_count].head = task;
        wait_queues[wait_queue_count].tail = task;
        wait_queue_count++;
    }
    
    task_t *new_task = runq_peek_highest();
    if (new_task != task) {
        task_t *old_task = task;
        runq_dequeue(new_task);
        new_task->state = TASK_STATE_RUNNING;
        current_task = new_task;
        sched_stats.context_switches++;
        
        enable_irq_restore();
        context_switch(old_task, new_task);
    }
    
    sched_lock_release();
}

void task_unblock(task_t *task) {
    sched_lock_acquire();
    
    if (task->state == TASK_STATE_BLOCKED) {
        task->state = TASK_STATE_READY;
        task->wait_object = NULL;
        runq_enqueue(task);
    }
    
    sched_lock_release();
}

/* ========================================================================
 * Task Exit / Wait
 * ======================================================================== */

void task_exit(int status) {
    if (!current_task || current_task == idle_task) return;
    
    sched_lock_acquire();
    
    current_task->exit_status = status;
    current_task->state = TASK_STATE_EXITED;
    
    if (current_task->exit_cb) {
        current_task->exit_cb(current_task, status);
    }
    
    runq_dequeue(current_task);
    free_stack(current_task->stack_base, current_task->stack_size);
    
    task_t *new_task = runq_peek_highest();
    task_t *old_task = current_task;
    
    current_task = new_task;
    new_task->state = TASK_STATE_RUNNING;
    runq_dequeue(new_task);
    sched_stats.context_switches++;
    
    context_switch(old_task, new_task);
    
    sched_lock_release();
}

int task_wait(task_t *task, int *status) {
    if (!task) return -1;
    
    while (task->state != TASK_STATE_EXITED) {
        task_sleep(10);
    }
    
    if (status) *status = task->exit_status;
    return 0;
}

/* ========================================================================
 * Public API
 * ======================================================================== */

task_t *task_current(void) {
    return current_task;
}

task_t *task_find_by_pid(uint32_t pid) {
    for (int i = 0; i < task_count; i++) {
        if (task_pool[i].pid == pid) {
            return &task_pool[i];
        }
    }
    return NULL;
}

void task_set_priority(task_t *task, uint8_t priority) {
    sched_lock_acquire();
    
    if (task->state == TASK_STATE_READY || task->state == TASK_STATE_RUNNING) {
        runq_dequeue(task);
        task->priority = priority;
        runq_enqueue(task);
    } else {
        task->priority = priority;
    }
    
    sched_lock_release();
}

/* ========================================================================
 * Debug / Introspection
 * ======================================================================== */

void task_list(void) {
    uart_puts("\n=== Task List ===\n");
    uart_puts("PID  PRI STATE       NAME\n");
    
    for (int i = 0; i < task_count; i++) {
        task_t *t = &task_pool[i];
        const char *state_str[] = {"READY", "RUNNING", "BLOCKED", "SLEEPING", "EXITED", "IRQ"};
        uart_puts(utoa(t->pid));
        uart_puts("   ");
        uart_puts(utoa(t->priority));
        uart_puts("   ");
        uart_puts(state_str[t->state]);
        uart_puts("   ");
        uart_puts(t->name);
        uart_puts("\n");
    }
    
    uart_puts("Idle task: ");
    uart_puts(idle_task ? idle_task->name : "none");
    uart_puts("\n");
}

void task_dump(task_t *task) {
    if (!task) return;
    
    uart_puts("\n=== Task Dump ===\n");
    uart_puts("Name: "); uart_puts(task->name); uart_puts("\n");
    uart_puts("PID: "); uart_puts(utoa(task->pid)); uart_puts("\n");
    uart_puts("Priority: "); uart_puts(utoa(task->priority)); uart_puts("\n");
    uart_puts("State: "); uart_puts(utoa(task->state)); uart_puts("\n");
    uart_puts("Stack: 0x"); uart_puts(utoa_hex(task->stack_base)); uart_puts(" - 0x"); uart_puts(utoa_hex(task->stack_limit)); uart_puts("\n");
    uart_puts("Runtime: "); uart_puts(utoa(task->runtime_ticks)); uart_puts(" ticks\n");
    uart_puts("Total: "); uart_puts(utoa(task->total_ticks)); uart_puts(" ticks\n");
}

const sched_stats_t *sched_get_stats(void) {
    return &sched_stats;
}

/* ========================================================================
 * IRQ Task Support
 * ======================================================================== */

task_t *irq_task_create(const char *name, void (*handler)(void), uint32_t irq_num) {
    task_t *task = task_create(name, (void (*)(void*))handler, NULL,
                              TASK_PRIO_IRQ, TASK_STACK_DEFAULT, 
                              TASK_FLAG_IRQ_HANDLER | TASK_FLAG_SYSTEM);
    if (task) {
        task->state = TASK_STATE_IRQ_HANDLER;
        /* Don't add to run queue - IRQ tasks are scheduled directly */
    }
    return task;
}

void irq_task_register(task_t *task, uint32_t irq_num) {
    extern void register_irq_handler(uint16_t irq_v, struct task* irq_handler);
    register_irq_handler((uint16_t)irq_num, task);
}

/* ========================================================================
 * Scheduler Entry Point
 * ======================================================================== */

void sched_start(void) {
    if (!idle_task) return;
    
    /* Start with highest priority task */
    current_task = runq_peek_highest();
    if (!current_task) current_task = idle_task;
    
    current_task->state = TASK_STATE_RUNNING;
    runq_dequeue(current_task);
    
    /* Enable timer interrupts for preemption */
    timer_init();
    
    uart_puts("sched: starting scheduler\n");
    
    /* Switch to first task */
    __asm__ volatile(
        "ldr x1, [%0, #248]       \n"
        "mov sp, x1               \n"
        "ldr x1, [%0, #256]       \n"
        "msr elr_el1, x1          \n"
        "ldr x1, [%0, #264]       \n"
        "msr spsr_el1, x1         \n"
        "ldp x0, x1, [%0, #0]     \n"
        "ldp x2, x3, [%0, #16]    \n"
        "ldp x4, x5, [%0, #32]    \n"
        "ldp x6, x7, [%0, #48]    \n"
        "ldp x8, x9, [%0, #64]    \n"
        "ldp x10, x11, [%0, #80]  \n"
        "ldp x12, x13, [%0, #96]  \n"
        "ldp x14, x15, [%0, #112] \n"
        "ldp x16, x17, [%0, #128] \n"
        "ldp x18, x19, [%0, #144] \n"
        "ldp x20, x21, [%0, #160] \n"
        "ldp x22, x23, [%0, #176] \n"
        "ldp x24, x25, [%0, #192] \n"
        "ldp x26, x27, [%0, #208] \n"
        "ldp x28, x29, [%0, #224] \n"
        "ldr x30, [%0, #240]      \n"
        "ret                      \n"
        :
        : "r"(&current_task->regs[0])
        : "x1", "memory"
    );
}