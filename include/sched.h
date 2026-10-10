#ifndef SCHED_H
#define SCHED_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Task states */
typedef enum {
    TASK_STATE_READY = 0,
    TASK_STATE_RUNNING = 1,
    TASK_STATE_BLOCKED = 2,
    TASK_STATE_SLEEPING = 3,
    TASK_STATE_EXITED = 4,
    TASK_STATE_IRQ_HANDLER = 5,
} task_state_t;

/* Task flags */
#define TASK_FLAG_PREEMPT        (1 << 0)
#define TASK_FLAG_SYSTEM         (1 << 1)
#define TASK_FLAG_IRQ_HANDLER    (1 << 2)
#define TASK_FLAG_CRITICAL       (1 << 3)

/* Priority levels (higher = more important) */
#define TASK_PRIO_IDLE           0
#define TASK_PRIO_LOW            10
#define TASK_PRIO_NORMAL         50
#define TASK_PRIO_HIGH           100
#define TASK_PRIO_REALTIME       200
#define TASK_PRIO_IRQ            255

/* Stack sizes */
#define TASK_STACK_MIN           0x1000   /* 4KB minimum */
#define TASK_STACK_DEFAULT       0x4000   /* 16KB default */
#define TASK_STACK_LARGE         0x10000  /* 64KB large */

/* Maximum tasks */
#define MAX_TASKS                32

/* Task control block */
typedef struct task {
    /* Register context (saved on context switch) */
    uint64_t regs[31];       /* x0-x30 */
    uint64_t sp;             /* Stack pointer */
    uint64_t elr;            /* Exception link register */
    uint64_t spsr;           /* Saved program status register */
    
    /* Stack */
    uint64_t stack_base;     /* Base of allocated stack (high address) */
    uint64_t stack_size;     /* Size of stack */
    uint64_t stack_limit;    /* Stack guard limit (low address) */
    
    /* Task metadata */
    char name[32];
    uint32_t pid;
    uint8_t priority;
    uint8_t state;
    uint16_t flags;
    
    /* Scheduling */
    uint64_t runtime_ticks;
    uint64_t total_ticks;
    uint64_t wake_time;      /* For sleeping tasks */
    
    /* Linked list for run queues */
    struct task *next;
    struct task *prev;
    
    /* Wait queue */
    struct task *wait_next;
    void *wait_object;
    
    /* Memory space (for future MMU support) */
    void *vm_space;
    
    /* Entry point */
    void (*entry)(void *arg);
    void *arg;
    
    /* Exit callback */
    void (*exit_cb)(struct task *, int status);
    int exit_status;
} task_t;

/* Scheduler statistics */
typedef struct {
    uint64_t total_ticks;
    uint64_t idle_ticks;
    uint64_t context_switches;
    uint64_t preemptions;
    uint64_t irq_entries;
    uint64_t irq_exits;
} sched_stats_t;

/* Public API */
void sched_init(void);
task_t *task_create(const char *name, void (*entry)(void *arg), void *arg,
                    uint8_t priority, size_t stack_size, uint16_t flags);
void task_destroy(task_t *task);
void task_yield(void);
void task_sleep(uint64_t ms);
void task_exit(int status);
int task_wait(task_t *task, int *status);
task_t *task_current(void);
task_t *task_find_by_pid(uint32_t pid);
void task_set_priority(task_t *task, uint8_t priority);
void task_block(task_t *task, void *wait_object);
void task_unblock(task_t *task);

/* IRQ tasks */
task_t *irq_task_create(const char *name, void (*handler)(void), uint32_t irq_num);
void irq_task_register(task_t *task, uint32_t irq_num);

/* Scheduler control */
void sched_start(void);           /* Never returns - begins scheduling */
void sched_tick(void);            /* Called from timer IRQ */
const sched_stats_t *sched_get_stats(void);

/* Debug */
void task_list(void);
void task_dump(task_t *task);

#endif /* SCHED_H */