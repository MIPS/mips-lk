/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 * Copyright (c) 2015 Travis Geiselbrecht
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <err.h>
#include <trace.h>
#include <debug.h>
#include <assert.h>
#include <stdint.h>
#include <bits.h>
#include <kernel/thread.h>
#include <kernel/debug.h>
#include <mips/m32c0.h>
#include <arch/mips.h>
#include <arch/mips/mmu.h>
#if WITH_LIB_UTHREAD
#include <arch/uthread_mmu.h>
#endif


#define LOCAL_TRACE 0

extern enum handler_return platform_irq(struct mips_iframe *iframe, uint num);
void mips_irq(struct mips_iframe *iframe, uint num);

struct fault_handler_table_entry {
    uint32_t epc;
    uint32_t fault_handler;
};

extern struct fault_handler_table_entry __fault_handler_table_start[];
extern struct fault_handler_table_entry __fault_handler_table_end[];

static int is_delay_slot(uint32_t cause)
{
    return !!(cause & CR_BD);
}

static int is_user_mode(uint32_t status)
{
    return !!(status & SR_KSU_USER);
}

static inline uint32_t exc_code(struct mips_iframe *iframe)
{
    return BITS_SHIFT(iframe->cause, 6, 2);
}

static const char* exc_str(uint32_t excode)
{
    const char *exc_str[] = {
        "EXC_INTR", "EXC_MOD", "EXC_TLBL", "EXC_TLBS",
        "EXC_ADEL", "EXC_ADES", "EXC_IBE", "EXC_DBE",
        "EXC_SYS", "EXC_BP", "EXC_RI", "EXC_CPU",
        "EXC_OVF", "EXC_TRAP", "EXC_MSAFPE", "EXC_FPE",
        "EXC_IS1", "EXC_IS2", "EXC_C2E", "EXC_TLBRI",
        "EXC_TLBXI", "EXC_MSAU", "EXC_MDMX", "EXC_WATCH",
        "EXC_MCHECK", "EXC_THREAD", "EXC_DSPU", "EXC_RES27",
        "EXC_RES28", "EXC_RES29", "EXC_RES30", "EXC_RES31",
    };
    const uint32_t array_size = sizeof(exc_str) / sizeof(exc_str[0]);

    assert(excode < array_size);
    return (excode < array_size) ? exc_str[excode] : "EXC_???";
}

static void dump_iframe_cause(struct mips_iframe *fr)
{
    uint32_t excode = exc_code(fr);
    uint32_t cause = fr->cause;

    dprintf(CRITICAL, "cause  0x%08x  ", cause);
    dprintf(CRITICAL, "%s(0x%02x) ", exc_str(excode), excode);
    if (excode == EXC_CPU) {
        uint32_t cause_ce = BITS_SHIFT(cause, 29, 28);
        dprintf(CRITICAL, "coprocessor %d ", cause_ce);
    }
    if (excode == EXC_ADEL) {
        if (fr->badvaddr & 0x3)
            dprintf(CRITICAL, "unaligned ");
        if (fr->epc == fr->badvaddr)
            dprintf(CRITICAL, "fetch ");
    }
    if ((excode == EXC_SYS) ||
        (excode == EXC_BP) ||
        (excode == EXC_RI) ||
        (excode == EXC_TRAP))
    {
        if (mips_read_c0_config3() & CFG3_BI)
            dprintf(CRITICAL, "instr %08x ", mips_read_c0_badinstr());
        else if (is_kseg0(fr->epc))
            dprintf(CRITICAL, "instr %08x ", *(uint32_t*)fr->epc);

        if (is_delay_slot(cause))
            dprintf(CRITICAL, "in BD slot ");
    }
    dprintf(CRITICAL, "\n");
}

/* dump for user panics with less information */
static void dump_iframe_user(struct mips_iframe *fr)
{
    struct thread *current_thread = get_current_thread();

    dprintf(CRITICAL, "current_thread name %s\n",
            current_thread ? current_thread->name : "");

    dprintf(CRITICAL, "epc    0x%08x\n", fr->epc);
    dprintf(CRITICAL, "ra     0x%08x\n", fr->ra);
    dprintf(CRITICAL, "badva  0x%08x\n", fr->badvaddr);
    dump_iframe_cause(fr);
}

static void dump_iframe(struct mips_iframe *fr, const char *msg, int dump_all)
{
    const char* default_die_msg = "die";

    dprintf(CRITICAL, "\n%s: %s\n", default_die_msg, msg ? msg : "");

    if (is_user_mode(fr->status) && !dump_all) {
        return dump_iframe_user(fr);
    }

    struct thread *current_thread = get_current_thread();

    dprintf(CRITICAL, "current_thread %p, name %s\n",
            current_thread, current_thread ? current_thread->name : "");

    dprintf(CRITICAL, "$0  0x%08x at  0x%08x v0  0x%08x v1  0x%08x\n", 0, fr->at, fr->v0, fr->v1);
    dprintf(CRITICAL, "a0  0x%08x a1  0x%08x a2  0x%08x a3  0x%08x\n", fr->a0, fr->a1, fr->a2, fr->a3);
    dprintf(CRITICAL, "t0  0x%08x t1  0x%08x t2  0x%08x t3  0x%08x\n", fr->t0, fr->t1, fr->t2, fr->t3);
    dprintf(CRITICAL, "t4  0x%08x t5  0x%08x t6  0x%08x t7  0x%08x\n", fr->t4, fr->t5, fr->t6, fr->t7);
    dprintf(CRITICAL, "t8  0x%08x t9  0x%08x gp  0x%08x sp  0x%08x\n", fr->t8, fr->t9, fr->gp, fr->sp);
    dprintf(CRITICAL, "hi  0x%08x lo  0x%08x\n", fr->hi, fr->lo);
    dprintf(CRITICAL, "epc    0x%08x\n", fr->epc);
    dprintf(CRITICAL, "ra     0x%08x\n", fr->ra);
    dprintf(CRITICAL, "badva  0x%08x\n", fr->badvaddr);
    dprintf(CRITICAL, "status 0x%08x  ", fr->status);

    switch (fr->status & SR_KSU_MASK) {
    case SR_KSU_USER:
        dprintf(CRITICAL, "USER ");
        break;
    case SR_KSU_SPVS:
        dprintf(CRITICAL, "SUPERVISOR ");
        break;
    case SR_KSU_KERN:
        dprintf(CRITICAL, "KERNEL ");
        break;
    default:
        dprintf(CRITICAL, "BAD MODE ");
        break;
    }
    if (fr->status & SR_ERL)
        dprintf(CRITICAL, "ERL ");
    if (fr->status & SR_EXL)
        dprintf(CRITICAL, "EXL ");
    if (fr->status & SR_IE)
        dprintf(CRITICAL, "IE ");

    dprintf(CRITICAL, "\n");

    dump_iframe_cause(fr);
}

/* die, including on exceptions taken in user mode */
static void exception_die_kernel(struct mips_iframe *iframe, const char *msg)
{
    const int dump_all = 1;
    dump_iframe(iframe, msg, dump_all);
    panic(msg);
    for (;;);
}

// returns 1 if the exception has been handled, otherwise does not return
static int exception_die(struct mips_iframe *iframe, const char *msg)
{
    dump_iframe(iframe, msg, 0);
#if WITH_LIB_UTHREAD
    if (is_user_mode(iframe->status)) {
        panic_fn_t panic_fn;
        panic_args_t panic_args;
        uthread_get_user_panic_fn(&panic_fn, &panic_args);
        if (panic_fn) {
            /* return to user panic function; clear return address register
             * from stack to prevent panic function from returning. */
            iframe->epc = (uint32_t)panic_fn;
            iframe->a0 = (uint32_t)panic_args;
            iframe->ra = 0;
            uthread_set_user_panic_fn((panic_fn_t)NULL, (panic_args_t)NULL);
            return 1;
        } else {
            uthread_exit(ERR_GENERIC);
            __UNREACHABLE;
        }
        return 0;
    }
#endif
    thread_exit(ERR_GENERIC);
    __UNREACHABLE;
    return 0;
}

static int fault_handler_table_hit(struct mips_iframe *iframe)
{
    struct fault_handler_table_entry *fault_handler;

    for (fault_handler = __fault_handler_table_start; fault_handler < __fault_handler_table_end; fault_handler++) {
        if (fault_handler->epc == iframe->epc) {
            iframe->epc = fault_handler->fault_handler;
            return 1;
        }
    }
    return 0;
}

// returns 1 if the exception has been handled, 0 otherwise
static int mips_tlb_exception_user(struct mips_iframe *iframe)
{
    int handled = 0;

    if (!is_user_mode(iframe->status))
        return handled;

#if WITH_LIB_UTHREAD
    status_t err;
    vaddr_t vaddr = iframe->badvaddr;
    paddr_t paddr;
    u_int mmu_flags = 0;

    err = mips_uthread_mmu_query(uthread_get_current(), vaddr, &paddr, &mmu_flags);
    if (err) {
        TRACEF("No page entry found\n");
        goto user_fail;
    }
    LTRACEF("tlb paddr %#lx mmu_flags %x\n", paddr, mmu_flags);

    uint32_t excode = exc_code(iframe);
    switch (excode) {
    case EXC_MOD:
        if ((mmu_flags & MMU_DIRTY) == 0) {
            TRACEF("Attempt to modify read-only page\n");
            goto user_fail;
        }
        break;
    case EXC_TLBL:
        if (mmu_flags & MMU_NO_READ) {
            TRACEF("Attempt to read no-read page\n");
            goto user_fail;
        }
        else {
            // map in the page
            // TODO ideally probe and replace existing TLB entry (using mips_tlbrwr2)
            // TODO hack: invalidate current entry and re-take _tlb_refill exception
            tlbhi_t entryhi = mips_read_c0_entryhi();
            assert((entryhi & ~0x1fffUL) == (vaddr & ~0x1fffUL) && "entryhi and badvaddr mismatch");
            mips_tlbinval(entryhi);
            handled = 1;
        }
        break;
    case EXC_TLBS:
    case EXC_TLBRI:
    case EXC_TLBXI:
        goto user_fail;
        break;
    default:
        assert(0 && "Not a tlb exception");
        goto user_fail;
        break;
    }
    return handled;

user_fail:
    handled = exception_die(iframe, "user tlb exception");
#endif
    return handled;
}

static int mips_tlb_exception(struct mips_iframe *iframe)
{
    // TODO move this check later if we want on demand user paging, otherwise
    // kernel copy_to_user will fail on demand accesses.
    if (fault_handler_table_hit(iframe))
        return 1;

    if (mips_tlb_exception_user(iframe))
        return 1;

    int handled = exception_die(iframe, "unhandled tlb exception");
    return handled;
}

static int mips_address_error(struct mips_iframe *iframe)
{
    if (fault_handler_table_hit(iframe))
            return 1;

    int handled = exception_die(iframe, "unhandled address error");
    return handled;
}

#if WITH_MIPS_IRQCOMPAT_MODE
static int mips_compat_irq(struct mips_iframe *iframe)
{
    uint32_t pending =
        BITS_SHIFT(iframe->cause & iframe->status, CAUSEB_IP7, CAUSEB_IP0);

    while (pending) {
        uint32_t irq_num = 31 - __builtin_clz(pending);
        mips_irq(iframe, irq_num);
        pending &= ~(1 << irq_num);
    }
    return 1;
}
#endif

int mips_gen_exception(struct mips_iframe *iframe)
{
    int handled = 0;
    uint32_t excode = exc_code(iframe);
    int delay_slot = is_delay_slot(iframe->cause);

    switch (excode) {
#if WITH_MIPS_IRQCOMPAT_MODE
    case EXC_INTR:
        handled = mips_compat_irq(iframe);
        break;
#endif
    case EXC_MOD:
    case EXC_TLBL:
    case EXC_TLBS:
    case EXC_TLBRI:
    case EXC_TLBXI:
        handled = mips_tlb_exception(iframe);
        break;
    case EXC_ADEL:
    case EXC_ADES:
        handled = mips_address_error(iframe);
        break;
    case EXC_SYS:
        if (delay_slot) {
            handled = exception_die(iframe, "not supported: syscall in delay slot");
            break;
        }

#ifdef WITH_LIB_SYSCALL
        {
            arch_enable_ints();

            extern void mips_syscall(struct mips_iframe *iframe);
            mips_syscall(iframe);

            arch_disable_ints();
        }
#else
        LTRACEF("SYSCALL, EPC 0x%x. Ignoring...\n", iframe->epc);
#endif
        iframe->epc += 4;
        handled = 1;
        break;
    case EXC_BP:
        TRACEF("BREAK, EPC 0x%x. Ignoring...\n", iframe->epc);

        if (delay_slot) {
            handled = exception_die(iframe, "not supported: breakpoint in delay slot");
            break;
        }

        iframe->epc += 4;
        handled = 1;
        break;
    default:
        break;
    }

    if (!handled)
        handled = exception_die(iframe, "fatal exception");

    return handled;
}

void mips_irq(struct mips_iframe *iframe, uint num)
{
    THREAD_STATS_INC(interrupts);
    KEVLOG_IRQ_ENTER(num);

    LTRACEF("IRQ %u, EPC 0x%x, old status 0x%x, status 0x%x\n",
            num, iframe->epc, iframe->status, mips_read_c0_status());

    enum handler_return ret = INT_NO_RESCHEDULE;

    // figure out which interrupt the timer is set to
    uint32_t ipti = BITS_SHIFT(mips_read_c0_intctl(), 31, 29);
    if (ipti >= 2 && ipti == num) {
        // builtin timer
        ret = mips_timer_irq();
#if PLATFORM_QEMU_MIPS
    } else if (num == 2) {
        ret = platform_irq(iframe, num);
#elif PLATFORM_MIPS_MALTA
    } else if (num == 2) {
        ret = platform_irq(iframe, num);
#endif
    } else {
#if PLATFORM_MIPS_VIRT
        ret = platform_irq(iframe, num);
#else
        exception_die_kernel(iframe, "unhandled irq");
#endif
    }

    KEVLOG_IRQ_EXIT(num);

    if (ret != INT_NO_RESCHEDULE)
        thread_preempt();
}
