/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
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
#include <assert.h>
#include <stdio.h>
#include <app/tests.h>
#include <kernel/thread.h>
#include <kernel/mutex.h>

static int suspended_thread_fn(void *arg)
{
    printf("suspended_thread kill test FAILED if this msg is printed\n");
    return 0;
}

int suspended_tests(void)
{
    thread_t *thread;

    // kill a suspended thread
    thread = thread_create("suspended_thread", &suspended_thread_fn, NULL,
            DEFAULT_PRIORITY, DEFAULT_STACK_SIZE);
    assert(thread->state == THREAD_SUSPENDED);
    thread_kill(thread, 0);
    printf("suspended_thread killed. Test PASSED.\n");
    return 0;
}

static int ready_thread_fn(void *arg)
{
    printf("\nready_thread started...\n");
    for(;;)
        thread_yield();
    return 0;
}

int ready_tests(void)
{
    thread_t *thread;

    // kill a ready thread
    thread = thread_create("ready_thread", &ready_thread_fn, NULL,
            DEFAULT_PRIORITY, DEFAULT_STACK_SIZE);
    thread_resume(thread);
    thread_yield();
    assert(thread->state == THREAD_READY);
    thread_kill(thread, 0);
    printf("ready_thread killed. Test PASSED.\n");

    return 0;
}

static int blocked_thread_fn(void *arg)
{
    mutex_t *m = (mutex_t *)arg;

    printf("\nblocked_thread started...\n");
    mutex_acquire(m);
    printf("blocked_thread kill test FAILED if this msg is printed\n");
    return 0;
}

static int timeout_blocked_thread_fn(void *arg)
{
    mutex_t *m = (mutex_t *)arg;

    printf("\ntimeout_blocked_thread started...\n");
    mutex_acquire_timeout(m, 1000);
    printf("timeout_blocked_thread kill test FAILED if this msg is printed\n");
    return 0;
}

int blocked_tests(void)
{
    thread_t *thread;
    mutex_t m;

    // kill a blocked thread
    mutex_init(&m);
    mutex_acquire(&m);
    thread = thread_create("blocked_thread", &blocked_thread_fn, &m,
            DEFAULT_PRIORITY, DEFAULT_STACK_SIZE);
    thread_resume(thread);
    thread_yield();
    assert(thread->state == THREAD_BLOCKED);
    thread_kill(thread, 0);
    mutex_release(&m);
    // Note: the killed thread was blocked on the mutex; the mutex count value
    // is invalid and the mutex unusable, destroy and re-initialize it.
    mutex_destroy(&m);
    printf("blocked_thread killed. Test PASSED.\n");

    // kill a timeout-blocked thread
    mutex_init(&m);
    mutex_acquire(&m);
    thread = thread_create("timeout_blocked_thread", &timeout_blocked_thread_fn,
            &m, DEFAULT_PRIORITY, DEFAULT_STACK_SIZE);
    thread_resume(thread);
    thread_yield();
    assert(thread->state == THREAD_BLOCKED);
    thread_kill(thread, 0);
    mutex_release(&m);
    mutex_destroy(&m);
    printf("timeout_blocked_thread killed. Test PASSED.\n");

    return 0;
}

static int sleep_thread_fn(void *arg)
{
    int delay = (int)arg;

    printf("\nsleep_thread started... sleeping %d\n", delay);
    thread_sleep(delay);
    printf("sleeping thread kill test FAILED if this msg is printed\n");

    return 0;
}

int sleep_tests(void)
{
    thread_t *thread;

    // kill a sleeping thread
    thread = thread_create("sleep_thread", &sleep_thread_fn, (void*)500,
            DEFAULT_PRIORITY, DEFAULT_STACK_SIZE);
    thread_resume(thread);
    thread_yield();
    assert(thread->state == THREAD_SLEEPING);
    thread_kill(thread, 0);
    printf("sleeping_thread killed. Test PASSED.\n");

    return 0;
}

static int dead_thread_fn(void *arg)
{
    printf("\ndead_thread started... exiting\n");
    return 0;
}

int dead_tests(void)
{
    thread_t *thread;

    // kill a dead thread
    thread = thread_create("dead_thread", &dead_thread_fn, NULL, DEFAULT_PRIORITY,
            DEFAULT_STACK_SIZE);
    thread_resume(thread);
    thread_yield();
    assert(thread->state == THREAD_DEATH);
    thread_kill(thread, 0);
    printf("dead_thread killed. Test PASSED.\n");

    return 0;
}

static int test_thread_fn(void *arg)
{
    printf("test_thread started...\n");
    for(;;)
        thread_yield();
    return 0;
}

static int join_thread_fn(void *arg)
{
    thread_t *t = (thread_t*)arg;

    printf("join_thread started...\n");
    int ret = thread_join(t, NULL, 1000);
    return ret;
}

int join_tests(void)
{
    thread_t *test_thread;
    thread_t *join_thread;
    int ret;

    printf("\nkill a thread that is currently being joined\n");
    test_thread = thread_create("test_thread", &test_thread_fn, NULL, DEFAULT_PRIORITY,
            DEFAULT_STACK_SIZE);
    thread_resume(test_thread);

    join_thread = thread_create("join_thread", &join_thread_fn, test_thread, DEFAULT_PRIORITY,
            DEFAULT_STACK_SIZE);
    thread_resume(join_thread);

    thread_yield();
    // kill test thread and check that thread_join is notified
    printf("killing test_thread...\n");
    thread_kill(test_thread, 0);
    thread_join(join_thread, &ret, 1500);
    if (ret == ERR_THREAD_DETACHED)
        printf("join_thread was notified of killed thread. Test PASSED.\n");
    else if (ret == ERR_TIMED_OUT)
        printf("join_thread timed out. Test FAILED.\n");
    else
        printf("join_thread returned %d. Test FAILED.\n", ret);

    return 0;
}

int thread_kill_tests(void)
{
    suspended_tests();
    ready_tests();
    blocked_tests();
    sleep_tests();
    dead_tests();
    join_tests();
    return 0;
}
