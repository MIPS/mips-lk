/*
 * Copyright (c) 2016 Imagination Technologies Ltd.
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

#include <lk/init.h>
#include <stdint.h>
#include <stdio.h>
#include <lib/trusty/uuid.h>
#include <lib/trusty/trusty_app.h>
#include <generated_syscalls.h>

uuid_t timer_app_uuid = {
	/* UUID : {c43565af-4235-4bf9-8a52-8d51e7a3e54b} */
	0xc43565af, 0x4235, 0x4bf9,
	  { 0x8a, 0x52, 0x8d, 0x51, 0xe7, 0xa3, 0xe5, 0x4b }
};

uuid_t skel_app_uuid = {
	/* UUID : {eca48f94-00aa-560e-8f8c-d94b50d484f3} */
	0xeca48f94, 0x00aa, 0x560e,
	  { 0x8f, 0x8c, 0xd9, 0x4b, 0x50, 0xd4, 0x84, 0xf3 }
};

uuid_t skel2_app_uuid = {
	/* UUID : {f7fc6e07-78d8-5efa-b4a9-ecf5e077fd63} */
	0xf7fc6e07, 0x78d8, 0x5efa,
	  { 0xb4, 0xa9, 0xec, 0xf5, 0xe0, 0x77, 0xfd, 0x63 }
};

uuid_t usertest_app_uuid = {
	/* App UUID:   {d26eb24f-858b-4049-b2c1-15668122c517} */
	0xd26eb24f, 0x858b, 0x4049,
	  { 0xb2, 0xc1, 0x15, 0x66, 0x81, 0x22, 0xc5, 0x17 }
};

struct app_info {
	const char *name;
	uuid_t *uuid;
};

struct app_info app_table[] = {
	{ "timer", &timer_app_uuid },
	{ "skel", &skel_app_uuid },
	{ "skel2", &skel2_app_uuid },
	{ "usertest", &usertest_app_uuid },
};

#define UUID_ELEMENTS_N (sizeof(app_table)/sizeof(*app_table))

// Optionally skip starting the parent app as the first instance and only run
// cloned child apps (assuming that the parent app was not auto-started, config
// TRUSTY_APP_CONFIG_KEY_AUTO_START). This is mostly interesting for testing.
#define PARENT_IS_FIRST_INSTANCE 1

// test implementation of sys_clone for exercising trusty_app_clone
long sys_clone(uuid_t* uuid)
{
	int res;
	trusty_app_t *ta;
	trusty_app_t *ta_clone;

#if PARENT_IS_FIRST_INSTANCE
	// if parent app is started, then consider it as the first instance
	res = trusty_app_start_instance(uuid, &ta);
	if (res == NO_ERROR)
		return res;
	if (res != ERR_ALREADY_STARTED)
		return res;
#endif

	// clone new instance and start it
	res = trusty_app_start_clone(uuid, &ta_clone);
	return res;
}

static int print_result(int ret, const char *funcname, int expect)
{
    if (ret == expect) {
        printf("%s: PASSED\n", funcname);
    } else {
        printf("%s: FAILED expected %d, got %d\n", funcname, expect, ret);
    }
    return ret;
}

#define RUN_TEST(name, expect) \
    print_result(name(), #name, expect)

#define RUN_TEST1(name, arg, expect) \
    print_result(name(arg), #name "(" #arg ")", expect)

#define RUN_TEST2(name, arg1, arg2, expect) \
    print_result(name(arg1, arg2), #name "(" #arg1 "," #arg2 ")", expect)

#define PRINT_APP_NAME_UUID(msg,name,u)					\
	dprintf(SPEW,							\
		"%s %s, uuid: 0x%x 0x%x 0x%x 0x%x%x 0x%x%x%x%x%x%x\n",	\
		msg, name,						\
		(u)->time_low, (u)->time_mid,				\
		(u)->time_hi_and_version,				\
		(u)->clock_seq_and_node[0],				\
		(u)->clock_seq_and_node[1],				\
		(u)->clock_seq_and_node[2],				\
		(u)->clock_seq_and_node[3],				\
		(u)->clock_seq_and_node[4],				\
		(u)->clock_seq_and_node[5],				\
		(u)->clock_seq_and_node[6],				\
		(u)->clock_seq_and_node[7]);

static int clone_test_clone_trusted_app(struct app_info* app, unsigned loop_index)
{
	PRINT_APP_NAME_UUID("Cloning", app->name, app->uuid);
	dprintf(SPEW, "loop_index %d\n", loop_index);
	return clone(app->uuid);
}

static int clone_test(unsigned clone_loop)
{
	int ret = 0;
	unsigned i, j;

	for (i = 0; i < clone_loop; i++) {
		for (j = 0; j < UUID_ELEMENTS_N; j++) {
			ret |= RUN_TEST2(clone_test_clone_trusted_app, &app_table[j], i, NO_ERROR);
		}
	}
	return ret;
}

#define CLONE_COPY_N (2)

static void clone_test_init(uint level)
{
	dprintf(SPEW, "Clone test. Cloning each app %d times\n", CLONE_COPY_N);
	RUN_TEST1(clone_test, CLONE_COPY_N, NO_ERROR);
	dprintf(SPEW, "Clone test. Done cloning each app %d times\n", CLONE_COPY_N);
}

// trusty_app's auto_start_apps is set to LK_INIT_LEVEL_APPS + 1, so set to
// LK_INIT_LEVEL_APPS + 2 to start afterwards.
LK_INIT_HOOK(clone_test, clone_test_init, LK_INIT_LEVEL_APPS + 2);
