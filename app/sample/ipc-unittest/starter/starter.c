/*
 * Copyright (C) 2016 Imagination Technologies Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <trusty_std.h>
#include <app/ipc_unittest/common.h>

#define LOG_TAG "ipc-unittest-starter"

/*
 *  This starter application gets the unittests to start running by opening a
 *  connection to app/sample/ipc-unittest/main/main.c.
 *
 *  This is a partial replacement for the Android unittest framework in
 *  https://android.googlesource.com/platform/system/core in file
 *  trusty/libtrusty/tipc-test/tipc_test.c
 *
 */
int main(void)
{
	int rc;
	char path[MAX_PORT_PATH_LEN];

	TLOGI ("Starter task for IPC unittest\n");

	/* connect to control port to start IPC unittest */
        sprintf(path, "%s.%s", SRV_PATH_BASE, "ctrl");
	rc = connect(path, IPC_CONNECT_WAIT_FOR_PORT);
	if (rc < 0) {
		TLOGI("failed (%d) to connect to ctrl port\n", rc );
		return rc;
	}

	return rc;
}
