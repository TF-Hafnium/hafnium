/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hf/dlog.h"
#include "hf/socket.h"

#include "test/hftest.h"
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define MAX_BUF_SIZE 256

static int finit_module(int fd, const char *param_values, int flags)
{
	return (int)syscall(SYS_finit_module, fd, param_values, flags);
}

static int delete_module(const char *name, int flags)
{
	return (int)syscall(SYS_delete_module, name, flags);
}

static void insmod_hafnium(void)
{
	int module_file = open("/hafnium.ko", O_RDONLY);
	if (module_file < 0) {
		FAIL("Failed to load Hafnium kernel module from /hafnium.ko");
		return;
	}
	EXPECT_EQ(finit_module(module_file, "", 0), 0);
	close(module_file);
}

static void rmmod_hafnium(void)
{
	int ret = delete_module("hafnium", 0);

	EXPECT_EQ(ret, 0);
	if (ret != 0) {
		HFTEST_LOG("Error %d (%s) removing hafnium kernel module.",
			   errno, strerror(errno));
	}
}

/**
 * Loads and unloads the Hafnium kernel module.
 */
TEST(linux, load_hafnium)
{
	insmod_hafnium();
	rmmod_hafnium();

	/* Removing a second time should fail. */
	EXPECT_EQ(delete_module("hafnium", 0), -1);
	EXPECT_EQ(errno, ENOENT);
}

/**
 * Uses the kernel module to send a socket message from the primary VM to a
 * secondary VM and echoes it back to the primary.
 */
TEST(linux, socket_echo_hafnium)
{
	ffa_id_t vm_id = HF_VM_ID_OFFSET + 1;
	int port = 10;
	int socket_id;
	struct hf_sockaddr addr;
	const char send_buf[] = "The quick brown fox jumps over the lazy dogs.";
	size_t send_len = sizeof(send_buf);
	char resp_buf[MAX_BUF_SIZE];
	ssize_t recv_len;

	ASSERT_LT(send_len, MAX_BUF_SIZE);

	insmod_hafnium();

	/* Create Hafnium socket. */
	socket_id = socket(PF_HF, SOCK_DGRAM, 0);
	if (socket_id == -1) {
		FAIL("Socket creation failed: %s", strerror(errno));
		return;
	}
	HFTEST_LOG("Socket created successfully.");

	/* Connect to requested VM & port. */
	addr.family = PF_HF;
	addr.vm_id = vm_id;
	addr.port = port;
	if (connect(socket_id, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		FAIL("Socket connection failed: %s", strerror(errno));
		return;
	}
	HFTEST_LOG("Socket to secondary VM %d connected on port %d.", vm_id,
		   port);

	/*
	 * Send a message to the secondary VM.
	 * Enable the confirm flag to try again in case port is busy.
	 */
	if (send(socket_id, send_buf, send_len, MSG_CONFIRM) < 0) {
		FAIL("Socket send() failed: %s", strerror(errno));
		return;
	}
	HFTEST_LOG("Packet with length %d sent.", send_len);

	/* Receive a response, which should be an echo of the sent packet. */
	recv_len = recv(socket_id, resp_buf, sizeof(resp_buf) - 1, 0);

	if (recv_len == -1) {
		FAIL("Socket recv() failed: %s", strerror(errno));
		return;
	}
	HFTEST_LOG("Packet with length %d received.", recv_len);

	EXPECT_EQ(recv_len, send_len);
	EXPECT_EQ(memcmp(send_buf, resp_buf, send_len), 0);

	EXPECT_EQ(close(socket_id), 0);
	rmmod_hafnium();
}
