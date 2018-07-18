// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2009-2018 ANSSI. All Rights Reserved.
/**
 * netd.c
 *
 * Net re-configuration daemon for CLIP.
 * Copyright (C) SGDN/DCSSI 2009
 * Copyright (C) SGDSN/ANSSI 2012-2014
 * Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
 **/


#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <arpa/inet.h>

#include <clip.h>

#define FAILURE_FILE	"/var/run/nonetwork"

#define ERROR(fmt, args...) \
	syslog(LOG_DAEMON|LOG_ERR, fmt"\n", ##args)

#define INFO(fmt, args...) \
	syslog(LOG_DAEMON|LOG_INFO, fmt"\n", ##args)

#define PERROR(fmt, args...) \
	syslog(LOG_DAEMON|LOG_ERR, fmt ": %s\n", ##args, strerror(errno))

#define _U __attribute__((unused))

#define SOCK_MAX	4U
static clip_sock_t g_socks[SOCK_MAX];
static unsigned int g_sock_num = 0;

static
int check_net(void)
{
	struct stat buf;

	if (!stat(FAILURE_FILE, &buf)) {
		ERROR("Network configuration failed, %s is present", 
							FAILURE_FILE);
		return -1;
	}

	if (errno == ENOENT) {
		INFO("Network reconfiguration successful");
		return 0;
	}

	PERROR("Stat %s", FAILURE_FILE);
	return -1;
}

static 
int run_external(char *script, char *arg)
{
	char *const argv[] = { 
		script, 
		arg, 
		NULL 
	};
	char *envp[] = { 
		"PATH=/bin:/sbin:/usr/bin:/usr/sbin",
		"CLIP_RC_SYSLOG=yes", 
		NULL 
	};
	int fd, ret;

	fd = open("/dev/null", O_RDWR|O_NOFOLLOW);
	if (fd < 0) {
		PERROR("failed to open /dev/null");
		return -1;
	}
	if (dup2(fd, STDIN_FILENO) < 0) {
		PERROR("failed to set stdin for script");
		return -1;
	}
	if (dup2(fd, STDOUT_FILENO) < 0) {
		PERROR("failed to set stdout for script");
		return -1;
	}
	if (dup2(fd, STDERR_FILENO) < 0) {
		PERROR("failed to set stderr for script");
		return -1;
	}
	if (fd > STDERR_FILENO) /* fd could already be stderr */
		(void)close(fd);

	ret = -execve(argv[0], argv, envp);
	if (ret)
		PERROR("Failed to run %s", script);
	return ret;
}

static 
int net_stop(void)
{
	INFO("Stopping network");
	return run_external(STOP_SCRIPT, "stop");
}

static 
int net_start(void)
{
	INFO("Starting network");
	return run_external(START_SCRIPT, "start");
}

static 
int wireless_list(void)
{
	INFO("Listing wireless cells");
	return run_external(LIST_SCRIPT, NULL);
}

static int 
list_handler(int s_com)
{
	pid_t pid, wret;
	int ret = -1, status;


	pid = fork();
	switch (pid) {
		case -1:
			PERROR("fork");
			if (write(s_com, "E", 1) != 1 && errno != EPIPE)
				PERROR("write N");
			close(s_com);
			return -1;
		case 0:
			close(s_com);
			exit(wireless_list());
		default:
			wret = waitpid(pid, &status, 0);
			if (wret == -1 || !WIFEXITED(status) 
					|| WEXITSTATUS(status)) {
				/* Internal error */
				if (write(s_com, "E", 1) != 1 && errno != EPIPE)
					PERROR("write N");
			} else {
				ret = 0;
				/* OK */
				if (write(s_com, "Y", 1) != 1 && errno != EPIPE)
					PERROR("write Y");
			}
			close(s_com);
			return ret;
	}
}

static int 
restart_handler(int s_com)
{
	pid_t pid, wret;
	int ret = -1, status;


	pid = fork();
	switch (pid) {
		case -1:
			PERROR("fork");
			if (write(s_com, "E", 1) != 1 && errno != EPIPE)
				PERROR("write N");
			close(s_com);
			return -1;
		case 0:
			close(s_com);
			exit(net_stop());
		default:
			wret = waitpid(pid, &status, 0);
			if (wret == -1 || !WIFEXITED(status) 
					|| WEXITSTATUS(status)) {
				/* Internal error */
				if (write(s_com, "E", 1) != 1 && errno != EPIPE)
					PERROR("write N");
				close(s_com);
				return -1;
			}
	}
	pid = fork();
	switch (pid) {
		case -1:
			PERROR("fork");
			if (write(s_com, "E", 1) != 1 && errno != EPIPE)
				PERROR("write N");
			close(s_com);
			return -1;
		case 0:
			close(s_com);
			exit(net_start());
		default:
			wret = waitpid(pid, &status, 0);
			if (!WIFEXITED(status) || WEXITSTATUS(status)) {
				/* Internal error */
				if (write(s_com, "E", 1) != 1 && errno != EPIPE)
					PERROR("write N");
			} else if (!check_net()) {
				ret = 0;
				/* OK */
				if (write(s_com, "Y", 1) != 1 && errno != EPIPE)
					PERROR("write Y");
			} else {
				/* Script ran OK, network config failed */
				if (write(s_com, "N", 1) != 1 && errno != EPIPE)
					PERROR("write N");
			}
			close(s_com);
			return ret;
	}
}

static int
conn_handler(int s_com, struct clip_sock_t *sock)
{
	char c;
	INFO("Connection accepted on %s socket", sock->name);

	if (read(s_com, &c, 1) != 1) {
		ERROR("Failed to read command");
		if (write(s_com, "E", 1) != 1 && errno != EPIPE)
			PERROR("write N");
		(void)close(s_com);
		return -1;
	}
	INFO("Read command : %c", c);

	switch (c) {
		case 'R':
			return restart_handler(s_com);
			break;
		case 'L':
			return list_handler(s_com);
			break;
		default:
			ERROR("Unsupported command: %c", c);
			if (write(s_com, "E", 1) != 1 && errno != EPIPE)
				PERROR("write N");
			(void)close(s_com);
			return -1;
	}
}

static int 
set_sock(const char *optarg)
{
	char *ptr;
	clip_sock_t *sock;

	if (g_sock_num >= SOCK_MAX) {
		ERROR("Too many socket arguments, max %u", SOCK_MAX);
		return -1;
	}

	sock = &g_socks[g_sock_num];
	ptr = strchr(optarg, ':');
	if (!ptr || ptr == optarg || !*(ptr+1)) {
		ERROR("Unsupported socket spec : %s, must be <name>:<path>",
				optarg);
		return -1;
	}

	sock->sock = -1;
	sock->handler = conn_handler;

	sock->name = strndup(optarg, ptr - optarg);
	if (!sock->name) {
		ERROR("Out of memory ?");
		return -1;
	}

	sock->path = strdup(ptr + 1);
	if (!sock->path) {
		ERROR("Out of memory ?");
		free(sock->name);
		return -1;
	}
	INFO("Listening on %s (%s)", sock->path, sock->name);
	g_sock_num++;
	return 0;
}

static int 
start_socks(void) {
	unsigned int i;
	int sock;
	for (i = 0; i < g_sock_num; i++) {
		memset(&(g_socks[i].sau), 0, sizeof(g_socks[i].sau));
		sock = clip_sock_listen(g_socks[i].path, &(g_socks[i].sau), 0);
		if (sock < 0)
			goto err;
		g_socks[i].sock = sock;
	}

	return 0;

err:
	for (i = 0; i < g_sock_num; i++) {
		if (g_socks[i].sock != -1)
			(void)close(g_socks[i].sock);
	}
	return -1;
}

static void
print_help(const char *argv0)
{
	const char *exe;
	if (argv0) {
		exe = strrchr(argv0, '/');
		if (exe) 
			exe++;
		else
			exe = argv0;
	} else 
		exe = "netd";

	printf("%s [-h] -s <name1>:<path1> [ -s <name2>:<path2> .. "
			"-s <name%u>:<path%u>\n", exe, SOCK_MAX, SOCK_MAX);
}

int 
main(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "s:h")) != -1) {
		switch (c) {
			case 's':
				if (set_sock(optarg))
					return EXIT_FAILURE;
				break;
			case 'h':
				print_help(argv[0]);
				return EXIT_SUCCESS;
			default:
				ERROR("Unsupported option: %c", c);
				return EXIT_FAILURE;
		}
	}

	if (!g_sock_num) {
		ERROR("At least one socket must be specified with -s");
		return EXIT_FAILURE;
	}

	closelog(); 	/* Needed to avoid confusing syslog with
			   the fd close loop from clip_daemonize...
			 */

	if (clip_daemonize()) {
		PERROR("clip_daemonize");
		return 1;
	}

	openlog("NETD", LOG_PID, LOG_DAEMON);

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		PERROR("signal");
		return EXIT_FAILURE;
	}

	if (start_socks()) {
		ERROR("Failed to start all sockets");
		return EXIT_FAILURE;
	}

	printf("num socks: %d\n", g_sock_num);
	for (;;) {
		if (clip_accept_one(g_socks, g_sock_num, 0))
			ERROR("Connection failed");
	}
		
	return EXIT_FAILURE;
}
