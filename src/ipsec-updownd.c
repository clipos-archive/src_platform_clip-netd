// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2009-2018 ANSSI. All Rights Reserved.
/**
 * ipsec-updownd.c
 *
 * IPsec child-SA updown daemon for CLIP.
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
#include <signal.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>

#include <clip.h>

#define NAME "ipsec-updownd"

#define SCRIPT "/sbin/ipsec-updown"

#define ERROR(fmt, args...) \
	syslog(LOG_DAEMON|LOG_ERR, fmt"\n", ##args)

#define INFO(fmt, args...) \
	syslog(LOG_DAEMON|LOG_INFO, fmt"\n", ##args)

#define PERROR(fmt, args...) \
	syslog(LOG_DAEMON|LOG_ERR, fmt": %s\n", ##args, strerror(errno))

#define _U __attribute__((unused))

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

	printf("%s [-h] -c <filedesc>\n", exe);
}

#define MAGIC_STRING	"CLIP-UPD-1.0"

struct ipsec_updown_msg {
	char magic[16];		/* Magic / version string */
	char action[8];		/* "up" or "down" */
	char config[32];	/* Config name */
	char type[8];		/* "host" or "client" */
	char iface[32];		/* Interface name or "unknown" */
	char my_id[128];	/* My ID */
	char peer_id[128];	/* Remote ID */
	char vip[16];		/* Virtual IP, e.g. "192.168.123.231" */
} __attribute__((packed));

typedef struct ipsec_updown_msg msg_t;

enum {
	EnvAction = 0,
	EnvConfig,
	EnvType,
	EnvIface,
	EnvMyId,
	EnvPeerId,
	EnvVirtualIP,
	EnvNull,
	EnvLast
};

static int
daemonize(int sock) 
{
	pid_t pid;
	int ret, fd, nofiles;

	pid = fork();
	switch (pid) {
		case -1:
			PERROR("First fork failed");
			return -1;
		case 0:
			break;
		default:
			_exit(0);
	}

	nofiles = getdtablesize();
	for (fd = 0; fd < nofiles; fd++) {
		if (fd == sock) 
			continue;
		ret = close(fd);
		if (ret == -1 && errno != EBADF && errno != ENODEV) {
			PERROR("Failed to close fd %d", fd);
			return -1;
		}
	}

	fd = open("/dev/null", O_RDWR|O_NONBLOCK);
	if (fd == -1) {
		PERROR("Open /dev/null failed");
		return -1;
	}
	if (dup2(fd, STDIN_FILENO) < 0 
			|| dup2(fd, STDOUT_FILENO) < 0 
			|| dup2(fd, STDERR_FILENO) < 0) {
		PERROR("Dup2 failed");
		return -1;
	}
	(void)close(fd);
	if (setsid() < 0) {
		PERROR("setsid() failed");
		return -1;
	}

	/* Refork, let group leader exit */
	pid = fork();
	switch (pid) {
		case -1:
			PERROR("Second fork failed");
			return -1;
		case 0:
			return 0;
		default:
			_exit(0);
	}
}

static int
write_pid(int sock) 
{
	char buf[8];

	memset(buf, 0, sizeof(buf));
	(void)snprintf(buf, sizeof(buf), "%d", getpid());

	for (;;) {
		ssize_t ret = write(sock, buf, sizeof(buf));
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			PERROR("Failed to write pid on socket");
			return -1;
		}
		if (ret != sizeof(buf)) {
			ERROR("Truncated pid write - wrote %zd bytes", ret);
			return -1;
		}
		return 0;
	}
}

static msg_t *
get_one_msg(int sock)
{
	msg_t *msg;
	char *ptr;
	size_t len;

	msg = malloc(sizeof(*msg));
	if (!msg) {
		ERROR("Failed to allocate message");
		return NULL;
	}
	memset(msg, 0, sizeof(*msg));

	ptr = (char *)msg;
	len = sizeof(*msg);

	while (len > 0) {
		ssize_t ret = read(sock, ptr, len);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			PERROR("Failed to read message");
			goto err;
		}

		if (ret == 0) { /* EOF */
			INFO("Read EOF, exiting");
			exit(EXIT_SUCCESS);
		}

		ptr += ret;
		len -= ret;
	}

	if (strcmp(msg->magic, MAGIC_STRING)) {
		ERROR("Invalid magic string in message: %s != %s", 
						msg->magic, MAGIC_STRING);
		goto err;
	}

	return msg;

err:
	free(msg);
	return NULL;
}

static int 
run_script(msg_t *msg)
{
	int fd;
	char *envp[EnvLast];
	char *argv[] = { strdup(SCRIPT), NULL };
	if (!argv[0]) {
		ERROR("Out of memory duplicating script command");
		return -1;
	}

	memset(envp, 0, sizeof(envp));

#define write_env(idx, var, field) do {			\
	if (asprintf(&envp[idx],  			\
			var"=%s", msg->field) < 0) { 	\
		ERROR("Out of memory printing "var); 	\
		return -1;				\
	}						\
} while (0)
	write_env(EnvAction, "UPDOWN_ACTION", action);
	write_env(EnvConfig, "UPDOWN_CONFIG", config);
	write_env(EnvType, "UPDOWN_TYPE", type);
	write_env(EnvIface, "UPDOWN_IFACE", iface);
	write_env(EnvMyId, "UPDOWN_MY_ID", my_id);
	write_env(EnvPeerId, "UPDOWN_PEER_ID", peer_id);
	write_env(EnvVirtualIP, "UPDOWN_VIRTUAL_IP", vip);

	INFO("Running script %s %s, config %s, virtual IP %s", 
			SCRIPT, msg->action, msg->config, msg->vip);

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

	if (execve(argv[0], argv, envp) != 0) {
		PERROR("Failed to run script");
		return -1;
	}

	return -1; /* Not reached...*/
}

static int
handle_one_event(int sock)
{
	pid_t pid, wret;
	char c = 'N';
	int ret = -1, status;
	msg_t *msg = get_one_msg(sock);
	if (!msg)
		goto out;

	pid = fork();
	switch (pid) {
		case -1:
			PERROR("Fork failed");
			goto out_free;
		case 0:
			exit(run_script(msg));
		default:
			for (;;) {
				wret = waitpid(pid, &status, 0);
				if (wret < 0) {
					if (errno == EINTR)
						continue;
					PERROR("waitpid() failed");
					goto out_free;
				}
				break;
			}
			if (WIFEXITED(status) && !WEXITSTATUS(status)) {
				ret = 0;
				c = 'Y';
			} else 
				ERROR("External script failed");
			break;
	}
	/* Fall through */		

out_free:
	free(msg);
out:
	for (;;) {
		if (write(sock, &c, 1) < 0) {
			if (errno == EINTR)
				continue;
			PERROR("Failed to write ack");
			ret = -1;
		}
		break;
	}

	return ret;
}

int 
main(int argc, char *argv[])
{
	int c, sock = -1;

	while ((c = getopt(argc, argv, "c:h")) != -1) {
		switch (c) {
			case 'c':
				sock = atoi(optarg);
				if (!sock) {
					ERROR("Invalid socket : %s", optarg);
					return EXIT_FAILURE;
				}
				break;
			case 'h':
				print_help(argv[0]);
				return EXIT_SUCCESS;
			default:
				ERROR("Unsupported option: %c", c);
				return EXIT_FAILURE;
		}
	}

	if (sock == -1) {
		ERROR("Missing socket argument");
		return EXIT_FAILURE;
	}

	closelog(); 	/* Needed to avoid confusing syslog with
			   the fd close loop from clip_daemonize...
			 */

	if (daemonize(sock)) {
		ERROR("Failed to daemonize");
		return EXIT_FAILURE;
	}

	openlog("ipsec-updownd", LOG_PID, LOG_DAEMON);

	if (write_pid(sock)) {
		ERROR("Failed to send my pid to parent daemon");
		return EXIT_FAILURE;
	}

	for (;;) {
		if (handle_one_event(sock))
			ERROR("Unhandled updown event");
	}
		
	return EXIT_FAILURE;
}
