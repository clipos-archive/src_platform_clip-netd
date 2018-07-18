// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2009-2018 ANSSI. All Rights Reserved.
/**
 * netd-client.c
 *
 * Net re-configuration client for CLIP.
 * Copyright (C) 2011 SGDSN/ANSSI
 * Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
 **/


#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <arpa/inet.h>

#define ERROR(fmt, args...) \
	fprintf(stderr, fmt"\n", ##args)

#define INFO(fmt, args...) \
	fprintf(stdout, fmt"\n", ##args)

#define PERROR(fmt, args...) \
	fprintf(stderr, fmt ": %s\n", ##args, strerror(errno))

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
		exe = "netd-client";

	printf("%s [-h] -s <path1>\n", exe);
}

int 
main(int argc, char *argv[])
{
	int c, s;
	char res;
	char *path = NULL;
	struct sockaddr_un addr;

	while ((c = getopt(argc, argv, "s:h")) != -1) {
		switch (c) {
			case 's':
				if (path) {
					ERROR("Multiple socket paths");
					return EXIT_FAILURE;
				}
				path = optarg;
				break;
			case 'h':
				print_help(argv[0]);
				return EXIT_SUCCESS;
			default:
				ERROR("Unsupported option: %c", c);
				return EXIT_FAILURE;
		}
	}

	if (!path) {
		ERROR("Missing socket path");
		return EXIT_FAILURE;
	}

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		PERROR("Failed to create socket");
		return EXIT_FAILURE;
	}

	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		PERROR("Failed to connect socket");
		return EXIT_FAILURE;
	}

	if (write(s, "R", 1) != 1) {
		PERROR("Failed to write command");
		return EXIT_FAILURE;
	}

	if (read(s, &res, 1) != 1) {
		PERROR("Failed to read ack from daemon");
		return EXIT_FAILURE;
	}
	close(s);
	
	INFO("%c", res);

	return (res == 'Y') ? EXIT_SUCCESS : EXIT_FAILURE;
}
