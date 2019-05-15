// SPDX-License-Identifier: GPL-2.0

#include <asm/unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include "mystruct.h"

#ifndef __NR_cpenc
#error cpenc system call not defined
#endif

//#define EXTRA_CREDIT
int main(int argc, char *argv[])
{
	int rc = 0, err_num;
	int opt;
	struct user_args *args;

	args = (struct user_args *)malloc(sizeof(struct user_args));
	if (!args) {
		printf("Could not allocate memory to arguments in userland\n");
		rc = -1;
		goto out;
	}

#ifdef EXTRA_CREDIT
	args->iscipher = 0;

	while ((opt = getopt(argc, argv, "edchp:C:")) != -1) {
#else
	while ((opt = getopt(argc, argv, "edchp:")) != -1) {
#endif
		switch (opt) {
			case'e':
				args->flag |= 1;
				break;
			case'd':
				args->flag |= 2;
				break;
			case'c':
				args->flag |= 4;
				break;
			case'h':
				printf("\nHELP is in ./xcpenc executable\n");
				goto out_free_args;
			case'p':
				args->keybuf = malloc(strlen(optarg));
				args->keylen = strlen(optarg);
				memcpy(args->keybuf, (void *)optarg,
				       strlen(optarg));
				break;
#ifdef EXTRA_CREDIT
			case'C':
				args->cipher = (char *)malloc(strlen(optarg) +
							     1);
				strcpy(args->cipher, optarg);
				args->iscipher = 1;
				break;
#endif
			case':':
				printf("Missing arguments for %c. ", optopt);
				printf("Try 'xcpenc -h' for more ");
				printf("information.\n");
				rc = -1;
				goto out_free_args;
			case'?':
				printf("Unknown option: %c. ", optopt);
				printf("Try 'xcpenc -h' for more ");
				printf("information.\n");
				rc = -1;
				goto out_free_args;
		}
	}

	/* Get all of the non-option arguments */
	if (optind < argc) {
		args->infile = (char *)malloc(strlen(argv[optind]) + 1);
		strcpy(args->infile, argv[optind++]);
	}
	if (optind < argc) {
		args->outfile = (char *)malloc(strlen(argv[optind]) + 1);
		strcpy(args->outfile, argv[optind++]);
	}

	if (optind < argc) {
		printf("Extra arguments are passed\n");
		printf("Try 'xcpenc -h' for more information.\n");
		rc = -1;
		goto out_free_args;
	}

	rc = syscall(__NR_cpenc, (void *)args);
	err_num = errno;
	if (rc == 0) {
		printf("Syscall returned %d\n", rc);
	} else {
		rc = err_num;
		printf("Syscall returned %d (", rc);
		printf("errno=%d, error=%s)\n", err_num, strerror(err_num));
	}
	/* free all memory assigned in userland */
out_free_args:
	if (args->infile)
		free(args->infile);
	if (args->outfile)
		free(args->outfile);
	if (args->keybuf)
		free(args->keybuf);
	if (args)
		free(args);
out:
	exit(rc);
}
