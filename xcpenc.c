// SPDX-License-Identifier: GPL-2.0

#include <asm/unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <openssl/md5.h>
#include "mystruct.h"

#ifndef __NR_cpenc
#error cpenc system call not defined
#endif

//#define EXTRA_CREDIT
/*
 * This is an help function that prints all the valid options that you can
 * specify to run this module
 */
void help(void)
{
#ifdef EXTRA_CREDIT
	printf("\nUsage: ./xcpenc {-p <password> {-e | -d }");
	printf(" [-C <cipher name>] | -c} ");
#else
	printf("\nUsage: ./xcpenc {-p <password> {-e | -d } | -c } ");
#endif
	printf("<input file> <output file>\n");
	printf("\nOptions :\n");
	printf("-p <password>    : specify password with -p to encrypt|");
	printf("decrypt the input file with password\n");
	printf("-e %14s: encrypt the input file to output file\n", " ");
	printf("-d %14s: decrypt the output file to output file\n", " ");
	printf("-c %14s: copy the input file to output file\n", " ");
#ifdef EXTRA_CREDIT
	printf("-C <cipher name> : the valid cipher name to encrypt|decrypt\n");
	printf("\t-C should be specified with -e | -s. It is not required ");
	printf("with -c\n");
#endif
	printf("\tspecify only one option : -e | -d | -c\n");
	printf("\t-p should be specified with -e | -d. It is not required ");
	printf("with -c\n");
	printf("\nArguments :\n");
	printf("<password> %3s: password to encrypt/decrypt ", " ");
	printf("the input file");
	printf("It should be\n%16satleast 6 characters long\n", " ");
	printf("<input file> %1s: input file that contains that data to ", " ");
	printf("encrypt|decrypt|copy\n");
	printf("<output file> : output file that contains ");
	printf("encrypted|decrypted|copied data\n");
#ifdef EXTRA_CREDIT
	printf("<cipher name> : cipher name to be used to encrypt|decrypt\n");
	printf("\tValid cipher names supported for this module are:\n\taes ");
	printf("| blowfish | des3_ede | serpent | cast5 | cast6 | camellia\n");
#endif
}

/*
 * This function generates a key of string password
 * using MD5 and populate it into key. The generated
 * key is 32 bits long
 */
void generate_key(char *password, unsigned char *key)
{
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, password, strlen(password));
	MD5_Final(key, &ctx);
}

/*
 * This function checks whether cipher name specified with -C
 * is valid or not
 */
bool is_valid_cipher(char *cipher)
{
	if (strcmp(cipher, "aes") && strcmp(cipher, "blowfish") &&
	    strcmp(cipher, "des3_ede") && strcmp(cipher, "serpent") &&
	    strcmp(cipher, "cast5") && strcmp(cipher, "cast6") &&
	    strcmp(cipher, "camellia")) {
		printf("Currently supporting aes | blowfish | des3_ede");
		printf(" | serpent | cast5 | cast6 | camellia\n");
		return false;
	}
	return true;
}

int main(int argc, char *argv[])
{
	int rc = 0, err_num, opt, i, index;
	struct user_args *args;

	args = (struct user_args *)malloc(sizeof(struct user_args));
	if (!args) {
		printf("Could not allocate memory to arguments in userland\n");
		rc = -1;
		goto out;
	}

	args->flag = 0;
	args->keylen = 0;
	args->infile = NULL;
	args->outfile = NULL;
	args->keybuf = NULL;
#ifdef EXTRA_CREDIT
	args->cipher = NULL;
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
				help();
				goto out_free_args;
			case'p':
				if (!optarg) {
					printf("Argument not specified with ");
					printf("-p. Try 'xcpenc -h' for more");
					printf("information.\n");
					rc = -1;
					goto out_free_args;
				}
				index = 0;
				for (i = 0; i < strlen(optarg); i++) {
					if (optarg[i] != '\n')
						optarg[index++] = optarg[i];
				}
				optarg[index] = '\0';

				if (strlen(optarg) < 6) {
					printf("Password should be atleast ");
					printf("6 characters long excluding\n");
					rc = -1;
					goto out_free_args;
				}

				unsigned char key[KEY_LENGTH];

				generate_key(optarg, key);
				args->keybuf = malloc(KEY_LENGTH);

				if (!(args->keybuf)) {
					printf("Could not allocate memory to");
					printf(" store key in userland.\n");
					rc = -1;
					goto out_free_args;
				}
				args->keylen = KEY_LENGTH;
				memcpy(args->keybuf, (void *)key, KEY_LENGTH);
				break;
#ifdef EXTRA_CREDIT
			case'C':
				if (!optarg) {
					printf("Argument not specified with ");
					printf("-C. Try 'xcpenc -h' for more");
					printf("information\n");
					rc = -1;
					goto out_free_args;
				}
				if (!strlen(optarg)) {
					printf("Cipher name specified is ");
					printf("empty\n");
					rc = -1;
					goto out_free_args;
				}
				if (!is_valid_cipher(optarg)) {
					printf("Currently supporting aes | ");
					printf("blowfish | des3_ede | cast5 ");
					printf("cast6 | camelia | serpent\n");
					rc = -1;
					goto out_free_args;
				}
				args->cipher = (char *)malloc(strlen(optarg)
							      + 1);
				args->iscipher = 1;
				strcpy(args->cipher, optarg);
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

	if (!(args->flag)) {
		printf("No option specified to encrypt/decrypt/copy. ");
		printf("Try 'xcpenc -h' for more information.\n");
		rc = -1;
		goto out_free_args;
	}

	if (args->flag & (args->flag - 1)) {
		printf("-e/-d/-c option specified together. ");
		printf("Try 'xcpenc -h' for more information.\n");
		rc = -1;
		goto out_free_args;
	}

	if ((args->flag & 0x4) && args->keybuf) {
		printf("Cannot specify -c (copy) option with -p. ");
		printf("Either remove -p or change -c to -e/-d.\n");
		printf("Try 'xcpenc -h' for more information.\n");
		rc = -1;
		goto out_free_args;
	}

	if ((args->flag & 0x1 || args->flag & 0x2) && !args->keylen) {
		printf("Must specify -p password with -e and -d option. ");
		printf("Try 'xcpenc -h' for more information.\n");
		rc = -1;
		goto out_free_args;
	}

	/* Get all of the non-option arguments */
	if (optind < argc) {
		if (argv[optind][0] == '\0') {
			printf("Input file name is empty. Use a valid name\n");
			rc = -1;
			goto out_free_args;
		}
		args->infile = (char *)malloc(strlen(argv[optind]) + 1);
		if (!(args->infile)) {
			printf("Could not allocate memory to input ");
			printf("file name\n");
			rc = -1;
			goto out_free_args;
		}
		strcpy(args->infile, argv[optind++]);
	} else {
		printf("Input file not specified. ");
		printf("Please check the arguments\n");
		rc = -1;
		goto out_free_args;
	}
	if (optind < argc) {
		if (argv[optind][0] == '\0') {
			printf("Output file name is empty. ");
			printf("Use a valid name\n");
			rc = -1;
			goto out_free_args;
		}
		args->outfile = (char *)malloc(strlen(argv[optind]) + 1);
		if (!(args->outfile)) {
			printf("Could not allocate memory to output ");
			printf("file name\n");
			rc = -1;
			goto out_free_args;
		}
		strcpy(args->outfile, argv[optind++]);
	} else {
		printf("Output file not specified. ");
		printf("Please check the arguments\n");
		rc = -1;
		goto out_free_args;
	}

	if (optind < argc) {
		printf("Extra arguments are passed\n");
		printf("Try 'xcpenc -h' for more information.\n");
		rc = -1;
		goto out_free_args;
	}

#ifdef EXTRA_CREDIT
	if (args->iscipher  && args->flag & 0x4) {
		printf("Cannot specify -c (copy) option with -C. ");
		printf("Either remove -C or change -c to -e/-d.\n");
		printf("Try 'xcpenc -h' for more information.\n");
		rc = -1;
		goto out_free_args;
	}
	/* by default set cipher name to aes if nothing mentioned */
	if (!args->iscipher) {
		args->cipher = (char *)malloc(4);
		strcpy(args->cipher, "aes");
		args->iscipher = 1;
	}
#endif
	rc = syscall(__NR_cpenc, (void *)args);
	err_num = errno;
	if (rc == 0) {
		printf("Syscall returned %d\n", rc);
	} else {
		rc =  err_num;
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
