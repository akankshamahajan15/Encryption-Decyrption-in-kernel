/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MYSTRUCT_H
#define _MYSTRUCT_H

/*#ifndef EXTRA_CREDIT
#define EXTRA_CREDIT
#endif
*/

#define KEY_LENGTH 16         /* MD5 keylength */
#define SHA256_LENGTH 32      /*SHA256 keylength */

struct user_args {
	char *infile;
	char *outfile;
	void *keybuf;
	unsigned int keylen;
	unsigned char flag;
#ifdef EXTRA_CREDIT
	char *cipher;
	unsigned char iscipher;
#endif
};

#endif
