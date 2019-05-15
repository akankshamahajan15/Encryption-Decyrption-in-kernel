// SPDX-License-Identifier: GPL-2.0

#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>	/* for access_ok */
#include <linux/slab.h>	        /* for kmalloc, kfree */
#include <linux/namei.h>	/* for getname, putname */
#include <linux/fs.h>		/* for extern definition of getname */
#include <linux/syscalls.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include "mystruct.h"

asmlinkage extern long (*sysptr)(void *arg);

/*
 * This function encrypts/decrypts buf which has buf_len bytes
 * using skcipher and ivdata passed.
 *
 * Return: 0 on success and < 0 on failure
 */
static int encrypt_decrypt(struct skcipher_request *req, void *buf, int buf_len,
			   char *ivdata, unsigned char flag)
{
	struct scatterlist *sg;
	struct crypto_wait *wait;
	int ret = 0;

	wait = kmalloc(sizeof(*wait), GFP_KERNEL);
	if (!wait) {
		ret = -ENOMEM;
		goto out1;
	}

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, wait);

	sg = kmalloc(sizeof(*sg), GFP_KERNEL);
	if (!sg) {
		ret =  -ENOMEM;
		goto out_kfree_wait;
	}

	sg_init_one(sg, buf, buf_len);
	skcipher_request_set_crypt(req, sg, sg, buf_len, ivdata);
	crypto_init_wait(wait);

	if (flag & 0x1)
		ret = crypto_wait_req(crypto_skcipher_encrypt(req), wait);
	else
		ret = crypto_wait_req(crypto_skcipher_decrypt(req), wait);

	kfree(sg);
out_kfree_wait:
	kfree(wait);
out1:
	return ret;
}

/*
 * This function first set up skcipher handle and its request and then it reads
 * in chunks of PAGE_SIZE from file and call encrypt_decrypt function and write
 * that data to output file. In case of copy it jumps to write portion after
 * read.
 *
 * Return: 0 on success and < 0 on failure
 */
int read_write(struct file *infile_ptr, struct file *outfile_ptr, void **ivdata,
	       void *key, unsigned int keylen, char *cipher_name,
	       unsigned char flag, u64 inode_encryptfile)
{
	ssize_t bytes_read = 0, bytes_wrote = 0, ret = 0;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	void *buf;
	loff_t infile_size;
#ifdef EXTRA_CREDIT
	u64 pageno = 0;
#endif
	if (flag & 0x1 || flag & 0x2) {
		skcipher = crypto_alloc_skcipher(cipher_name, 0, 0);
		if (IS_ERR(skcipher)) {
			ret = PTR_ERR(skcipher);
			goto out_read_write;
		}
		req = skcipher_request_alloc(skcipher, GFP_KERNEL);
		if (!req) {
			ret = -ENOMEM;
			goto out_clean_cipher_handles;
		}
		if (crypto_skcipher_setkey(skcipher, key, keylen)) {
			pr_err("Error in setting key in skcipher\n");
			ret = -EAGAIN;
			goto out_clean_cipher_handles;
		}
	}

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out_clean_cipher_handles;
	}

	infile_size = infile_ptr->f_inode->i_size;
	while ((bytes_read = kernel_read(infile_ptr, buf, PAGE_SIZE,
					 &infile_ptr->f_pos)) > 0) {
		/* if flag is 0x4 then directly jump to writing in file */
		if (flag & 0x4)
			goto out_write_in_file;
#ifdef EXTRA_CREDIT
		/* copy 8 bytes page number then 8 bytes inode number */
		memcpy((*ivdata), (void *)&pageno, 8);
		memcpy((void *)((char *)(*ivdata) + 8),
		       (void *)&inode_encryptfile, 8);
		pageno++;
#endif
		ret = encrypt_decrypt(req, buf, bytes_read, (char *)(*ivdata),
				      flag);
		if (ret < 0)
			goto out_kfree_buf;

out_write_in_file:
		bytes_wrote = kernel_write(outfile_ptr, buf, bytes_read,
					   &outfile_ptr->f_pos);
		if (bytes_wrote < 0) {
			pr_err("Error in writing data to output file\n");
			ret = bytes_wrote;
			goto out_clean_cipher_handles;
		}
	}
	/*
	 * if bytes read is  0 but it fails on reading
	 * then set ret to -EINVAL
	 */
	if (bytes_read < 0 || infile_size < infile_ptr->f_pos) {
		ret = bytes_read ? bytes_read : -EINVAL;
		goto out_kfree_buf;
	}

out_kfree_buf:
	kfree(buf);
out_clean_cipher_handles:
	if (flag & 0x1 || flag & 0x2) {
		kfree(req);
		if (skcipher)
			crypto_free_skcipher(skcipher);
	}
out_read_write:
	return ret;
}

/*
 * This function takes user address space, check its validity
 * and address space.
 *
 * Return: 0 on success and < 0 on failure
 */
int address_check(void *user_buf, int len)
{
	if (!user_buf) {
		pr_err("User argument is empty\n");
		return -EINVAL;
	}

	/* check validity of address space of user arguments */
	if (!access_ok(VERIFY_READ, user_buf, len)) {
		pr_err("User address space is not valid\n");
		return -EFAULT;
	}
	return 0;
}

/*
 * This functions checks if flag passed is valid or not. Flag = 1 for encyrpt,
 * 2 for decrypt and 4 for copying. It also checks if password passed is valid
 * and is passed with -e/-d only.
 *
 * Return: 0 on success and < 0 on failure
 */
int check_flag_password(unsigned char flag, unsigned int pass_len)
{
	if (!flag) {
		pr_err("No option specified to encrypt/decrypt/copy. Try 'xcpenc -h' for more information.\n");
		return  -EINVAL;
	}
	if (flag & (flag - 1)) {
		pr_err("-e/-d/-c option specified together. Try 'xcpenc -h' for more information.\n");
		return -EINVAL;
	}
	if (flag & 0x4 && pass_len) {
		pr_err("Cannot specify -c (copy) option with -p. Either remove -p or change -c to -e/-d\n");
		pr_err("Try 'xcpenc -h' for more information.\n");
		return -EINVAL;
	}

	/* check related to encryption/decryption only */
	if (flag & 0x1 || flag & 0x2) {
		if (!pass_len) {
			pr_err("Password length is empty. Check the password again\n");
			return -EINVAL;
		}
		if (pass_len < 6) {
			pr_err("Password should be atleast 6 characters long\n");
			return -EINVAL;
		}
	}
	return 0;
}

/*
 * This function sets fs to KERNEL_MODE and populates file_stat
 * using vfs_stat.
 *
 * Returns: 0 if file present else < 0
 */
int get_stat(const char *name, struct kstat **file_stat)
{
	mm_segment_t old_fs;
	int ret;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = vfs_stat(name, *(file_stat));
	set_fs(old_fs);
	return ret;
}

/*
 * This function returns the length of
 * the string passed
 */
int get_string_len(char *str)
{
	int i = 0;

	while (str[i] != '\0')
		i++;
	return i;
}

/*
 * This function compares 2 char pointers and checks whether
 * 2 strings are same or not
 *
 * Returns: 0 if same else return difference of 2 chars
 */
int str_cmp(const char *s1, const char *s2)
{
	while (*s1 && (*s1 == *s2)) {
		s1++;
		s2++;
	}
	return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

/*
 * This funciton writes key, inode and cipher name in preamble.
 * Inode and cipher name is for extra credit part. Inode is used to generate
 * different IV data for each page size.
 *
 * Return: 0 on success and < 0 on failure
 */
int preamble_encrypt(void **keybuf, unsigned int keylen, char *cipher_name,
		     struct file **outfile_ptr, u64 *inode)
{
	ssize_t bytes_wrote = 0;

	/* write key in preamble */
	bytes_wrote = kernel_write(*outfile_ptr, *keybuf, keylen,
				   &((*outfile_ptr)->f_pos));
	if (bytes_wrote < 0)
		return bytes_wrote;

#ifdef EXTRA_CREDIT
	/* write inode number in preamble */
	bytes_wrote = kernel_write(*outfile_ptr, (void *)inode, 8,
				   &((*outfile_ptr)->f_pos));
	if (bytes_wrote < 0)
		return bytes_wrote;

	/* write cipher name in preamble */
	 bytes_wrote = kernel_write(*outfile_ptr, (void *)cipher_name,
				    get_string_len(cipher_name) + 1,
				   &((*outfile_ptr)->f_pos));
	if (bytes_wrote < 0)
		return bytes_wrote;

#endif

	return 0;
}

/*
 * This function reads key, inode and cipher name from preamble. Inode and
 * cipher name is for extra credit part. It also checks if key passed and key
 * stored while encryption matches or not. Same is for cipher name. By default
 * cipher name is "aes" if no cipher is passed.
 *
 * Return: 0 on success and < 0 on failure
 */
int preamble_decrypt(void **keybuf, unsigned int keylen, char *cipher_name,
		     struct file *infile_ptr, u64 *inode)
{
	void *decrypt_keybuf = NULL;
	ssize_t bytes_read;
	int ret = 0;
#ifdef EXTRA_CREDIT
	char *decrypt_cipher_name;
#endif
	decrypt_keybuf = kmalloc(keylen, GFP_KERNEL);
	if (!decrypt_keybuf) {
		ret = -ENOMEM;
		goto out_preamble;
	}

	/* read key from input file */
	bytes_read =  kernel_read(infile_ptr, decrypt_keybuf, keylen,
				  &infile_ptr->f_pos);
	if (bytes_read < 0) {
		ret = bytes_read;
		pr_err("Error in reading key from preamble\n");
		goto out_kfree_decrypt_keybuf;
	}

	if (memcmp(decrypt_keybuf, *keybuf, keylen)) {
		pr_err("Key provided for decryption doesn't match\n");
		ret = -EACCES;
		goto out_kfree_decrypt_keybuf;
	}

#ifdef EXTRA_CREDIT
	/* read inode_number of encrypted file */
	bytes_read = kernel_read(infile_ptr, (void *)inode, 8,
				 &infile_ptr->f_pos);
	if (bytes_read < 0) {
		pr_err("Error in reading inode from preamble\n");
		ret = bytes_read;
		goto out_kfree_decrypt_keybuf;
	}
	/* allocate memory to cipher name */
	decrypt_cipher_name = kmalloc(get_string_len(cipher_name) + 1,
				      GFP_KERNEL);
	if (!decrypt_cipher_name) {
		ret = -ENOMEM;
		goto out_kfree_decrypt_keybuf;
	}

	/* read inode_number of encrypted file */
	bytes_read = kernel_read(infile_ptr, (void *)decrypt_cipher_name,
				 get_string_len(cipher_name) + 1,
				 &infile_ptr->f_pos);
	if (bytes_read < 0) {
		pr_err("Error in reading cipher name from preamble\n");
		ret = bytes_read;
		goto out_kfree_cipher_name;
	}
	if (str_cmp(decrypt_cipher_name, cipher_name)) {
		pr_err("Cipher provided for decryption doesn't match\n");
		ret = -EACCES;
		goto out_kfree_cipher_name;
	}

out_kfree_cipher_name:
	kfree(decrypt_cipher_name);
#endif

out_kfree_decrypt_keybuf:
	kfree(decrypt_keybuf);
out_preamble:
	return ret;
}

/*
 * This functions takes key(in_data) of length key_len(in_len) bytes and
 * using sha256 hash that key.
 *
 * Return: 0 on success and < 0 on failure
 */
int hash_key(void *in_data, unsigned int in_len, void *out_data)
{
	int ret = 0;
	struct shash_desc *desc;
	struct crypto_shash *tfm;
	int desc_size;

	memset(out_data, 0, SHA256_LENGTH);
	tfm = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		pr_err("Could not allocate memory to tfm for sha256\n");
		ret = PTR_ERR(desc->tfm);
		goto out_hash_key;
	}

	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);

	desc = kmalloc(desc_size, GFP_KERNEL);
	if (!desc) {
		ret = -ENOMEM;
		goto out_free_shash;
	}
	desc->tfm =  tfm;

	ret = crypto_shash_digest(desc, (u8 *)in_data, in_len, (u8 *)out_data);
	if (ret < 0) {
		pr_err("Error in hashing the key\n");
		goto out_free_desc;
	}

out_free_desc:
	desc->tfm = NULL;
	kfree(desc);
out_free_shash:
	crypto_free_shash(tfm);
out_hash_key:
	return ret;
}

/*
 * This function sets cipher_name to aes and cipher_full_name to ctr-aes-aesni
 * that can be used directly during creating skcipher instead of using for loop
 * there. It also sets key length to 32 bytes.
 */
int set_aes_cipher(char **cipher_full_name, char **cipher_name,
		   unsigned int *keylen)
{
	*cipher_full_name = kmalloc(14, GFP_KERNEL);
	if (!*cipher_full_name)
		return -ENOMEM;
	memcpy(*cipher_full_name, "ctr-aes-aesni", 14);
	*cipher_name = kmalloc(4, GFP_KERNEL);
	memcpy(*cipher_name, "aes", 4);
	*keylen = 32;
	return 0;
}

/* This function is for EXTRA CREDIT part. It checks if cipher name passed
 * is valid and then set cipher_name and cipher_full_name accordingly.
 * It also sets keylen depending upon that cipher and then realloc the key
 * to save memory if max key len required is less than 32 bytes.
 * If no cipher name is passed, aes is set by default.
 */
int set_cipher(const char *name, void **ivdata, void **hashed_key,
	       unsigned int *keylen, char **cipher_full_name,
	       char **cipher_name)
{
	unsigned int old_keylen = 32;
	int ret = 0;

	if (!str_cmp(name, "blowfish")) {
		*cipher_full_name = kmalloc(17, GFP_KERNEL);
		memcpy(*cipher_full_name, "ctr-blowfish-asm", 17);
		*cipher_name = kmalloc(9, GFP_KERNEL);
		memcpy(*cipher_name, "blowfish", 9);
	} else if (!str_cmp(name, "des3_ede")) {
		*cipher_full_name = kmalloc(17, GFP_KERNEL);
		memcpy(*cipher_full_name, "ctr-des3_ede-asm", 17);
		*cipher_name = kmalloc(9, GFP_KERNEL);
		memcpy(*cipher_name, "des3_ede", 9);
		*keylen = 24;
	} else if (!str_cmp(name, "serpent")) {
		*cipher_full_name = kmalloc(17, GFP_KERNEL);
		memcpy(*cipher_full_name, "ctr-serpent-sse2", 17);
		*cipher_name = kmalloc(8, GFP_KERNEL);
		memcpy(*cipher_name, "serpent", 8);
	} else if (!str_cmp(name, "camellia")) {
		*cipher_full_name = kmalloc(17, GFP_KERNEL);
		memcpy(*cipher_full_name, "ctr-camellia-asm", 17);
		*cipher_name = kmalloc(9, GFP_KERNEL);
		memcpy(*cipher_name, "camellia", 9);
	} else if (!str_cmp(name, "cast6")) {
		*cipher_full_name = kmalloc(14, GFP_KERNEL);
		memcpy(*cipher_full_name, "ctr-cast6-avx", 14);
		*cipher_name = kmalloc(6, GFP_KERNEL);
		memcpy(*cipher_name, "cast6", 6);
	} else if (!str_cmp(name, "cast5")) {
		*cipher_full_name = kmalloc(14, GFP_KERNEL);
		memcpy(*cipher_full_name, "ctr-cast5-avx", 14);
		*cipher_name = kmalloc(6, GFP_KERNEL);
		memcpy(*cipher_name, "cast5", 6);
		*keylen = 16;
	} else if (!str_cmp(name, "aes")) {
		ret = set_aes_cipher(cipher_full_name, cipher_name, keylen);
	} else {
		pr_err("Cipher name specified is not valid\n");
		pr_err("Try 'xcpenc -h' for more information.\n");
		ret = -EINVAL;
	}
	/* realloc if maximum key length required for cipher is < 32 bytes */
	if (old_keylen != *keylen)
		*hashed_key = krealloc(*hashed_key, *keylen, GFP_KERNEL);
	return ret;
}

asmlinkage long cpenc(void *arg)
{
	void *karg, *ivdata = NULL, *hashed_key = NULL;
	struct kstat *outfile_stat, *infile_stat;
	struct file *infile_ptr, *outfile_ptr;
	struct filename *kinfile, *koutfile;
	bool is_outfile_exist = false;
	char *cipher_name = NULL;
	int ret = 0;
	mm_segment_t old_fs;
	unsigned char flag;
	u64 inode_encryptfile;  /* inode of encrypted file */
	unsigned int pass_len;  /* length of password passed*/
	char *cipher_full_name = NULL;
#ifdef EXTRA_CREDIT
	struct filename *filecipher = NULL;
#endif

	ret = address_check(arg, sizeof(struct user_args));
	if (ret < 0) {
		pr_err("Error in address_check function of user arguments\n");
		goto out;
	}

	/* allocate kernel space to copy user space arguments */
	karg = kmalloc(sizeof(struct user_args), GFP_KERNEL);
	if (!karg) {
		ret = -ENOMEM;
		goto out;
	}

	/* copy arguments from user space to kernel space */
	if (copy_from_user(karg, arg, sizeof(struct user_args))) {
		pr_err("Error in copy arguments from user to kernel memory\n");
		ret = -EFAULT;
		goto out_kfree_karg;
	}

	flag = ((struct user_args *)karg)->flag;
	pass_len = ((struct user_args *)karg)->keylen;
	((struct user_args *)karg)->keybuf = NULL;

	/* CHECKS RELATED TO FLAG AND PASSWORD */
	ret = check_flag_password(flag, pass_len);
	if (ret < 0)
		goto out_kfree_karg;

	/* CHECKS REALTED TO ENCRYPTION/DECRYPTION KEY AND IVDATA */
	if (flag & 0x1 || flag & 0x2) {
		ret = address_check(((struct user_args *)arg)->keybuf,
				    pass_len);
		if (ret < 0)
			goto out_kfree_karg;

		/* allocate kernel space to copy user space arguments */
		((struct user_args *)karg)->keybuf = kmalloc(pass_len,
							     GFP_KERNEL);
		if (!(((struct user_args *)karg)->keybuf)) {
			ret = -ENOMEM;
			goto out_kfree_karg;
		}

		/* copy arguments from user space to kernel space */
		if (copy_from_user(((struct user_args *)karg)->keybuf,
				   ((struct user_args *)arg)->keybuf,
				   pass_len)) {
			pr_err("Error in copy password from user to kernel memory\n");
			ret = -EFAULT;
			goto out_kfree_keybuf;
		}

		hashed_key = kmalloc(SHA256_LENGTH, GFP_KERNEL);
		if (!hashed_key) {
			ret = -ENOMEM;
			goto out_kfree_keybuf;
		}

		ret = hash_key(((struct user_args *)karg)->keybuf, pass_len,
			       hashed_key);
		if (ret < 0)
			goto out_kfree_hashed_key;

		/* by default setting IV data to zero for skcipher */
		ivdata = kmalloc(16, GFP_KERNEL);
		if (!ivdata) {
			ret =  -ENOMEM;
			goto out_kfree_hashed_key;
		}
		memset(ivdata, 123456, 16);

#ifdef EXTRA_CREDIT
		/* CHECKS RELATED TO CIPHER NAME */
		if (((struct user_args *)karg)->iscipher) {
			filecipher = getname(((struct user_args *)arg)->cipher);
			if (IS_ERR(filecipher)) {
				pr_err("Error in copy cipher name in kernel memory\n");
				ret = PTR_ERR(filecipher);
				goto out_kfree_hashed_key;
			}

			/*
			 * set cipher name and key length and also truncate key
			 * memory to save memory
			 */
			ret = set_cipher(filecipher->name, &ivdata, &hashed_key,
					 &pass_len, &cipher_full_name,
					 &cipher_name);
			putname(filecipher);
			if (ret < 0)
				goto out_kfree_cipher_name;
		} else {
			/* by default, aes is set */
			ret = set_aes_cipher(&cipher_full_name, &cipher_name,
					     &pass_len);
			if (ret < 0)
				goto out_kfree_cipher_name;
		}
#else
		ret = set_aes_cipher(&cipher_full_name, &cipher_name,
				     &pass_len);
		if (ret < 0)
			goto out_kfree_cipher_name;
#endif
	}

	/* CHECKS RELATED TO INPUT FILE */
	/* copy input file name from user space to kernel space */
	kinfile = getname(((struct user_args *)karg)->infile);
	if (IS_ERR(kinfile)) {
		pr_err("Error in copy input file name in kernel memory\n");
		ret = PTR_ERR(kinfile);
		goto out_kfree_cipher_name;
	}

	/* check if file exist for reading */
	infile_stat = kmalloc(sizeof(*infile_stat), GFP_KERNEL);
	if (!infile_stat) {
		ret = -ENOMEM;
		goto out_kfree_kinfile;
	}

	ret = get_stat(kinfile->name, &infile_stat);
	if (ret < 0) {
		pr_err("Input file doesn't exist\n");
		goto out_kfree_infile_stat;
	}

	/* check if input file is regular file or not*/
	if (!S_ISREG(infile_stat->mode)) {
		pr_err("Input file is not a regular file\n");
		ret = -EINVAL;
		goto out_kfree_infile_stat;
	}

	/* open input file for reading */
	infile_ptr = filp_open(kinfile->name, O_RDONLY, 0);
	if (IS_ERR(infile_ptr)) {
		pr_err("Error in opening input file for reading\n");
		ret = PTR_ERR(infile_ptr);
		goto out_kfree_infile_stat;
	}

	/* CHECKS RELATED TO OUTPUT FILE */
	/* copy output file name from user space to kernel space */
	koutfile = getname(((struct user_args *)karg)->outfile);
	if (IS_ERR(koutfile)) {
		pr_err("Error in copy output file name in kernel memory\n");
		ret = PTR_ERR(koutfile);
		goto out_close_infile;
	}

	/* check if file exist for writing */
	outfile_stat = kmalloc(sizeof(*outfile_stat), GFP_KERNEL);
	if (!outfile_stat) {
		ret = -ENOMEM;
		goto out_kfree_koutfile;
	}

	/*check if outfile exist and point to same file */
	ret = get_stat(koutfile->name, &outfile_stat);
	if (!ret) {
		/* open output file to check the superblock */
		outfile_ptr = filp_open(koutfile->name, O_WRONLY, 0777);
		if (IS_ERR(outfile_ptr)) {
			pr_err("Error in opening output file for writing\n");
			ret = PTR_ERR(outfile_ptr);
			goto out_kfree_outfile_stat;
		}

		if (outfile_stat->ino == infile_stat->ino &&
		    outfile_ptr->f_inode->i_sb->s_id  ==
		    infile_ptr->f_inode->i_sb->s_id) {
			pr_err("Input and Output file point to same file\n");
			ret = -EINVAL;
			filp_close(outfile_ptr, NULL);
			goto out_kfree_outfile_stat;
		}
		filp_close(outfile_ptr, NULL);

		/* check if output file is already present is not regular*/
		if (!S_ISREG(outfile_stat->mode)) {
			pr_err("Output file already present is not a regular file\n");
			ret = -EINVAL;
			goto out_kfree_outfile_stat;
		}
	}

	ret = 0;	/* reset ret to 0 */
	outfile_ptr = filp_open(koutfile->name, O_WRONLY | O_TRUNC
				| O_CREAT, 0777);
	if (IS_ERR(outfile_ptr)) {
		pr_err("Error in opening output file for writing\n");
		ret = PTR_ERR(outfile_ptr);
		goto out_kfree_outfile_stat;
	}

	/* set is_outfile_exist to delete outfile if some error occurs */
	is_outfile_exist = true;

	/* change output file permission equal to input file permissions */
	outfile_ptr->f_inode->i_mode = infile_ptr->f_inode->i_mode;

	/* PREAMBLE READING/WRITING */
	inode_encryptfile = infile_stat->ino;
	if (flag & 0x1) {
		ret = preamble_encrypt(&hashed_key, pass_len, cipher_name,
				       &outfile_ptr, &inode_encryptfile);
		if (ret < 0)
			goto out_close_outfile;
	} else if (flag & 0x2) {
		ret = preamble_decrypt(&hashed_key, pass_len, cipher_name,
				       infile_ptr, &inode_encryptfile);
		if (ret < 0)
			goto out_close_outfile;
	}

	/* READING WRITING THE CONTENT OF INPUT AND OUTPUT FILE */
	ret = read_write(infile_ptr, outfile_ptr, &ivdata, hashed_key, pass_len,
			 cipher_full_name, flag, inode_encryptfile);
	if (ret < 0)
		pr_err("Error in reading writing files\n");

	/* CLEANUP */
out_close_outfile:
	filp_close(outfile_ptr, NULL);
	/* delete file if exists and  ret < 0 (failure) */
	if (ret < 0 && is_outfile_exist) {
		old_fs = get_fs();
		set_fs(KERNEL_DS);
		inode_lock(outfile_ptr->f_path.dentry->d_parent->d_inode);
		vfs_unlink(outfile_ptr->f_path.dentry->d_parent->d_inode,
			   outfile_ptr->f_path.dentry, NULL);
		inode_unlock(outfile_ptr->f_path.dentry->d_parent->d_inode);
		set_fs(old_fs);
	}
out_kfree_outfile_stat:
	kfree(outfile_stat);
out_kfree_koutfile:
	putname(koutfile);
out_close_infile:
	filp_close(infile_ptr, NULL);
out_kfree_infile_stat:
	kfree(infile_stat);
out_kfree_kinfile:
	putname(kinfile);
out_kfree_cipher_name:
		kfree(cipher_full_name);
		kfree(cipher_name);
		kfree(ivdata);
out_kfree_hashed_key:
		kfree(hashed_key);
out_kfree_keybuf:
	if (((struct user_args *)karg)->keybuf)
		kfree(((struct user_args *)karg)->keybuf);
out_kfree_karg:
	kfree(karg);
out:
	return ret;
}

static int __init init_sys_cpenc(void)
{
	pr_info("installed new sys_cpenc module\n");
	if (!sysptr)
		sysptr = cpenc;
	return 0;
}

static void  __exit exit_sys_cpenc(void)
{
	if (sysptr)
		sysptr = NULL;
	pr_info("removed sys_cpenc module\n");
}
module_init(init_sys_cpenc);
module_exit(exit_sys_cpenc);
MODULE_LICENSE("GPL");
