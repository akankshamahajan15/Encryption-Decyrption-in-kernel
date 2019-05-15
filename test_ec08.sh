#!/bin/sh

# This is a NEGATIVE testcase when wrong cipher name is passed during
# decryption and it should fail with permission denied. This run
# user program (xcpenc_nochecks) with NO checks at user level

# BY DEFAULT : "aes" is stored in preamble if no cipher is specified
# in extra credit work. SO on decryption cipher should be "aes" if specified 
# explicitly with -C option

echo dummy test > infile_ec

echo  "" >> results_ec
echo  "" >> log_ec
echo test_ec08.sh: Negative testcase Wrong cipher name in decryption>> results_ec
echo test_ec08.sh: Negative testcase Wrong cipher name in decryption>> log_ec

echo ./xcpenc_nocheck -e -p password  infile_ec encryptfile_ec -C blowfish>> results_ec
echo ./xcpenc_nocheck  -e -p password  infile_ec encryptfile_ec -C blowfish>>  log_ec

./xcpenc_nocheck  -e -p "password"  infile_ec encryptfile_ec -C blowfish>> log_ec

retval=$?
if test $retval != 0 ; then
	echo encryption: xcpenc_nocheck  failed with error: $retval >> results_ec
else
	echo encryption: xcpenc_nocheck  program succeeded >> results_ec
fi

echo  "" >> results_ec
echo  "" >> log_ec


echo ./xcpenc_nocheck  -d -p password encryptfile_ec decryptfile_ec -C serpent>> results_ec
echo ./xcpenc_nocheck  -d -p password encryptfile_ec decryptfile_ec -C serpent>> log_ec

./xcpenc_nocheck  -d -p "password"  encryptfile_ec decryptfile_ec -C serpent>> log_ec

retval=$?
if test $retval != 0 ; then
        echo decryption: xcpenc_nocheck  failed with error: $retval >> results_ec
else
        echo decryption: xcpenc_nocheck  program succeeded >> results_ec
fi

echo "------------------------------------------------------------------------------" >> results_ec
echo "------------------------------------------------------------------------------" >> log_ec
