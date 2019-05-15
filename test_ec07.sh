#!/bin/sh

# This is a NEGATIVE testcase when wrong cipher name is passed during
# decryption and it should fail with permission denied. This run
# user program (xcpenc) with all checks at user level

echo dummy test > infile_ec

echo  "" >> results_ec
echo  "" >> log_ec
echo test_ec07.sh: Negative testcase Wrong cipher name in decryption>> results_ec
echo test_ec07.sh: Negative testcase Wrong cipher name in decryption>> log_ec

echo ./xcpenc -e -p password  infile_ec encryptfile_ec -C blowfish >> results_ec
echo ./xcpenc -e -p password  infile_ec encryptfile_ec -C blowfish>>  log_ec

./xcpenc -e -p "password"  infile_ec encryptfile_ec -C blowfish>> log_ec

retval=$?
if test $retval != 0 ; then
	echo encryption: xcpenc failed with error: $retval >> results_ec
else
	echo encryption: xcpenc program succeeded >> results_ec
fi

echo  "" >> results_ec
echo  "" >> log_ec


echo ./xcpenc -d -p password encryptfile_ec decryptfile_ec -C serpent>> results_ec
echo ./xcpenc -d -p password encryptfile_ec decryptfile_ec -C serpent>> log_ec

./xcpenc -d -p "password"  encryptfile_ec decryptfile_ec -C serpent>> log_ec

retval=$?
if test $retval != 0 ; then
        echo decryption: xcpenc failed with error: $retval >> results_ec
else
        echo decryption: xcpenc program succeeded >> results_ec
fi

echo "------------------------------------------------------------------------------" >> results_ec
echo "------------------------------------------------------------------------------" >> log_ec
