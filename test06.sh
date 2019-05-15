#!/bin/sh

# This is a NEGATIVE testcase when wrong password is passed during
# decryption and it should fail with permission denied. This run
# user program (xcpenc_nocheck) with NO checks at user level

echo dummy test > infile

echo  "" >> results
echo  "" >> log
echo test06.sh: Negative testcase : Wrong password during decryption>> results
echo test06.sh: Negative testcase : Wrong password during decryption>> log

echo ./xcpenc_nocheck -e -p password  infile encryptfile >> results
echo ./xcpenc_nocheck -e -p password  infile encryptfile >>  log

./xcpenc_nocheck -e -p "password"  infile encryptfile >> log

retval=$?
if test $retval != 0 ; then
	echo encryption: xcpenc_nocheck failed with error: $retval >> results
else
	echo encryption: xcpenc_nocheck program succeeded >> results
fi

echo  "" >> results
echo  "" >> log


echo ./xcpenc_nocheck -d -p password123 encryptfile decryptfile >> results
echo ./xcpenc_nocheck -d -p password123 encryptfile decryptfile >> log

./xcpenc_nocheck -d -p "password123"  encryptfile decryptfile >> log

retval=$?
if test $retval != 0 ; then
        echo decryption: xcpenc_nocheck failed with error: $retval >> results
else
        echo decryption: xcpenc_nocheck program succeeded >> results
fi

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
