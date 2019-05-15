#!/bin/sh

# This is a NEGATIVE testcase when wrong password is passed during
# decryption and it should fail with permission denied. This run
# user program (xcpenc) with all checks

echo dummy test > infile

echo  "" >> results
echo  "" >> log
echo test05.sh: Negative testcase Wrong password during decryption >> results
echo test05.sh: Negative testcase Wrong password during decryption >> log

echo ./xcpenc -e -p password  infile encryptfile >> results
echo ./xcpenc -e -p password  infile encryptfile >>  log

./xcpenc -e -p "password"  infile encryptfile >> log

retval=$?
if test $retval != 0 ; then
	echo encryption: xcpenc failed with error: $retval >> results
else
	echo encryption: xcpenc program succeeded >> results
fi

echo  "" >> results
echo  "" >> log


echo ./xcpenc -d -p password123 encryptfile decryptfile >> results
echo ./xcpenc -d -p password123 encryptfile decryptfile >> log

./xcpenc -d -p "password123"  encryptfile decryptfile >> log

retval=$?
if test $retval != 0 ; then
        echo decryption: xcpenc failed with error: $retval >> results
else
        echo decryption: xcpenc program succeeded >> results
fi

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
