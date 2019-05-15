#!/bin/sh

# This test basic functionality of encryption decryption and compare whether
# two files after encryption  and then decryption are same or not
# by invoking user program (xcpenc_nocheck) with NO checks at all.
# infile      : input file
# encryptfile : file after decryption
# decryptfile : file after decryption

echo dummy test > infile

echo  "" >> results
echo  "" >> log
echo test03.sh:  >> results
echo test03.sh:  >> log

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


echo ./xcpenc_nocheck -d -p password encryptfile decryptfile >> results
echo ./xcpenc_nocheck -d -p password encryptfile decryptfile >> log

./xcpenc_nocheck -d -p "password"  encryptfile decryptfile >> log

retval=$?
if test $retval != 0 ; then
        echo decryption: xcpenc_nocheck failed with error: $retval >> results
else
        echo decryption: xcpenc_nocheck program succeeded >> results
fi

echo "" >> results

# now verify that the two files are the same before encryption and after decryption
if cmp infile decryptfile ; then
	echo "contents of infile and decryptfile are same" >> results
else
	echo "contents of infile and decryptfile DIFFER" >> results
fi

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
