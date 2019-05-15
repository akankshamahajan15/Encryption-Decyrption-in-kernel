#!/bin/sh

# This test basic functionality of encryption decryption and compare whether
# two files after encryption  and then decryption are same or not
# by invoking user program (xcpenc) with all checks.
# infile      : input file
# encryptfile : file after decryption
# decryptfile : file after decryption

/bin/rm -f infile encryptfile decryptfile
echo dummy test > infile

echo  "" >> results
echo  "" >> log
echo test01.sh:  >> results
echo test01.sh:  >> log

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


echo ./xcpenc -d -p password encryptfile decryptfile >> results
echo ./xcpenc -d -p password encryptfile decryptfile >> log

./xcpenc -d -p "password"  encryptfile decryptfile >> log

retval=$?
if test $retval != 0 ; then
        echo decryption: xcpenc failed with error: $retval >> results
else
        echo decryption: xcpenc program succeeded >> results
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
