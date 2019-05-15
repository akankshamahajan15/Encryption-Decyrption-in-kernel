#!/bin/sh

# This test basic functionality of encryption decryption and whether two files
# after encryption  and then decryption are same or not.
# IV will be set to page_number + inode number of encryption file and by
# default cipher name is set to aes if not mentioned.
# This run user program (xcepnc_nocheck) with NO checks in user program
# infile_ec     : input file
# encryptfile_ec : file after decryption
# decryptfile_ec : file after decryption

echo dummy test > infile_ec

echo  "" >> results_ec
echo  "" >> log_ec
echo test_ec03.sh:  >> results_ec
echo test_ec03.sh:  >> log_ec

echo ./xcpenc_nocheck -e -p password  infile_ec encryptfile_ec >> results_ec
echo ./xcpenc_nocheck -e -p password  infile_ec encryptfile_ec >>  log_ec

./xcpenc_nocheck -e -p "password"  infile_ec encryptfile_ec >> log_ec

retval=$?
if test $retval != 0 ; then
	echo encryption: xcpenc_nocheck failed with error: $retval >> results_ec
else
	echo encryption: xcpenc_nocheck program succeeded >> results_ec
fi

echo  "" >> results_ec
echo  "" >> log_ec


echo ./xcpenc_nocheck -d -p password encryptfile_ec decryptfile_ec >> results_ec
echo ./xcpenc_nocheck -d -p password encryptfile_ec decryptfile_ec >> log_ec

./xcpenc_nocheck -d -p "password"  encryptfile_ec decryptfile_ec >> log_ec

retval=$?
if test $retval != 0 ; then
        echo decryption: xcpenc_nocheck failed with error: $retval >> results_ec
else
        echo decryption: xcpenc_nocheck program succeeded >> results_ec
fi

echo "" >> results_ec

# now verify that the two files are the same before encryption and after decryption
if cmp infile_ec decryptfile_ec ; then
	echo "contents of infile_ec and decryptfile_ec are same" >> results_ec
else
	echo "contents of infile_ec and decryptfile_ec DIFFER" >> results_ec
fi

echo "------------------------------------------------------------------------------" >> results_ec
echo "------------------------------------------------------------------------------" >> log_ec
