#!/bin/sh

# This test basic functionality of encryption decryption with cipher name passed 
# with -C option and  checks whether two files after encryption and then decryption
# are same or not. 
# IV will be set to page_number + inode number of encryption file and by
# This run user program (xcepnc) with all checks in user program

echo dummy test > infile_ec

echo  "" >> results_ec
echo  "" >> log_ec
echo test_ec05.sh:  >> results_ec
echo test_ec05.sh:  >> log_ec

echo ./xcpenc -e -p password  infile_ec encryptfile_ec -C des3_ede >> results_ec
echo ./xcpenc -e -p password  infile_ec encryptfile_ec -C des3_ede >>  log_ec

./xcpenc -e -p "password"  infile_ec encryptfile_ec -C des3_ede >> log_ec

retval=$?
if test $retval != 0 ; then
	echo encryption: xcpenc failed with error: $retval >> results_ec
else
	echo encryption: xcpenc program succeeded >> results_ec
fi

echo  "" >> results_ec
echo  "" >> log_ec


echo ./xcpenc -d -p password encryptfile_ec decryptfile_ec -C des3_ede >> results_ec
echo ./xcpenc -d -p password encryptfile_ec decryptfile_ec -C des3_ede >> log_ec

./xcpenc -d -p "password"  encryptfile_ec decryptfile_ec -C des3_ede >> log_ec

retval=$?
if test $retval != 0 ; then
        echo decryption: xcpenc failed with error: $retval >> results_ec
else
        echo decryption: xcpenc program succeeded >> results_ec
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
