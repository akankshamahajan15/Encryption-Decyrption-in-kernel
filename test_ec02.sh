#!/bin/sh

# This test basic functionality of copy command and compare whether
# two files after copy are same or not by invoking
# user program (xcpenc) with all checks. In this case IV will not be set
# and no cipher name is passed. It is general copy command
# infile      : input file
# outfile     : output file after copy

echo dummy test > infile_ec

echo  "" >> results_ec
echo  "" >> log_ec
echo test_ec02.sh:  >> results_ec
echo test_ec02.sh:  >> log_ec

echo ./xcpenc -c  infile_ec outfile_ec >> results_ec
echo ./xcpenc -c  infile_ec outfile_ec >>  log_ec

./xcpenc -c  infile_ec outfile_ec >> log_ec

retval=$?
if test $retval != 0 ; then
	echo xcpenc failed with error: $retval >> results_ec
else
	echo xcpenc program succeeded >> results_ec
fi

echo "" >> results_ec

# now verify that the two files are the same before encryption and after decryption
if cmp infile_ec outfile_ec ; then
	echo "contents of infile_ec and outfile_ec are same" >> results_ec
else
	echo "contents of infile_ec and outfile_ec DIFFER" >> results_ec
fi

echo "------------------------------------------------------------------------------" >> results_ec
echo "------------------------------------------------------------------------------" >> log_ec
