#!/bin/sh

# This test basic functionality of copy command and compare whether
# two files after copy are same or not by invoking 
# user program (xcpenc) with all checks.
# infile      : input file
# outfile     : output file after copy

echo dummy test > infile

echo  "" >> results
echo  "" >> log
echo test02.sh:  >> results
echo test02.sh:  >> log

echo ./xcpenc -c  infile outfile >> results
echo ./xcpenc -c  infile outfile >>  log

./xcpenc -c  infile outfile >> log

retval=$?
if test $retval != 0 ; then
	echo xcpenc failed with error: $retval >> results
else
	echo xcpenc program succeeded >> results
fi

echo "" >> results

# now verify that the two files are the same before encryption and after decryption
if cmp infile outfile ; then
	echo "contents of infile and outfile are same" >> results
else
	echo "contents of infile and outfile DIFFER" >> results
fi

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
