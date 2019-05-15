#!/bin/sh

# This test basic functionality of copy command and compare whether
# two files after copy are same or not by invoking
# user program (xcpenc_nochecl) with NO checks at all.
# infile      : input file
# outfile     : output file after copy

echo dummy test > infile

echo  "" >> results
echo  "" >> log
echo test04.sh:  >> results
echo test04.sh:  >> log

echo ./xcpenc_nocheck -c  infile outfile >> results
echo ./xcpenc_nocheck -c  infile outfile >>  log

./xcpenc_nocheck -c  infile outfile >> log

retval=$?
if test $retval != 0 ; then
	echo xcpenc_nocheck failed with error: $retval >> results
else
	echo xcpenc_nocheck program succeeded >> results
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
