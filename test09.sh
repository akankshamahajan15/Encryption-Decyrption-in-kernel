#!/bin/sh

# This test has NEGATIVE testcase related to input file and output file and
# all following testcases should fail. This run user program (xcpenc) with all checks

/bin/rm -f infile

echo  "" >> results
echo  "" >> log
echo test09.sh: Negative testcases of files >> results
echo test09.sh: Negative testcase of files >> log

# When input file is not present, it will fail
# Same is for output file
echo Input file not present >> results
echo ./xcpenc -e  -p password  infile encryptfile >> results
echo ./xcpenc -e  -p password  infile encryptfile>>  log

./xcpenc -e  -p "password"  infile encryptfile >> log
retval=$?
if test $retval != 0 ; then
	echo xcpenc failed with error: $retval >> results
else
	echo xcpenc program succeeded >> results
fi

echo  "" >> results
echo  "" >> log

echo dummy_test > infile

# When input and output file point to same file. It will fail
# even in case of hardlinks
echo same input output file >> results
echo ./xcpenc -c infile infile >> results
echo ./xcpenc -c infile infile >> log

./xcpenc -c infile infile >> log

retval=$?
if test $retval != 0 ; then
        echo xcpenc failed with error: $retval >> results
else
        echo xcpenc program succeeded >> results
fi

echo  "" >> results
echo  "" >> log

# When one file name is not mentioned, it will fail
echo one file is missing >> results
echo ./xcpenc -d -p password infile  >> results
echo ./xcpenc -d -p password infile  >> log

./xcpenc -d  -p password infile >> log

retval=$?
if test $retval != 0 ; then
        echo xcpenc failed with error: $retval >> results
else
        echo xcpenc program succeeded >> results
fi

echo  "" >> results
echo  "" >> log

# When empty string is passed in name of any file name,
# it will fail
echo empty string passed for filenames >> results
echo ./xcpenc -d -p password "" decryptfile >> results
echo ./xcpenc -d -p password "" decryptfile >> log

./xcpenc -d -p password  "" decryptfile >> log

retval=$?
if test $retval != 0 ; then
        echo xcpenc failed with error: $retval >> results
else
        echo xcpenc program succeeded >> results
fi

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
