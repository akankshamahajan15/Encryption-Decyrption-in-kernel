#!/bin/sh

# This test has NEGATIVE testcase related to passwords and flags and all following
# testcases should fail. This run user program (xcpenc_nocheck) with No checks at all

echo dummy test > infile

echo  "" >> results
echo  "" >> log
echo test08.sh: Negative testcases of password, options >> results
echo test08.sh: Negative testcase of password, options >> log

# Multiple options specified -e, -d, -c all at once. It should fail
echo Multiple options >> results
echo ./xcpenc_nocheck -e -d -c -p password  infile encryptfile >> results
echo ./xcpenc_nocheck -e -d -c -p password  infile encryptfile>>  log

./xcpenc_nocheck -e -d -c -p "password"  infile encryptfile >> log
retval=$?
if test $retval != 0 ; then
	echo xcpenc_nocheck failed with error: $retval >> results
else
	echo xcpenc_nocheck program succeeded >> results
fi

echo  "" >> results
echo  "" >> log

# -p is specified with copy command -c. It should fail.
echo -p specified with -c >> results
echo ./xcpenc_nocheck -c -p password infile outfile >> results
echo ./xcpenc_nocheck -c -p password infile outfile >> log
./xcpenc_nocheck -c -p "password"  infile outfile >> log

retval=$?
if test $retval != 0 ; then
        echo xcpenc_nocheck failed with error: $retval >> results
else
        echo xcpenc_nocheck program succeeded >> results
fi

echo  "" >> results
echo  "" >> log

# password length should be >= 6 characters. This should fail
echo password length is less than 6 characters >> results
echo ./xcpenc_nocheck -p pass infile encryptfile >> results
echo ./xcpenc_nocheck -p pass infile encryptfile >> log

./xcpenc_nocheck -p pass  infile encryptfile >> log

retval=$?
if test $retval != 0 ; then
        echo xcpenc_nocheck failed with error: $retval >> results
else
        echo xcpenc_nocheck program succeeded >> results
fi

echo  "" >> results
echo  "" >> log

# When with encryption/decryption, no password is specified.
# It should fail
echo No password >> results
echo ./xcpenc_nocheck -d infile decryptfile >> results
echo ./xcpenc_nocheck -d infile decryptfile >> log

./xcpenc_nocheck -d  infile decryptfile >> log

retval=$?
if test $retval != 0 ; then
        echo xcpenc_nocheck failed with error: $retval >> results
else
        echo xcpenc_nocheck program succeeded >> results
fi

echo  "" >> results
echo  "" >> log

# When password is specified but no option to encrypt/decrypt
# is specified. This testcase should fail
echo No option spciefied with password >> results
echo ./xcpenc_nocheck -p password infile decryptfile >> results
echo ./xcpenc_nocheck -p password infile decryptfile >> log
./xcpenc_nocheck -p password  infile decryptfile >> log

retval=$?
if test $retval != 0 ; then
        echo xcpenc_nocheck failed with error: $retval >> results
else
        echo xcpenc_nocheck program succeeded >> results
fi

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
