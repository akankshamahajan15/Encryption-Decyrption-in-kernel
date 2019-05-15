#!/bin/sh

# This test has NEGATIVE testcase related to -C and copy flag -c and all following
# testcases should fail. This run user program (xcpenc_nocheck) with NO checks

echo dummy test > infile_ec

echo  "" >> results_ec
echo  "" >> log_ec
echo test_ec10.sh: Negative testcase   >> results_ec
echo test_ec10.sh: Negative testcase  >> log_ec

# When -C is specified with -c (copy) it will fail
echo -C specified with -c   >> results_ec
echo ./xcpenc_nocheck -c  infile_ec outfile_ec -C cast6 >> results_ec
echo ./xcpenc_nocheck -c  infile_ec outfile_ec -C cast6>>  log_ec

./xcpenc_nocheck -e -c  infile_ec outfile_ec -C cast6>> log_ec

retval=$?
if test $retval != 0 ; then
	echo encryption: xcpenc_nocheck failed with error: $retval >> results_ec
else
	echo encryption: xcpenc_nocheck program succeeded >> results_ec
fi

echo  "" >> results_ec
echo  "" >> log_ec

# when wrong or invalid cipher name is specified, it will fail
echo wrong cipher name specified >> results_ec
echo ./xcpenc_nocheck -p password -e infile_ec outfile_ec -C abcde >> results_ec
echo ./xcpenc_nocheck -p password -e infile_ec outfile_ec -C abcde >> log_ec
./xcpenc_nocheck  -p "password" -e infile_ec outfile_ec  -C abcde >> log_ec

retval=$?
if test $retval != 0 ; then
        echo xcpenc_nocheck failed with error: $retval >> results_ec
else
        echo xcpenc_nocheck program succeeded >> results_ec
fi

echo "------------------------------------------------------------------------------" >> results_ec
echo "------------------------------------------------------------------------------" >> log_ec
