#!/bin/sh

# This test has NEGATIVE testcase related to -C and copy flag -c and all following
# testcases should fail. This run user program (xcpenc) with all checks

echo dummy test > infile_ec

echo  "" >> results_ec
echo  "" >> log_ec
echo test_ec09.sh: Negative testcase   >> results_ec
echo test_ec09.sh: Negative testcase  >> log_ec

# When -C is specified with -c (copy) it will fail
echo -C specified with -c   >> results_ec
echo ./xcpenc -c  infile_ec outfile_ec -C cast6 >> results_ec
echo ./xcpenc -c  infile_ec outfile_ec -C cast6>>  log_ec

./xcpenc -c  infile_ec outfile_ec -C cast6>> log_ec

retval=$?
if test $retval != 0 ; then
	echo encryption: xcpenc failed with error: $retval >> results_ec
else
	echo encryption: xcpenc program succeeded >> results_ec
fi

echo  "" >> results_ec
echo  "" >> log_ec

# when wrong or invalid cipher name is specified, it will fail
echo wrong cipher name specified >> results_ec
echo ./xcpenc -p password -e infile_ec outfile_ec -C abcde >> results_ec
echo ./xcpenc -p password -e infile_ec outfile_ec -C abcde >> log_ec
./xcpenc  -p "password" -e infile_ec outfile_ec -C abcde>> log_ec

retval=$?
if test $retval != 0 ; then
        echo xcpenc failed with error: $retval >> results_ec
else
        echo xcpenc program succeeded >> results_ec
fi

echo "------------------------------------------------------------------------------" >> results_ec
echo "------------------------------------------------------------------------------" >> log_ec
