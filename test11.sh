#!/bin/sh

# This test has NEGATIVE testcase when no argumnets is passed and
# run user program (xcpenc) with all checks

echo dummy test > infile

echo  "" >> results
echo  "" >> log
echo test11.sh: Negative tescase No arguments passed >> results
echo test11.sh: Negative tescase No arguments passed >> log

echo ./xcpenc >> results
echo ./xcpenc >>  log

./xcpenc >> log

retval=$?
if test $retval != 0 ; then
	echo xcpenc failed with error: $retval >> results
else
	echo xcpenc program succeeded >> results
fi

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
