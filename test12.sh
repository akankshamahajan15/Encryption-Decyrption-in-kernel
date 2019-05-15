#!/bin/sh

# This test has NEGATIVE testcase when no argumnets is passed and
# run user program (xcpenc_nocheck) with NO checks at all

echo dummy test > infile

echo  "" >> results
echo  "" >> log
echo test12.sh: Negative tescase No arguments passed  >> results
echo test12.sh: Negative tescase No arguments passed >> log

echo ./xcpenc_nocheck >> results
echo ./xcpenc_nocheck >>  log

./xcpenc_nocheck >> log

retval=$?
if test $retval != 0 ; then
	echo xcpenc_nocheck failed with error: $retval >> results
else
	echo xcpenc_nocheck program succeeded >> results
fi

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
