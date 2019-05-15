#!/bin/sh

# This test basic functionality of encryption decryption and whether two files
# after encryption are same or not

/bin/rm -f log_ec
/bin/rm -f results_ec

touch log_ec
touch results_ec

echo ""
echo "EXTRA CREDIT scripts"
echo ""
for i in {01..10}
do
    echo running script test_ec$i.sh
    ./test_ec$i.sh
    echo completed script test_ec$i.sh
    echo ""
done
