#!/bin/sh

# This test basic functionality of encryption decryption and whether two files
# after encryption are same or not

/bin/rm -f log
/bin/rm -f results

touch log
touch results

for i in {01..12}
do
    echo running script test$i.sh
    ./test$i.sh
    echo completed script test$i.sh
    echo ""
done
