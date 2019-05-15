obj-m += sys_xcpenc.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: xcpenc cpenc xcpenc_nocheck

xcpenc: xcpenc.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi xcpenc.c -o xcpenc -lcrypto

xcpenc_nocheck: xcpenc_nocheck.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi xcpenc_nocheck.c -o xcpenc_nocheck

cpenc:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xcpenc xcpenc_nocheck
