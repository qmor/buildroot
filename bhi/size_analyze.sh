#!/bin/sh
cwd=$(pwd)
cd ..
rm -rf output/build/linux-custom/
make -j32
cd output/build/linux-custom/
size */built-in.a | sort -n -r -k 4 > sizes.txt
objdump -x vmlinux > syms.txt
cd ${cwd}
