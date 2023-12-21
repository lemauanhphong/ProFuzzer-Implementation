#!/bin/sh
export CC=afl-cc
export CXX=afl-c++
cd exiv2-0.26 
make configure
./configure --disable-shared
make clean all -j10
