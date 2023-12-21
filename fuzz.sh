export AFL_CUSTOM_MUTATOR_ONLY=1
export AFL_CUSTOM_MUTATOR_LIBRARY="mutator/mutator.so"
export AFL_DISABLE_TRIM=1
export IGNORE_EXE_STDOUT=1
export TARGET="target/exiv2-0.26/bin/exiv2"
g++ -shared -Wall -O3 -fPIC -Imutator/include/probe -I/AFLplusplus/include mutator/mutator.cpp probe/probe.cpp mutator/fields.cpp -o mutator/mutator.so -lstdc++fs
afl-fuzz -i seeds -o out $TARGET @@

