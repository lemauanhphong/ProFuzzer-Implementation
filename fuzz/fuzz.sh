export AFL_CUSTOM_MUTATOR_ONLY=1
export AFL_CUSTOM_MUTATOR_LIBRARY="/src/mutator/exploration.so"
export AFL_DISABLE_TRIM=1
export IGNORE_EXE_STDOUT=1
export TARGET="../target/vuln"
g++ -shared -Wall -O3 -fPIC -I../mutator/include ../mutator/exploration.cpp ../probe/probe.cpp  -o ../mutator/exploration.so -lstdc++fs &&
# g++ -shared -Wall -O3 ../mutator/exploitation.cpp -o ../mutator/exploitation.so
# gcc -shared -Wall -O3 ../mutator/exploration.c -o ../mutator/exploration.so
# gcc -shared -Wall -O3 ../mutator/exploitation.c -o ../mutator/exploitation.so
afl-fuzz -i ../seeds/ -o ../output ../target/vuln


