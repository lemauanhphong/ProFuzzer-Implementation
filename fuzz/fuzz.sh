export AFL_CUSTOM_MUTATOR_ONLY=1
export AFL_CUSTOM_MUTATOR_LIBRARY="/home/paml/doanvuive/ProFuzzer-Implementation/mutator/exploration.so"
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
g++ -shared -Wall -O3 -I ../mutator/include ../mutator/exploration.cpp ../probe/probe.cpp -fPIC -o ../mutator/exploration.so -lstdc++fs
# g++ -shared -Wall -O3 ../mutator/exploitation.cpp -o ../mutator/exploitation.so
# gcc -shared -Wall -O3 ../mutator/exploration.c -o ../mutator/exploration.so
# gcc -shared -Wall -O3 ../mutator/exploitation.c -o ../mutator/exploitation.so
afl-fuzz -i ../seeds/ -o ../output ../target/vuln


