export AFL_BENCH_UNTIL_CRASH=1 # exit to stop the probing engine
export AFL_CUSTOM_MUTATOR_ONLY=1
export AFL_CUSTOM_MUTATOR_LIBRARY="$PWD/probe/probe.so"
export AFL_DEBUG=1
export AFL_NO_UI=1
gcc -g -shared -Wall -O3 probe/probe.c -o probe/probe.so -I include/AFLplusplus
afl-fuzz -i seeds/ -o output/probe ./target/vuln