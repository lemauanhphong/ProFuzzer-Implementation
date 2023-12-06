export IGNORE_EXE_STDOUT=1
# export AFL_DEBUG=1
g++ -g -o probe probe.cpp -lstdc++fs && ./probe ../seeds/input template/ ../target/vuln
