--- hello eosio.ck project ---
 An example contract for testing RSA signature verification with `eosio.ck` library.

 -- How to Build with CMake and Make --
   - cd into the 'build' directory
   - run the command 'cmake ..'
   - run the command 'make'

 - After build -
   - The built smart contract is under the 'helloeosiock' directory in the 'build/examples' directory
   - You can then do a 'set contract' action with 'cleos' and point to the './build/examples/helloeosiock' directory

- Additions to cmake should be done to the CMakeLists.txt in the './src' directory and not in the top level CMakeLists.txt

 -- How to build with eosio-cpp --
   - cd into the 'build' directory
   - run the command 'eosio-cpp -abigen ../src/helloeosiock.cpp -o helloeosiock.wasm -I ../include/'

 - After build -
   - The built smart contract is in the 'build/examples/helloeosiock' directory
   - You can then do a 'set contract' action with 'cleos' and point to the 'build/examples/helloeosiock' directory
