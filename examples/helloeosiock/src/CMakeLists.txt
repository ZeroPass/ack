project(helloeosiock)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)

add_contract( helloeosiock helloeosiock helloeosiock.cpp )
target_include_directories( helloeosiock PUBLIC ${CMAKE_SOURCE_DIR}/../include  ${PROJECT_SOURCE_DIR}/../../../include )
