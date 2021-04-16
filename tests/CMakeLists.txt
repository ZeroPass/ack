cmake_minimum_required( VERSION 3.14 )
project( eosio_ck_tests )

set( EOSIO_WASM_OLD_BEHAVIOR "Off" )
find_package( eosio.cdt REQUIRED )

set( EOSIO_CK_TEST_SOURCES
  ${PROJECT_SOURCE_DIR}/main.cpp
)

add_native_executable( ${PROJECT_NAME} ${EOSIO_CK_TEST_SOURCES} )
target_include_directories( ${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/../include )