cmake_minimum_required( VERSION 3.14 )
project( eosio_ck_tests )

find_package( cdt REQUIRED )

set( EOSIO_CK_TEST_SOURCES
  ${PROJECT_SOURCE_DIR}/main.cpp
)

add_native_executable( ${PROJECT_NAME} ${EOSIO_CK_TEST_SOURCES} )
target_include_directories( ${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include )
target_include_directories( ${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/../include )

target_compile_definitions( ${PROJECT_NAME} PUBLIC
  $<$<BOOL:${EOSIO_CK_ENABLE_DEBUG_LOG}>:EOSIO_CK_ENABLE_DEBUG_LOG=1>
)
