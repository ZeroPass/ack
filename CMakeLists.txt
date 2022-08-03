cmake_minimum_required( VERSION 3.14 )
project( eosio.ck )

option( EOSIO_CK_BUILD_TESTS    "Build tests"             ON )
option( EOSIO_CK_BUILD_EXAMPLES "Build examples"          ON )

# Find CDT
if ( CDT_ROOT STREQUAL "" OR NOT CDT_ROOT )
  find_package( cdt REQUIRED )
endif()

# Include examples
if ( EOSIO_CK_BUILD_EXAMPLES )
  add_subdirectory( examples )
endif()

add_library( ${PROJECT_NAME} INTERFACE )
target_include_directories( ${PROJECT_NAME} INTERFACE "${CMAKE_SOURCE_DIR}/include" )

include( ExternalProject )

# Include tests
if ( EOSIO_CK_BUILD_TESTS )
  ExternalProject_Add(
    eosio_ck_tests
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/tests/
    BINARY_DIR ${CMAKE_BINARY_DIR}/tests/
    CMAKE_ARGS
      "-DCMAKE_TOOLCHAIN_FILE=${CDT_ROOT}/lib/cmake/cdt/CDTWasmToolchain.cmake"
      "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
    UPDATE_COMMAND ""
    PATCH_COMMAND ""
    TEST_COMMAND ""
    INSTALL_COMMAND ""
    BUILD_ALWAYS 1
  )

  include (CTest)
  enable_testing()
  add_test( eosio_ck_tests ${CMAKE_BINARY_DIR}/tests/eosio_ck_tests )
endif( EOSIO_CK_BUILD_TESTS )

message( "Building examples..........${EOSIO_CK_BUILD_EXAMPLES}" )
message( "Building tests.............${EOSIO_CK_BUILD_TESTS}" )
