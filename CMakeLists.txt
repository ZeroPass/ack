cmake_minimum_required( VERSION 3.14 )
project( eosio.ck )

#option( EOSIO_CK_BUILD_EXAMPLES "build example contracts" ON )
option( EOSIO_CK_BUILD_TESTS    "build tests"             ON )

# Find EOSIO.CDT
set( EOSIO_WASM_OLD_BEHAVIOR "Off" )
if ( EOSIO_CDT_ROOT STREQUAL "" OR NOT EOSIO_CDT_ROOT )
  find_package( eosio.cdt REQUIRED )
endif()

add_library(${PROJECT_NAME} INTERFACE)
target_include_directories(${PROJECT_NAME} INTERFACE "${CMAKE_SOURCE_DIR}/include")


include( ExternalProject )
#[[
if ( EOSIO_CK_BUILD_EXAMPLES )
  ExternalProject_Add(
    eosio_ck_examples
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/examples
    BINARY_DIR ${CMAKE_BINARY_DIR}/examples
    CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${EOSIO_CDT_ROOT}/lib/cmake/eosio.cdt/EosioWasmToolchain.cmake
    UPDATE_COMMAND ""
    PATCH_COMMAND ""
    TEST_COMMAND ""
    INSTALL_COMMAND ""
    BUILD_ALWAYS 1
  )
endif()
]]

if ( EOSIO_CK_BUILD_TESTS )
#[[
ExternalProject_Add(
    eosio_ck_tests
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/tests
    BINARY_DIR ${CMAKE_BINARY_DIR}/tests
    CMAKE_ARGS
      "-DEOSIO_CDT_ROOT=${EOSIO_CDT_ROOT}"
      "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
      "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}"
      "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
    UPDATE_COMMAND ""
    PATCH_COMMAND ""
    TEST_COMMAND ""
    INSTALL_COMMAND ""
    BUILD_ALWAYS 1
  )
  ]]
  ExternalProject_Add(
    eosio_ck_tests
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/tests/
    BINARY_DIR ${CMAKE_BINARY_DIR}/tests/
    CMAKE_ARGS
      "-DCMAKE_TOOLCHAIN_FILE=${EOSIO_CDT_ROOT}/lib/cmake/eosio.cdt/EosioWasmToolchain.cmake"
      "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
    UPDATE_COMMAND ""
    PATCH_COMMAND ""
    TEST_COMMAND ""
    INSTALL_COMMAND ""
    BUILD_ALWAYS 1
  )

  ### add a new test
  include (CTest)
  enable_testing()
  #[[
  if ( EOSIO_CK_BUILD_EXAMPLES_TESTS )
    add_test( eosio_ck_examples ${CMAKE_BINARY_DIR}/examples/ )
  endif()
  ]]
  if ( EOSIO_CK_BUILD_TESTS )
    add_test( eosio_ck_tests ${CMAKE_BINARY_DIR}/tests/ )
  endif()
endif()

#message("Building examples..........${EOSIO_CK_BUILD_EXAMPLES}")
message("Building tests.............${EOSIO_CK_BUILD_TESTS}")
