cmake_minimum_required( VERSION 3.14 )
project( eosio.ck )

option( EOSIO_CK_BUILD_TESTS      "Build tests"               ON )
option( EOSIO_CK_BUILD_EXAMPLES   "Build examples"            ON )
option( EOSIO_CK_ENABLE_DEBUG_LOG "Enable debug log printout" OFF )

# Find CDT
if ( EOSIO_CDT_ROOT STREQUAL "" OR NOT EOSIO_CDT_ROOT )
  find_package( eosio.cdt REQUIRED )
endif()

# Make library interface
add_library( ${PROJECT_NAME} INTERFACE )
target_include_directories( ${PROJECT_NAME} INTERFACE "${CMAKE_SOURCE_DIR}/include" )
target_compile_definitions( ${PROJECT_NAME} INTERFACE
  $<$<BOOL:${EOSIO_CK_ENABLE_DEBUG_LOG}>:EOSIO_CK_ENABLE_DEBUG_LOG=1>
)

# Include examples
if ( EOSIO_CK_BUILD_EXAMPLES )
  add_subdirectory( examples )
endif()

# Include tests
if ( EOSIO_CK_BUILD_TESTS )
  include( ExternalProject )

  ExternalProject_Add(
    eosio_ck_tests
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/tests/
    BINARY_DIR ${CMAKE_BINARY_DIR}/tests/
    CMAKE_ARGS
      "-DCMAKE_TOOLCHAIN_FILE=${EOSIO_CDT_ROOT}/lib/cmake/eosio.cdt/EosioCDTWasmToolchain.cmake"
      "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
      "-DEOSIO_CK_ENABLE_DEBUG_LOG=${EOSIO_CK_ENABLE_DEBUG_LOG}"
      "-DCMAKE_CXX_FLAGS_RELEASE='-O3 -g -DNDEBUG'" # -g required in order for the tests to compile in time
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

message( "Building examples............${EOSIO_CK_BUILD_EXAMPLES}" )
message( "Building tests...............${EOSIO_CK_BUILD_TESTS}" )
message( "Debug log enabled............${EOSIO_CK_ENABLE_DEBUG_LOG}" )
