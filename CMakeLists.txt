cmake_minimum_required( VERSION 3.14 )
project( ack )

option( ACK_BUILD_TESTS      "Build tests"               ON  )
option( ACK_BUILD_EXAMPLES   "Build examples"            ON  )
option( ACK_ENABLE_DEBUG_LOG "Enable debug log printout" OFF )

# Find CDT
if ( CDT_ROOT STREQUAL "" OR NOT CDT_ROOT )
  find_package( cdt REQUIRED )
endif()

# Make library interface
add_library( ${PROJECT_NAME} INTERFACE )
target_include_directories( ${PROJECT_NAME} INTERFACE "${CMAKE_SOURCE_DIR}/include" )
target_compile_definitions( ${PROJECT_NAME} INTERFACE
  $<$<BOOL:${ACK_ENABLE_DEBUG_LOG}>:ACK_ENABLE_DEBUG_LOG=1>
)

# Include examples
if ( ACK_BUILD_EXAMPLES )
  add_subdirectory( examples )
endif()

# Include tests
if ( ACK_BUILD_TESTS )
  include( ExternalProject )

  ExternalProject_Add(
    ack_tests
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/tests/
    BINARY_DIR ${CMAKE_BINARY_DIR}/tests/
    CMAKE_ARGS
      "-DCMAKE_TOOLCHAIN_FILE=${CDT_ROOT}/lib/cmake/cdt/CDTWasmToolchain.cmake"
      "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
      "-DACK_ENABLE_DEBUG_LOG=${ACK_ENABLE_DEBUG_LOG}"
      "-DCMAKE_CXX_FLAGS_RELEASE='-O3 -g -DNDEBUG'" # -g required in order for the tests to compile in time
    UPDATE_COMMAND ""
    PATCH_COMMAND ""
    TEST_COMMAND ""
    INSTALL_COMMAND ""
    BUILD_ALWAYS 1
  )

  include (CTest)
  enable_testing()
  add_test( ack_tests ${CMAKE_BINARY_DIR}/tests/ack_tests )
endif( ACK_BUILD_TESTS )

message( "Building examples............${ACK_BUILD_EXAMPLES}" )
message( "Building tests...............${ACK_BUILD_TESTS}" )
message( "Debug log enabled............${ACK_ENABLE_DEBUG_LOG}" )
