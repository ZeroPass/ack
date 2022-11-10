cmake_minimum_required( VERSION 3.14 )
include( ExternalProject )

# if no cdt root is given use default path
if( CDT_ROOT STREQUAL "" OR NOT CDT_ROOT )
   find_package( cdt )
endif()

ExternalProject_Add(
   helloack_project
   SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src
   BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/
   CMAKE_ARGS
      "-DACK_NO_INTRINSICS=${ACK_NO_INTRINSICS}"
      "-DACK_ENABLE_DEBUG_LOG=${ACK_ENABLE_DEBUG_LOG}"
      "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
      "-DCMAKE_TOOLCHAIN_FILE=${CDT_ROOT}/lib/cmake/cdt/CDTWasmToolchain.cmake"
   UPDATE_COMMAND ""
   PATCH_COMMAND ""
   TEST_COMMAND ""
   INSTALL_COMMAND ""
   BUILD_ALWAYS 1
)