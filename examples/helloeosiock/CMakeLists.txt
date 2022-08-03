cmake_minimum_required( VERSION 3.14 )
include( ExternalProject )

# if no cdt root is given use default path
if( CDT_ROOT STREQUAL "" OR NOT CDT_ROOT )
   find_package( cdt )
endif()

ExternalProject_Add(
   helloeosiock_project
   SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src
   BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/
   CMAKE_ARGS
      "-DCMAKE_TOOLCHAIN_FILE=${CDT_ROOT}/lib/cmake/cdt/CDTWasmToolchain.cmake"
      "-DEOSIO_CK_ENABLE_DEBUG_LOG=${EOSIO_CK_ENABLE_DEBUG_LOG}"
   UPDATE_COMMAND ""
   PATCH_COMMAND ""
   TEST_COMMAND ""
   INSTALL_COMMAND ""
   BUILD_ALWAYS 1
)