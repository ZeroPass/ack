cmake_minimum_required( VERSION 3.14 )
include( ExternalProject )

# if no cdt root is given use default path
if( EOSIO_CDT_ROOT STREQUAL "" OR NOT EOSIO_CDT_ROOT )
   set(EOSIO_WASM_OLD_BEHAVIOR "Off")
   find_package( eosio.cdt )
endif()

ExternalProject_Add(
   helloeosiock_project
   SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src
   BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/
   CMAKE_ARGS
      "-DCMAKE_TOOLCHAIN_FILE=${EOSIO_CDT_ROOT}/lib/cmake/eosio.cdt/EosioWasmToolchain.cmake"
      "-DEOSIO_CK_ENABLE_DEBUG_LOG=${EOSIO_CK_ENABLE_DEBUG_LOG}"
   UPDATE_COMMAND ""
   PATCH_COMMAND ""
   TEST_COMMAND ""
   INSTALL_COMMAND ""
   BUILD_ALWAYS 1
)