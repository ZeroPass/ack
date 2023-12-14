cmake_minimum_required( VERSION 3.14 )
project( ack_tests )

find_package( cdt REQUIRED )

set( ACK_TESTS_SRC_DIR
  ${PROJECT_SOURCE_DIR}/src
)

# ack_gen_tests
add_native_executable( ack_gen_tests ${ACK_TESTS_SRC_DIR}/ack_gen_tests.cpp )
target_include_directories( ack_gen_tests PRIVATE ${PROJECT_SOURCE_DIR}/include )
target_include_directories( ack_gen_tests PRIVATE ${PROJECT_SOURCE_DIR}/../include )

target_compile_definitions( ack_gen_tests PRIVATE
  ACK_NO_INTRINSICS=1
  $<$<BOOL:${ACK_ENABLE_DEBUG_LOG}>:ACK_ENABLE_DEBUG_LOG=1>
)

# ack_ecc_tests
add_native_executable( ack_ecc_tests ${ACK_TESTS_SRC_DIR}/ack_ecc_tests.cpp )
target_include_directories( ack_ecc_tests PRIVATE ${PROJECT_SOURCE_DIR}/include )
target_include_directories( ack_ecc_tests PRIVATE ${PROJECT_SOURCE_DIR}/../include )

target_compile_definitions( ack_ecc_tests PRIVATE
  ACK_NO_INTRINSICS=1
  $<$<BOOL:${ACK_ENABLE_DEBUG_LOG}>:ACK_ENABLE_DEBUG_LOG=1>
)

# ack_rsa_tests
add_native_executable( ack_rsa_tests ${ACK_TESTS_SRC_DIR}/ack_rsa_tests.cpp )
target_include_directories( ack_rsa_tests PRIVATE ${PROJECT_SOURCE_DIR}/include )
target_include_directories( ack_rsa_tests PRIVATE ${PROJECT_SOURCE_DIR}/../include )

target_compile_definitions( ack_rsa_tests PRIVATE
  ACK_NO_INTRINSICS=1
  $<$<BOOL:${ACK_ENABLE_DEBUG_LOG}>:ACK_ENABLE_DEBUG_LOG=1>
)
