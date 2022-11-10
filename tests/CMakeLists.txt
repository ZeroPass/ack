cmake_minimum_required( VERSION 3.14 )
project( ack_tests )

find_package( cdt REQUIRED )

set( ACK_TEST_SOURCES
  ${PROJECT_SOURCE_DIR}/main.cpp
)

add_native_executable( ${PROJECT_NAME} ${ACK_TEST_SOURCES} )
target_include_directories( ${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/include )
target_include_directories( ${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/../include )

target_compile_definitions( ${PROJECT_NAME} PRIVATE
  ACK_NO_INTRINSICS=1
  $<$<BOOL:${ACK_ENABLE_DEBUG_LOG}>:ACK_ENABLE_DEBUG_LOG=1>
)
