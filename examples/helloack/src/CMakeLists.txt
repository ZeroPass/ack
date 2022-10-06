cmake_minimum_required( VERSION 3.14 )
project( helloack )
find_package( cdt )

add_contract( helloack helloack helloack.cpp )
target_include_directories( helloack PUBLIC
    ${CMAKE_SOURCE_DIR}/../include
    ${PROJECT_SOURCE_DIR}/../../../include
)

target_compile_definitions( ${PROJECT_NAME} INTERFACE
  $<$<BOOL:${ACK_ENABLE_DEBUG_LOG}>:ACK_ENABLE_DEBUG_LOG=1>
)