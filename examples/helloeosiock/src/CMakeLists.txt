cmake_minimum_required( VERSION 3.14 )
project( helloeosiock )
find_package( cdt )

add_contract( helloeosiock helloeosiock helloeosiock.cpp )
target_include_directories( helloeosiock PUBLIC
    ${CMAKE_SOURCE_DIR}/../include
    ${PROJECT_SOURCE_DIR}/../../../include
)

target_compile_definitions( ${PROJECT_NAME} INTERFACE
  $<$<BOOL:${EOSIO_CK_ENABLE_DEBUG_LOG}>:EOSIO_CK_ENABLE_DEBUG_LOG=1>
)
