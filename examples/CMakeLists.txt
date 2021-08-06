cmake_minimum_required( VERSION 3.14 )
project( eosio_ck_examples )

option( EOSIO_CK_EXAMPLES_BUILD_HELLOEOSIOCK "Build Hello eosio.ck example"          ON )

if ( EOSIO_CK_EXAMPLES_BUILD_HELLOEOSIOCK )
  add_subdirectory( helloeosiock )
endif()