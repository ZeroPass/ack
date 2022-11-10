cmake_minimum_required( VERSION 3.14 )
project( ack_examples )

option( ACK_EXAMPLES_BUILD_HELLOACK "Build Hello ack example" ON )

if ( ACK_EXAMPLES_BUILD_HELLOACK )
  add_subdirectory( helloack )
endif()