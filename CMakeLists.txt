cmake_minimum_required(VERSION 2.8)

project (network)

SET(CMAKE_SYSTEM_NAME Linux)  

if(APPLE)
  include_directories( /usr/local/include )
  link_directories( /usr/local/lib/ )
endif()

IF(PLATFORM_X86)
add_definitions(-DPLATFORM_X86)
ENDIF(PLATFORM_X86)

include_directories( lib/include/ )
file(GLOB headers "lib/include/*.h" )
file(GLOB sources "lib/src/*.c" )

add_library(network SHARED ${sources} ${headers})

target_link_libraries( network orcania database )

install(TARGETS network DESTINATION /usr/local/lib)
install(FILES "lib/include/network.h" DESTINATION /usr/local/include)
