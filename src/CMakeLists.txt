
cmake_minimum_required (VERSION 2.6.4)

project (DNSLIB)

set(CMAKE_CXX_FLAGS "-Wall -O2")
#set(CMAKE_CXX_FLAGS "-Wall -g")

set(SOURCES buffer.cpp message.cpp rr.cpp qs.cpp)

add_library (dnslib ${SOURCES})

add_executable (unittests unittests.cpp)
target_link_libraries (unittests dnslib)

add_executable (fakesrv fakesrv.cpp)
target_link_libraries (fakesrv dnslib)

add_executable (fakecli fakecli.cpp)
target_link_libraries (fakecli dnslib)

target_compile_options(unittests PRIVATE -Werror -Wall -Wextra)