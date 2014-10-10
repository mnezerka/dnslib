
cmake_minimum_required (VERSION 2.8.11)

project (DNSLIB)

#set(CMAKE_CXX_FLAGS "-Wall -O2 -g")
set(CMAKE_CXX_FLAGS "-Wall -g")

add_executable (unittests buffer.cpp message.cpp rr.cpp qs.cpp unittests.cpp)
add_executable (fakesrv buffer.cpp message.cpp rr.cpp qs.cpp fakesrv.cpp)
