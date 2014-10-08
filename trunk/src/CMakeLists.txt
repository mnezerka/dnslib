
cmake_minimum_required (VERSION 2.8.11)

project (DNSSIM)

#add_executable (dnssim message.cpp query.cpp response.cpp logger.cpp main.cpp)
add_executable (unittests buffer.cpp message.cpp rr.cpp logger.cpp unittests.cpp)

add_executable (fakesrv buffer.cpp message.cpp rr.cpp logger.cpp fakesrv.cpp)
