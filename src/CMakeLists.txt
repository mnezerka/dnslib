
cmake_minimum_required (VERSION 2.8.11)

project (DNSSIM)

#add_executable (dnssim message.cpp query.cpp response.cpp logger.cpp main.cpp)
add_executable (unittests message.cpp logger.cpp unittests.cpp)

add_executable (fakesrv message.cpp logger.cpp fakesrv.cpp)
