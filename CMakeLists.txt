cmake_minimum_required(VERSION 3.10)

file(GLOB_RECURSE CXX_SRC "arduino_main/*.cpp")

add_executable(arduino_communication ${CXX_SRC})