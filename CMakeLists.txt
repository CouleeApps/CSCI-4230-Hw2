cmake_minimum_required(VERSION 3.0)
project(Crypto2)

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_CXX_FLAGS "-Wall")

add_executable(client client.cpp des.h)
add_executable(server server.cpp des.h)