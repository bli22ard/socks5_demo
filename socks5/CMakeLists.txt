cmake_minimum_required(VERSION 3.13.4)
PROJECT(socks5_demo)
find_package (Threads)

aux_source_directory(. DIR_SRCS)

add_executable(socks5_demo ${DIR_SRCS})
target_link_libraries (socks5_demo ${CMAKE_THREAD_LIBS_INIT})
