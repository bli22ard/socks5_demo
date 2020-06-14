cmake_minimum_required(VERSION 3.15)
PROJECT(socks5_demo)

aux_source_directory(. DIR_SRCS)

add_executable(socks5_demo ${DIR_SRCS})
