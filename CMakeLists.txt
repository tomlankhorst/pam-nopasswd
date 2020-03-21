cmake_minimum_required(VERSION 3.15)
project(pam_nopasswd C)

set(CMAKE_C_STANDARD 11)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_library(libpam REQUIRED)
include_directories(${libpam_INCLUDE_DIRS})

add_library(pam_nopasswd_64 SHARED pam_nopasswd.c)
target_link_libraries(pam_nopasswd_64 ${libpam_LIBRARIES} -m64)