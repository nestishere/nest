cmake_minimum_required(VERSION 3.16)
project(nest_phase0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

add_executable(crypto_demo crypto_demo.cpp)
target_include_directories(crypto_demo PRIVATE ${SODIUM_INCLUDE_DIRS})
target_link_libraries(crypto_demo PRIVATE ${SODIUM_LIBRARIES})
target_compile_options(crypto_demo PRIVATE ${SODIUM_CFLAGS_OTHER})
