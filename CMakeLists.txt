cmake_minimum_required(VERSION 3.10)
project(oscore C CXX)

set(CMAKE_C_STANDARD 99)
set(MONGOOSE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mongoose)
set(CRYPTOAUTH_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cryptoauthlib)

add_library(mongoose STATIC ${MONGOOSE_SOURCE_DIR}/mongoose.c)
target_compile_definitions(mongoose PUBLIC MG_ENABLE_COAP)
target_include_directories(mongoose PUBLIC ${MONGOOSE_SOURCE_DIR})

add_subdirectory(src)
