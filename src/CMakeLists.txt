include_directories(${CMAKE_SOURCE_DIR}/include)

option(WITH_WOLFSSL "use wolfSSL" OFF)

add_executable(edhoc-test test.c utils.c utils.h cwt.c cwt.h utils.c utils.h protocol.c protocol.h edhoc.c edhoc.h types.h cose.c cose.h)

if(WITH_WOLFSSL)
  message(STATUS "WITH_WOLFSSL")
  add_definitions(-DUSE_WOLFSSL=1)
  target_link_libraries(edhoc-test wolfssl)
endif()

target_link_libraries(edhoc-test tinycbor)
