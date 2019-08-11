include_directories(${CMAKE_SOURCE_DIR}/include)

option(WITH_CRYPTOAUTH "use CryptoAuthLib" OFF)
option(WITH_WOLFSSL "use wolfSSL" ON)

set(SOURCES utils.c utils.h cwt.c cwt.h utils.c utils.h edhoc_protocol.c edhoc_protocol.h edhoc.c edhoc.h types.h
        cose.c cose.h oscore.c oscore.h)

add_executable(tests ${SOURCES} tests.cpp edhoc_test.c edhoc_test.h oscore_test.c oscore_test.h cose_test.c cose_test.h)
add_library(oscore ${SOURCES})

set(LIBS tinycbor)

if(WITH_CRYPTOAUTH)
    message(STATUS "WITH_CRYPTOAUTH")
    add_definitions(-DUSE_CRYPTOAUTH=1)
    include_directories(${CRYPTOAUTH_SOURCE_DIR}/lib)
    list(APPEND LIBS ${CRYPTOAUTH_SOURCE_DIR}/lib/libcryptoauth.a)
endif()
if(WITH_WOLFSSL)
  message(STATUS "WITH_WOLFSSL")
  add_definitions(-DUSE_WOLFSSL=1)
  list(APPEND LIBS wolfssl)
endif()

target_link_libraries(tests ${LIBS})
target_link_libraries(oscore ${LIBS})
