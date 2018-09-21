include_directories(${CMAKE_SOURCE_DIR}/include)

option(WITH_CRYPTOAUTH "use CryptoAuthLib" ON)
option(WITH_MBEDTLS "use mbed TLS" ON)

add_executable(edhoc-test test.c utils.c utils.h cwt.c cwt.h utils.c utils.h protocol.c protocol.h edhoc.c edhoc.h types.h cose.c cose.h)

if(WITH_CRYPTOAUTH)
    message(STATUS "WITH_CRYPTOAUTH")
    add_definitions(-DUSE_CRYPTOAUTH=1)
    target_include_directories(edhoc-test PUBLIC ${CRYPTOAUTH_SOURCE_DIR}/lib)
    target_link_libraries(edhoc-test ${CRYPTOAUTH_SOURCE_DIR}/.build/libcryptoauth.a)
endif()
if(WITH_MBEDTLS)
    message(STATUS "WITH_MBEDTLS")
    add_definitions(-DUSE_MBEDTLS=1)
    target_link_libraries(edhoc-test mbedtls mbedcrypto)
endif()

target_link_libraries(edhoc-test tinycbor)
