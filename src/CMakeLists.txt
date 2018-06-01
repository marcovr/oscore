include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(ace-rs-mg main.c hkdf.c hkdf.h utils.c utils.h cwt.c cwt.h utils.c utils.h edhoc.c edhoc.h types.h cose.c cose.h)
target_include_directories(ace-rs-mg PUBLIC ${CRYPTOAUTH_SOURCE_DIR}/lib)
target_link_libraries(ace-rs-mg mongoose mbedtls mbedcrypto tinycbor ${CRYPTOAUTH_SOURCE_DIR}/.build/libcryptoauth.a)
