cmake_minimum_required(VERSION 3.10)
project(oscore C CXX)

set(CMAKE_C_STANDARD 99)
set(SOURCE_FILES src/*.c)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/build)
set(MONGOOSE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mongoose)
set(CRYPTOAUTH_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cryptoauthlib)

#add_library(mongoose STATIC ${MONGOOSE_SOURCE_DIR}/mongoose.c)
#target_compile_definitions(mongoose PUBLIC MG_ENABLE_COAP)
#target_include_directories(mongoose PUBLIC ${MONGOOSE_SOURCE_DIR})

find_package(Doxygen)
if (DOXYGEN_FOUND)
    set(BUILD_DOC_DIR build/docs)
    if(NOT EXISTS ${BUILD_DOC_DIR})
        file(MAKE_DIRECTORY ${BUILD_DOC_DIR})
    endif()

    add_custom_target(Doxygen ALL
            COMMAND ${CMAKE_COMMAND} -E echo_append "Building Documentation..."
            COMMAND ${DOXYGEN_EXECUTABLE} doxygen/Doxyfile
            COMMAND ${CMAKE_COMMAND} -E echo "Done."
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM)
else (DOXYGEN_FOUND)
    message("Doxygen needs to be installed to generate the documentation.")
endif (DOXYGEN_FOUND)

add_subdirectory(src)
