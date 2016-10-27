CMAKE_MINIMUM_REQUIRED(VERSION 2.8.11)
CMAKE_POLICY(SET CMP0003 NEW)

FIND_PACKAGE(OpenSSL)

INCLUDE_DIRECTORIES(
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

SET(CMAKE_SHARED_LINKER_FLAGS "-L${OPENSSL_LIBRARIES}")
LINK_DIRECTORIES(${OPENSSL_LIB_DIR})

SET(SRCS
    src/h2get.c
    src/h2get_mruby.c
    src/h2get_read.c
    src/hpack.c
    src/read_bits.c
    src/plain.c
    src/ssl.c)

IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" AND SANITIZE)
	SET(CMAKE_C_FLAGS "-fsanitize=address")
ENDIF()
FOREACH(SRC ${SRCS})
	SET_SOURCE_FILES_PROPERTIES(${SRC} PROPERTIES COMPILE_FLAGS "-std=c11 -g -O0 -fno-omit-frame-pointer -D_GNU_SOURCE -Wall -Wmissing-prototypes -Wstrict-prototypes -Werror")
ENDFOREACH(SRC)

ADD_EXECUTABLE(h2get
    ${SRCS}
)

#
# Tests
#
ENABLE_TESTING()

MACRO(DECL_TEST _NAME)
    ADD_EXECUTABLE(${_NAME} ${ARGN})
    SET_TARGET_PROPERTIES(${_NAME} PROPERTIES COMPILE_FLAGS "-DTEST -D${_NAME}=main")
    ADD_TEST(${_NAME} ${CMAKE_CURRENT_BINARY_DIR}/${_NAME})
ENDMACRO()

DECL_TEST(test_decode_int src/hpack.c src/read_bits.c)
DECL_TEST(test_read_bits src/read_bits.c)
DECL_TEST(test_decode_string src/hpack.c src/read_bits.c)
DECL_TEST(test_decode_header_frame src/hpack.c src/read_bits.c src/hpack.c)
DECL_TEST(test_decode_header_successive_frames src/hpack.c src/read_bits.c src/hpack.c)

ADD_CUSTOM_TARGET(check ${CMAKE_COMMAND} -E env CTEST_OUTPUT_ON_FAILURE=1
	${CMAKE_CTEST_COMMAND} -C $<CONFIG> --verbose
	WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

TARGET_LINK_LIBRARIES(h2get ${OPENSSL_LIBRARIES})

FIND_PROGRAM(CLANG_FORMAT_BIN clang-format)
IF (CLANG_FORMAT_BIN)
	ADD_CUSTOM_TARGET(fmt ${CLANG_FORMAT_BIN} -sort-includes -i ${SRCS})
ENDIF()

IF (${CMAKE_C_COMPILER_ID} STREQUAL "Clang")
	SET(MRUBY_TOOLCHAIN "clang")
ELSE ()
	SET(MRUBY_TOOLCHAIN "gcc")
ENDIF ()

ADD_CUSTOM_TARGET(mruby MRUBY_TOOLCHAIN=${MRUBY_TOOLCHAIN}
			MRUBY_CONFIG=${CMAKE_CURRENT_SOURCE_DIR}/misc/mruby_config.rb
			MRUBY_BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}/mruby ruby minirake
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deps/mruby-1.2.0)

TARGET_INCLUDE_DIRECTORIES(h2get BEFORE PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/deps/mruby-1.2.0/include)
    # note: the paths need to be determined before libmruby.flags.mak is generated
TARGET_LINK_LIBRARIES(h2get "${CMAKE_CURRENT_BINARY_DIR}/mruby/host/lib/libmruby.a" m)
ADD_DEPENDENCIES(h2get mruby)

