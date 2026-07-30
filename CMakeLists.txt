cmake_minimum_required(VERSION 3.20)
project(adaptive_6lowpan VERSION 1.0.0 LANGUAGES C)

option(ADAPTIVE_WITH_LIBOQS "Enable ML-KEM/liboqs production provider" OFF)
option(ADAPTIVE_BUILD_TESTS "Build tests" ON)
option(ADAPTIVE_BUILD_DEMO "Build host demonstration" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(ADAPTIVE_CORE_SOURCES
  src/types.c
  src/config.c
  src/metrics.c
  src/hmm.c
  src/wavelet_db4.c
  src/codec.c
  src/coap_block.c
  src/security.c
  src/security_oqs.c
  src/aad.c
  src/pipeline.c
  src/receiver.c
)

add_library(adaptive6lowpan STATIC ${ADAPTIVE_CORE_SOURCES})
target_include_directories(adaptive6lowpan PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(adaptive6lowpan PUBLIC m)
target_compile_options(adaptive6lowpan PRIVATE
  -Wall -Wextra -Wpedantic
)

if(ADAPTIVE_WITH_LIBOQS)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(LIBOQS REQUIRED IMPORTED_TARGET liboqs)
  find_package(OpenSSL REQUIRED COMPONENTS Crypto)
  target_compile_definitions(adaptive6lowpan PRIVATE ADAPTIVE_WITH_LIBOQS)
  target_link_libraries(adaptive6lowpan PRIVATE
    PkgConfig::LIBOQS OpenSSL::Crypto
  )
endif()

add_library(adaptive_test_security STATIC src/security_test.c)
target_include_directories(adaptive_test_security PUBLIC include)

if(ADAPTIVE_BUILD_DEMO)
  add_executable(adaptive_demo src/main.c)
  target_link_libraries(adaptive_demo PRIVATE
    adaptive6lowpan adaptive_test_security
  )
endif()

if(ADAPTIVE_BUILD_TESTS)
  enable_testing()
  add_executable(adaptive_tests tests/test_main.c)
  target_link_libraries(adaptive_tests PRIVATE
    adaptive6lowpan adaptive_test_security
  )
  add_test(NAME adaptive_tests
           COMMAND adaptive_tests
           WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()
