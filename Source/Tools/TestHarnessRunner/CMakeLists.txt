list(APPEND LIBS FEXCore Common JemallocLibs ${PTHREAD_LIB})

# macOS requires Security framework for SecRandomCopyBytes
if (APPLE)
  find_library(SECURITY_FRAMEWORK Security)
  list(APPEND LIBS ${SECURITY_FRAMEWORK})
endif()

set(SRCS TestHarnessRunner.cpp)
if (NOT MINGW)
  list(APPEND SRCS TestHarnessRunner/HostRunner.cpp)
  list(APPEND LIBS LinuxEmulation CommonTools)
endif()

add_executable(TestHarnessRunner ${SRCS})

if (ENABLE_VIXL_SIMULATOR)
  target_compile_definitions(TestHarnessRunner PRIVATE "-DVIXL_SIMULATOR=1")
endif()

target_include_directories(TestHarnessRunner PRIVATE ${CMAKE_BINARY_DIR}/generated)

target_link_libraries(TestHarnessRunner PRIVATE ${LIBS})
