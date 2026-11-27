cmake_minimum_required(VERSION 3.16)
project(varta VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Sources are UTF-8 (Ukrainian text, arrows in the GUI). MSVC otherwise assumes the
# Windows ANSI code page and mangles them.
if(MSVC)
  add_compile_options(/utf-8)
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Everything except main.cpp goes into a library so the tests can link it.
add_library(varta_core STATIC
  src/util.cpp
  src/net.cpp
  src/config.cpp
  src/blocklists.cpp
  src/rules.cpp
  src/hosts.cpp
  src/firewall.cpp
  src/platform.cpp
  src/app.cpp
  src/menu.cpp
)
target_include_directories(varta_core PUBLIC src)

if(MSVC)
  target_compile_options(varta_core PRIVATE /W4)
  target_compile_definitions(varta_core PUBLIC _CRT_SECURE_NO_WARNINGS)
else()
  target_compile_options(varta_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(WIN32)
  target_link_libraries(varta_core PUBLIC ws2_32 advapi32)
endif()

add_executable(varta src/main.cpp)
target_link_libraries(varta PRIVATE varta_core)

option(VARTA_BUILD_TESTS "Build unit tests" ON)
if(VARTA_BUILD_TESTS)
  enable_testing()
  add_executable(varta_tests tests/test_main.cpp)
  target_link_libraries(varta_tests PRIVATE varta_core)
  add_test(NAME varta_tests COMMAND varta_tests)
endif()

install(TARGETS varta RUNTIME DESTINATION bin)

# ---------------------------------------------------------------------------------------
# vartad: interactive application firewall daemon
#   Linux:   libnetfilter_queue (NFQUEUE) + nftables/iptables
#   Windows: WinDivert 2.2 (pass -DVARTA_WINDIVERT_DIR=path/to/WinDivert-2.2.2-A)
set(VARTAD_COMMON
  daemon/json.cpp
  daemon/packet.cpp
  daemon/ipdb.cpp
  daemon/apprules.cpp
  daemon/engine.cpp
)
set(VARTAD_OK OFF)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(NFQ IMPORTED_TARGET libnetfilter_queue)
  endif()
  if(NFQ_FOUND)
    add_library(vartad_core STATIC ${VARTAD_COMMON} daemon/procinfo.cpp daemon/linux_daemon.cpp)
    target_link_libraries(vartad_core PUBLIC varta_core PkgConfig::NFQ)
    set(VARTAD_OK ON)
  else()
    message(STATUS "libnetfilter_queue not found - vartad will not be built "
                   "(sudo apt install libnetfilter-queue-dev)")
  endif()
elseif(WIN32)
  set(VARTA_WINDIVERT_DIR "${CMAKE_SOURCE_DIR}/third_party/WinDivert" CACHE PATH "Extracted WinDivert release")
  if(EXISTS "${VARTA_WINDIVERT_DIR}/include/windivert.h")
    add_library(vartad_core STATIC ${VARTAD_COMMON} daemon/procinfo_win.cpp daemon/windows_daemon.cpp)
    target_include_directories(vartad_core PRIVATE "${VARTA_WINDIVERT_DIR}/include")
    # WinDivert.dll is loaded at run time (LoadLibrary), so nothing to link against.
    target_link_libraries(vartad_core PUBLIC varta_core ws2_32 iphlpapi advapi32 ntdll)
    target_compile_definitions(vartad_core PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
    set(VARTAD_OK ON)
  else()
    message(STATUS "WinDivert not found in ${VARTA_WINDIVERT_DIR} - vartad will not be built. "
                   "Download WinDivert-2.2.2-A.zip from github.com/basil00/WinDivert/releases")
  endif()
endif()

if(VARTAD_OK)
  target_include_directories(vartad_core PUBLIC daemon)
  if(NOT MSVC)
    target_compile_options(vartad_core PRIVATE -Wall -Wextra)
  endif()
  add_executable(vartad daemon/main.cpp)
  target_link_libraries(vartad PRIVATE vartad_core)
  if(WIN32)
    # The DLL and driver must sit next to vartad.exe.
    add_custom_command(TARGET vartad POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${VARTA_WINDIVERT_DIR}/x64/WinDivert.dll" "${VARTA_WINDIVERT_DIR}/x64/WinDivert64.sys"
        $<TARGET_FILE_DIR:vartad>)
    install(TARGETS vartad RUNTIME DESTINATION .)
    install(FILES "${VARTA_WINDIVERT_DIR}/x64/WinDivert.dll" "${VARTA_WINDIVERT_DIR}/x64/WinDivert64.sys"
                  "${VARTA_WINDIVERT_DIR}/LICENSE" DESTINATION .)
  else()
    install(TARGETS vartad RUNTIME DESTINATION sbin)
  endif()
  if(VARTA_BUILD_TESTS)
    add_executable(varta_daemon_tests tests/test_daemon.cpp)
    target_link_libraries(varta_daemon_tests PRIVATE vartad_core)
    add_test(NAME varta_daemon_tests COMMAND varta_daemon_tests)
  endif()
endif()

# ---------------------------------------------------------------------------------------
# varta-gui: Qt 6 desktop app (tray icon, connection prompts, live log, rules editor)
option(VARTA_BUILD_GUI "Build the Qt GUI" ON)
if(VARTA_BUILD_GUI)
  find_package(Qt6 QUIET COMPONENTS Widgets Network)
  if(Qt6_FOUND)
    add_subdirectory(gui)
  else()
    message(STATUS "Qt 6 not found - varta-gui will not be built (sudo apt install qt6-base-dev)")
  endif()
endif()
