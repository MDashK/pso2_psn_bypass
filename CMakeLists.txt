cmake_minimum_required(VERSION 3.0)

project(netcheck_bypass)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Por favor define VITASDK no environment")
  endif()
endif()

include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O2 -fno-builtin")

add_executable(netcheck_bypass
  pso2_netcheck_bypass.c
)

set_target_properties(netcheck_bypass PROPERTIES
  LINK_FLAGS "-nostdlib"
)

target_link_libraries(netcheck_bypass
  taihen_stub
  SceLibKernel_stub
  SceIofilemgr_stub
  gcc
)

add_custom_command(OUTPUT netcheck_bypass.velf
  COMMAND /usr/local/vitasdk/bin/vita-elf-create
          -m module_start,module_stop,module_stop
          netcheck_bypass
          netcheck_bypass.velf
  DEPENDS netcheck_bypass
)

add_custom_command(OUTPUT netcheck_bypass.suprx
  COMMAND /usr/local/vitasdk/bin/vita-make-fself
          -c netcheck_bypass.velf
          netcheck_bypass.suprx
  DEPENDS netcheck_bypass.velf
)

add_custom_target(suprx ALL DEPENDS netcheck_bypass.suprx)
