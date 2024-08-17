cmake_minimum_required(VERSION 3.13)

include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)
project(onboard_project C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(PICO_BOARD pico_w)
set(PICO_TIME_DEFAULT_ALARM_POOL_DISABLED 1)

pico_sdk_init()

add_executable(onboard
    events.c
    main.c
    network.c
    storage.c
    timer.c
    )

target_include_directories(onboard PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}
    )

pico_enable_stdio_usb(onboard 1)
pico_enable_stdio_uart(onboard 0)

target_link_libraries(onboard
    hardware_flash
    hardware_sync
    pico_cyw43_arch_lwip_poll
    pico_stdlib
    )

pico_add_extra_outputs(onboard)

