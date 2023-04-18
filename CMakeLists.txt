#
# Copyright (c) 2022 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wifi_ble_provisioning)

# target_sources(app PRIVATE src/main.c
#                            src/mqtt_connection.c
# )
FILE(GLOB app_sources src/*.c)
target_sources(app PRIVATE ${app_sources})

zephyr_library_include_directories(inc)

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)


add_subdirectory(src/mqtt)

#Generate http client docs
add_subdirectory(src/http_client)
generate_inc_file_for_target(
    app
    src/http_client/https-cert.der
    ${gen_dir}/https-cert.der.inc
    )

#Generate Http server docs
add_subdirectory(src/http_server)
foreach(inc_file
	mt-http-server-cert.der
	mt-http-server-key.der
	response_big.html.bin
	response_100k.html.bin
    response_small.html.bin
    )
  generate_inc_file_for_target(
    app
    src/http_server/${inc_file}
    ${gen_dir}/${inc_file}.inc
    )
endforeach()

# add_definitions(-DNORDIC_PLATFORM)

# rapidxml interface library
# add_subdirectory(rapidxml/)

# Add microSDC library target objects
# add_subdirectory(microSDC/)