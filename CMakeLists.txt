cmake_minimum_required(VERSION 3.10)

project(syndiag VERSION 0.0.0)

include(CheckIncludeFile)
include(CheckSymbolExists)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

configure_file(
	systemd/syndiagd.service.in
	${CMAKE_BINARY_DIR}/systemd/syndiagd.service)
configure_file(
	openrc/syndiagd.in
	${CMAKE_BINARY_DIR}/openrc/syndiagd
	@ONLY)
configure_file(
	src/config.h.in
	${CMAKE_BINARY_DIR}/config.h)

add_compile_options(-Wall -Wextra -Wno-unused-parameter)
add_compile_definitions(_DEFAULT_SOURCE)

CHECK_SYMBOL_EXISTS(SOL_TCP "netinet/tcp.h" HAVE_SOL_TCP)
if (NOT ${SOL_TCP})
	message(FATAL_ERROR "no SOL_TCP in <netinet/tcp.h>")
endif()

add_library(libsyndiag STATIC src/util.c)

add_executable(syndiag src/syndiag.c)
add_executable(syndiagd src/syndiagd.c)
target_include_directories(syndiag PRIVATE ${CMAKE_BINARY_DIR})
target_include_directories(syndiagd PRIVATE ${CMAKE_BINARY_DIR})
target_include_directories(libsyndiag PRIVATE ${CMAKE_BINARY_DIR})
target_link_libraries(syndiag PRIVATE libsyndiag)
target_link_libraries(syndiagd PRIVATE libsyndiag)

install(TARGETS syndiag syndiagd)
install(
	FILES ${CMAKE_BINARY_DIR}/systemd/syndiagd.service
	DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
install(
	FILES ${CMAKE_BINARY_DIR}/openrc/syndiagd.service
	DESTINATION /etc/init.d)
