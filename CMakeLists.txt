cmake_minimum_required(VERSION 3.19)

project(syndiag VERSION 0.0.0 LANGUAGES C)

include(CheckIncludeFile)
include(CheckSymbolExists)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

add_compile_options(
	-Wall
	-Wextra
	-Wno-unused-parameter
	-Werror=implicit-function-declaration
	-D_GNU_SOURCE)

# check Linux-specific features
CHECK_SYMBOL_EXISTS(SOL_TCP "netinet/tcp.h" HAVE_SOL_TCP)
CHECK_SYMBOL_EXISTS(TCP_REPAIR_WINDOW "netinet/tcp.h" HAVE_TCP_REPAIR_WINDOW)
CHECK_SYMBOL_EXISTS(SO_RCVBUFFORCE "sys/socket.h" HAVE_SO_RCVBUFFORCE)
if (NOT HAVE_SOL_TCP)
	message(FATAL_ERROR "no SOL_TCP in <netinet/tcp.h>")
endif()
if (NOT HAVE_TCP_REPAIR_WINDOW)
	message(FATAL_ERROR "no TCP_REPAIR_WINDOW in <netinet/tcp.h>")
endif()

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
configure_file(
	src/syndiag-run
	${CMAKE_BINARY_DIR}/syndiag-run
	COPYONLY)
configure_file(
	src/read-syndiag
	${CMAKE_BINARY_DIR}/read-syndiag
	COPYONLY)

# Stupid CMake won't let me have a lib named "syndiag" and an exec named
# "syndiag" at the same time
add_library(libsyndiag STATIC src/util.c)

add_executable(syndiag src/syndiag.c)
add_executable(syndiagd src/syndiagd.c)
add_executable(util-func-tests test/suites/util-func-tests.c)
include_directories(src)
target_include_directories(syndiag PRIVATE ${CMAKE_BINARY_DIR})
target_include_directories(syndiagd PRIVATE ${CMAKE_BINARY_DIR})
target_include_directories(libsyndiag PRIVATE ${CMAKE_BINARY_DIR})
target_link_libraries(syndiag PRIVATE libsyndiag)
target_link_libraries(syndiagd PRIVATE libsyndiag)
target_link_libraries(util-func-tests PRIVATE libsyndiag)

install(TARGETS syndiag syndiagd)
install(
	FILES ${CMAKE_BINARY_DIR}/systemd/syndiagd.service
	DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
install(
	FILES ${CMAKE_BINARY_DIR}/openrc/syndiagd
	DESTINATION /etc/init.d)
install(
	FILES ${CMAKE_BINARY_DIR}/syndiag-run ${CMAKE_BINARY_DIR}/read-syndiag
	DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

# optional setcap on executables for convenience
install(
	CODE "execute_process(
		COMMAND setcap cap_net_admin=ep ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/syndiag
		COMMAND setcap cap_net_admin=ep ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/syndiagd
		COMMAND true
		COMMAND_ERROR_IS_FATAL LAST
)")
