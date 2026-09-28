# Test-only dependency build: fetch and build pinned sdbusplus, AMI phosphor-dbus-interfaces,
# and AMI phosphor-logging from source, mirroring the Meson subproject pattern so that
# test builds are isolated from the system-installed versions.

# Allow FetchContent_Populate()
cmake_policy(SET CMP0169 OLD)

include(FetchContent)

# fetch sdbusplus at pinned revision
FetchContent_Declare(sdbusplus
    GIT_REPOSITORY https://github.com/openbmc/sdbusplus.git
    GIT_TAG 663b7b73184a8687c5c9add63cb58e06d3073f01)
FetchContent_GetProperties(sdbusplus)
if(NOT sdbusplus_POPULATED)
    FetchContent_Populate(sdbusplus)
endif()

# build and install sdbusplus if not already done
set(SDBUSPLUS_INSTALL_DIR ${CMAKE_BINARY_DIR}/_local_install/sdbusplus)
file(GLOB _sdbusplus_lib "${SDBUSPLUS_INSTALL_DIR}/lib*/libsdbusplus.so*")
if(NOT _sdbusplus_lib)
    execute_process(COMMAND meson setup --wipe
        --prefix=${SDBUSPLUS_INSTALL_DIR} --buildtype=release
        -Dtests=disabled -Dexamples=disabled
        ${CMAKE_BINARY_DIR}/_local_build/sdbusplus ${sdbusplus_SOURCE_DIR}
        RESULT_VARIABLE _r)
    if(NOT _r EQUAL 0)
        message(FATAL_ERROR "meson setup failed for sdbusplus")
    endif()
    execute_process(COMMAND ninja -C ${CMAKE_BINARY_DIR}/_local_build/sdbusplus install
        RESULT_VARIABLE _r)
    if(NOT _r EQUAL 0)
        message(FATAL_ERROR "ninja install failed for sdbusplus")
    endif()
endif()

# sdbus++ is not installed by meson at this commit; wrap the source-tree scripts
file(MAKE_DIRECTORY "${SDBUSPLUS_INSTALL_DIR}/bin")
file(WRITE "${SDBUSPLUS_INSTALL_DIR}/bin/sdbus++"
    "#!/bin/sh\nexec python3 \"${sdbusplus_SOURCE_DIR}/tools/sdbus++\" \"$@\"\n")
file(WRITE "${SDBUSPLUS_INSTALL_DIR}/bin/sdbus++-gen-meson"
    "#!/bin/sh\nexec bash \"${sdbusplus_SOURCE_DIR}/tools/sdbus++-gen-meson\" \"$@\"\n")
execute_process(COMMAND chmod +x
    "${SDBUSPLUS_INSTALL_DIR}/bin/sdbus++"
    "${SDBUSPLUS_INSTALL_DIR}/bin/sdbus++-gen-meson")

# locate the installed pkg-config directory (handles lib/ vs lib/x86_64-linux-gnu/)
file(GLOB_RECURSE _sdbusplus_pc_file "${SDBUSPLUS_INSTALL_DIR}/sdbusplus.pc")
if(_sdbusplus_pc_file)
    list(GET _sdbusplus_pc_file 0 _f)
    get_filename_component(SDBUSPLUS_PKG_PATH "${_f}" DIRECTORY)
endif()

# fetch phosphor-dbus-interfaces from AMI repository
FetchContent_Declare(phosphor_dbus_interfaces
    GIT_REPOSITORY https://git.ami.com/core/ami-bmc/one-tree/core/phosphor-dbus-interfaces.git
    GIT_TAG HEAD)
FetchContent_GetProperties(phosphor_dbus_interfaces)
if(NOT phosphor_dbus_interfaces_POPULATED)
    FetchContent_Populate(phosphor_dbus_interfaces)
endif()

# build phosphor-dbus-interfaces using local sdbus++ so generated bindings match pinned sdbusplus API
set(PDI_INSTALL_DIR ${CMAKE_BINARY_DIR}/_local_install/phosphor-dbus-interfaces)
if(NOT EXISTS ${PDI_INSTALL_DIR}/include)
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E env
            "PATH=${SDBUSPLUS_INSTALL_DIR}/bin:$ENV{PATH}"
            "PKG_CONFIG_PATH=${SDBUSPLUS_PKG_PATH}"
            meson setup --wipe
            --prefix=${PDI_INSTALL_DIR} --buildtype=release
            -Dtests=disabled
            "-Dcpp_args=-I${SDBUSPLUS_INSTALL_DIR}/include"
            ${CMAKE_BINARY_DIR}/_local_build/phosphor-dbus-interfaces
            ${phosphor_dbus_interfaces_SOURCE_DIR}
        RESULT_VARIABLE _r)
    if(NOT _r EQUAL 0)
        message(FATAL_ERROR "meson setup failed for phosphor-dbus-interfaces")
    endif()
    execute_process(COMMAND ninja -C ${CMAKE_BINARY_DIR}/_local_build/phosphor-dbus-interfaces install
        RESULT_VARIABLE _r)
    if(NOT _r EQUAL 0)
        message(FATAL_ERROR "ninja install failed for phosphor-dbus-interfaces")
    endif()
endif()

file(GLOB_RECURSE _pdi_pc_file "${PDI_INSTALL_DIR}/phosphor-dbus-interfaces.pc")
if(_pdi_pc_file)
    list(GET _pdi_pc_file 0 _f)
    get_filename_component(PDI_PKG_PATH "${_f}" DIRECTORY)
endif()

# fetch phosphor-logging from AMI repository
FetchContent_Declare(phosphor_logging
    GIT_REPOSITORY https://git.ami.com/core/ami-bmc/one-tree/core/phosphor-logging.git
    GIT_TAG HEAD)
FetchContent_GetProperties(phosphor_logging)
if(NOT phosphor_logging_POPULATED)
    FetchContent_Populate(phosphor_logging)
endif()

# build only the library (libonly=true skips binaries that depend on system phosphor-dbus-interfaces)
set(PHOSPHOR_LOGGING_INSTALL_DIR ${CMAKE_BINARY_DIR}/_local_install/phosphor-logging)
file(GLOB _plog_lib "${PHOSPHOR_LOGGING_INSTALL_DIR}/lib*/libphosphor_logging.so*")
if(NOT _plog_lib)
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E env
            "PATH=${SDBUSPLUS_INSTALL_DIR}/bin:$ENV{PATH}"
            "PKG_CONFIG_PATH=${SDBUSPLUS_PKG_PATH}:${PDI_PKG_PATH}"
            meson setup --wipe
            --prefix=${PHOSPHOR_LOGGING_INSTALL_DIR} --buildtype=release
            -Dtests=disabled
            -Dlibonly=true
            "-Dcpp_args=-I${SDBUSPLUS_INSTALL_DIR}/include -I${PDI_INSTALL_DIR}/include"
            ${CMAKE_BINARY_DIR}/_local_build/phosphor-logging
            ${phosphor_logging_SOURCE_DIR}
        RESULT_VARIABLE _r)
    if(NOT _r EQUAL 0)
        message(FATAL_ERROR "meson setup failed for phosphor-logging")
    endif()
    execute_process(COMMAND ninja -C ${CMAKE_BINARY_DIR}/_local_build/phosphor-logging install
        RESULT_VARIABLE _r)
    if(NOT _r EQUAL 0)
        message(FATAL_ERROR "ninja install failed for phosphor-logging")
    endif()
endif()

# expose local install dirs for include and link; explicit paths handle lib/x86_64-linux-gnu/ layout
file(GLOB _sdbusplus_libdirs
    "${SDBUSPLUS_INSTALL_DIR}/lib"
    "${SDBUSPLUS_INSTALL_DIR}/lib/x86_64-linux-gnu"
    "${SDBUSPLUS_INSTALL_DIR}/lib64")
file(GLOB _pdi_libdirs
    "${PDI_INSTALL_DIR}/lib"
    "${PDI_INSTALL_DIR}/lib/x86_64-linux-gnu"
    "${PDI_INSTALL_DIR}/lib64")
file(GLOB _plog_libdirs
    "${PHOSPHOR_LOGGING_INSTALL_DIR}/lib"
    "${PHOSPHOR_LOGGING_INSTALL_DIR}/lib/x86_64-linux-gnu"
    "${PHOSPHOR_LOGGING_INSTALL_DIR}/lib64")

include_directories(BEFORE
    ${SDBUSPLUS_INSTALL_DIR}/include
    ${PDI_INSTALL_DIR}/include
    ${PHOSPHOR_LOGGING_INSTALL_DIR}/include)
link_directories(${_sdbusplus_libdirs} ${_pdi_libdirs} ${_plog_libdirs})
set(SDBUSPLUS_LIB sdbusplus)
set(PHOSPHOR_LOGGING_LIB phosphor_logging)
