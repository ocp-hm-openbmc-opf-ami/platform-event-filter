cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(pef-alert-manager CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})
add_definitions(-DBOOST_ERROR_CODE_HEADER_ONLY)
add_definitions(-DBOOST_SYSTEM_NO_DEPRECATED)
add_definitions(-DBOOST_ALL_NO_LIB)
add_definitions(-DBOOST_NO_RTTI)
add_definitions(-DBOOST_NO_TYPEID)
add_definitions(-DBOOST_ASIO_DISABLE_THREADS)

set(SOURCE_FILES
    src/pef_config.cpp
    src/snmp_notification.cpp
    src/Encryption.cpp)
set(SRC_FILES
    src/pef_action.cpp
    src/snmp_notification.cpp
    src/Encryption.cpp)

option(PEF_NEW_DBUS_DEBUG "Enable debug prints for new list-based D-Bus paths" ON)

# import libsystemd
find_package(PkgConfig REQUIRED)
pkg_check_modules(SYSTEMD libsystemd REQUIRED)

# import sdbusplus
find_package(PkgConfig REQUIRED)
pkg_check_modules(SDBUSPLUSPLUS sdbusplus REQUIRED)

pkg_check_modules(NETSNMP REQUIRED netsnmp)

add_executable(pef-configuration ${SOURCE_FILES})
add_executable(pef-event-filtering ${SRC_FILES})

if(PEF_NEW_DBUS_DEBUG)
    target_compile_definitions(pef-event-filtering PRIVATE PEF_NEW_DBUS_DEBUG=1)
endif()

target_link_libraries(pef-configuration systemd)
target_link_libraries(pef-configuration boost_coroutine)
target_link_libraries(pef-configuration sdbusplus -lstdc++fs)
target_link_libraries(pef-configuration phosphor_logging)
target_link_libraries(pef-configuration ${Boost_LIBRARIES})
target_include_directories(pef-configuration PRIVATE
    ${NETSNMP_INCLUDE_DIRS})
target_compile_options(pef-configuration PRIVATE
    ${NETSNMP_CFLAGS_OTHER})
target_link_directories(pef-configuration PRIVATE
    ${NETSNMP_LIBRARY_DIRS})
target_link_libraries(pef-configuration
    ${NETSNMP_LIBRARIES}
    crypto)

target_link_libraries(pef-event-filtering systemd)
target_link_libraries(pef-event-filtering boost_coroutine)
target_link_libraries(pef-event-filtering sdbusplus -lstdc++fs)
target_link_libraries(pef-event-filtering ${Boost_LIBRARIES})
target_include_directories(pef-event-filtering PRIVATE
    ${NETSNMP_INCLUDE_DIRS})
target_compile_options(pef-event-filtering PRIVATE
    ${NETSNMP_CFLAGS_OTHER})
target_link_directories(pef-event-filtering PRIVATE
    ${NETSNMP_LIBRARY_DIRS})
target_link_libraries(pef-event-filtering
    ${NETSNMP_LIBRARIES}
    crypto)
pkg_get_variable(SYSTEMD_SYSTEM_UNIT_DIR systemd systemdsystemunitdir)


link_directories(${EXTERNAL_INSTALL_LOCATION}/lib)

set(SERVICE_FILES
    ${PROJECT_SOURCE_DIR}/service_files/pef-configuration.service
    ${PROJECT_SOURCE_DIR}/service_files/pef-event-filtering.service)
set(CONFIG_FILES
    ${PROJECT_SOURCE_DIR}/pef_configurations/pef-alert-manager.json)

install(TARGETS pef-configuration DESTINATION bin)
install(FILES ${SERVICE_FILES} DESTINATION ${SYSTEMD_SYSTEM_UNIT_DIR})
install(FILES ${CONFIG_FILES} DESTINATION /usr/share/pef-alert-manager/)

install(TARGETS pef-event-filtering DESTINATION bin)
