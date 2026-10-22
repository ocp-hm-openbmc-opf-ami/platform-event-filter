cmake_minimum_required(VERSION 3.14)

# Use GTest pre-installed by the Docker image (google-googletest layer)
find_package(GTest REQUIRED)
include(GoogleTest)

# ---- test_encryption ----
# Tests: base64_encode, base64_decode, AES_GenerateAndSaveKeys,
#        AES_GetKeyFromFile, encryptString, decryptString
add_executable(test_encryption
    test_encryption.cpp
    ${CMAKE_SOURCE_DIR}/src/Encryption.cpp)
target_include_directories(test_encryption PRIVATE
    ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_encryption PRIVATE
    GTest::gtest_main
    crypto)
gtest_discover_tests(test_encryption)

# ---- test_pef_utils ----
# Tests: retrieveSensorTypeFromPath, getSensorNameFromPath (inline in pef_utils.hpp)
add_executable(test_pef_utils
    test_pef_utils.cpp)
target_include_directories(test_pef_utils PRIVATE
    ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_pef_utils PRIVATE
    GTest::gtest_main
    ${SDBUSPLUS_LIB}
    ${PHOSPHOR_LOGGING_LIB}
    systemd)
gtest_discover_tests(test_pef_utils)

# ---- test_pef_config_update ----
# Tests: findEntryNo, updateJsonFile, parseJsonData (static/free fns in pef_config_update.hpp)
add_executable(test_pef_config_update
    test_pef_config_update.cpp)
target_include_directories(test_pef_config_update PRIVATE
    ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_pef_config_update PRIVATE
    GTest::gtest_main
    ${SDBUSPLUS_LIB}
    ${PHOSPHOR_LOGGING_LIB}
    systemd)
gtest_discover_tests(test_pef_config_update)

# ---- test_snmp_notification ----
# Links snmp_notification.cpp to instrument addPDUVar + sendTrap paths
add_executable(test_snmp_notification
    test_snmp_notification.cpp
    ${CMAKE_SOURCE_DIR}/src/snmp_notification.cpp
    ${CMAKE_SOURCE_DIR}/src/Encryption.cpp)
target_include_directories(test_snmp_notification PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${NETSNMP_INCLUDE_DIRS})
target_compile_options(test_snmp_notification PRIVATE
    ${NETSNMP_CFLAGS_OTHER})
target_link_directories(test_snmp_notification PRIVATE
    ${NETSNMP_LIBRARY_DIRS})
target_link_libraries(test_snmp_notification PRIVATE
    GTest::gtest_main
    ${SDBUSPLUS_LIB}
    ${PHOSPHOR_LOGGING_LIB}
    systemd
    netsnmp
    crypto)
gtest_discover_tests(test_snmp_notification)

# ---- test_sdrutils ----
# Tests: CmpStrVersion, IPMIStatsEntry (inline in sdrutils.hpp)
add_executable(test_sdrutils
    test_sdrutils.cpp)
target_include_directories(test_sdrutils PRIVATE
    ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_sdrutils PRIVATE
    GTest::gtest_main
    ${SDBUSPLUS_LIB}
    ${PHOSPHOR_LOGGING_LIB}
    systemd)
gtest_discover_tests(test_sdrutils)

# ---- test_pef_config_funcs ----
# Tests: validateIPv4Address, validateIPv6Address, parseJSONConfig
# pef_config.cpp has main(); --allow-multiple-definition keeps GTest's main.
# sendOBMCErrorNotification is stubbed in the test source.
add_executable(test_pef_config_funcs
    test_pef_config_funcs.cpp
    ${CMAKE_SOURCE_DIR}/src/pef_config.cpp
    ${CMAKE_SOURCE_DIR}/src/Encryption.cpp)
target_include_directories(test_pef_config_funcs PRIVATE
    ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_pef_config_funcs PRIVATE
    GTest::gtest
    ${SDBUSPLUS_LIB}
    ${PHOSPHOR_LOGGING_LIB}
    systemd
    boost_coroutine
    crypto)
target_link_options(test_pef_config_funcs PRIVATE -Wl,--allow-multiple-definition)
gtest_discover_tests(test_pef_config_funcs)

# ---- test_pef_action_funcs ----
# Tests: getCurrentTime, resolveHost
# pef_action.cpp has main(); --allow-multiple-definition keeps GTest's main.
# sendOBMCErrorNotification is stubbed in the test source.
add_executable(test_pef_action_funcs
    test_pef_action_funcs.cpp
    ${CMAKE_SOURCE_DIR}/src/pef_action.cpp
    ${CMAKE_SOURCE_DIR}/src/Encryption.cpp)
target_include_directories(test_pef_action_funcs PRIVATE
    ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_pef_action_funcs PRIVATE
    GTest::gtest
    ${SDBUSPLUS_LIB}
    ${PHOSPHOR_LOGGING_LIB}
    systemd
    boost_coroutine
    crypto)
target_link_options(test_pef_action_funcs PRIVATE -Wl,--allow-multiple-definition)
gtest_discover_tests(test_pef_action_funcs)
