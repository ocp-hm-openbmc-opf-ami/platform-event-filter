#pragma once

#include <iostream>

#ifdef PEF_NEW_DBUS_DEBUG
#define PEF_DBG(msg)                                                           \
    do                                                                         \
    {                                                                          \
        std::cerr << "[PEF_NEW_DBUS_DEBUG] " << msg << std::endl;              \
    } while (0)

#define PEF_SNMP_DBG(msg)                                                      \
    do                                                                         \
    {                                                                          \
        std::cerr << "[PEF_SNMP_DEBUG] " << msg << std::endl;                  \
    } while (0)

#define PEF_ENC_DBG(msg)                                                       \
    do                                                                         \
    {                                                                          \
        std::cerr << "[PEF_ENC_DEBUG] " << msg << std::endl;                   \
    } while (0)
#else
#define PEF_DBG(msg)                                                           \
    do                                                                         \
    {                                                                          \
    } while (0)

#define PEF_SNMP_DBG(msg)                                                      \
    do                                                                         \
    {                                                                          \
    } while (0)

#define PEF_ENC_DBG(msg)                                                       \
    do                                                                         \
    {                                                                          \
    } while (0)
#endif
