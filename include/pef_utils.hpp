#pragma once
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include <iostream>
#include <string>

constexpr auto PROP_INTF = "org.freedesktop.DBus.Properties";
constexpr auto METHOD_GET = "Get";
constexpr auto METHOD_GET_ALL = "GetAll";
constexpr auto METHOD_SET = "Set";
constexpr auto MAPPER_BUSNAME = "xyz.openbmc_project.ObjectMapper";
constexpr auto MAPPER_INTERFACE = "xyz.openbmc_project.ObjectMapper";
constexpr auto MAPPER_PATH = "/xyz/openbmc_project/object_mapper";

using DbusProperty = std::string;
using Value =
    std::variant<uint8_t, uint16_t, std::string, std::vector<std::string>>;
using PropertyMap = std::map<DbusProperty, Value>;

struct pefConfInfo
{
    uint8_t PEFControl;
    uint8_t PEFActionGblControl;
    uint8_t PEFStartupDly;
    uint8_t PEFAlertStartupDly;
};

struct EvtFilterTblEntry
{
    uint8_t entry;
    uint8_t FilterConfig;
    uint8_t EvtFilterAction;
    uint8_t AlertPolicyNum;
    uint8_t EventSeverity;
    uint8_t GenIDByte1;
    uint8_t GenIDByte2;
    uint8_t SensorType;
    uint8_t SensorNum;
    uint8_t EventTrigger;
    uint16_t EventData1OffsetMask;
    uint8_t EventData1ANDMask;
    uint8_t EventData1Cmp1;
    uint8_t EventData1Cmp2;
    uint8_t EventData2ANDMask;
    uint8_t EventData2Cmp1;
    uint8_t EventData2Cmp2;
    uint8_t EventData3ANDMask;
    uint8_t EventData3Cmp1;
    uint8_t EventData3Cmp2;
};

struct AlertPolicyTbl
{
    uint8_t AlertPolicyEntry;
    uint8_t AlertPolicyGroupNum;
    uint8_t EnableAlert;
    uint8_t PolicyAction;
    uint8_t ChannelNo;
    uint8_t DestinationSel;
    std::string EventSpecificAlertStr;
    uint8_t AlertStingkey;
};

struct AlertStringTbl
{
    uint8_t AlertStrinEntry;
    uint8_t EventFilterSel;
    uint8_t AlertStringSet;
    uint16_t AlertString0;
    uint16_t AlertString1;
    uint16_t AlertString2;
};

struct pefDestSelector
{
    uint8_t LanChannel;
    uint8_t DestinationType;
};

inline static std::string retrieveSensorTypeFromPath(const std::string& path,
                                                     uint8_t /*sensorType*/)
{
    // Path format: /xyz/openbmc_project/sensors/<type>/<name>
    size_t typeEnd = path.rfind('/');
    if (typeEnd == std::string::npos)
    {
        return path;
    }
    size_t typeStart = path.rfind('/', typeEnd - 1);
    if (typeStart == std::string::npos)
    {
        return path;
    }
    return path.substr(typeStart + 1, typeEnd - (typeStart + 1));
}

inline static std::string getSensorNameFromPath(const std::string& path)
{
    size_t nameStart = path.rfind('/');
    if (nameStart == std::string::npos)
    {
        return path;
    }
    return path.substr(nameStart + 1);
}
