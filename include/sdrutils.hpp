#include <boost/algorithm/string.hpp>
#include <boost/bimap.hpp>
#include <boost/container/flat_map.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus/match.hpp>

#include <cstring>

#pragma once

struct CmpStrVersion
{
    bool operator()(std::string a, std::string b) const
    {
        return strverscmp(a.c_str(), b.c_str()) < 0;
    }
};

using SensorSubTree = boost::container::flat_map<
    std::string,
    boost::container::flat_map<std::string, std::vector<std::string>>,
    CmpStrVersion>;

using SensorNumMap = boost::bimap<int, std::string>;

static constexpr uint16_t maxSensorsPerLUN = 255;
static constexpr uint16_t maxIPMISensors = (maxSensorsPerLUN * 3);
static constexpr uint16_t lun1Sensor0 = 0x100;
static constexpr uint16_t lun3Sensor0 = 0x300;
static constexpr uint16_t invalidSensorNumber = 0xFFFF;

namespace details
{
inline static void filterSensors(SensorSubTree& subtree)
{
    subtree.erase(
        std::remove_if(subtree.begin(), subtree.end(),
                       [](SensorSubTree::value_type& kv) {
                           auto& [_, serviceToIfaces] = kv;

                           static std::array<const char*, 2> serviceFilter = {
                               "xyz.openbmc_project.Pmt",
                               "xyz.openbmc_project.pldm"};

                           for (const char* service : serviceFilter)
                           {
                               serviceToIfaces.erase(service);
                           }

                           return serviceToIfaces.empty();
                       }),
        subtree.end());
}

inline static uint16_t getSensorSubtree(std::shared_ptr<SensorSubTree>& subtree)
{
    static std::shared_ptr<SensorSubTree> sensorTreePtr;
    static uint16_t sensorUpdatedIndex = 0;
    sd_bus* bus = NULL;
    int ret = sd_bus_default_system(&bus);
    if (ret < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to connect to system bus",
            phosphor::logging::entry("ERRNO=0x%X", -ret));
        sd_bus_unref(bus);
        return sensorUpdatedIndex;
    }
    sdbusplus::bus::bus dbus(bus);
    static sdbusplus::bus::match::match sensorAdded(
        dbus,
        "type='signal',member='InterfacesAdded',arg0path='/xyz/openbmc_project/"
        "sensors/'",
        [](sdbusplus::message::message& m) { sensorTreePtr.reset(); });

    static sdbusplus::bus::match::match sensorRemoved(
        dbus,
        "type='signal',member='InterfacesRemoved',arg0path='/xyz/"
        "openbmc_project/sensors/'",
        [](sdbusplus::message::message& m) { sensorTreePtr.reset(); });

    if (sensorTreePtr)
    {
        subtree = sensorTreePtr;
        return sensorUpdatedIndex;
    }

    sensorTreePtr = std::make_shared<SensorSubTree>();

    auto mapperCall =
        dbus.new_method_call("xyz.openbmc_project.ObjectMapper",
                             "/xyz/openbmc_project/object_mapper",
                             "xyz.openbmc_project.ObjectMapper", "GetSubTree");
    static constexpr const auto depth = 2;
    static constexpr std::array<const char*, 8> interfaces = {
        "xyz.openbmc_project.Sensor.Value",
        "xyz.openbmc_project.Inventory.Item.Cpu",
        "xyz.openbmc_project.Inventory.Item.Watchdog",
        "xyz.openbmc_project.Sensor.State",
        "xyz.openbmc_project.Sensor.EventOnly",
        "xyz.openbmc_project.Sensor.Threshold.Warning",
        "xyz.openbmc_project.Sensor.Threshold.Critical",
        "xyz.openbmc_project.Sensor.Threshold.NonRecoverable"};
    mapperCall.append("/xyz/openbmc_project/sensors", depth, interfaces);

    try
    {
        auto mapperReply = dbus.call(mapperCall);
        mapperReply.read(*sensorTreePtr);
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return sensorUpdatedIndex;
    }
    details::filterSensors(*sensorTreePtr);
    subtree = sensorTreePtr;
    sensorUpdatedIndex++;
    return sensorUpdatedIndex;
}

inline static bool getSensorNumMap(std::shared_ptr<SensorNumMap>& sensorNumMap)
{
    static std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    bool sensorNumMapUpated = false;
    static uint16_t prevSensorUpdatedIndex = 0;
    std::shared_ptr<SensorSubTree> sensorTree;
    uint16_t curSensorUpdatedIndex = details::getSensorSubtree(sensorTree);
    if (!sensorTree)
    {
        return sensorNumMapUpated;
    }

    if ((curSensorUpdatedIndex == prevSensorUpdatedIndex) && sensorNumMapPtr)
    {
        sensorNumMap = sensorNumMapPtr;
        return sensorNumMapUpated;
    }
    prevSensorUpdatedIndex = curSensorUpdatedIndex;

    sensorNumMapPtr = std::make_shared<SensorNumMap>();

    uint16_t sensorNum = 0;
    uint16_t sensorIndex = 0;
    for (const auto& sensor : *sensorTree)
    {
        sensorNumMapPtr->insert(
            SensorNumMap::value_type(sensorNum, sensor.first));

        sensorIndex++;
        if (sensorIndex == maxSensorsPerLUN)
        {
            sensorIndex = lun1Sensor0;
        }
        else if (sensorIndex == (lun1Sensor0 | maxSensorsPerLUN))
        {
            // Skip assigning LUN 0x2 any sensors
            sensorIndex = lun3Sensor0;
        }
        else if (sensorIndex == (lun3Sensor0 | maxSensorsPerLUN))
        {
            throw std::out_of_range("Maximum number of IPMI sensors exceeded.");
        }
        sensorNum = sensorIndex;
    }
    sensorNumMap = sensorNumMapPtr;
    sensorNumMapUpated = true;
    return sensorNumMapUpated;
}
} // namespace details

inline static bool getSensorSubtree(SensorSubTree& subtree)
{
    std::shared_ptr<SensorSubTree> sensorTree;
    details::getSensorSubtree(sensorTree);
    if (!sensorTree)
    {
        return false;
    }

    subtree = *sensorTree;
    return true;
}

struct CmpStr
{
    bool operator()(const char* a, const char* b) const
    {
        return std::strcmp(a, b) < 0;
    }
};

enum class SensorTypeCodes : uint8_t
{
    reserved = 0x0,
    temperature = 0x1,
    voltage = 0x2,
    current = 0x3,
    fan = 0x4,
    processor = 0x07,
    powersupply = 0x08,
    powerunit = 0x09,
    coolingdevice = 0x0A,
    logging = 0x10,
    os = 0x20,
    acpisystem = 0x22,
    watchdog2 = 0x23,
    managementsubsystemhealth = 0x28,
    battery = 0x29,
    other = 0xB,
};

const static boost::container::flat_map<const char*, SensorTypeCodes, CmpStr>
    sensorTypes{
        {{"temperature", SensorTypeCodes::temperature},
         {"voltage", SensorTypeCodes::voltage},
         {"current", SensorTypeCodes::current},
         {"fan_tach", SensorTypeCodes::fan},
         {"fan_pwm", SensorTypeCodes::fan},
         {"cpu", SensorTypeCodes::processor},
         {"powersupply", SensorTypeCodes::powersupply},
         {"powerunit", SensorTypeCodes::powerunit},
         {"coolingdevice", SensorTypeCodes::coolingdevice},
         {"logging", SensorTypeCodes::logging},
         {"os", SensorTypeCodes::os},
         {"acpisystem", SensorTypeCodes::acpisystem},
         {"watchdog", SensorTypeCodes::watchdog2},
         {"bmcfirmwarehealth", SensorTypeCodes::managementsubsystemhealth},
         {"battery", SensorTypeCodes::battery},
         {"power", SensorTypeCodes::other}}};

inline static std::string getSensorTypeStringFromPath(const std::string& path)
{
    // get sensor type string from path, path is defined as
    // /xyz/openbmc_project/sensors/<type>/label
    size_t typeEnd = path.rfind("/");
    if (typeEnd == std::string::npos)
    {
        return path;
    }
    size_t typeStart = path.rfind("/", typeEnd - 1);
    if (typeStart == std::string::npos)
    {
        return path;
    }
    // Start at the character after the '/'
    typeStart++;
    return path.substr(typeStart, typeEnd - typeStart);
}

inline static uint8_t getSensorTypeFromPath(const std::string& path)
{
    uint8_t sensorType = 0;
    std::string type = getSensorTypeStringFromPath(path);
    auto findSensor = sensorTypes.find(type.c_str());
    if (findSensor != sensorTypes.end())
    {
        sensorType = static_cast<uint8_t>(findSensor->second);
    } // else default 0x0 RESERVED

    return sensorType;
}

inline static uint8_t getSensorNumberFromPath(const std::string& path)
{
    std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    details::getSensorNumMap(sensorNumMapPtr);
    if (!sensorNumMapPtr)
    {
        return 0xFF;
    }

    try
    {
        return sensorNumMapPtr->right.at(path);
    }
    catch (std::out_of_range& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return 0xFF;
    }
}

inline static uint8_t getSensorEventTypeFromPath(const std::string& path)
{
    // TODO: Add support for additional reading types as needed
    return 0x1; // reading type = threshold
}

inline static std::string getPathFromSensorNumber(uint8_t sensorNum)
{
    std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    details::getSensorNumMap(sensorNumMapPtr);
    if (!sensorNumMapPtr)
    {
        return std::string();
    }

    try
    {
        return sensorNumMapPtr->left.at(sensorNum);
    }
    catch (std::out_of_range& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return std::string();
    }
}

inline static std::string retrieveSensorTypeFromPath(std::string& path,
                                                     const uint8_t sensorType)
{
    uint8_t typeFromPath = getSensorTypeFromPath(path);
    if (typeFromPath != sensorType)
    {
        path.clear(); // Assume the sensor's D-Bus object is not availalbe, if
                      // the sensor type is not matching

        for (const auto& itr : sensorTypes)
        {
            if (static_cast<uint8_t>(itr.second) == sensorType)
            {
                return itr.first;
            }
        }
        return "Unknown";
    }
    return getSensorTypeStringFromPath(path);
}

inline static std::string getSensorNameFromPath(const std::string& path)
{
    if (!path.empty())
    {
        std::size_t found = path.find_last_of("/\\");
        return path.substr(found + 1);
    }
    return "Unknown";
}
