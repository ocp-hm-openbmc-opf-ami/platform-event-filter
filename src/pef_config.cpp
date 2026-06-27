/********************************
 *PEF Configuration Process
 *Author: Raghul R
 *Email : raghulr@ami.com
 *
 * ******************************/

#include "pef_config.hpp"

#include "pef_debug.hpp"
#include "pef_utils.hpp"
#include "sdrutils.hpp"
#include "snmp.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <arpa/inet.h>
#include <netdb.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <variant>
#include <vector>

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

/* Need a custom deleter for freeing up addrinfo */
struct AddrDeleter
{
    void operator()(addrinfo* addrPtr) const
    {
        freeaddrinfo(addrPtr);
    }
};

using AddrPtr = std::unique_ptr<addrinfo, AddrDeleter>;

std::map<uint8_t, std::string> getSensorNumNameMap()
{
    std::map<uint8_t, std::string> sensorMap;
    std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    ::details::getSensorNumMap(sensorNumMapPtr);
    if (!sensorNumMapPtr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get sensor number map");
        return sensorMap;
    }

    for (const auto& entry : sensorNumMapPtr->left)
    {
        uint8_t sensorNum = static_cast<uint8_t>(entry.first);
        const std::string& path = entry.second;
        std::string sensorName = getSensorNameFromPath(path);
        sensorMap[sensorNum] = sensorName;
    }

    return sensorMap;
}

std::map<std::string, std::map<uint8_t, std::string>>
    getSensorNumNameMapByType()
{
    std::map<std::string, std::map<uint8_t, std::string>> groupedMap;
    std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    ::details::getSensorNumMap(sensorNumMapPtr);
    if (!sensorNumMapPtr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get sensor number map");
        return groupedMap;
    }

    for (const auto& entry : sensorNumMapPtr->left)
    {
        uint8_t sensorNum = static_cast<uint8_t>(entry.first);
        const std::string& path = entry.second;
        std::string sensorType = getSensorTypeStringFromPath(path);
        std::string sensorName = getSensorNameFromPath(path);
        groupedMap[sensorType][sensorNum] = sensorName;
    }

    return groupedMap;
}

std::vector<std::pair<uint8_t, std::string>> getSensorNumNameMapForType(
    const std::string& sensorType)
{
    std::map<uint8_t, std::string> filteredMap;
    std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    ::details::getSensorNumMap(sensorNumMapPtr);
    if (!sensorNumMapPtr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get sensor number map");
        return {};
    }

    bool allTypes = (sensorType == "All");

    for (const auto& entry : sensorNumMapPtr->left)
    {
        uint8_t sensorNum = static_cast<uint8_t>(entry.first);
        const std::string& path = entry.second;
        std::string type = getSensorTypeStringFromPath(path);
        if (allTypes || type == sensorType)
        {
            std::string sensorName = getSensorNameFromPath(path);
            filteredMap[sensorNum] = sensorName;
        }
    }

    std::vector<std::pair<uint8_t, std::string>> result;
    // Add synthetic "All" entry first
    if (allTypes)
    {
        result.emplace_back(255, "All");
    }
    for (const auto& [num, name] : filteredMap)
    {
        result.emplace_back(num, name);
    }

    return result;
}

std::map<std::string, uint8_t> getAvailableSensorTypes()
{
    std::map<std::string, uint8_t> typeMap;
    std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    ::details::getSensorNumMap(sensorNumMapPtr);
    if (!sensorNumMapPtr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get sensor number map");
        return typeMap;
    }

    for (const auto& entry : sensorNumMapPtr->left)
    {
        const std::string& path = entry.second;
        std::string type = getSensorTypeStringFromPath(path);
        if (typeMap.find(type) != typeMap.end())
        {
            continue;
        }
        auto findSensor = sensorTypes.find(type.c_str());
        if (findSensor != sensorTypes.end())
        {
            typeMap[type] = static_cast<uint8_t>(findSensor->second.first);
        }
    }

    // Add synthetic "all" entry with type code 255
    typeMap["All"] = 255;

    return typeMap;
}

bool validateIPv4Address(const std::string& address)
{
    PEF_DBG("validateIPv4Address input=" << address);
    if (address.empty())
    {
        return true;
    }

    // First, try direct IPv4 validation
    unsigned char buf[sizeof(struct in_addr)];
    if (inet_pton(AF_INET, address.c_str(), buf) == 1)
    {
        return true;
    }

    // Reject strings that look like incomplete IP addresses (only digits and
    // dots) This prevents "10.0.0" or "10.0" from being treated as hostnames
    bool validIPv4Chars = true;
    for (char c : address)
    {
        if (!std::isdigit(c) && c != '.')
        {
            validIPv4Chars = false;
            break;
        }
    }
    if (validIPv4Chars)
    {
        PEF_DBG("validateIPv4Address reject incomplete IPv4-like string="
                << address);
        return false;
    }

    // If not a direct IPv4, try as hostname and verify it resolves to IPv4
    addrinfo hints{};
    addrinfo* addr = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int result = getaddrinfo(address.c_str(), NULL, &hints, &addr);
    if (result != 0)
    {
        PEF_DBG("validateIPv4Address hostname resolution failed input="
                << address << " rc=" << result);
        return false;
    }

    AddrPtr addrPtr{addr};
    PEF_DBG("validateIPv4Address hostname resolved to IPv4 input=" << address);
    return true;
}

bool validateIPv6Address(const std::string& address)
{
    PEF_DBG("validateIPv6Address input=" << address);
    if (address.empty())
    {
        return true;
    }

    // First, try direct IPv6 validation
    unsigned char buf[sizeof(struct in6_addr)];
    if (inet_pton(AF_INET6, address.c_str(), buf) == 1)
    {
        return true;
    }

    // Reject strings that look like incomplete IPv6 addresses (hex digits and
    // colons) This prevents "2001:db8" or similar from being treated as
    // hostnames
    bool validIPv6Chars = true;
    bool hasColon = false;

    for (char c : address)
    {
        if (c == ':')
        {
            hasColon = true;
        }
        if (!std::isxdigit(c) && c != ':')
        {
            validIPv6Chars = false;
            break;
        }
    }

    if (hasColon && validIPv6Chars)
    {
        PEF_DBG("validateIPv6Address reject incomplete IPv6-like string="
                << address);
        return false;
    }

    // If not a direct IPv6, try as hostname and verify it resolves to IPv6
    addrinfo hints{};
    addrinfo* addr = nullptr;
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;

    int result = getaddrinfo(address.c_str(), NULL, &hints, &addr);
    if (result != 0)
    {
        PEF_DBG("validateIPv6Address hostname resolution failed input="
                << address << " rc=" << result);
        return false;
    }

    AddrPtr addrPtr{addr};
    PEF_DBG("validateIPv6Address hostname resolved to IPv6 input=" << address);
    return true;
}

bool isCommStrValid(const std::string& value)
{
    PEF_DBG("isCommStrValid inputLen=" << value.size());
    try
    {
        auto bus = sdbusplus::bus::new_default();
        auto method = bus.new_method_call(snmpBusName, snmpRootPath,
                                          "org.freedesktop.DBus.ObjectManager",
                                          "GetManagedObjects");

        auto reply = bus.call(method);
        std::map<sdbusplus::message::object_path,
                 std::map<std::string,
                          std::map<std::string, std::variant<std::string>>>>
            objTree;
        reply.read(objTree);

        for (const auto& objIter : objTree)
        {
            auto& intfMap = objIter.second;
            auto& commStrProps = intfMap.at(snmpCommStrIntf);

            std::string commStr =
                std::get<std::string>(commStrProps.at("CommunityString"));

            if (commStr == value)
            {
                PEF_DBG("isCommStrValid matched in object="
                        << std::string(objIter.first));
                return true;
            }
        }
    }
    catch (const std::exception& e)
    {
        const std::string errorMsg =
            std::string("Failed to validate community string: ") + e.what();
        phosphor::logging::log<phosphor::logging::level::ERR>(errorMsg.c_str());
    }

    PEF_DBG("isCommStrValid no match");
    return false;
}

namespace
{

using TestDbusValue = std::variant<uint8_t, std::string, std::vector<uint8_t>,
                                   std::vector<std::string>>;
using TestPropertyMap = std::map<std::string, TestDbusValue>;

static constexpr const char* testUserManagerBus =
    "xyz.openbmc_project.User.Manager";
static constexpr const char* testUserMgrObjPath = "/xyz/openbmc_project/user";
static constexpr const char* testUserAccPolicyIntf =
    "xyz.openbmc_project.User.AccountPolicy";
static constexpr const char* testGetMapMethod = "GetChannelInterfaceMap";
static constexpr const char* testUserObjPathPrefix =
    "/xyz/openbmc_project/user/";
static constexpr const char* testUserAttributesIface =
    "xyz.openbmc_project.User.Attributes";
static constexpr const char* testPropIntf = "org.freedesktop.DBus.Properties";
static constexpr const char* testMethodGet = "Get";
static constexpr const char* testMethodGetAll = "GetAll";
static constexpr const char* testMailService = "xyz.openbmc_project.mail";
static constexpr const char* testMailObjPath =
    "/xyz/openbmc_project/mail/alert";
static constexpr const char* testMailIface = "xyz.openbmc_project.mail.alert";

bool isEthInterfaceName(const std::string& interfaceName)
{
    return interfaceName.rfind("eth", 0) == 0;
}

std::vector<std::string> getAvailableEthInterfaces()
{
    static constexpr const char* channelConfigFile =
        "/etc/ipmi/channel_config.json";
    std::vector<std::string> ethInterfaces;

    std::ifstream ifs(channelConfigFile);
    if (!ifs.is_open())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getAvailableEthInterfaces: failed to open channel_config.json");
        return ethInterfaces;
    }

    Json channelData;
    try
    {
        channelData = Json::parse(ifs);
    }
    catch (const Json::parse_error& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getAvailableEthInterfaces: failed to parse channel_config.json",
            phosphor::logging::entry("ERROR=%s", e.what()));
        return ethInterfaces;
    }

    for (const auto& [channelNum, channelObj] : channelData.items())
    {
        if (!channelObj.is_object())
        {
            continue;
        }
        bool isValid = channelObj.value("is_valid", false);
        if (!isValid)
        {
            continue;
        }
        std::string name = channelObj.value("name", "");
        if (!isEthInterfaceName(name))
        {
            continue;
        }
        if (std::find(ethInterfaces.begin(), ethInterfaces.end(), name) ==
            ethInterfaces.end())
        {
            ethInterfaces.push_back(name);
            PEF_DBG("getAvailableEthInterfaces accepted channel="
                    << channelNum << " iface=" << name);
        }
    }

    if (ethInterfaces.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getAvailableEthInterfaces: no eth interfaces in channel_config.json");
    }

    return ethInterfaces;
}

std::string getTestTimestamp()
{
    std::time_t now = std::time(nullptr);
    std::tm* tmInfo = std::localtime(&now);
    if (tmInfo == nullptr)
    {
        PEF_DBG("getTestTimestamp localtime returned nullptr");
        return "";
    }

    char buffer[80] = {};
    std::strftime(buffer, sizeof(buffer), "%a %b %d %H:%M:%S %Z %Y", tmInfo);
    PEF_DBG("getTestTimestamp value=" << buffer);
    return std::string(buffer);
}

std::optional<std::string> getInterfaceNameForChannelForTest(uint8_t channelNo)
{
    PEF_DBG("getInterfaceNameForChannelForTest channel="
            << static_cast<int>(channelNo));
    try
    {
        auto bus = sdbusplus::bus::new_default();
        auto method =
            bus.new_method_call(testUserManagerBus, testUserMgrObjPath,
                                testUserAccPolicyIntf, testGetMapMethod);
        std::map<uint8_t, std::string> channelMap;
        auto reply = bus.call(method);
        reply.read(channelMap);
        PEF_DBG("getInterfaceNameForChannelForTest channelMap size="
                << channelMap.size());

        auto it = channelMap.find(channelNo);
        if (it != channelMap.end() && isEthInterfaceName(it->second))
        {
            PEF_DBG("getInterfaceNameForChannelForTest resolved iface="
                    << it->second);
            return it->second;
        }
        if (it == channelMap.end())
        {
            PEF_DBG("getInterfaceNameForChannelForTest channel not found");
        }
        else
        {
            PEF_DBG("getInterfaceNameForChannelForTest non-eth iface="
                    << it->second);
        }
    }
    catch (const std::exception& e)
    {
        PEF_DBG("getInterfaceNameForChannelForTest exception=" << e.what());
        const std::string errorMsg =
            std::string(
                "TestDestination failed to resolve channel interface: ") +
            e.what();
        phosphor::logging::log<phosphor::logging::level::ERR>(errorMsg.c_str());
    }

    PEF_DBG("getInterfaceNameForChannelForTest returning nullopt");
    return std::nullopt;
}

std::optional<std::string> getSmtpMailIDForTest(
    const std::string& selectedUserName)
{
    PEF_DBG("getSmtpMailIDForTest user=" << selectedUserName);
    if (selectedUserName.empty())
    {
        PEF_DBG("getSmtpMailIDForTest empty username");
        return std::nullopt;
    }

    try
    {
        auto bus = sdbusplus::bus::new_default();
        std::variant<std::string> variant;
        const std::string userObjPath =
            std::string(testUserObjPathPrefix) + selectedUserName;
        auto method =
            bus.new_method_call(testUserManagerBus, userObjPath.c_str(),
                                testPropIntf, testMethodGet);
        method.append(std::string(testUserAttributesIface), "SMTPMailID");
        PEF_DBG("getSmtpMailIDForTest calling Get path=" << userObjPath);
        auto reply = bus.call(method);
        reply.read(variant);
        const auto& mailId = std::get<std::string>(variant);
        PEF_DBG("getSmtpMailIDForTest mailIdEmpty=" << mailId.empty());
        return mailId;
    }
    catch (const std::exception& e)
    {
        PEF_DBG("getSmtpMailIDForTest exception=" << e.what());
        const std::string errorMsg =
            std::string("TestDestination failed to read SMTPMailID: ") +
            e.what();
        phosphor::logging::log<phosphor::logging::level::ERR>(errorMsg.c_str());
    }

    PEF_DBG("getSmtpMailIDForTest returning nullopt");
    return std::nullopt;
}

bool sendTestMailForDestination(const std::string& mailId, uint8_t channelNo,
                                uint8_t destinationSel)
{
    PEF_DBG("sendTestMailForDestination channel="
            << static_cast<int>(channelNo)
            << " destinationSel=" << static_cast<int>(destinationSel)
            << " mailIdEmpty=" << mailId.empty());
    if (mailId.empty())
    {
        PEF_DBG("sendTestMailForDestination empty mailId");
        return false;
    }

    try
    {
        auto bus = sdbusplus::bus::new_default();
        auto sendAlert =
            bus.new_method_call(testMailService, testMailObjPath, testMailIface,
                                "ForgotPassSendMail");

        std::string subject = "PEF Test Alert";
        std::string body = "PEF test alert triggered for channel " +
                           std::to_string(channelNo) + " destination " +
                           std::to_string(destinationSel);
        PEF_DBG("sendTestMailForDestination method path="
                << testMailObjPath << " iface=" << testMailIface);
        sendAlert.append(mailId.c_str(), subject.c_str(), body.c_str());
        auto reply = bus.call(sendAlert);
        PEF_DBG("sendTestMailForDestination method_error="
                << reply.is_method_error());
        return !reply.is_method_error();
    }
    catch (const std::exception& e)
    {
        PEF_DBG("sendTestMailForDestination exception=" << e.what());
        const std::string errorMsg =
            std::string("TestDestination failed to send test mail: ") +
            e.what();
        phosphor::logging::log<phosphor::logging::level::ERR>(errorMsg.c_str());
        return false;
    }
}

bool dispatchTestDestination(uint8_t channelNo, uint8_t destinationSel)
{
    PEF_DBG("dispatchTestDestination channel="
            << static_cast<int>(channelNo)
            << " destinationSel=" << static_cast<int>(destinationSel));
    try
    {
        if (destinationSel == 0)
        {
            PEF_DBG("dispatchTestDestination invalid destinationSel=0");
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "TestDestination invalid destination selector");
            return false;
        }

        const auto ifaceNameOpt = getInterfaceNameForChannelForTest(channelNo);
        if (!ifaceNameOpt.has_value())
        {
            PEF_DBG("dispatchTestDestination no interface for channel="
                    << static_cast<int>(channelNo));
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "TestDestination no interface for channel");
            return false;
        }
        const std::string& ifaceName = ifaceNameOpt.value();
        PEF_DBG("dispatchTestDestination resolved interface=" << ifaceName);

        // Read LAN config directly from JSON file instead of D-Bus GetAll
        // to avoid ELOOP error (service calling itself synchronously).
        Json lanData;
        {
            Json mergedData = parseJSONConfig(pefLanParamConfFile);
            if (!mergedData.is_discarded())
            {
                if (mergedData.contains("Interfaces") &&
                    mergedData["Interfaces"].is_object() &&
                    mergedData["Interfaces"].contains(ifaceName))
                {
                    lanData = mergedData["Interfaces"][ifaceName];
                }
                else if (mergedData.contains(ifaceName))
                {
                    lanData = mergedData[ifaceName];
                }
            }
        }
        PEF_DBG("dispatchTestDestination lanData valid="
                << (!lanData.is_null() && !lanData.is_discarded())
                << " hasConfig=" << (lanData.contains("Config")));

        if (lanData.is_null() || lanData.is_discarded() ||
            !lanData.contains("Config"))
        {
            PEF_DBG(
                "dispatchTestDestination no config for iface=" << ifaceName);
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "TestDestination missing LAN config for interface");
            return false;
        }

        auto& cfg = lanData["Config"];
        if (!cfg.contains("Type") || !cfg["Type"].is_array())
        {
            PEF_DBG(
                "dispatchTestDestination Type array missing in config for iface="
                << ifaceName);
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "TestDestination missing Type property in LAN config");
            return false;
        }

        const auto& typeArr = cfg["Type"];
        const size_t selectedIndex = static_cast<size_t>(destinationSel - 1);
        PEF_DBG("dispatchTestDestination typeArrSize="
                << typeArr.size() << " selectedIndex=" << selectedIndex);
        if (selectedIndex >= typeArr.size())
        {
            PEF_DBG("dispatchTestDestination selectedIndex out of range "
                    << "selectedIndex=" << selectedIndex
                    << " size=" << typeArr.size());
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "TestDestination destination selector out of range");
            return false;
        }

        const uint8_t destinationType =
            static_cast<uint8_t>(typeArr[selectedIndex].get<uint32_t>());
        PEF_DBG("dispatchTestDestination destinationType="
                << static_cast<int>(destinationType));
        if (destinationType <= 2)
        {
            PEF_DBG("dispatchTestDestination SNMP branch channel="
                    << static_cast<int>(channelNo)
                    << " destinationSel=" << static_cast<int>(destinationSel));
            const bool sent =
                phosphor::network::snmp::sendOBMCErrorNotification(
                    static_cast<uint32_t>(0xFFFF), getTestTimestamp(),
                    "Information", "PEF SNMP test notification", "PEFTestEvent",
                    "Asserted", "", "", "PEF_SNMP_TEST", channelNo,
                    destinationSel);
            PEF_DBG("dispatchTestDestination SNMP send result=" << sent);
            if (!sent)
            {
                PEF_DBG("dispatchTestDestination SNMP send failed for channel="
                        << static_cast<int>(channelNo) << " destinationSel="
                        << static_cast<int>(destinationSel));
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "TestDestination trap send failed");
                return false;
            }
            PEF_DBG("dispatchTestDestination SNMP send succeeded");
            return true;
        }

        if (destinationType == 3)
        {
            PEF_DBG("dispatchTestDestination SMTP branch channel="
                    << static_cast<int>(channelNo)
                    << " destinationSel=" << static_cast<int>(destinationSel));
            if (!cfg.contains("UserName") || !cfg["UserName"].is_array())
            {
                PEF_DBG(
                    "dispatchTestDestination UserName array missing in config for iface="
                    << ifaceName);
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "TestDestination missing UserName property for SMTP destination");
                return false;
            }
            const auto& userArr = cfg["UserName"];
            PEF_DBG("dispatchTestDestination smtp userArrSize="
                    << userArr.size() << " selectedIndex=" << selectedIndex);
            if (selectedIndex >= userArr.size())
            {
                PEF_DBG("dispatchTestDestination SMTP user index out of range "
                        << "selectedIndex=" << selectedIndex
                        << " size=" << userArr.size());
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "TestDestination SMTP user index out of range");
                return false;
            }

            const std::string selectedUser =
                userArr[selectedIndex].get<std::string>();
            const auto smtpMailId = getSmtpMailIDForTest(selectedUser);
            PEF_DBG("dispatchTestDestination SMTP user="
                    << selectedUser << " mailIdPresent="
                    << smtpMailId.has_value() << " mailIdEmpty="
                    << (!smtpMailId.has_value() || smtpMailId->empty()));
            if (!smtpMailId.has_value() || smtpMailId->empty())
            {
                PEF_DBG(
                    "dispatchTestDestination SMTP mail id unavailable for user="
                    << selectedUser);
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "TestDestination SMTPMailID unavailable");
                return false;
            }

            if (!sendTestMailForDestination(smtpMailId.value(), channelNo,
                                            destinationSel))
            {
                PEF_DBG("dispatchTestDestination SMTP send failed for user="
                        << selectedUser);
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "TestDestination test mail send failed");
                return false;
            }
            PEF_DBG("dispatchTestDestination SMTP send succeeded for user="
                    << selectedUser);
            return true;
        }

        PEF_DBG("dispatchTestDestination unsupported destinationType="
                << static_cast<int>(destinationType));
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "TestDestination unsupported destination type");
        return false;
    }
    catch (const sdbusplus::exception_t& e)
    {
        PEF_DBG(
            "dispatchTestDestination caught sdbusplus exception=" << e.what());
        const std::string errorMsg =
            std::string("TestDestination dispatch D-Bus failure: ") + e.what();
        phosphor::logging::log<phosphor::logging::level::ERR>(errorMsg.c_str());
        return false;
    }
    catch (const std::out_of_range& e)
    {
        PEF_DBG("dispatchTestDestination caught out_of_range=" << e.what());
        const std::string errorMsg =
            std::string("TestDestination dispatch missing property: ") +
            e.what();
        phosphor::logging::log<phosphor::logging::level::ERR>(errorMsg.c_str());
        return false;
    }
    catch (const std::bad_variant_access& e)
    {
        PEF_DBG(
            "dispatchTestDestination caught bad_variant_access=" << e.what());
        const std::string errorMsg =
            std::string("TestDestination dispatch property type mismatch: ") +
            e.what();
        phosphor::logging::log<phosphor::logging::level::ERR>(errorMsg.c_str());
        return false;
    }
    catch (const std::exception& e)
    {
        PEF_DBG("dispatchTestDestination caught std::exception=" << e.what());
        const std::string errorMsg =
            std::string("TestDestination dispatch failed: ") + e.what();
        phosphor::logging::log<phosphor::logging::level::ERR>(errorMsg.c_str());
        return false;
    }
}

bool TestDestination(uint8_t channelNo, uint8_t destinationSel)
{
    PEF_DBG("TestDestination request channel="
            << static_cast<int>(channelNo)
            << " destinationSel=" << static_cast<int>(destinationSel));

    if (channelNo > 15)
    {
        PEF_DBG("TestDestination invalid channel max check failed value="
                << static_cast<int>(channelNo));
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "TestDestination invalid channel: exceeds maximum value");
        return false;
    }

    try
    {
        auto bus = sdbusplus::bus::new_default();
        auto method =
            bus.new_method_call(testUserManagerBus, testUserMgrObjPath,
                                testUserAccPolicyIntf, testGetMapMethod);
        std::map<uint8_t, std::string> channelMap;
        auto reply = bus.call(method);
        reply.read(channelMap);
        PEF_DBG("TestDestination channelMap size=" << channelMap.size());

        std::map<uint8_t, std::string> allowedEthChannelMap;
        for (const auto& [mapChannelNo, interfaceName] : channelMap)
        {
            if (isEthInterfaceName(interfaceName))
            {
                PEF_DBG("TestDestination allowedEth channel="
                        << static_cast<int>(mapChannelNo)
                        << " iface=" << interfaceName);
                allowedEthChannelMap.emplace(mapChannelNo, interfaceName);
            }
            else
            {
                PEF_DBG("TestDestination skipping non-eth channel="
                        << static_cast<int>(mapChannelNo)
                        << " iface=" << interfaceName);
            }
        }

        auto it = allowedEthChannelMap.find(channelNo);
        if (it == allowedEthChannelMap.end())
        {
            PEF_DBG("TestDestination channel not present in eth map channel="
                    << static_cast<int>(channelNo));
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "TestDestination invalid channel: not in available eth channel map");
            return false;
        }
        PEF_DBG("TestDestination validated channel interface=" << it->second);
    }
    catch (const std::exception& e)
    {
        PEF_DBG("TestDestination validate channel map exception=" << e.what());
        const std::string errorMsg =
            std::string("TestDestination failed to validate channel map: ") +
            e.what();
        phosphor::logging::log<phosphor::logging::level::ERR>(errorMsg.c_str());
        return false;
    }

    // added for redfish sync this may change later
    destinationSel++;
    uint8_t maxDestinationSelLocal = (maxDestinationSel - 1);
    if (destinationSel == 0 || destinationSel > maxDestinationSelLocal)
    {
        PEF_DBG("TestDestination invalid destination selector value="
                << static_cast<int>(destinationSel));
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "TestDestination invalid destination selector");
        return false;
    }

    const bool result = dispatchTestDestination(channelNo, destinationSel);
    PEF_DBG("TestDestination final result="
            << result << " channel=" << static_cast<int>(channelNo)
            << " destinationSel=" << static_cast<int>(destinationSel));
    return result;
}

} // namespace

Json parseJSONConfig(const std::string& configFile)
{
    PEF_DBG("parseJSONConfig file=" << configFile);
    std::ifstream jsonFile(configFile);
    if (!jsonFile.is_open())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "parseJSONConfig: Cannot open PEF config path");
    }
    auto data = Json::parse(jsonFile, nullptr, false);
    if (data.is_discarded())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "parseJSONConfig: readings JSON parser failure");
        PEF_DBG("parseJSONConfig parse failed file=" << configFile);
    }
    else
    {
        PEF_DBG("parseJSONConfig parse success file=" << configFile);
    }

    return data;
}

// Persist a LAN param value (under Config) into the shared JSON file.
// If selectorPath is provided (e.g. "DestinationSelector/00"), the value is
// stored under Config[selectorPath split into objects].
void updateLanParamConfigValue(
    const std::string& interfaceName, const std::string& propName,
    const Json& value,
    const std::optional<std::string>& selectorPath = std::nullopt)
{
    PEF_DBG("updateLanParamConfigValue iface="
            << interfaceName << " prop=" << propName << " selector="
            << (selectorPath ? *selectorPath : std::string("<none>")));
    Json data = Json::object();

    std::ifstream in(pefLanParamConfFile);
    if (in.is_open())
    {
        data = Json::parse(in, nullptr, false);
        if (data.is_discarded())
        {
            data = Json::object();
        }
    }

    Json* container = nullptr;
    auto interfacesIt = data.find("Interfaces");
    if (interfacesIt != data.end() && interfacesIt->is_object())
    {
        container = &data["Interfaces"];
    }
    else
    {
        container = &data;
    }

    if (selectorPath)
    {
        std::stringstream ss(*selectorPath);
        std::string segment;
        Json* cursor = &(*container)[interfaceName]["Config"];
        while (std::getline(ss, segment, '/'))
        {
            cursor = &((*cursor)[segment]);
        }
        (*cursor)[propName] = value;
    }
    else
    {
        (*container)[interfaceName]["Config"][propName] = value;
    }

    std::ofstream out(pefLanParamConfFile, std::ios::out | std::ios::trunc);
    if (!out.is_open())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "updateLanParamConfigValue: Cannot open config path");
        return;
    }

    out << data.dump(4);
}

void parsePefConfToDbus(std::shared_ptr<sdbusplus::asio::connection> conn,
                        sdbusplus::asio::object_server& objectServer)
{
    try
    {
        PEF_DBG("parsePefConfToDbus start");
        auto data = parseJSONConfig(pefConfFilePath);
        PEF_DBG("parsePefConfToDbus loaded base config");
        for (const auto& pefConfData : data["PEFConfInfo"])
        {
            auto pefConfInfoIface =
                objectServer.add_interface(pefObj, pefConfInfoIntf);

            pefConfInfoIface->register_property(
                "Version", static_cast<uint8_t>(pefConfData["Version"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            pefConfInfoIface->register_property(
                "ActionSupported",
                static_cast<uint8_t>(pefConfData["ActionSupported"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            pefConfInfoIface->register_property(
                "MaxEventTblEntry",
                static_cast<uint8_t>(pefConfData["MaxEventTblEntry"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            pefConfInfoIface->register_property(
                "PEFControl", static_cast<uint8_t>(pefConfData["PEFControl"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            pefConfInfoIface->register_property(
                "PEFActionGblControl",
                static_cast<uint8_t>(pefConfData["PEFActionGblControl"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            pefConfInfoIface->register_property(
                "PEFStartupDly",
                static_cast<uint8_t>(pefConfData["PEFStartupDly"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            pefConfInfoIface->register_property(
                "PEFAlertStartupDly",
                static_cast<uint8_t>(pefConfData["PEFAlertStartupDly"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            pefConfInfoIface->register_property(
                "LastBMCProcessedEventID",
                static_cast<uint16_t>(pefConfData["LastBMCProcessedEventID"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            pefConfInfoIface->register_property(
                "LastSWProcessedEventID",
                static_cast<uint16_t>(pefConfData["LastSWProcessedEventID"]),
                sdbusplus::asio::PropertyPermission::readWrite);

            pefConfInfoIface->register_property(
                "Subject", static_cast<std::string>(pefConfData["Subject"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            pefConfInfoIface->register_property(
                "Message", static_cast<std::string>(pefConfData["Message"]),
                sdbusplus::asio::PropertyPermission::readWrite);

            pefConfInfoIface->initialize(true);
        }

        for (const auto& systemGuid : data["SystemGUID"])
        {
            std::shared_ptr<sdbusplus::asio::dbus_interface> systemGuidIface =
                objectServer.add_interface(pefObj, systemGUIDIntf);
            systemGuidIface->register_property(
                "SystemGUID0", static_cast<uint8_t>(systemGuid["SystemGUID0"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            systemGuidIface->register_property(
                "SystemGUID1", static_cast<uint8_t>(systemGuid["SystemGUID1"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            systemGuidIface->register_property(
                "SystemGUID2", static_cast<uint8_t>(systemGuid["SystemGUID2"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            systemGuidIface->register_property(
                "SystemGUID3", static_cast<uint8_t>(systemGuid["SystemGUID3"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            systemGuidIface->register_property(
                "SystemGUID4", static_cast<uint8_t>(systemGuid["SystemGUID4"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            systemGuidIface->register_property(
                "SystemGUID5", static_cast<uint8_t>(systemGuid["SystemGUID5"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            systemGuidIface->register_property(
                "SystemGUID6", static_cast<uint8_t>(systemGuid["SystemGUID6"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            systemGuidIface->register_property(
                "SystemGUID7", static_cast<uint8_t>(systemGuid["SystemGUID7"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            systemGuidIface->register_property(
                "SystemGUID8", static_cast<uint8_t>(systemGuid["SystemGUID8"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            systemGuidIface->register_property(
                "SystemGUID9", static_cast<uint8_t>(systemGuid["SystemGUID9"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            systemGuidIface->register_property(
                "SystemGUID10",
                static_cast<uint8_t>(systemGuid["SystemGUID10"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            systemGuidIface->register_property(
                "SystemGUID11",
                static_cast<uint8_t>(systemGuid["SystemGUID11"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            systemGuidIface->register_property(
                "SystemGUID12",
                static_cast<uint8_t>(systemGuid["SystemGUID12"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            systemGuidIface->register_property(
                "SystemGUID13",
                static_cast<uint8_t>(systemGuid["SystemGUID13"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            systemGuidIface->register_property(
                "SystemGUID14",
                static_cast<uint8_t>(systemGuid["SystemGUID14"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            systemGuidIface->register_property(
                "SystemGUID15",
                static_cast<uint8_t>(systemGuid["SystemGUID15"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            systemGuidIface->initialize(true);
        }

        for (const auto& oemParamData : data["OEMParam"])
        {
            std::shared_ptr<sdbusplus::asio::dbus_interface> oemParamIface =
                objectServer.add_interface(pefObj, oemParamIntf);
            oemParamIface->register_property(
                "OemParam0", static_cast<uint8_t>(oemParamData["OEMParam0"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam1", static_cast<uint8_t>(oemParamData["OEMParam1"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam2", static_cast<uint8_t>(oemParamData["OEMParam2"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam3", static_cast<uint8_t>(oemParamData["OEMParam3"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam4", static_cast<uint8_t>(oemParamData["OEMParam4"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam5", static_cast<uint8_t>(oemParamData["OEMParam5"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam6", static_cast<uint8_t>(oemParamData["OEMParam6"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam7", static_cast<uint8_t>(oemParamData["OEMParam7"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam8", static_cast<uint8_t>(oemParamData["OEMParam8"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam9", static_cast<uint8_t>(oemParamData["OEMParam9"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam10", static_cast<uint8_t>(oemParamData["OEMParam10"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam11", static_cast<uint8_t>(oemParamData["OEMParam11"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam12", static_cast<uint8_t>(oemParamData["OEMParam12"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam13", static_cast<uint8_t>(oemParamData["OEMParam13"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam14", static_cast<uint8_t>(oemParamData["OEMParam14"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam15", static_cast<uint8_t>(oemParamData["OEMParam15"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam16", static_cast<uint8_t>(oemParamData["OEMParam16"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam17", static_cast<uint8_t>(oemParamData["OEMParam17"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam18", static_cast<uint8_t>(oemParamData["OEMParam18"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam19", static_cast<uint8_t>(oemParamData["OEMParam19"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam20", static_cast<uint8_t>(oemParamData["OEMParam20"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam21", static_cast<uint8_t>(oemParamData["OEMParam21"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam22", static_cast<uint8_t>(oemParamData["OEMParam22"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam23", static_cast<uint8_t>(oemParamData["OEMParam23"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam24", static_cast<uint8_t>(oemParamData["OEMParam24"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam25", static_cast<uint8_t>(oemParamData["OEMParam25"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam26", static_cast<uint8_t>(oemParamData["OEMParam26"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam27", static_cast<uint8_t>(oemParamData["OEMParam27"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam28", static_cast<uint8_t>(oemParamData["OEMParam28"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam29", static_cast<uint8_t>(oemParamData["OEMParam29"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam30", static_cast<uint8_t>(oemParamData["OEMParam30"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->register_property(
                "OemParam31", static_cast<uint8_t>(oemParamData["OEMParam31"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            oemParamIface->initialize(true);
        }

        // Group 40 event filter entries into four lists of 10 entries each
        // and expose them as array properties.
        std::map<int, const char*> eventFilterObjMap = {
            {0, eventFilterTableObjGrp1},
            {1, eventFilterTableObjGrp2},
            {2, eventFilterTableObjGrp3},
            {3, eventFilterTableObjGrp4}};

        std::map<int, std::vector<Json>> eventFilterBuckets = {
            {0, {}}, {1, {}}, {2, {}}, {3, {}}};

        int eventIdx = 0;
        for (const auto& eventFilterTableData : data["EventFilterTable"])
        {
            int bucket = eventIdx / 10;
            if (bucket > 3)
            {
                bucket = 3;
            }
            eventFilterBuckets[bucket].push_back(eventFilterTableData);
            ++eventIdx;
        }

        for (const auto& [bucket, entries] : eventFilterBuckets)
        {
            if (entries.empty())
            {
                continue;
            }

            auto objIt = eventFilterObjMap.find(bucket);
            if (objIt == eventFilterObjMap.end())
            {
                continue;
            }

            std::vector<uint8_t> entryIds;
            std::vector<uint8_t> filterConfig;
            std::vector<uint8_t> evtFilterAction;
            std::vector<uint8_t> alertPolicyNum;
            std::vector<uint8_t> eventSeverity;
            std::vector<uint8_t> genIdByte1;
            std::vector<uint8_t> genIdByte2;
            std::vector<uint8_t> sensorType;
            std::vector<uint8_t> sensorNum;
            std::vector<uint8_t> eventTrigger;
            std::vector<uint16_t> eventData1OffsetMask;
            std::vector<uint8_t> eventData1AndMask;
            std::vector<uint8_t> eventData1Cmp1;
            std::vector<uint8_t> eventData1Cmp2;
            std::vector<uint8_t> eventData2AndMask;
            std::vector<uint8_t> eventData2Cmp1;
            std::vector<uint8_t> eventData2Cmp2;
            std::vector<uint8_t> eventData3AndMask;
            std::vector<uint8_t> eventData3Cmp1;
            std::vector<uint8_t> eventData3Cmp2;

            for (const auto& eventFilterTableData : entries)
            {
                entryIds.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("EventFilterTableEntry", 0)));
                filterConfig.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("FilterConfig", 0)));
                evtFilterAction.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("EvtFilterAction", 0)));
                alertPolicyNum.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("AlertPolicyNum", 0)));
                eventSeverity.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("EventSeverity", 0)));
                genIdByte1.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("GenIDByte1", 0)));
                genIdByte2.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("GenIDByte2", 0)));
                sensorType.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("SensorType", 0)));
                sensorNum.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("SensorNum", 0)));
                eventTrigger.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("EventTrigger", 0)));
                eventData1OffsetMask.push_back(static_cast<uint16_t>(
                    eventFilterTableData.value("EventData1OffsetMask", 0)));
                eventData1AndMask.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("EventData1ANDMask", 0)));
                eventData1Cmp1.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("EventData1Cmp1", 0)));
                eventData1Cmp2.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("EventData1Cmp2", 0)));
                eventData2AndMask.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("EventData2ANDMask", 0)));
                eventData2Cmp1.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("EventData2Cmp1", 0)));
                eventData2Cmp2.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("EventData2Cmp2", 0)));
                eventData3AndMask.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("EventData3ANDMask", 0)));
                eventData3Cmp1.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("EventData3Cmp1", 0)));
                eventData3Cmp2.push_back(static_cast<uint8_t>(
                    eventFilterTableData.value("EventData3Cmp2", 0)));
            }

            std::shared_ptr<sdbusplus::asio::dbus_interface>
                eventFilterTblIface = objectServer.add_interface(
                    objIt->second, eventFilterTableIntf);

            eventFilterTblIface->register_property(
                "EventFilterTableEntry", entryIds,
                [](const std::vector<uint8_t>& value,
                   std::vector<uint8_t>& property) {
                    for (const auto& entry : value)
                    {
                        if (entry == 0x00)
                        {
                            PEF_DBG("EventFilterTableEntry invalid zero entry");
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Invalid EventFilterTableEntry");
                            return false;
                        }
                        if (entry > eventFilterTableMaxEntry)
                        {
                            PEF_DBG("EventFilterTableEntry invalid value="
                                    << static_cast<int>(entry));
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Invalid EventFilterTableEntry: exceeds maximum");
                            return false;
                        }
                    }
                    property = value;
                    return true;
                });
            eventFilterTblIface->register_property(
                "FilterConfig", filterConfig,
                [](const std::vector<uint8_t>& value,
                   std::vector<uint8_t>& property) {
                    for (const auto& config : value)
                    {
                        // Check bits[4:0] are reserved and must be 0
                        if ((config & filterConfigReservedBits) != 0)
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Invalid FilterConfig");
                            return false;
                        }
                        // Check bits[6:5] are not 11b (reserved)
                        if (((config >> 5) & 0x3) == filterConfigReserved1)
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Invalid FilterConfig");
                            return false;
                        }
                        // Check bits[6:5] are not 01b (reserved)
                        if (((config >> 5) & 0x3) == filterConfigReserved2)
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Invalid FilterConfig");
                            return false;
                        }
                    }
                    property = value;
                    return true;
                });
            eventFilterTblIface->register_property(
                "EvtFilterAction", evtFilterAction,
                [](const std::vector<uint8_t>& value,
                   std::vector<uint8_t>& property) {
                    for (const auto& action : value)
                    {
                        if (action > evtFilterActionMaxValue)
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Invalid EvtFilterAction");
                            return false;
                        }
                    }
                    property = value;
                    return true;
                });
            eventFilterTblIface->register_property(
                "AlertPolicyNum", alertPolicyNum,
                [](const std::vector<uint8_t>& value,
                   std::vector<uint8_t>& property) {
                    for (const auto& policyNum : value)
                    {
                        if (policyNum > alertPolicyNumMaxValue)
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Invalid AlertPolicyNum");
                            return false;
                        }
                    }
                    property = value;
                    return true;
                });
            eventFilterTblIface->register_property(
                "EventSeverity", eventSeverity,
                [](const std::vector<uint8_t>& value,
                   std::vector<uint8_t>& property) {
                    for (const auto& severity : value)
                    {
                        if ((((~severity) + 1) & severity) != severity ||
                            severity > 0x20)
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Invalid EventSeverity");
                            return false;
                        }
                    }
                    property = value;
                    return true;
                });
            eventFilterTblIface->register_property(
                "GenIDByte1", genIdByte1,
                sdbusplus::asio::PropertyPermission::readWrite);
            eventFilterTblIface->register_property(
                "GenIDByte2", genIdByte2,
                sdbusplus::asio::PropertyPermission::readWrite);
            eventFilterTblIface->register_property(
                "SensorType", sensorType,
                [](const std::vector<uint8_t>& value,
                   std::vector<uint8_t>& property) {
                    for (const auto& type : value)
                    {
                        if (type == 0x00 || type == 0xFF)
                        {
                            continue; // wildcard: match any sensor type
                        }
                        bool valid = false;
                        for (const auto& [name, code] : sensorTypes)
                        {
                            if (static_cast<uint8_t>(code.first) == type)
                            {
                                valid = true;
                                break;
                            }
                        }
                        if (!valid)
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Invalid SensorType");
                            return false;
                        }
                    }
                    property = value;
                    return true;
                });
            eventFilterTblIface->register_property(
                "SensorNum", sensorNum,
                [](const std::vector<uint8_t>& value,
                   std::vector<uint8_t>& property) {
                    std::shared_ptr<SensorNumMap> sensorNumMapPtr;
                    ::details::getSensorNumMap(sensorNumMapPtr);
                    if (!sensorNumMapPtr)
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            "SensorNum validation failed: sensor map "
                            "unavailable");
                        return false;
                    }
                    for (const auto& num : value)
                    {
                        if (num == 0xFF)
                        {
                            continue; // wildcard: match any sensor
                        }
                        if (sensorNumMapPtr->left.find(num) ==
                            sensorNumMapPtr->left.end())
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Invalid SensorNum");
                            return false;
                        }
                    }
                    property = value;
                    return true;
                });
            eventFilterTblIface->register_property(
                "EventTrigger", eventTrigger,
                sdbusplus::asio::PropertyPermission::readWrite);
            eventFilterTblIface->register_property(
                "EventData1OffsetMask", eventData1OffsetMask,
                sdbusplus::asio::PropertyPermission::readWrite);
            eventFilterTblIface->register_property(
                "EventData1ANDMask", eventData1AndMask,
                sdbusplus::asio::PropertyPermission::readWrite);
            eventFilterTblIface->register_property(
                "EventData1Cmp1", eventData1Cmp1,
                sdbusplus::asio::PropertyPermission::readWrite);
            eventFilterTblIface->register_property(
                "EventData1Cmp2", eventData1Cmp2,
                sdbusplus::asio::PropertyPermission::readWrite);
            eventFilterTblIface->register_property(
                "EventData2ANDMask", eventData2AndMask,
                sdbusplus::asio::PropertyPermission::readWrite);
            eventFilterTblIface->register_property(
                "EventData2Cmp1", eventData2Cmp1,
                sdbusplus::asio::PropertyPermission::readWrite);
            eventFilterTblIface->register_property(
                "EventData2Cmp2", eventData2Cmp2,
                sdbusplus::asio::PropertyPermission::readWrite);
            eventFilterTblIface->register_property(
                "EventData3ANDMask", eventData3AndMask,
                sdbusplus::asio::PropertyPermission::readWrite);
            eventFilterTblIface->register_property(
                "EventData3Cmp1", eventData3Cmp1,
                sdbusplus::asio::PropertyPermission::readWrite);
            eventFilterTblIface->register_property(
                "EventData3Cmp2", eventData3Cmp2,
                sdbusplus::asio::PropertyPermission::readWrite);

            eventFilterTblIface->initialize(true);
        }

        // Group alert policies into four lists (15 entries each) and expose
        // one object per LAN interface: eth0..eth3.
        std::map<int, const char*> alertPolicyObjMap = {
            {0, alertPolicyTableObjEth0},
            {1, alertPolicyTableObjEth1},
            {2, alertPolicyTableObjEth2},
            {3, alertPolicyTableObjEth3}};

        std::map<int, std::vector<Json>> alertPolicyBuckets = {
            {0, {}}, {1, {}}, {2, {}}, {3, {}}};

        int policyIdx = 0;
        for (const auto& alertPolicyTblData : data["AlertPolicyTable"])
        {
            int bucket = policyIdx / 15;
            if (bucket > 3)
            {
                bucket = 3;
            }
            alertPolicyBuckets[bucket].push_back(alertPolicyTblData);
            ++policyIdx;
        }

        for (const auto& [bucket, entries] : alertPolicyBuckets)
        {
            if (entries.empty())
            {
                continue;
            }

            auto objIt = alertPolicyObjMap.find(bucket);
            if (objIt == alertPolicyObjMap.end())
            {
                continue;
            }

            std::vector<uint8_t> groupNums;
            std::vector<uint8_t> enableAlerts;
            std::vector<uint8_t> policyActions;
            std::vector<uint8_t> channelNos;
            std::vector<uint8_t> destinationSels;
            std::vector<std::string> eventSpecificStrs;
            std::vector<uint8_t> alertStingKeys;

            for (const auto& alertPolicyTblData : entries)
            {
                groupNums.push_back(static_cast<uint8_t>(
                    alertPolicyTblData.value("AlertPolicyGroupNum", 0)));
                enableAlerts.push_back(static_cast<uint8_t>(
                    alertPolicyTblData.value("EnableAlert", 0)));
                policyActions.push_back(static_cast<uint8_t>(
                    alertPolicyTblData.value("PolicyAction", 0)));
                channelNos.push_back(static_cast<uint8_t>(
                    alertPolicyTblData.value("ChannelNo", 0)));
                destinationSels.push_back(static_cast<uint8_t>(
                    alertPolicyTblData.value("DestinationSel", 0)));
                eventSpecificStrs.push_back(static_cast<std::string>(
                    alertPolicyTblData.value("EventSpecificAlertStr", "")));
                alertStingKeys.push_back(static_cast<uint8_t>(
                    alertPolicyTblData.value("AlertStingkey", 0)));
            }

            std::shared_ptr<sdbusplus::asio::dbus_interface>
                alertPolicyTblIface = objectServer.add_interface(
                    objIt->second, alertPolicyTableIntf);

            alertPolicyTblIface->register_property(
                "AlertPolicyGroupNum", groupNums,
                [](const std::vector<uint8_t>& value,
                   std::vector<uint8_t>& property) {
                    for (const auto& groupNum : value)
                    {
                        if (groupNum == 0 || groupNum > maxAlertPolicyGroupNum)
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Invalid AlertPolicyGroupNum");
                            return false;
                        }
                    }
                    property = value;
                    return true;
                });
            alertPolicyTblIface->register_property(
                "EnableAlert", enableAlerts,
                [](const std::vector<uint8_t>& value,
                   std::vector<uint8_t>& property) {
                    for (const auto& enable : value)
                    {
                        if (enable > 1)
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Invalid EnableAlert");
                            return false;
                        }
                    }
                    property = value;
                    return true;
                });
            alertPolicyTblIface->register_property(
                "PolicyAction", policyActions,
                [](const std::vector<uint8_t>& value,
                   std::vector<uint8_t>& property) {
                    for (const auto& action : value)
                    {
                        if (action > policyActionMaxValue)
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Invalid PolicyAction");
                            return false;
                        }
                    }
                    property = value;
                    return true;
                });
            alertPolicyTblIface->register_property(
                "ChannelNo", channelNos,
                [](const std::vector<uint8_t>& value,
                   std::vector<uint8_t>& property) {
                    for (const auto& channelNo : value)
                    {
                        if (channelNo > 15)
                        {
                            PEF_DBG(
                                "ChannelNo validation failed max check value="
                                << static_cast<int>(channelNo));
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Invalid ChannelNo: exceeds maximum value");
                            return false;
                        }

                        try
                        {
                            auto bus = sdbusplus::bus::new_default();
                            auto method = bus.new_method_call(
                                userMgrBusName, userMgrRootPath,
                                accountPolicyIntf, getChInterfaceMapMethod);

                            auto reply = bus.call(method);
                            std::map<uint8_t, std::string> channelMap;
                            reply.read(channelMap);

                            // Check if channel number exists in the map
                            if (channelMap.find(channelNo) == channelMap.end())
                            {
                                PEF_DBG(
                                    "ChannelNo validation failed not in map value="
                                    << static_cast<int>(channelNo));
                                phosphor::logging::log<
                                    phosphor::logging::level::ERR>(
                                    "Invalid ChannelNo: channel not found");
                                return false;
                            }

                            if (!isEthInterfaceName(channelMap[channelNo]))
                            {
                                PEF_DBG(
                                    "ChannelNo validation failed non-eth iface="
                                    << channelMap[channelNo] << " value="
                                    << static_cast<int>(channelNo));
                                phosphor::logging::log<
                                    phosphor::logging::level::ERR>(
                                    "Invalid ChannelNo: interface is not LAN");
                                return false;
                            }
                        }
                        catch (const sdbusplus::exception_t& e)
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Failed to validate ChannelNo");
                            return false;
                        }
                    }
                    property = value;
                    return true;
                });
            alertPolicyTblIface->register_property(
                "DestinationSel", destinationSels,
                [](const std::vector<uint8_t>& value,
                   std::vector<uint8_t>& property) {
                    for (const auto& destSel : value)
                    {
                        if (destSel > maxDestinationSel)
                        {
                            PEF_DBG("DestinationSel validation failed value="
                                    << static_cast<int>(destSel));
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Invalid DestinationSel: exceeds maximum value");
                            return false;
                        }
                    }
                    property = value;
                    return true;
                });
            alertPolicyTblIface->register_property(
                "EventSpecificAlertStr", eventSpecificStrs,
                sdbusplus::asio::PropertyPermission::readOnly);
            alertPolicyTblIface->register_property(
                "AlertStingkey", alertStingKeys,
                sdbusplus::asio::PropertyPermission::readOnly);

            alertPolicyTblIface->initialize(true);
        }

        // Group 40 alert string entries into four lists of 10 entries each
        // and expose them as array properties.
        std::map<int, const char*> alertStringObjMap = {
            {0, alertStringTableObjGrp1},
            {1, alertStringTableObjGrp2},
            {2, alertStringTableObjGrp3},
            {3, alertStringTableObjGrp4}};

        std::map<int, std::vector<Json>> alertStringBuckets = {
            {0, {}}, {1, {}}, {2, {}}, {3, {}}};

        int alertStrIdx = 0;
        for (const auto& alertStringTblData : data["AlertStringTable"])
        {
            int bucket = alertStrIdx / 10;
            if (bucket > 3)
            {
                bucket = 3;
            }
            alertStringBuckets[bucket].push_back(alertStringTblData);
            ++alertStrIdx;
        }

        for (const auto& [bucket, entries] : alertStringBuckets)
        {
            if (entries.empty())
            {
                continue;
            }

            auto objIt = alertStringObjMap.find(bucket);
            if (objIt == alertStringObjMap.end())
            {
                continue;
            }

            std::vector<uint8_t> entryIds;
            std::vector<uint8_t> eventFilterSel;
            std::vector<uint8_t> alertStringSet;
            std::vector<uint16_t> alertString0;
            std::vector<uint16_t> alertString1;
            std::vector<uint16_t> alertString2;

            for (const auto& alertStringTblData : entries)
            {
                entryIds.push_back(static_cast<uint8_t>(
                    alertStringTblData.value("AlertStringTableEntry", 0)));
                eventFilterSel.push_back(static_cast<uint8_t>(
                    alertStringTblData.value("EventFilterSel", 0)));
                alertStringSet.push_back(static_cast<uint8_t>(
                    alertStringTblData.value("AlertStringSet", 0)));
                alertString0.push_back(static_cast<uint16_t>(
                    alertStringTblData.value("AlertString0", 0)));
                alertString1.push_back(static_cast<uint16_t>(
                    alertStringTblData.value("AlertString1", 0)));
                alertString2.push_back(static_cast<uint16_t>(
                    alertStringTblData.value("AlertString2", 0)));
            }

            std::shared_ptr<sdbusplus::asio::dbus_interface>
                alertStringTblIface = objectServer.add_interface(
                    objIt->second, alertStringTableIntf);

            alertStringTblIface->register_property(
                "AlertStringTableEntry", entryIds,
                sdbusplus::asio::PropertyPermission::readWrite);
            alertStringTblIface->register_property(
                "EventFilterSel", eventFilterSel,
                sdbusplus::asio::PropertyPermission::readWrite);
            alertStringTblIface->register_property(
                "AlertStringSet", alertStringSet,
                sdbusplus::asio::PropertyPermission::readWrite);
            alertStringTblIface->register_property(
                "AlertString0", alertString0,
                sdbusplus::asio::PropertyPermission::readWrite);
            alertStringTblIface->register_property(
                "AlertString1", alertString1,
                sdbusplus::asio::PropertyPermission::readWrite);
            alertStringTblIface->register_property(
                "AlertString2", alertString2,
                sdbusplus::asio::PropertyPermission::readWrite);

            alertStringTblIface->initialize(true);
        }

        for (const auto& destSelTable : data["DestinationSelector"])
        {
            int lanDestEntry = 0;
            lanDestEntry = destSelTable["LanDestination"];
            std::string destStrObjName =
                destStringTableObj + std::to_string(lanDestEntry);
            std::shared_ptr<sdbusplus::asio::dbus_interface> destSelIface =
                objectServer.add_interface(destStrObjName, destStringTableIntf);
            destSelIface->register_property(
                "LanChannel", static_cast<uint8_t>(destSelTable["LanChannel"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            destSelIface->register_property(
                "DestinationSelector",
                static_cast<uint8_t>(destSelTable["DestinationType"]),
                sdbusplus::asio::PropertyPermission::readWrite);
            destSelIface->initialize(true);
        }

        /* Load LAN parameter config and populate per-platform eth* objects */
        const std::map<std::string, const char*> legacyLanFiles = {
            {"eth0", pefLanParamConfFile_eth0},
            {"eth1", pefLanParamConfFile_eth1},
            {"eth2", pefLanParamConfFile_eth2},
            {"eth3", pefLanParamConfFile_eth3}};

        std::vector<std::string> lanInterfaces = getAvailableEthInterfaces();
        PEF_DBG("parsePefConfToDbus discovered LAN interface count="
                << lanInterfaces.size());
        if (lanInterfaces.empty())
        {
            PEF_DBG("parsePefConfToDbus no eth interfaces from channel map; "
                    "using legacy eth fallback");
            for (const auto& [ifaceName, _] : legacyLanFiles)
            {
                lanInterfaces.push_back(ifaceName);
            }
            PEF_DBG("parsePefConfToDbus fallback LAN interface count="
                    << lanInterfaces.size());
        }

        Json mergedLanData = parseJSONConfig(pefLanParamConfFile);
        Json mergedLanConfigs = Json::object();
        bool mergedLanConfigsAvailable = false;

        if (!mergedLanData.is_discarded())
        {
            if (mergedLanData.contains("Interfaces") &&
                mergedLanData["Interfaces"].is_object())
            {
                mergedLanConfigs = mergedLanData["Interfaces"];
                mergedLanConfigsAvailable = true;
            }
            else if (mergedLanData.is_object())
            {
                mergedLanConfigs = mergedLanData;
                mergedLanConfigsAvailable = true;
            }
        }

        for (const auto& ifaceName : lanInterfaces)
        {
            const std::string objPath =
                std::string(pefObj) + "/Interface_" + ifaceName;
            PEF_DBG("parsePefConfToDbus LAN iface begin="
                    << ifaceName << " objPath=" << objPath);
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "parsePefConfToDbus: creating LAN interface object");
            Json lanData;
            if (mergedLanConfigsAvailable &&
                mergedLanConfigs.contains(ifaceName))
            {
                lanData = mergedLanConfigs[ifaceName];
            }
            else
            {
                auto legacyIt = legacyLanFiles.find(ifaceName);
                if (legacyIt != legacyLanFiles.end())
                {
                    lanData = parseJSONConfig(legacyIt->second);
                }
            }

            if (lanData.is_discarded() || !lanData.contains("Config"))
            {
                PEF_DBG(
                    "parsePefConfToDbus LAN iface missing config, using defaults="
                    << ifaceName);
                lanData = Json::object();
                lanData["Config"] = Json::object();
            }
            try
            {
                auto& cfg = lanData["Config"];
                std::shared_ptr<sdbusplus::asio::dbus_interface> lanIface =
                    objectServer.add_interface(objPath, pefLanParamIntf);
                lanIface->register_property(
                    "CommunityString",
                    cfg.value("CommunityString", std::string("")),
                    [ifaceName](const std::string& value,
                                std::string& property) {
                        PEF_DBG("CommunityString update iface="
                                << ifaceName << " len=" << value.length());
                        if (value.length() > communityStringMaxLength)
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Invalid CommunityString: exceeds maximum length");
                            return false;
                        }
                        // Validate non-empty strings against SNMP configuration
                        // Empty strings are allowed for SNMPv3 which uses
                        // username auth
                        if (!value.empty() && !isCommStrValid(value))
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Invalid CommunityString: not found in SNMP configuration");
                            return false;
                        }
                        property = value;
                        updateLanParamConfigValue(ifaceName, "CommunityString",
                                                  value);
                        return true;
                    });
                lanIface->register_property(
                    "NumberofDestinations",
                    static_cast<uint8_t>(cfg.value("NumberofDestinations", 0)),
                    sdbusplus::asio::PropertyPermission::readOnly);

                // Collect destination entries from merged config (flat arrays
                // only) Expect arrays directly under Config: IPv4, IPv6,
                // UserName, Type, Timeout, Retries. Skip interface if arrays
                // are missing.
                const bool hasFlatArrays =
                    cfg.contains("IPv4") && cfg["IPv4"].is_array() &&
                    cfg.contains("IPv6") && cfg["IPv6"].is_array() &&
                    cfg.contains("UserName") && cfg["UserName"].is_array() &&
                    cfg.contains("Type") && cfg["Type"].is_array() &&
                    cfg.contains("Timeout") && cfg["Timeout"].is_array() &&
                    cfg.contains("Retries") && cfg["Retries"].is_array();

                if (!hasFlatArrays)
                {
                    PEF_DBG("parsePefConfToDbus LAN iface missing flat arrays="
                            << ifaceName);
                    lanIface->initialize(true);
                    continue;
                }

                try
                {
                    const uint8_t destCount = cfg.value(
                        "NumberofDestinations", static_cast<uint8_t>(0));
                    PEF_DBG("LAN iface=" << ifaceName << " destCount="
                                         << static_cast<int>(destCount));

                    auto ensureSized = [&](auto vec, const auto& fillVal) {
                        if (destCount && vec.size() < destCount)
                        {
                            vec.insert(vec.end(), destCount - vec.size(),
                                       fillVal);
                        }
                        return vec;
                    };

                    // IPv4/IPv6/UserName as array of strings
                    std::vector<std::string> ipv4Arr =
                        ensureSized(cfg["IPv4"].get<std::vector<std::string>>(),
                                    std::string("0.0.0.0"));
                    std::vector<std::string> ipv6Arr = ensureSized(
                        cfg["IPv6"].get<std::vector<std::string>>(),
                        std::string("0000:0000:0000:0000:0000:0000:0000:0000"));
                    std::vector<std::string> userArr = ensureSized(
                        cfg["UserName"].get<std::vector<std::string>>(),
                        std::string(""));

                    // Type/Timeout/Retries as arrays of uint8_t
                    std::vector<uint8_t> typeArr;
                    for (const auto& v : cfg["Type"])
                    {
                        typeArr.push_back(
                            static_cast<uint8_t>(v.get<uint32_t>()));
                    }
                    typeArr = ensureSized(typeArr, static_cast<uint8_t>(0));
                    auto sharedTypes =
                        std::make_shared<std::vector<uint8_t>>(typeArr);

                    std::vector<uint8_t> retriesArr;
                    for (const auto& v : cfg["Retries"])
                    {
                        retriesArr.push_back(
                            static_cast<uint8_t>(v.get<uint32_t>()));
                    }
                    retriesArr =
                        ensureSized(retriesArr, static_cast<uint8_t>(0));

                    std::vector<uint8_t> timeoutArr;
                    for (const auto& v : cfg["Timeout"])
                    {
                        timeoutArr.push_back(
                            static_cast<uint8_t>(v.get<uint32_t>()));
                    }
                    timeoutArr =
                        ensureSized(timeoutArr, static_cast<uint8_t>(0));

                    std::vector<uint8_t> addressTypeArr;
                    for (const auto& v : cfg["AddressType"])
                    {
                        addressTypeArr.push_back(
                            static_cast<uint8_t>(v.get<uint32_t>()));
                    }
                    addressTypeArr =
                        ensureSized(addressTypeArr, static_cast<uint8_t>(1));
                    PEF_DBG("LAN iface="
                            << ifaceName << " arraySizes IPv4="
                            << ipv4Arr.size() << " IPv6=" << ipv6Arr.size()
                            << " UserName=" << userArr.size()
                            << " Type=" << typeArr.size()
                            << " Timeout=" << timeoutArr.size()
                            << " Retries=" << retriesArr.size()
                            << " AddressType=" << addressTypeArr.size());

                    lanIface->register_property(
                        "IPv4", ipv4Arr,
                        [ifaceName](const std::vector<std::string>& value,
                                    std::vector<std::string>& property) {
                            for (const auto& ipv4 : value)
                            {
                                if (!validateIPv4Address(ipv4))
                                {
                                    PEF_DBG("IPv4 validation failed iface="
                                            << ifaceName << " value=" << ipv4);
                                    phosphor::logging::log<
                                        phosphor::logging::level::ERR>(
                                        "Invalid IPv4 address");
                                    return false;
                                }
                            }
                            property = value;
                            updateLanParamConfigValue(ifaceName, "IPv4", value);
                            return true;
                        });
                    lanIface->register_property(
                        "IPv6", ipv6Arr,
                        [ifaceName](const std::vector<std::string>& value,
                                    std::vector<std::string>& property) {
                            for (const auto& ipv6 : value)
                            {
                                if (!validateIPv6Address(ipv6))
                                {
                                    PEF_DBG("IPv6 validation failed iface="
                                            << ifaceName << " value=" << ipv6);
                                    phosphor::logging::log<
                                        phosphor::logging::level::ERR>(
                                        "Invalid IPv6 address");
                                    return false;
                                }
                            }
                            property = value;
                            updateLanParamConfigValue(ifaceName, "IPv6", value);
                            return true;
                        });
                    lanIface->register_property(
                        "userName", userArr,
                        [ifaceName, objPath,
                         sharedTypes](const std::vector<std::string>& value,
                                      std::vector<std::string>& property) {
                            // Use shared Type array for cross-validation
                            const auto& currentTypes = *sharedTypes;

                            for (size_t i = 0; i < value.size(); ++i)
                            {
                                const auto& name = value[i];
                                if (name.empty())
                                {
                                    continue;
                                }
                                // Validate user exists in User Manager
                                try
                                {
                                    auto bus = sdbusplus::bus::new_default();
                                    const std::string userObjPath =
                                        std::string(testUserObjPathPrefix) +
                                        name;
                                    auto method = bus.new_method_call(
                                        testUserManagerBus, userObjPath.c_str(),
                                        testPropIntf, testMethodGetAll);
                                    method.append(testUserAttributesIface);
                                    auto reply = bus.call(method);
                                    if (reply.is_method_error())
                                    {
                                        phosphor::logging::log<
                                            phosphor::logging::level::ERR>(
                                            "userName validation failed: user "
                                            "does not exist",
                                            phosphor::logging::entry(
                                                "USER=%s", name.c_str()));
                                        return false;
                                    }
                                }
                                catch (const sdbusplus::exception::exception& e)
                                {
                                    phosphor::logging::log<
                                        phosphor::logging::level::ERR>(
                                        "userName validation failed: user "
                                        "does not exist",
                                        phosphor::logging::entry("USER=%s",
                                                                 name.c_str()),
                                        phosphor::logging::entry("EXCEPTION=%s",
                                                                 e.what()));
                                    return false;
                                }

                                // Cross-validate with Type at same index
                                uint8_t type = 0;
                                if (i < currentTypes.size())
                                {
                                    type = currentTypes[i];
                                }

                                if (type == destinationTypeVersion3)
                                {
                                    // SNMPv3: check SNMP access enabled
                                    try
                                    {
                                        auto bus =
                                            sdbusplus::bus::new_default();
                                        const std::string userObjPath =
                                            std::string(testUserObjPathPrefix) +
                                            name;
                                        auto method = bus.new_method_call(
                                            testUserManagerBus,
                                            userObjPath.c_str(), testPropIntf,
                                            testMethodGet);
                                        method.append(
                                            std::string(
                                                testUserAttributesIface),
                                            "SNMPAccessEnableStatus");
                                        auto reply = bus.call(method);
                                        std::variant<bool> variant;
                                        reply.read(variant);
                                        bool snmpEnabled =
                                            std::get<bool>(variant);
                                        if (!snmpEnabled)
                                        {
                                            PEF_DBG("userName validation: SNMP "
                                                    "access not enabled "
                                                    "for user "
                                                    << name);
                                            phosphor::logging::log<
                                                phosphor::logging::level::ERR>(
                                                "Invalid userName: SNMPv3 "
                                                "requires SNMP access "
                                                "enabled for user",
                                                phosphor::logging::entry(
                                                    "USER=%s", name.c_str()));
                                            return false;
                                        }
                                    }
                                    catch (const std::exception& e)
                                    {
                                        PEF_DBG("userName validation: failed "
                                                "to check SNMP access for "
                                                << name << " err=" << e.what());
                                        phosphor::logging::log<
                                            phosphor::logging::level::ERR>(
                                            "userName validation failed: "
                                            "unable to verify SNMP access",
                                            phosphor::logging::entry(
                                                "USER=%s", name.c_str()));
                                        return false;
                                    }
                                }
                                else if (type == destinationTypeSMTP)
                                {
                                    // SMTP: check mail ID configured
                                    try
                                    {
                                        auto bus =
                                            sdbusplus::bus::new_default();
                                        const std::string userObjPath =
                                            std::string(testUserObjPathPrefix) +
                                            name;
                                        auto method = bus.new_method_call(
                                            testUserManagerBus,
                                            userObjPath.c_str(), testPropIntf,
                                            testMethodGet);
                                        method.append(
                                            std::string(
                                                testUserAttributesIface),
                                            "SMTPMailID");
                                        auto reply = bus.call(method);
                                        std::variant<std::string> variant;
                                        reply.read(variant);
                                        const auto& mailId =
                                            std::get<std::string>(variant);
                                        if (mailId.empty())
                                        {
                                            PEF_DBG("userName validation: SMTP "
                                                    "mail ID not configured"
                                                    " for user "
                                                    << name);
                                            phosphor::logging::log<
                                                phosphor::logging::level::ERR>(
                                                "Invalid userName: SMTP "
                                                "requires mail ID "
                                                "configured for user",
                                                phosphor::logging::entry(
                                                    "USER=%s", name.c_str()));
                                            return false;
                                        }
                                    }
                                    catch (const std::exception& e)
                                    {
                                        PEF_DBG("userName validation: failed "
                                                "to check SMTP mail ID for "
                                                << name << " err=" << e.what());
                                        phosphor::logging::log<
                                            phosphor::logging::level::ERR>(
                                            "userName validation failed: "
                                            "unable to verify SMTP mail ID",
                                            phosphor::logging::entry(
                                                "USER=%s", name.c_str()));
                                        return false;
                                    }
                                }
                            }
                            property = value;
                            updateLanParamConfigValue(ifaceName, "UserName",
                                                      value);
                            return true;
                        });
                    lanIface->register_property(
                        "Type", typeArr,
                        [ifaceName,
                         sharedTypes](const std::vector<uint8_t>& value,
                                      std::vector<uint8_t>& property) {
                            for (const auto& type : value)
                            {
                                // 0 = SNMPv1, 1 = SNMPv2c, 2 = SNMPv3,
                                // 3 = SMTP, 6 = OEM1, 7 = OEM2
                                if (type > destinationTypeVersion3 &&
                                    type != destinationTypeSMTP &&
                                    type != destinationTypeOem1 &&
                                    type != destinationTypeOem2)
                                {
                                    PEF_DBG("Type validation failed iface="
                                            << ifaceName << " value="
                                            << static_cast<int>(type));
                                    phosphor::logging::log<
                                        phosphor::logging::level::ERR>(
                                        "Invalid Type value");
                                    return false;
                                }
                            }
                            property = value;
                            *sharedTypes = value;
                            updateLanParamConfigValue(ifaceName, "Type", value);
                            return true;
                        });
                    lanIface->register_property(
                        "Timeout", timeoutArr,
                        [ifaceName](const std::vector<uint8_t>& value,
                                    std::vector<uint8_t>& property) {
                            property = value;
                            updateLanParamConfigValue(ifaceName, "Timeout",
                                                      value);
                            return true;
                        });
                    lanIface->register_property(
                        "Retries", retriesArr,
                        [ifaceName](const std::vector<uint8_t>& value,
                                    std::vector<uint8_t>& property) {
                            for (const auto& retry : value)
                            {
                                if (retry > retriesMaxValue)
                                {
                                    PEF_DBG("Retries validation failed iface="
                                            << ifaceName << " value="
                                            << static_cast<int>(retry));
                                    phosphor::logging::log<
                                        phosphor::logging::level::ERR>(
                                        "Invalid Retries value");
                                    return false;
                                }
                            }
                            property = value;
                            updateLanParamConfigValue(ifaceName, "Retries",
                                                      value);
                            return true;
                        });
                    lanIface->register_property(
                        "AddressType", addressTypeArr,
                        [ifaceName](const std::vector<uint8_t>& value,
                                    std::vector<uint8_t>& property) {
                            for (const auto& addrType : value)
                            {
                                // Validate AddressType is either 0 (IPv4) or 1
                                // (IPv6)
                                if (addrType != 0x1 && addrType != 0x2)
                                {
                                    PEF_DBG(
                                        "AddressType validation failed iface="
                                        << ifaceName << " value="
                                        << static_cast<int>(addrType));
                                    phosphor::logging::log<
                                        phosphor::logging::level::ERR>(
                                        "Invalid AddressType value");
                                    return false;
                                }
                            }
                            property = value;
                            updateLanParamConfigValue(ifaceName, "AddressType",
                                                      value);
                            return true;
                        });
                }
                catch (nlohmann::json::exception& e)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "parsePefConf: Error parsing flat-format LAN destinations");
                }

                // initialize parent LAN interface
                lanIface->initialize(true);
                PEF_DBG(
                    "parsePefConfToDbus LAN iface initialized=" << ifaceName);
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "parsePefConfToDbus: LAN interface object initialized");
            }
            catch (nlohmann::json::exception& e)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "parsePefConf: Error parsing LAN param config");
            }
        }
        PEF_DBG("parsePefConfToDbus complete");
    }
    catch (nlohmann::json::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "parsePefConf: Error parsing PEF config file");
        return;
    }
    catch (std::out_of_range& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "parsePefConf: Error invalid type");
        return;
    }
    return;
}

int main()
{
    PEF_DBG("pef-alert-manager main start");
    boost::asio::io_context io;
    auto conn = std::make_shared<sdbusplus::asio::connection>(io);
    conn->request_name(pefBus);
    auto server = sdbusplus::asio::object_server(conn);

    std::shared_ptr<sdbusplus::asio::dbus_interface> pefPostponeTmrIface =
        server.add_interface(pefArmPostponeTmrObj, pefPostponeTmrIntf);
    pefPostponeTmrIface->register_property(
        "ArmPEFPostponeTmr", static_cast<uint8_t>(0),
        sdbusplus::asio::PropertyPermission::readWrite);
    pefPostponeTmrIface->initialize(true);

    std::shared_ptr<sdbusplus::asio::dbus_interface> pefCountdownTmrIface =
        server.add_interface(pefArmPostponeTmrObj, pefCountdownTmrIntf);
    pefCountdownTmrIface->register_property(
        "TmrCountdownValue", static_cast<uint8_t>(0),
        sdbusplus::asio::PropertyPermission::readWrite);
    pefCountdownTmrIface->initialize(true);

    std::shared_ptr<sdbusplus::asio::dbus_interface> pefSnmpTestIface =
        server.add_interface(pefObj, pefSnmpTestIntf);
    pefSnmpTestIface->register_method("TestDestination", TestDestination);
    pefSnmpTestIface->register_method(
        "TestSNMP", [](uint8_t channelNo, uint8_t destinationSel) -> bool {
            const bool sent =
                phosphor::network::snmp::sendOBMCErrorNotification(
                    static_cast<uint32_t>(0xFFFF), getTestTimestamp(),
                    "Information", "PEF SNMP test notification", "PEFTestEvent",
                    "Asserted", "", "", "PEF_SNMP_TEST", channelNo,
                    destinationSel);
            return sent;
        });
    pefSnmpTestIface->initialize(true);

    std::shared_ptr<sdbusplus::asio::dbus_interface> pefSensorInfoIface =
        server.add_interface(pefObj, pefSensorInfoIntf);
    pefSensorInfoIface->register_method(
        "GetSensorNumNameMap", []() -> std::map<uint8_t, std::string> {
            return getSensorNumNameMap();
        });
    pefSensorInfoIface->register_method(
        "GetSensorNumNameMapByType",
        []() -> std::map<std::string, std::map<uint8_t, std::string>> {
            return getSensorNumNameMapByType();
        });
    pefSensorInfoIface->register_method(
        "GetSensorNumNameMapForType",
        [](const std::string& sensorType)
            -> std::vector<std::pair<uint8_t, std::string>> {
            return getSensorNumNameMapForType(sensorType);
        });
    pefSensorInfoIface->register_method(
        "GetAvailableSensorTypes", []() -> std::map<std::string, uint8_t> {
            return getAvailableSensorTypes();
        });
    pefSensorInfoIface->initialize(true);

    parsePefConfToDbus(conn, server);
    PEF_DBG("pef-alert-manager entering io.run");
    io.run();
    return 0;
}
