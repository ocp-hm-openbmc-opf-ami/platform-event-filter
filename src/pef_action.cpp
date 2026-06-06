/********************************
 *PEF and Alerting Process
 *Author: Raghul R
 *Email : raghulr@ami.com
 *
 * ******************************/

#include "pef_action.hpp"

#include "pef_config_update.hpp"
#include "pef_debug.hpp"
#include "snmp.hpp"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <nlohmann/json.hpp>
#include <snmp.hpp>
#include <snmp_notification.hpp>

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

bool retryEnable = false;
uint8_t retryCount = 0;
uint32_t timeInterval = 0;
uint8_t alertsLimit = 0;

static size_t getImmediateChildObjectPathCount(const std::string& parentPath);
using EthChannelMap = std::vector<std::pair<uint8_t, std::string>>;
static EthChannelMap getEthChannelInterfaceMap();
static std::optional<pefConfInfo> getPefConfInfo();
static std::optional<std::string> getSmtpMailID(
    const std::string& selectedUserName);
static std::string getInterfaceNameForChannel(uint8_t channelNo,
                                              const EthChannelMap& ethMap);
static int getChannelForInterfaceName(const std::string& ifaceName,
                                      const EthChannelMap& ethMap);

static EthChannelMap getEthChannelInterfaceMap()
{
    EthChannelMap ethMap;
    try
    {
        auto method = conn->new_method_call(userManagerBus, userMgrObjPath,
                                            userAccPolicyIntf, getMapMethod);
        std::map<uint8_t, std::string> channelMap;
        auto reply = conn->call(method);
        reply.read(channelMap);

        for (const auto& [channel, iface] : channelMap)
        {
            if (iface.rfind("eth", 0) == 0)
            {
                ethMap.emplace_back(channel, iface);
            }
            else
            {}
        }
    }
    catch (const std::exception& e)
    {}

    return ethMap;
}

static std::string getInterfaceNameForChannel(uint8_t channelNo,
                                              const EthChannelMap& ethMap)
{
    for (const auto& [channel, iface] : ethMap)
    {
        if (channel == channelNo)
        {
            return iface;
        }
    }
    return "";
}

static int getChannelForInterfaceName(const std::string& ifaceName,
                                      const EthChannelMap& ethMap)
{
    for (const auto& [channel, iface] : ethMap)
    {
        if (iface == ifaceName)
        {
            return static_cast<int>(channel);
        }
    }
    return -1;
}

static void toHexStr(const std::vector<uint8_t>& data, std::string& hexStr)
{
    std::stringstream stream;
    stream << std::hex << std::uppercase << std::setfill('0');
    for (size_t idx = 0; idx < data.size(); ++idx)
    {
        const int v = data[idx];
        stream << std::setw(2) << v;
    }
    hexStr = stream.str();
}

static void PEFActionSELLOG(uint8_t Action)
{
    auto bus = sdbusplus::bus::new_default();

    // Define the SEL entry details
    std::string message = "SEL Entry For Pef Action";
    std::string selDataStr;
    std::vector<uint8_t> selData = {0xC4, Action, 0xFF};
    toHexStr(selData, selDataStr);
    std::map<std::string, std::string> addData;
    addData["SENSOR_PATH"] = "";
    addData["GENERATOR_ID"] = std::to_string(0x0020);
    addData["RECORD_TYPE"] = std::to_string(0x02); // System Event Record
    addData["EVENT_DIR"] = std::to_string(0x1);    // Assert
    addData["SENSOR_TYPE"] = std::to_string(0x12); // SYSTEM EVENT Sensor Type
    addData["SENSOR_DATA"] = selDataStr;
    addData["EVENT_TYPE"] = std::to_string(0x6F);  // Sensor Specific Event Type

    auto method = bus.new_method_call(
        "xyz.openbmc_project.Logging", "/xyz/openbmc_project/logging",
        "xyz.openbmc_project.Logging.Create", "Create");

    // Append the parameters to the method call
    std::string journalMsg(
        message + ": " + " RecordType=" + std::to_string(02) +
        ", GeneratorID=" + std::to_string(0x2000) +
        ", EventDir=" + std::to_string(0x6F) + ", EventData=" + selDataStr);

    method.append(journalMsg,
                  "xyz.openbmc_project.Logging.Entry.Level.Informational",
                  addData);

    // Send the method call
    try
    {
        bus.call(method);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to add PEF Action SEL entry:",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
    }
}

std::string getCurrentTime()
{
    std::time_t currentTime = std::time(nullptr);
    struct tm* timeInfo = std::localtime(&currentTime);

    char buffer[80];
    std::strftime(buffer, sizeof(buffer), "%a %b %d %H:%M:%S %Z %Y", timeInfo);

    return buffer;
}

std::string getIPAddress(
    const std::optional<std::string>& ifaceName = std::nullopt)
{
    struct ifaddrs* ifAddrStruct = nullptr;
    struct ifaddrs* ifa = nullptr;
    void* addrPtr = nullptr;
    std::string ipAddress;
    size_t ifaIdx = 0;

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next, ++ifaIdx)
    {
        if ((ifa->ifa_addr != nullptr) && (ifa->ifa_addr->sa_family == AF_INET))
        {
            if (ifaceName.has_value() &&
                (std::strcmp(ifa->ifa_name, ifaceName.value().c_str()) != 0))
            {
                continue;
            }

            addrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
            char buffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, addrPtr, buffer, sizeof(buffer));
            if (std::strcmp(ifa->ifa_name, "lo") != 0)
            {
                ipAddress = buffer;
                break;
            }
        }
    }

    if (ifAddrStruct != nullptr)
    {
        freeifaddrs(ifAddrStruct);
    }

    return ipAddress;
}
static bool getPowerStatus()
{
    bool pwrGood = false;
    std::string pwrStatus;
    Value variant;
    try
    {
        auto method = conn->new_method_call(pwrService, pwrStateObjPath,
                                            PROP_INTF, METHOD_GET);
        method.append(pwrStateIface, "CurrentPowerState");
        auto reply = conn->call(method);
        reply.read(variant);
        pwrStatus = std::get<std::string>(variant);
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get PEFControl Value",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return pwrGood;
    }
    if (pwrStatus == "xyz.openbmc_project.State.Chassis.PowerState.On")
    {
        pwrGood = true;
    }
    return pwrGood;
}

static std::optional<pefConfInfo> getPefConfInfo()
{
    pefConfInfo pefcfgInfo = {};
    try
    {
        PropertyMap pefCfgValues;
        auto method =
            conn->new_method_call(pefBus, pefObj, PROP_INTF, METHOD_GET_ALL);
        method.append(pefConfInfoIntf);
        auto reply = conn->call(method);
        if (reply.is_method_error())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to get all Event Filtering properties");
            return std::nullopt;
        }
        reply.read(pefCfgValues);

        pefcfgInfo.PEFControl =
            std::get<uint8_t>(pefCfgValues.at("PEFControl"));
        pefcfgInfo.PEFActionGblControl =
            std::get<uint8_t>(pefCfgValues.at("PEFActionGblControl"));
        pefcfgInfo.PEFStartupDly =
            std::get<uint8_t>(pefCfgValues.at("PEFStartupDly"));
        pefcfgInfo.PEFAlertStartupDly =
            std::get<uint8_t>(pefCfgValues.at("PEFAlertStartupDly"));
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to fetch pef conf info Entries config",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return std::nullopt;
    }

    return pefcfgInfo;
}

static std::optional<std::string> getSmtpMailID(
    const std::string& selectedUserName)
{
    if (selectedUserName.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "selectedUserName is empty; cannot read SMTPMailID");
        return std::nullopt;
    }

    try
    {
        Value variant;
        const std::string userObjPath =
            std::string(userObjPathPrefix) + selectedUserName;
        auto method = conn->new_method_call(userManagerBus, userObjPath.c_str(),
                                            PROP_INTF, METHOD_GET);
        method.append(userAttributesIface, "SMTPMailID");
        auto reply = conn->call(method);
        if (reply.is_method_error())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to get SMTPMailID");
            return std::nullopt;
        }
        reply.read(variant);
        return std::get<std::string>(variant);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to read SMTPMailID",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return std::nullopt;
    }
}

static int initiateStateTransition(std::string powerAction)
{
    auto method =
        conn->new_method_call(pwrService, pwrCtlObjPath, PROP_INTF, METHOD_SET);
    method.append(pwrCtlIface, "RequestedHostTransition");
    method.append(std::variant<std::string>(powerAction.c_str()));

    auto reply = conn->call(method);

    if (reply.is_method_error())
    {
        std::cerr << "Failed to set RequestedHostTransition\n";
        return -1;
    }
    return 0;
}

static int initiateChassisStateTransition(std::string powerAction)
{
    auto method = conn->new_method_call(pwrService, pwrStateObjPath, PROP_INTF,
                                        METHOD_SET);
    method.append(pwrStateIface, "RequestedPowerTransition");
    method.append(std::variant<std::string>(powerAction.c_str()));

    auto reply = conn->call(method);

    if (reply.is_method_error())
    {
        std::cerr << "Failed to set RequestedPowerTransition\n";
        return -1;
    }
    return 0;
}

static bool checkSampleEvent(struct EventMsgData* eveMsgData)
{
    // sample event1
    if ((eveMsgData->sensorNum == 0x30) && (eveMsgData->sensorType == 0x01) &&
        ((eveMsgData->eventType & 0x7f) == 0x01) &&
        (eveMsgData->eventData[0] == 0x09) &&
        (eveMsgData->eventData[1] == 0xff) &&
        (eveMsgData->eventData[2] == 0xff))
    {
        return true;
    } // sample event2
    else if ((eveMsgData->sensorNum == 0x60) &&
             (eveMsgData->sensorType == 0x02) &&
             ((eveMsgData->eventType & 0x7f) == 0x01) &&
             (eveMsgData->eventData[0] == 0x02) &&
             (eveMsgData->eventData[1] == 0xff) &&
             (eveMsgData->eventData[2] == 0xff))
    {
        return true;
    } // sample event3
    else if ((eveMsgData->sensorNum == 0x53) &&
             (eveMsgData->sensorType == 0x0c) &&
             ((eveMsgData->eventType & 0x7f) == 0x6f) &&
             (eveMsgData->eventData[0] == 0x00) &&
             (eveMsgData->eventData[1] == 0xff) &&
             (eveMsgData->eventData[2] == 0xff))
    {
        return true;
    }

    return false;
}

static uint16_t sendSNMPAlert(struct EventMsgData* eventMsg, uint8_t channelNo,
                              uint8_t destinationSel)
{
    std::string sensorPath = getPathFromSensorNumber(eventMsg->sensorNum);
    const std::string sensorType =
        retrieveSensorTypeFromPath(sensorPath, eventMsg->sensorType);
    const std::string sensorName = getSensorNameFromPath(sensorPath);
    std::string severity;
    std::string direction = "Asserted";
    uint8_t sensorEventType = (eventMsg->eventType & EVENT_TYPE);
    uint8_t eventData = (eventMsg->eventData[0] & EVENT_STATE);
    bool assert = (eventMsg->eventType & EVENT_DIRECTION) ? false : true;

    const auto ethMap = getEthChannelInterfaceMap();
    const std::string ifaceName = getInterfaceNameForChannel(channelNo, ethMap);
    if (ifaceName.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to resolve interface for SNMP alert channel");
        return -1;
    }

    std::string bmcIPAddress = getIPAddress(ifaceName);
    if (bmcIPAddress.empty())
    {
        bmcIPAddress = getIPAddress();
    }

    if (sensorEventType != static_cast<uint8_t>(EventTypeCode::sensor_specific))
    {
        switch (eventData)
        {
            case 0x02:
            case 0x09:
                severity = "Critical";
                break;
            case 0x00:
            case 0x07:
                severity = "Warning";
                break;
        }
        if (!assert)
        {
            severity = "OK";
            direction = "Deasserted";
        }
    }
    else
    {
        severity = "Information";
    }
    std::string eventDataMsg = "unknown event";
    if (!(eventMsg->msgStr).empty())
    {
        eventDataMsg = eventMsg->msgStr;
    }
    else
    {
        uint8_t eventType = (eventMsg->eventType & EVENT_TYPE);
        if (eventType == static_cast<uint8_t>(EventTypeCode::threshold))
        {
            auto it = THRESHOLD_EVENT_TABLE.find(eventData);
            if (it != THRESHOLD_EVENT_TABLE.end())
                eventDataMsg = it->second;
        }
        else if (eventType == static_cast<uint8_t>(EventTypeCode::generic))
        {
            auto it = GENERIC_EVENT_TABLE.find(eventMsg->sensorType);
            if (it != GENERIC_EVENT_TABLE.end())
            {
                const auto& offset = it->second;
                auto eventIt = offset.find(eventData);
                if (eventIt != offset.end())
                    eventDataMsg = eventIt->second;
            }
        }
        else if (eventType ==
                 static_cast<uint8_t>(EventTypeCode::sensor_specific))
        {
            auto it = SENSOR_SPECIFIC_EVENT_TABLE.find(eventMsg->sensorType);
            if (it != SENSOR_SPECIFIC_EVENT_TABLE.end())
            {
                const auto& offset = it->second;
                auto eventIt = offset.find(eventData);
                if (eventIt != offset.end())
                {
                    std::string eventStr = eventIt->second;
                    eventDataMsg = sensorName + " " + direction + " " +
                                   eventStr;
                }
            }
        }
    }
    std::string timeStamp = getCurrentTime();
    std::string hostName;
    std::string EventSubjectSN;
    std::string adddata;
    Value variant;
    auto method = conn->new_method_call(networkService, networkObjPath,
                                        PROP_INTF, METHOD_GET);
    method.append(networkIface, "HostName");
    auto reply = conn->call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get HostName method");
    }
    reply.read(variant);
    hostName = std::get<std::string>(variant);
    hostName = hostName + ":" + bmcIPAddress;

    try
    {
        if (retryEnable)
        {
            auto retryMethod = conn->new_method_call(
                pendtaskService, pendtaskPath, pendtaskIface, "retryAlert");
            std::string identifier = std::to_string(eventMsg->recordId);
            nlohmann::json payloadJson = {
                {"timeStamp", timeStamp},
                {"severity", severity},
                {"eventDataMsg", eventDataMsg},
                {"sensorName", sensorName},
                {"sensorType", sensorType},
                {"direction", direction},
                {"eventSubjectSN", EventSubjectSN},
                {"additionalData", adddata},
                {"hostName", hostName}};
            std::string payload = payloadJson.dump();
            retryMethod.append("snmp", identifier, payload);
            auto retryReply = conn->call(retryMethod);
            bool retryQueued = false;
            retryReply.read(retryQueued);
            if (retryQueued)
            {
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    "SNMP alert queued for retry");
            }
            else
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "SNMP alert retry queue rejected "
                    "request");
                return -1;
            }
        }
        else
        {
            phosphor::network::snmp::sendOBMCErrorNotification(
                static_cast<uint32_t>(eventMsg->recordId), timeStamp, severity,
                eventDataMsg, sensorName, direction, EventSubjectSN, adddata,
                hostName, channelNo, destinationSel);
        }
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to send SNMP Trap");
        return -1;
    }

    return 0;
}

bool resolveHost(const std::string& host)
{
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC; /* allow IPv4 or IPv6 */
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (rc == 0 && res)
    {
        freeaddrinfo(res);
        return true;
    }
    return false;
}

bool isMailAlertConfigured()
{
    const char* primaryMailIfc = "xyz.openbmc_project.mail.alert.primary";
    const char* secondaryMailIfc = "xyz.openbmc_project.mail.alert.secondary";
    bool primaryEnable = false;
    bool secondaryEnable = false;
    auto bus = sdbusplus::bus::new_default();
    /* Check primary mail service */
    try
    {
        auto primaryProxy = bus.new_method_call(
            mailService, mailObjPath, "org.freedesktop.DBus.Properties", "Get");
        primaryProxy.append(primaryMailIfc, "Enable");
        auto reply = bus.call(primaryProxy);
        std::variant<bool> value;
        reply.read(value);
        primaryEnable = std::get<bool>(value);
        if (primaryEnable)
        {
            auto hostProxy =
                bus.new_method_call(mailService, mailObjPath,
                                    "org.freedesktop.DBus.Properties", "Get");
            hostProxy.append(primaryMailIfc, "Host");
            auto hostReply = bus.call(hostProxy);
            std::variant<std::string> hostVal;
            hostReply.read(hostVal);
            std::string host = std::get<std::string>(hostVal);
            if (resolveHost(host))
            {
                return true;
            }
        }
    }
    catch (const sdbusplus::exception::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get primary mail configuration",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
    }

    /* Check secondary mail service */
    try
    {
        auto secondaryProxy = bus.new_method_call(
            mailService, mailObjPath, "org.freedesktop.DBus.Properties", "Get");
        secondaryProxy.append(secondaryMailIfc, "Enable");
        auto reply = bus.call(secondaryProxy);
        std::variant<bool> value;
        reply.read(value);
        secondaryEnable = std::get<bool>(value);
        if (secondaryEnable)
        {
            auto hostProxy =
                bus.new_method_call(mailService, mailObjPath,
                                    "org.freedesktop.DBus.Properties", "Get");
            hostProxy.append(secondaryMailIfc, "Host");
            auto hostReply = bus.call(hostProxy);
            std::variant<std::string> hostVal;
            hostReply.read(hostVal);
            std::string host = std::get<std::string>(hostVal);
            if (resolveHost(host))
            {
                return true;
            }
        }
    }
    catch (const sdbusplus::exception::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get secondary mail configuration",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
    }
    return false;
}

static uint16_t sendSmtpAlert(struct EventMsgData* eveMsg,
                              const std::string& smtpMailID)
{
    std::string sensorPath = getPathFromSensorNumber(eveMsg->sensorNum);
    const std::string sensorType =
        retrieveSensorTypeFromPath(sensorPath, eveMsg->sensorType);
    const std::string sensorName = getSensorNameFromPath(sensorPath);
    std::string severity;
    uint8_t sensorEveType = (eveMsg->eventType & 0x7f);
    uint8_t evnDat = (eveMsg->eventData[0] & 0x0F);
    bool assert = (eveMsg->eventType & 0x80) ? false : true;
    if (sensorEveType != static_cast<uint8_t>(EventTypeCode::sensor_specific))
    {
        if (evnDat == 0x02 || evnDat == 0x09)
        {
            severity = "Critical";
        }
        else if (evnDat == 0x00 || evnDat == 0x07)
        {
            severity = "Warning";
        }

        if (!assert)
        {
            severity = "Ok";
        }
    }
    else
    {
        // Initilize Severity for Discrete sensor
        severity = "Information";
    }

    std::string eventDataMsg = "unknown event";
    if (!(eveMsg->msgStr).empty())
    {
        eventDataMsg = eveMsg->msgStr;
    }
    else
    {
        uint8_t eveType = (eveMsg->eventType & 0x7f);

        if (eveType == static_cast<uint8_t>(EventTypeCode::threshold))
        {
            auto it = THRESHOLD_EVENT_TABLE.find(evnDat);
            if (it != THRESHOLD_EVENT_TABLE.end())
                eventDataMsg = it->second;
        }
        else if (eveType == static_cast<uint8_t>(EventTypeCode::generic))
        {
            auto it = GENERIC_EVENT_TABLE.find(eveMsg->sensorType);
            if (it != GENERIC_EVENT_TABLE.end())
            {
                const auto& offset = it->second;
                auto eventIt = offset.find(evnDat);
                if (eventIt != offset.end())
                    eventDataMsg = eventIt->second;
            }
        }
        else if (eveType ==
                 static_cast<uint8_t>(EventTypeCode::sensor_specific))
        {
            auto it = SENSOR_SPECIFIC_EVENT_TABLE.find(eveMsg->sensorType);
            if (it != SENSOR_SPECIFIC_EVENT_TABLE.end())
            {
                const auto& offset = it->second;
                auto eventIt = offset.find(evnDat);
                if (eventIt != offset.end())
                    eventDataMsg = eventIt->second;
            }
        }
    }

    std::string hostName;
    std::string Subject;
    std::string Message;
    std::string alertSubject;
    try
    {
        Value variant;
        auto method =
            conn->new_method_call(pefBus, pefObj, PROP_INTF, METHOD_GET);
        method.append(pefConfInfoIntf, "Subject");
        auto reply = conn->call(method);
        if (reply.is_method_error())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to get Subject");
        }
        reply.read(variant);
        Subject = std::get<std::string>(variant);
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get Subject");
    }

    try
    {
        Value variant;
        auto method = conn->new_method_call(networkService, networkObjPath,
                                            PROP_INTF, METHOD_GET);
        method.append(networkIface, "HostName");
        auto reply = conn->call(method);
        if (reply.is_method_error())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to get HostName method");
        }
        reply.read(variant);
        hostName = std::get<std::string>(variant);
        if (Subject.empty())
        {
            if (severity == "Ok")
            {
                alertSubject = "Message from " + hostName;
            }
            else
            {
                alertSubject = "Alert from " + hostName;
            }
        }
        else
        {
            alertSubject = Subject;
        }
    }
    catch (sdbusplus::exception_t& e)
    {
        alertSubject = "PEF Alert";
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get HostName");
    }

    std::string alertBody;

    try
    {
        Value variant;

        auto method =
            conn->new_method_call(pefBus, pefObj, PROP_INTF, METHOD_GET);
        method.append(pefConfInfoIntf, "Message");
        auto reply = conn->call(method);
        reply.read(variant);
        Message = std::get<std::string>(variant);
        alertBody = Message + "\r\n";
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get Message");
    }

    bool samEve = false;
    samEve = checkSampleEvent(eveMsg);
    if (samEve == true)
    {
        alertBody += "Sensor Name : Not Found";
    }
    else
    {
        alertBody += "Sensor Name : " + sensorName + "\r\n" + "Sensor Type : " +
                     sensorType + " \r\n" + "Severity    : " + severity +
                     "\r\n" + "Description : " + eventDataMsg;
    }
    if (!smtpMailID.empty())
    {
        alertBody += "\r\nMail ID     : " + smtpMailID;
    }

    uint16_t mailstatus = 0;
    if (smtpMailID.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SMTPMailID is empty, cannot call ForgotPassSendMail");
        return -1;
    }

    try
    {
        if (retryEnable)
        {
            if (isMailAlertConfigured())
            {
                auto retryMethod = conn->new_method_call(
                    pendtaskService, pendtaskPath, pendtaskIface, "retryAlert");
                retryMethod.append("smtp", alertSubject, alertBody);
                auto retryReply = conn->call(retryMethod);
                bool retryQueued = false;
                retryReply.read(retryQueued);
                if (retryQueued)
                {
                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        "SMTP alert queued for retry");
                    mailstatus = 0;
                }
                else
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "SMTP alert failed and retry queue rejected "
                        "request",
                        phosphor::logging::entry("ORIGINAL_STATUS=%d",
                                                 mailstatus));
                }
            }
            else
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Mail alert is not configured or mail host is unreachable. "
                    "Skipping SMTP alert send");
                return -1;
            }
        }
        else
        {
            auto sendAlert = conn->new_method_call(mailService, mailObjPath,
                                                   mailIface, sendMailMethod);
            sendAlert.append(alertSubject.c_str(), alertBody.c_str());
            auto replyStatus = conn->call(sendAlert);
            if (replyStatus.is_method_error())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Failed to call send alert method");
                return -1;
            }
            replyStatus.read(mailstatus);
        }
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "D-Bus exception while sending or queueing SMTP alert",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return -1;
    }

    return mailstatus;
}

static std::vector<AlertPolicyTbl> checkAlertPoicyTbl(int alertPolicyNo)
{
    using AlertPolicyValue =
        std::variant<std::vector<uint8_t>, std::vector<std::string>>;
    using AlertPolicyMap = std::map<std::string, AlertPolicyValue>;

    std::vector<AlertPolicyTbl> matchedAltPolEntries;
    if (alertPolicyNo <= 0)
    {
        return matchedAltPolEntries;
    }

    static constexpr const char* alertPolicyTableObj =
        "/xyz/openbmc_project/PefAlertManager/AlertPolicyTable";
    std::vector<std::string> policyObjs;
    try
    {
        auto method = conn->new_method_call(
            MAPPER_BUSNAME, MAPPER_PATH, MAPPER_INTERFACE, "GetSubTreePaths");
        method.append(std::string(alertPolicyTableObj), 1,
                      std::vector<std::string>{});
        auto reply = conn->call(method);
        reply.read(policyObjs);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get AlertPolicyTable child object paths",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return matchedAltPolEntries;
    }

    const std::string childPrefix = std::string(alertPolicyTableObj) + "/";
    for (const auto& policyObj : policyObjs)
    {
        if (policyObj.rfind(childPrefix, 0) != 0)
        {
            continue;
        }

        try
        {
            AlertPolicyMap alertPolicyValues;
            auto method = conn->new_method_call(pefBus, policyObj.c_str(),
                                                PROP_INTF, METHOD_GET_ALL);
            method.append(alertPolicyTableIntf);
            auto reply = conn->call(method);
            if (reply.is_method_error())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Failed to get all Alert policy properties");
                continue;
            }
            reply.read(alertPolicyValues);

            for (const auto& [propName, propVal] : alertPolicyValues)
            {
                if (const auto* vals =
                        std::get_if<std::vector<uint8_t>>(&propVal))
                {}
                else if (const auto* vals =
                             std::get_if<std::vector<std::string>>(&propVal))
                {}
                else
                {}
            }

            const auto& groupNums = std::get<std::vector<uint8_t>>(
                alertPolicyValues.at("AlertPolicyGroupNum"));

            if (alertPolicyValues.count("EnableAlert"))
            {
                const auto& enableVals = std::get<std::vector<uint8_t>>(
                    alertPolicyValues.at("EnableAlert"));
            }
            if (alertPolicyValues.count("PolicyAction"))
            {
                const auto& vals = std::get<std::vector<uint8_t>>(
                    alertPolicyValues.at("PolicyAction"));
            }
            if (alertPolicyValues.count("ChannelNo"))
            {
                const auto& vals = std::get<std::vector<uint8_t>>(
                    alertPolicyValues.at("ChannelNo"));
            }
            if (alertPolicyValues.count("DestinationSel"))
            {
                const auto& vals = std::get<std::vector<uint8_t>>(
                    alertPolicyValues.at("DestinationSel"));
            }
            if (alertPolicyValues.count("EventSpecificAlertStr"))
            {
                const auto& vals = std::get<std::vector<std::string>>(
                    alertPolicyValues.at("EventSpecificAlertStr"));
            }

            for (size_t entryIndex = 0; entryIndex < groupNums.size();
                 ++entryIndex)
            {
                int dbgEnableAlert = -1;
                int dbgPolicyAction = -1;
                int dbgChannelNo = -1;
                int dbgDestinationSel = -1;
                std::string dbgEventSpecificAlertStr = "<na>";

                if (alertPolicyValues.count("EnableAlert"))
                {
                    const auto& vals = std::get<std::vector<uint8_t>>(
                        alertPolicyValues.at("EnableAlert"));
                    if (entryIndex < vals.size())
                    {
                        dbgEnableAlert = static_cast<int>(vals[entryIndex]);
                    }
                }
                if (alertPolicyValues.count("PolicyAction"))
                {
                    const auto& vals = std::get<std::vector<uint8_t>>(
                        alertPolicyValues.at("PolicyAction"));
                    if (entryIndex < vals.size())
                    {
                        dbgPolicyAction = static_cast<int>(vals[entryIndex]);
                    }
                }
                if (alertPolicyValues.count("ChannelNo"))
                {
                    const auto& vals = std::get<std::vector<uint8_t>>(
                        alertPolicyValues.at("ChannelNo"));
                    if (entryIndex < vals.size())
                    {
                        dbgChannelNo = static_cast<int>(vals[entryIndex]);
                    }
                }
                if (alertPolicyValues.count("DestinationSel"))
                {
                    const auto& vals = std::get<std::vector<uint8_t>>(
                        alertPolicyValues.at("DestinationSel"));
                    if (entryIndex < vals.size())
                    {
                        dbgDestinationSel = static_cast<int>(vals[entryIndex]);
                    }
                }
                if (alertPolicyValues.count("EventSpecificAlertStr"))
                {
                    const auto& vals = std::get<std::vector<std::string>>(
                        alertPolicyValues.at("EventSpecificAlertStr"));
                    if (entryIndex < vals.size())
                    {
                        dbgEventSpecificAlertStr = vals[entryIndex];
                    }
                }

                uint8_t enableAlertValue = 0xFF;
                if (alertPolicyValues.count("EnableAlert"))
                {
                    const auto& enableVals = std::get<std::vector<uint8_t>>(
                        alertPolicyValues.at("EnableAlert"));
                    if (entryIndex < enableVals.size())
                    {
                        enableAlertValue = enableVals[entryIndex];
                    }
                    if ((entryIndex >= enableVals.size()) ||
                        (enableVals[entryIndex] != 1))
                    {
                        continue;
                    }
                }

                const uint8_t groupNum = groupNums[entryIndex];
                if (groupNum != static_cast<uint8_t>(alertPolicyNo))
                {
                    continue;
                }

                AlertPolicyTbl alertPlyTbl = {};
                alertPlyTbl.AlertPolicyGroupNum = groupNum;

                if (alertPolicyValues.count("EnableAlert"))
                {
                    const auto& vals = std::get<std::vector<uint8_t>>(
                        alertPolicyValues.at("EnableAlert"));
                    if (entryIndex < vals.size())
                    {
                        alertPlyTbl.EnableAlert = vals[entryIndex];
                    }
                }

                if (alertPolicyValues.count("PolicyAction"))
                {
                    const auto& vals = std::get<std::vector<uint8_t>>(
                        alertPolicyValues.at("PolicyAction"));
                    if (entryIndex < vals.size())
                    {
                        alertPlyTbl.PolicyAction = vals[entryIndex];
                    }
                }

                if (alertPolicyValues.count("ChannelNo"))
                {
                    const auto& vals = std::get<std::vector<uint8_t>>(
                        alertPolicyValues.at("ChannelNo"));
                    if (entryIndex < vals.size())
                    {
                        alertPlyTbl.ChannelNo = vals[entryIndex];
                    }
                }

                if (alertPolicyValues.count("DestinationSel"))
                {
                    const auto& vals = std::get<std::vector<uint8_t>>(
                        alertPolicyValues.at("DestinationSel"));
                    if (entryIndex < vals.size())
                    {
                        alertPlyTbl.DestinationSel = vals[entryIndex];
                    }
                }

                if (alertPolicyValues.count("EventSpecificAlertStr"))
                {
                    const auto& vals = std::get<std::vector<std::string>>(
                        alertPolicyValues.at("EventSpecificAlertStr"));
                    if (entryIndex < vals.size())
                    {
                        alertPlyTbl.EventSpecificAlertStr = vals[entryIndex];
                    }
                }

                matchedAltPolEntries.push_back(alertPlyTbl);
            }
        }
        catch (sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to fetch Alert Policy Table Entries config",
                phosphor::logging::entry("EXCEPTION=%s", e.what()));
            continue;
        }
    }

    return matchedAltPolEntries;
}

static void performPefAction(
    const std::vector<EvtFilterTblEntry>& matEveFltEntries,
    struct EventMsgData* eveMsg, const EthChannelMap& ethMap,
    const pefConfInfo& pefcfgInfo)
{
    for (size_t entryIdx = 0; entryIdx < matEveFltEntries.size(); ++entryIdx)
    {
        const auto& eveFltTblEntry = matEveFltEntries[entryIdx];
#if 1
        if (((eveFltTblEntry.EvtFilterAction & POWER_OFF_ACTION) ==
             POWER_OFF_ACTION) ||
            ((eveFltTblEntry.EvtFilterAction & POWER_CYCLE_ACTION) ==
             POWER_CYCLE_ACTION) ||
            ((eveFltTblEntry.EvtFilterAction & RESET_ACTION) == RESET_ACTION))
        {
            if (((eveFltTblEntry.EvtFilterAction & POWER_OFF_ACTION) ==
                 POWER_OFF_ACTION) &&
                ((pefcfgInfo.PEFActionGblControl & POWER_OFF_ACTION) ==
                 POWER_OFF_ACTION))
            {
                if (pefcfgInfo.PEFControl & 0x02)
                    PEFActionSELLOG(POWER_OFF_ACTION);
                int rc = initiateChassisStateTransition(pwrCtlOff);
                if (rc < 0)
                    std::cerr << "Failed to do power action\n";
            }
            else if ((((eveFltTblEntry.EvtFilterAction & POWER_CYCLE_ACTION) ==
                       POWER_CYCLE_ACTION) &&
                      ((pefcfgInfo.PEFActionGblControl & POWER_CYCLE_ACTION) ==
                       POWER_CYCLE_ACTION)) ||
                     (((eveFltTblEntry.EvtFilterAction & RESET_ACTION) ==
                       RESET_ACTION) &&
                      ((pefcfgInfo.PEFActionGblControl & RESET_ACTION) ==
                       RESET_ACTION)))
            {
                if (pefcfgInfo.PEFControl & 0x02)
                {
                    if (((eveFltTblEntry.EvtFilterAction &
                          POWER_CYCLE_ACTION) == POWER_CYCLE_ACTION) &&
                        ((pefcfgInfo.PEFActionGblControl &
                          POWER_CYCLE_ACTION) == POWER_CYCLE_ACTION))
                    {
                        PEFActionSELLOG(POWER_CYCLE_ACTION);
                    }
                    else if (((eveFltTblEntry.EvtFilterAction & RESET_ACTION) ==
                              RESET_ACTION) &&
                             ((pefcfgInfo.PEFActionGblControl & RESET_ACTION) ==
                              RESET_ACTION))
                    {
                        PEFActionSELLOG(RESET_ACTION);
                    }
                }
                bool power = getPowerStatus();
                if (power == true)
                {
                    int rc = initiateStateTransition(pwrStateReset);
                    if (rc < 0)
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            "Failed to do power action");
                    }
                }
                else
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "Failed to do power action");
                }
            }
        }
#endif
        if (((eveFltTblEntry.EvtFilterAction & ALERT_ACTION) == ALERT_ACTION) &&
            ((pefcfgInfo.PEFActionGblControl & ALERT_ACTION) == ALERT_ACTION))
        {
            int AlertpolNum = 0;
            AlertpolNum = eveFltTblEntry.AlertPolicyNum & 0x0F;
            std::vector<AlertPolicyTbl> Alertpolicy{};
            Alertpolicy = checkAlertPoicyTbl(AlertpolNum);
            if (0 != Alertpolicy.size())
            {
                for (size_t policyIdx = 0; policyIdx < Alertpolicy.size();
                     ++policyIdx)
                {
                    const auto& AlertPlyTbl = Alertpolicy[policyIdx];
                    if (0 != (AlertPlyTbl.AlertPolicyGroupNum /*& 0x08*/))
                    {
                        uint16_t alertStatus = static_cast<uint16_t>(-1);
                        pefDestSelector pefDestInfo;
                        pefDestInfo = {};
                        std::string selectedUserName;

                        try
                        {
                            const uint8_t channelNo = static_cast<uint8_t>(
                                AlertPlyTbl.ChannelNo);      // &0x07);
                            const size_t destinationIndex = static_cast<size_t>(
                                AlertPlyTbl.DestinationSel); //&0x0F);

                            const std::string ifaceName =
                                getInterfaceNameForChannel(channelNo, ethMap);
                            if (ifaceName.empty())
                            {
                                continue;
                            }

                            const int reverseChannel =
                                getChannelForInterfaceName(ifaceName, ethMap);

                            std::string lanObjPath =
                                "/xyz/openbmc_project/PefAlertManager/Interface_" +
                                ifaceName;

                            using LanParamValue =
                                std::variant<std::vector<uint8_t>,
                                             std::vector<std::string>>;
                            using LanParamMap =
                                std::map<std::string, LanParamValue>;

                            LanParamMap lanParamValues;
                            auto method = conn->new_method_call(
                                pefBus, lanObjPath.c_str(), PROP_INTF,
                                METHOD_GET_ALL);
                            method.append(
                                "xyz.openbmc_project.pef.LanParamConfig");
                            auto reply = conn->call(method);
                            if (reply.is_method_error())
                            {
                                phosphor::logging::log<
                                    phosphor::logging::level::ERR>(
                                    "Failed to get LAN destination properties");
                                continue;
                            }

                            reply.read(lanParamValues);
                            if (!lanParamValues.count("Type"))
                            {
                                continue;
                            }

                            const auto& typeEntries =
                                std::get<std::vector<uint8_t>>(
                                    lanParamValues.at("Type"));
                            if (typeEntries.empty())
                            {
                                continue;
                            }

                            size_t selectedIndex = 0;

                            if (destinationIndex < typeEntries.size())
                            {
                                selectedIndex = destinationIndex;
                            }
                            else
                            {
                                continue;
                            }
                            selectedIndex -= 1; // DestinationSel
                            pefDestInfo.DestinationType =
                                typeEntries[selectedIndex];

                            if (lanParamValues.count("userName"))
                            {
                                const auto& userNameEntries =
                                    std::get<std::vector<std::string>>(
                                        lanParamValues.at("userName"));
                                if (selectedIndex < userNameEntries.size())
                                {
                                    selectedUserName =
                                        userNameEntries[selectedIndex];
                                }
                            }

                            if ((pefDestInfo.DestinationType == 3) &&
                                selectedUserName.empty())
                            {
                                continue;
                            }
                        }
                        catch (sdbusplus::exception_t& e)
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Failed to fetch Destination conf info for Pef",
                                phosphor::logging::entry("EXCEPTION=%s",
                                                         e.what()));
                            continue;
                        }
                        if (pefDestInfo.DestinationType == 3)
                        {
                            if (pefcfgInfo.PEFControl & 0x02)
                                PEFActionSELLOG(ALERT_ACTION);
                            std::string smtpMailID;
                            const auto smtpMailIdOpt =
                                getSmtpMailID(selectedUserName);
                            if (smtpMailIdOpt.has_value())
                            {
                                smtpMailID = smtpMailIdOpt.value();
                            }

                            alertStatus = sendSmtpAlert(eveMsg, smtpMailID);
                            if (alertStatus == 0)
                            {
                                phosphor::logging::log<
                                    phosphor::logging::level::INFO>(
                                    "Alert Send Sucessfully!!!");
                                try
                                {
                                    auto method = conn->new_method_call(
                                        pefBus, pefObj,
                                        "org.freedesktop.DBus.Properties",
                                        "Set");
                                    method.append(pefConfInfoIntf,
                                                  "LastBMCProcessedEventID");
                                    method.append(std::variant<uint16_t>(
                                        eveMsg->recordId));
                                    auto reply = conn->call(method);
                                }
                                catch (std::exception& e)
                                {
                                    phosphor::logging::log<
                                        phosphor::logging::level::ERR>(
                                        "Failed to set "
                                        "LastBMCProcessedEventID",
                                        phosphor::logging::entry("EXCEPTION=%s",
                                                                 e.what()));
                                }
                            }
                            else
                            {}
                        }
                        if (pefDestInfo.DestinationType <= 2)
                        {
                            if (pefcfgInfo.PEFControl & 0x02)
                                PEFActionSELLOG(ALERT_ACTION);
                            alertStatus = sendSNMPAlert(
                                eveMsg,
                                static_cast<uint8_t>(AlertPlyTbl.ChannelNo),
                                static_cast<uint8_t>(
                                    AlertPlyTbl.DestinationSel));
                            if (alertStatus == 0)
                            {
                                phosphor::logging::log<
                                    phosphor::logging::level::INFO>(
                                    "SNMP Trap Send Sucessfully!!!");
                            }
                            else
                            {
                                phosphor::logging::log<
                                    phosphor::logging::level::INFO>(
                                    "Failed to send SNMP Trap");
                            }
                        }
                        if ((pefDestInfo.DestinationType != 0) &&
                            (pefDestInfo.DestinationType != 1) &&
                            (pefDestInfo.DestinationType != 2) &&
                            (pefDestInfo.DestinationType != 3))
                        {}
                    }
                    else
                    {}
                }
            }
            else
            {}
        }
        else
        {}
    }
    return;
}

static uint8_t pefEveDataMatch(uint8_t value, uint8_t andMask, uint8_t cmp1,
                               uint8_t cmp2)
{
    uint8_t match;
    uint8_t temp1, temp2, cmp2Flag = 1;

    temp1 = (value & andMask);

    if ((temp1 & cmp1) == (cmp2 & cmp1))
    {
        match = 1;
        if (ALL_BITS_MATCH_EXACT != cmp1)
        {
            temp2 = temp1 & ~cmp1;

            if (ALL_ZERO_BITS != cmp2)
            {
                if (0 == (temp2 & cmp2))
                {
                    match = 0;
                }
                else
                {
                    cmp2Flag = 0;
                }
            }

            if (cmp2Flag && (cmp2 != ALL_ONE_BITS))
            {
                if (0 == ((~(temp2 | cmp1) & ~cmp2) & 0xFF))
                {
                    match = 0;
                }
                else
                {
                    match = 1;
                }
            }
        }
    }
    else
    {
        match = 0;
    }
    return match;
}

static size_t getImmediateChildObjectPathCount(const std::string& parentPath)
{
    try
    {
        std::vector<std::string> objPaths;
        auto method = conn->new_method_call(
            MAPPER_BUSNAME, MAPPER_PATH, MAPPER_INTERFACE, "GetSubTreePaths");
        method.append(parentPath, 1, std::vector<std::string>{});
        auto reply = conn->call(method);
        reply.read(objPaths);

        size_t childCount = 0;
        const std::string childPrefix = parentPath + "/";
        for (size_t pathIdx = 0; pathIdx < objPaths.size(); ++pathIdx)
        {
            const auto& path = objPaths[pathIdx];
            if (path.rfind(childPrefix, 0) == 0)
            {
                childCount++;
            }
        }
        return childCount;
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to count child object paths",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
    }
    return 0;
}

static void eventFilteringProcess(struct EventMsgData* eventMsg)
{
    using EventFilterValue =
        std::variant<std::vector<uint8_t>, std::vector<uint16_t>>;
    using EventFilterMap = std::map<std::string, EventFilterValue>;

    const size_t eventFilterChildPathCount = getImmediateChildObjectPathCount(
        "/xyz/openbmc_project/PefAlertManager/EventFilterTable");
    if (eventFilterChildPathCount == 0)
    {
        return;
    }

    std::vector<EvtFilterTblEntry> matchedEveFltEntries;
    for (size_t groupIndex = 1; groupIndex <= eventFilterChildPathCount;
         ++groupIndex)
    {
        std::string eveFltEntryObj =
            "/xyz/openbmc_project/PefAlertManager/EventFilterTable/List" +
            std::to_string(groupIndex);
        try
        {
            EventFilterMap values;
            auto method = conn->new_method_call(pefBus, eveFltEntryObj.c_str(),
                                                PROP_INTF, METHOD_GET_ALL);
            method.append(eventFilterTableIntf);
            auto reply = conn->call(method);
            if (reply.is_method_error())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Failed to get all properties");
            }
            reply.read(values);

            const auto& filterConfig =
                std::get<std::vector<uint8_t>>(values.at("FilterConfig"));
            const auto& genIdByte1 =
                std::get<std::vector<uint8_t>>(values.at("GenIDByte1"));
            const auto& genIdByte2 =
                std::get<std::vector<uint8_t>>(values.at("GenIDByte2"));
            const auto& sensorType =
                std::get<std::vector<uint8_t>>(values.at("SensorType"));
            const auto& sensorNum =
                std::get<std::vector<uint8_t>>(values.at("SensorNum"));
            const auto& eventTrigger =
                std::get<std::vector<uint8_t>>(values.at("EventTrigger"));
            const auto& eventData1AndMask =
                std::get<std::vector<uint8_t>>(values.at("EventData1ANDMask"));
            const auto& eventData1Cmp1 =
                std::get<std::vector<uint8_t>>(values.at("EventData1Cmp1"));
            const auto& eventData1Cmp2 =
                std::get<std::vector<uint8_t>>(values.at("EventData1Cmp2"));
            const auto& eventData2AndMask =
                std::get<std::vector<uint8_t>>(values.at("EventData2ANDMask"));
            const auto& eventData2Cmp1 =
                std::get<std::vector<uint8_t>>(values.at("EventData2Cmp1"));
            const auto& eventData2Cmp2 =
                std::get<std::vector<uint8_t>>(values.at("EventData2Cmp2"));
            const auto& eventData3AndMask =
                std::get<std::vector<uint8_t>>(values.at("EventData3ANDMask"));
            const auto& eventData3Cmp1 =
                std::get<std::vector<uint8_t>>(values.at("EventData3Cmp1"));
            const auto& eventData3Cmp2 =
                std::get<std::vector<uint8_t>>(values.at("EventData3Cmp2"));
            const auto& eventData1OffsetMask = std::get<std::vector<uint16_t>>(
                values.at("EventData1OffsetMask"));
            const auto& evtFilterAction =
                std::get<std::vector<uint8_t>>(values.at("EvtFilterAction"));
            const auto& alertPolicyNum =
                std::get<std::vector<uint8_t>>(values.at("AlertPolicyNum"));
            const auto& eventSeverity =
                std::get<std::vector<uint8_t>>(values.at("EventSeverity"));

            const size_t entryCount = filterConfig.size();
            for (size_t idx = 0; idx < entryCount; ++idx)
            {
                if (idx >= genIdByte1.size() || idx >= genIdByte2.size() ||
                    idx >= sensorType.size() || idx >= sensorNum.size() ||
                    idx >= eventTrigger.size() ||
                    idx >= eventData1AndMask.size() ||
                    idx >= eventData1Cmp1.size() ||
                    idx >= eventData1Cmp2.size() ||
                    idx >= eventData2AndMask.size() ||
                    idx >= eventData2Cmp1.size() ||
                    idx >= eventData2Cmp2.size() ||
                    idx >= eventData3AndMask.size() ||
                    idx >= eventData3Cmp1.size() ||
                    idx >= eventData3Cmp2.size() ||
                    idx >= eventData1OffsetMask.size() ||
                    idx >= evtFilterAction.size() ||
                    idx >= alertPolicyNum.size() || idx >= eventSeverity.size())
                {
                    continue;
                }

                EvtFilterTblEntry eveFltTblEntry = {};
                uint16_t OffsetMask = 1;

                eveFltTblEntry.FilterConfig = filterConfig[idx];
                eveFltTblEntry.GenIDByte1 = genIdByte1[idx];
                eveFltTblEntry.GenIDByte2 = genIdByte2[idx];
                eveFltTblEntry.SensorType = sensorType[idx];
                eveFltTblEntry.SensorNum = sensorNum[idx];
                eveFltTblEntry.EventTrigger = eventTrigger[idx];
                eveFltTblEntry.EventData1ANDMask = eventData1AndMask[idx];
                eveFltTblEntry.EventData1Cmp1 = eventData1Cmp1[idx];
                eveFltTblEntry.EventData1Cmp2 = eventData1Cmp2[idx];
                eveFltTblEntry.EventData2ANDMask = eventData2AndMask[idx];
                eveFltTblEntry.EventData2Cmp1 = eventData2Cmp1[idx];
                eveFltTblEntry.EventData2Cmp2 = eventData2Cmp2[idx];
                eveFltTblEntry.EventData3ANDMask = eventData3AndMask[idx];
                eveFltTblEntry.EventData3Cmp1 = eventData3Cmp1[idx];
                eveFltTblEntry.EventData3Cmp2 = eventData3Cmp2[idx];
                eveFltTblEntry.EventData1OffsetMask = eventData1OffsetMask[idx];
                eveFltTblEntry.EvtFilterAction = evtFilterAction[idx];
                eveFltTblEntry.AlertPolicyNum = alertPolicyNum[idx];
                eveFltTblEntry.EventSeverity = eventSeverity[idx];

                // around 40 filter checking for current event filter is enabled
                // or not
                if (0 == (eveFltTblEntry.FilterConfig & 0x80))
                {
                    continue;
                }

                if (((eveFltTblEntry.GenIDByte1 != 0xFF) &&
                     (eveFltTblEntry.GenIDByte1 != eventMsg->generatorId1)) ||
                    ((eveFltTblEntry.GenIDByte2 != 0xFF) &&
                     (eveFltTblEntry.GenIDByte2 != eventMsg->generatorId2)) ||
                    (0 == eventMsg->sensorType) ||
                    ((eveFltTblEntry.SensorType != 0xFF) &&
                     (eveFltTblEntry.SensorType != eventMsg->sensorType)) ||
                    ((eveFltTblEntry.SensorNum != 0xFF) &&
                     (eveFltTblEntry.SensorNum != eventMsg->sensorNum)) ||
                    ((eveFltTblEntry.EventTrigger != 0xFF) &&
                     (eveFltTblEntry.EventTrigger != eventMsg->eventType)))
                {
                    continue;
                }

                if (0 == pefEveDataMatch(eventMsg->eventData[0],
                                         eveFltTblEntry.EventData1ANDMask,
                                         eveFltTblEntry.EventData1Cmp1,
                                         eveFltTblEntry.EventData1Cmp2))
                {
                    continue;
                }
                if (0 == pefEveDataMatch(eventMsg->eventData[1],
                                         eveFltTblEntry.EventData2ANDMask,
                                         eveFltTblEntry.EventData2Cmp1,
                                         eveFltTblEntry.EventData2Cmp2))
                {
                    continue;
                }
                if (0 == pefEveDataMatch(eventMsg->eventData[2],
                                         eveFltTblEntry.EventData3ANDMask,
                                         eveFltTblEntry.EventData3Cmp1,
                                         eveFltTblEntry.EventData3Cmp2))
                {
                    continue;
                }

                OffsetMask = OffsetMask << (eventMsg->eventData[0] & 0x0F);
                if (0 == (OffsetMask & eveFltTblEntry.EventData1OffsetMask))
                {
                    continue;
                }

                matchedEveFltEntries.push_back(eveFltTblEntry);
            }
        }
        catch (sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to fetch Event Filtering Table Entry connfig",
                phosphor::logging::entry("EXCEPTION=%s", e.what()));
            continue;
        }
    }

    if (0 != matchedEveFltEntries.size())
    {
        const auto ethMap = getEthChannelInterfaceMap();
        const auto pefCfgInfo = getPefConfInfo();
        if (!pefCfgInfo.has_value())
        {
            return;
        }
        for (size_t matchedIdx = 0; matchedIdx < matchedEveFltEntries.size();
             ++matchedIdx)
        {
            const auto& entry = matchedEveFltEntries[matchedIdx];
        }
        performPefAction(matchedEveFltEntries, eventMsg, ethMap,
                         pefCfgInfo.value());
    }
    else
    {
        return;
    }
    return;
}

static void pefTask(const uint16_t& recId, const uint8_t& senType,
                    const uint8_t& senNum, const uint8_t& eveType,
                    const uint8_t& eveData1, const uint8_t& eveData2,
                    const uint8_t& eveData3, const uint16_t& genId,
                    const std::string& msgStr)
{
    EventMsgData eveMsg = {};
    eveMsg.recordId = recId;
    eveMsg.sensorType = senType;
    eveMsg.eventType = eveType;
    eveMsg.sensorNum = senNum;
    eveMsg.generatorId1 = ((genId >> 8) & 0xff);
    eveMsg.generatorId2 = (genId & 0xff);
    eveMsg.eventData[0] = eveData1;
    eveMsg.eventData[1] = eveData2;
    eveMsg.eventData[2] = eveData3;
    eveMsg.msgStr = msgStr;

    uint8_t pefCtl = 0;
    Value variant;
    try
    {
        auto method =
            conn->new_method_call(pefBus, pefObj, PROP_INTF, METHOD_GET);
        method.append(pefConfInfoIntf, "PEFControl");
        auto reply = conn->call(method);
        reply.read(variant);
        pefCtl = std::get<uint8_t>(variant);
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get PEFControl Value",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return;
    }

    uint8_t pefPostponeTimer = 0;
    Value var;
    try
    {
        auto method = conn->new_method_call(pefBus, pefPostponeTmrObj,
                                            PROP_INTF, METHOD_GET);
        method.append(pefPostponeTmrIface, "ArmPEFPostponeTmr");
        auto reply = conn->call(method);
        reply.read(var);
        pefPostponeTimer = std::get<uint8_t>(var);
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get PEFControl Value",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return;
    }

    if ((pefPostponeTimer == 0xFE) ||
        ((pefPostponeTimer != 0x00) && (pefPostponeTimer != 0xFF)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "PEF Task is Disabled by Postpone Timer");
        return;
    }
    // If PEF Disabled
    if (0 == (pefCtl & 0x01))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "PEF Action is Disabled");
        return;
    }

    eventFilteringProcess(&eveMsg);
    return;
}

static void saveConfig(bool retryEnable, uint8_t retryCount,
                       uint32_t timeInterval, uint8_t alertsLimit)
{
    try
    {
        std::filesystem::create_directories(
            std::filesystem::path(retryConfigFile).parent_path());

        std::ofstream outFile(retryConfigFile);
        if (!outFile)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to open retry config file for writing");
            return;
        }

        outFile << nlohmann::json{{"retryEnable", retryEnable},
                                  {"retryCount", retryCount},
                                  {"timeInterval", timeInterval},
                                  {"alertsLimit", alertsLimit}}
                       .dump(4);

        if (!outFile.good())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to write retry config");
        }
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Exception while saving config",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
    }
}

int main()
{
    try
    {
        conn->request_name(pefEventFilteringBus);

        auto server = sdbusplus::asio::object_server(conn);

        std::shared_ptr<sdbusplus::asio::dbus_interface> pefTaskIface =
            server.add_interface(pefEventFilteringObj, pefTaskIntf);

        std::ifstream file(retryConfigFile);
        if (file)
        {
            try
            {
                auto config = nlohmann::json::parse(file);
                retryEnable = config.value("retryEnable", false);
                retryCount = std::min(config.value("retryCount", 0), MAX_RETRY);
                timeInterval =
                    std::min(config.value("timeInterval", 0), MAX_INTERVAL);
                alertsLimit =
                    std::min(config.value("alertsLimit", 0), MAX_ALERTS_LIMIT);
            }
            catch (const nlohmann::json::exception& e)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Failed to parse retry config, using defaults",
                    phosphor::logging::entry("EXCEPTION=%s", e.what()));
            }
        }

        // Register doPefTask method
        pefTaskIface->register_method("doPefTask", pefTask);
        pefTaskIface->register_property(
            "retryEnable", retryEnable, [&](const bool& newVal, bool& oldVal) {
                oldVal = newVal;
                retryEnable = newVal;
                saveConfig(retryEnable, retryCount, timeInterval, alertsLimit);
                return true;
            });
        pefTaskIface->register_property(
            "retryCount", retryCount,
            [&](const uint8_t& newVal, uint8_t& oldVal) {
                if (!retryEnable)
                {
                    throw sdbusplus::exception::SdBusError(
                        -EPERM,
                        "retryEnable must be true before setting retryCount");
                }
                if (newVal > MAX_RETRY)
                {
                    throw sdbusplus::exception::SdBusError(
                        -EINVAL, "retryCount exceeds MAX_RETRY");
                }
                oldVal = newVal;
                retryCount = newVal;
                saveConfig(retryEnable, retryCount, timeInterval, alertsLimit);
                return true;
            });
        pefTaskIface->register_property(
            "timeInterval", timeInterval,
            [&](const uint32_t& newVal, uint32_t& oldVal) {
                if (!retryEnable)
                {
                    throw sdbusplus::exception::SdBusError(
                        -EPERM,
                        "retryEnable must be true before setting timeInterval");
                }
                if (newVal > MAX_INTERVAL)
                {
                    throw sdbusplus::exception::SdBusError(
                        -EINVAL, "timeInterval exceeds MAX_INTERVAL");
                }
                oldVal = newVal;
                timeInterval = newVal;
                saveConfig(retryEnable, retryCount, timeInterval, alertsLimit);
                return true;
            });
        pefTaskIface->register_property(
            "alertsLimit", alertsLimit,
            [&](const uint8_t& newVal, uint8_t& oldVal) {
                if (!retryEnable)
                {
                    throw sdbusplus::exception::SdBusError(
                        -EPERM, "retryEnable must be true before setting "
                                "alertsLimit");
                }
                if (newVal > MAX_ALERTS_LIMIT)
                {
                    throw sdbusplus::exception::SdBusError(
                        -EINVAL, "alertsLimit exceeds MAX_ALERTS_LIMIT");
                }
                oldVal = newVal;
                alertsLimit = newVal;
                saveConfig(retryEnable, retryCount, timeInterval, alertsLimit);
                return true;
            });
        pefTaskIface->initialize();

        // Reguster getSensorNum and GetSensorName  method
        std::shared_ptr<sdbusplus::asio::dbus_interface> pefSetSensorIface =
            server.add_interface(pefSetSensorObj, pefSetSensorIntf);

        pefSetSensorIface->register_method("SetSensorNumber", SetSensorNumber);

        pefSetSensorIface->register_method("GetSensorName", GetSensorName);
        pefSetSensorIface->register_method("GetFilterEnable", GetFilterEnable);
        pefSetSensorIface->register_method("SetFilterEnable", SetFilterEnable);
        pefSetSensorIface->initialize();

        sdbusplus::bus::match::match EventFilterTableMonitor =
            startEventFilterTableMonitor(conn);
        sdbusplus::bus::match::match AlertPolicyTableMonitor =
            startAlertPolicyTableMonitor(conn);
        sdbusplus::bus::match::match PefConfInfoMonitor =
            startPefConfInfoMonitor(conn);
        sdbusplus::bus::match::match ArmPefPostponeTimerMonitor =
            startArmPefPostponeTimerMonitor(conn);
        sdbusplus::bus::match::match DestinationSelectorMonitor =
            startDestinationSelectorMonitor(conn);

        io.run();
        return 0;
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        std::cerr << "D-Bus error: " << e.what() << std::endl;
        return 1;
    }
    catch (const boost::system::system_error& e)
    {
        std::cerr << "Boost system error: " << e.what() << std::endl;
        return 1;
    }
}
