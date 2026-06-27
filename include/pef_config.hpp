#pragma once
// #include <boost/asio/io_service.hpp>
#include <nlohmann/json.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/message.hpp>

#include <iostream>
#include <map>
#include <string>

using Json = nlohmann::json;

static constexpr const char* pefBus = "xyz.openbmc_project.pef.alert.manager";
static constexpr const char* pefObj = "/xyz/openbmc_project/PefAlertManager";
static constexpr const char* pefDbusIntf =
    "xyz.openbmc_project.pef.configurations";
static constexpr const char* pefSnmpTestIntf =
    "xyz.openbmc_project.pef.SnmpTest";
static constexpr const char* pefSensorInfoIntf =
    "xyz.openbmc_project.pef.SensorInfo";
static constexpr const char* pefConfInfoIntf =
    "xyz.openbmc_project.pef.PEFConfInfo";
static constexpr const char* pefArmPostponeTmrObj =
    "/xyz/openbmc_project/PefAlertManager/ArmPostponeTimer";
static constexpr const char* pefPostponeTmrIntf =
    "xyz.openbmc_project.pef.PEFPostponeTimer";
static constexpr const char* pefCountdownTmrIntf =
    "xyz.openbmc_project.pef.CountdownTmr";
static constexpr const char* systemGUIDIntf =
    "xyz.openbmc_project.pef.SystemGUID";
static constexpr const char* oemParamIntf = "xyz.openbmc_project.pef.OEMParam";
static constexpr const char* eventFilterTableObj =
    "/xyz/openbmc_project/PefAlertManager/EventFilterTable/Entry";
static constexpr const char* eventFilterTableIntf =
    "xyz.openbmc_project.pef.EventFilterTable";
static constexpr const char* eventFilterTableObjGrp1 =
    "/xyz/openbmc_project/PefAlertManager/EventFilterTable/List1";
static constexpr const char* eventFilterTableObjGrp2 =
    "/xyz/openbmc_project/PefAlertManager/EventFilterTable/List2";
static constexpr const char* eventFilterTableObjGrp3 =
    "/xyz/openbmc_project/PefAlertManager/EventFilterTable/List3";
static constexpr const char* eventFilterTableObjGrp4 =
    "/xyz/openbmc_project/PefAlertManager/EventFilterTable/List4";
static constexpr const char* alertPolicyTableObj =
    "/xyz/openbmc_project/PefAlertManager/AlertPolicyTable/Entry";
static constexpr const char* alertPolicyTableIntf =
    "xyz.openbmc_project.pef.AlertPolicyTable";
static constexpr const char* alertPolicyTableObjEth0 =
    "/xyz/openbmc_project/PefAlertManager/AlertPolicyTable/PolicyList_eth0";
static constexpr const char* alertPolicyTableObjEth1 =
    "/xyz/openbmc_project/PefAlertManager/AlertPolicyTable/PolicyList_eth1";
static constexpr const char* alertPolicyTableObjEth2 =
    "/xyz/openbmc_project/PefAlertManager/AlertPolicyTable/PolicyList_eth2";
static constexpr const char* alertPolicyTableObjEth3 =
    "/xyz/openbmc_project/PefAlertManager/AlertPolicyTable/PolicyList_eth3";
static constexpr const char* alertStringTableObj =
    "/xyz/openbmc_project/PefAlertManager/AlertStringTable/Entry";
static constexpr const char* alertStringTableIntf =
    "xyz.openbmc_project.pef.AlertStringTable";
static constexpr const char* alertStringTableObjGrp1 =
    "/xyz/openbmc_project/PefAlertManager/AlertStringTable/List1";
static constexpr const char* alertStringTableObjGrp2 =
    "/xyz/openbmc_project/PefAlertManager/AlertStringTable/List2";
static constexpr const char* alertStringTableObjGrp3 =
    "/xyz/openbmc_project/PefAlertManager/AlertStringTable/List3";
static constexpr const char* alertStringTableObjGrp4 =
    "/xyz/openbmc_project/PefAlertManager/AlertStringTable/List4";
static constexpr const char* destStringTableObj =
    "/xyz/openbmc_project/PefAlertManager/DestinationSelector/Entry";
static constexpr const char* destStringTableIntf =
    "xyz.openbmc_project.pef.DestinationSelectorTable";

static constexpr const char* pefLanParamConfFile =
    "/var/lib/pef-alert-manager/pef-lan-param-config.json";

static constexpr const char* pefLanParamConfFile_eth0 =
    "/var/lib/pef-alert-manager/pef-lan-param-config-eth0.json";
static constexpr const char* pefLanParamConfFile_eth1 =
    "/var/lib/pef-alert-manager/pef-lan-param-config-eth1.json";
static constexpr const char* pefLanParamConfFile_eth2 =
    "/var/lib/pef-alert-manager/pef-lan-param-config-eth2.json";
static constexpr const char* pefLanParamConfFile_eth3 =
    "/var/lib/pef-alert-manager/pef-lan-param-config-eth3.json";

static constexpr const char* pefLanParamObj_eth0 =
    "/xyz/openbmc_project/PefAlertManager/Interface_eth0";
static constexpr const char* pefLanParamObj_eth1 =
    "/xyz/openbmc_project/PefAlertManager/Interface_eth1";
static constexpr const char* pefLanParamObj_eth2 =
    "/xyz/openbmc_project/PefAlertManager/Interface_eth2";
static constexpr const char* pefLanParamObj_eth3 =
    "/xyz/openbmc_project/PefAlertManager/Interface_eth3";

static constexpr const char* pefLanParamIntf =
    "xyz.openbmc_project.pef.LanParamConfig";

// Note: MAC arrays were removed from LAN param JSON files; only
// IPv4/IPv6/UserName remain

// static constexpr const char* pefConfFilePath =
// "/usr/share/pef-alert-manager/pef-alert-manager.json";
static constexpr const char* pefConfFilePath =
    "/var/lib/pef-alert-manager/pef-alert-manager.json";

static constexpr uint8_t communityStringMaxLength = 18;
static constexpr uint8_t retriesMaxValue = 7;
static constexpr uint8_t eventFilterTableMaxEntry = 40;
static constexpr uint8_t filterConfigReservedBits = 0x1F;
static constexpr uint8_t filterConfigReserved1 = 0x3;
static constexpr uint8_t filterConfigReserved2 = 0x1;
static constexpr uint8_t evtFilterActionMaxValue = 0x7F;
static constexpr uint8_t alertPolicyNumMaxValue = 0x7F;
static constexpr uint8_t maxAlertPolicyGroupNum = 15;
static constexpr uint8_t policyActionMaxValue = 4;
static constexpr uint8_t maxDestinationSel = 15;
static constexpr uint8_t destinationTypeVersion3 = 2;
static constexpr uint8_t destinationTypeSMTP = 3;
static constexpr uint8_t destinationTypeOem1 = 6;
static constexpr uint8_t destinationTypeOem2 = 7;

static constexpr const char* userMgrBusName =
    "xyz.openbmc_project.User.Manager";
static constexpr const char* userMgrRootPath = "/xyz/openbmc_project/user";
static constexpr const char* accountPolicyIntf =
    "xyz.openbmc_project.User.AccountPolicy";
static constexpr const char* getChInterfaceMapMethod = "GetChannelInterfaceMap";

static constexpr const char* snmpBusName = "xyz.openbmc_project.Snmp.Conf";
static constexpr const char* snmpRootPath =
    "/xyz/openbmc_project/snmp/CommunityStrManager";
static constexpr const char* snmpCommStrIntf =
    "xyz.openbmc_project.Snmp.CommunityStrManager";

static constexpr const char* userManagerBus =
    "xyz.openbmc_project.User.Manager";
static constexpr const char* userMgrObjPath = "/xyz/openbmc_project/user";
static constexpr const char* userAccPolicyIntf =
    "xyz.openbmc_project.User.AccountPolicy";
static constexpr const char* getMapMethod = "GetChannelInterfaceMap";
static constexpr const char* userObjPathPrefix = "/xyz/openbmc_project/user/";
static constexpr const char* userAttributesIface =
    "xyz.openbmc_project.User.Attributes";
static constexpr const char* propIntf = "org.freedesktop.DBus.Properties";
static constexpr const char* methodGet = "Get";
static constexpr const char* methodGetAll = "GetAll";
static constexpr const char* mailService = "xyz.openbmc_project.mail";
static constexpr const char* mailObjPath = "/xyz/openbmc_project/mail/alert";
static constexpr const char* mailIface = "xyz.openbmc_project.mail.alert";

/**
 *parseJSONConfig -Parse out JSON config file
 */
Json parseJSONConfig(const std::string& configFile);

/**
 *validateIPv4Address - Validate IPv4 address
 *@param address - IPv4 address or hostname to validate
 *@return true if valid IPv4 or resolves to IPv4, false otherwise
 **/
bool validateIPv4Address(const std::string& address);

/**
 *validateIPv6Address - Validate IPv6 address
 *@param address - IPv6 address or hostname to validate
 *@return true if valid IPv6 or resolves to IPv6, false otherwise
 **/
bool validateIPv6Address(const std::string& address);

/**
 *isCommStrValid - Validate community string against SNMP configuration
 *@param value - Community string to validate
 *@return true if valid, false otherwise
 **/
bool isCommStrValid(const std::string& value);

/**
 *getSensorNumNameMap - Get a map of sensor numbers to sensor names
 *@return map of sensor number (uint8_t) to sensor name (string)
 **/
std::map<uint8_t, std::string> getSensorNumNameMap();

/**
 *getSensorNumNameMapByType - Get sensors grouped by type
 *@return map of sensor type string to map of sensor number to sensor name
 **/
std::map<std::string, std::map<uint8_t, std::string>>
    getSensorNumNameMapByType();

/**
 *getSensorNumNameMapForType - Get sensors filtered by a specific type
 *@param sensorType - sensor type string (e.g. "temperature", "fan_tach", "All")
 *@return vector of (sensor number, sensor name) pairs; "All" entry first if
 *applicable
 **/
std::vector<std::pair<uint8_t, std::string>> getSensorNumNameMapForType(
    const std::string& sensorType);

/**
 *getAvailableSensorTypes - Get available sensor types with a sample sensor
 *number
 *@return map of sensor type string to one sensor number (uint8_t) of that type
 **/
std::map<std::string, uint8_t> getAvailableSensorTypes();

/**
 *parsePefConfToDbus - Parse all configuration data from json and create dbus
 *property for json entries.
 **/
void parsePefConfToDbus(std::shared_ptr<sdbusplus::asio::connection> conn,
                        sdbusplus::asio::object_server& objectServer);
