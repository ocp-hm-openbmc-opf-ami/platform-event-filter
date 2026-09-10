#include "snmp_notification.hpp"

#include "Encryption.hpp"
#include "pef_config.hpp"
#include "pef_debug.hpp"

#include <arpa/inet.h>
#include <grp.h>
#include <netdb.h>

#include <sdbusplus/bus.hpp>

#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <variant>

namespace phosphor
{
namespace network
{
namespace snmp
{
namespace
{

using DbusInterface = std::string;
using DbusProperty = std::string;
using DbusValue = std::variant<bool, uint8_t, int16_t, uint16_t, int32_t,
                               uint32_t, int64_t, uint64_t, std::string,
                               std::vector<uint8_t>, std::vector<std::string>>;
using PropertyMap = std::map<DbusProperty, DbusValue>;
using DbusInterfaceMap = std::map<DbusInterface, PropertyMap>;
using ObjectValueTree =
    std::map<sdbusplus::message::object_path, DbusInterfaceMap>;

struct AddrDeleter
{
    void operator()(addrinfo* addrPtr) const
    {
        freeaddrinfo(addrPtr);
    }
};

using AddrPtr = std::unique_ptr<addrinfo, AddrDeleter>;
using SessionPtr = std::unique_ptr<netsnmp_session, decltype(&::snmp_close)>;

struct ManagerProperty
{
    std::string ipaddress;
    std::string version;
    std::string community;
    std::string userName;
    std::string algorithm;
    std::string encryption;
    std::string password;
};

std::map<uint8_t, std::string> getEthChannelInterfaceMap(sdbusplus::bus_t& bus)
{
    static constexpr const char* userMgrBus =
        "xyz.openbmc_project.User.Manager";
    static constexpr const char* userMgrObj = "/xyz/openbmc_project/user";
    static constexpr const char* userAccPolicyIntf =
        "xyz.openbmc_project.User.AccountPolicy";
    static constexpr const char* getMapMethod = "GetChannelInterfaceMap";

    std::map<uint8_t, std::string> ethMap;
    try
    {
        auto method = bus.new_method_call(userMgrBus, userMgrObj,
                                          userAccPolicyIntf, getMapMethod);
        std::map<uint8_t, std::string> channelMap;
        auto reply = bus.call(method);
        reply.read(channelMap);

        for (const auto& [channel, iface] : channelMap)
        {
            if (iface.rfind("eth", 0) == 0)
            {
                ethMap.emplace(channel, iface);
                PEF_SNMP_DBG("Channel map eth entry channel="
                             << static_cast<int>(channel)
                             << " iface=" << iface);
            }
            else
            {
                PEF_SNMP_DBG("Channel map non-eth entry skipped channel="
                             << static_cast<int>(channel)
                             << " iface=" << iface);
            }
        }
    }
    catch (const std::exception& e)
    {
        PEF_SNMP_DBG("Failed to fetch channel interface map: " << e.what());
    }

    return ethMap;
}

ObjectValueTree getManagedObjects(sdbusplus::bus_t& bus,
                                  const std::string& service,
                                  const std::string& objPath)
{
    PEF_SNMP_DBG(
        "GetManagedObjects service=" << service << " path=" << objPath);
    ObjectValueTree interfaces;
    auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                      "org.freedesktop.DBus.ObjectManager",
                                      "GetManagedObjects");
    auto reply = bus.call(method);
    reply.read(interfaces);
    PEF_SNMP_DBG("GetManagedObjects result objects=" << interfaces.size());
    return interfaces;
}

std::string formatPeerAddress(const std::string& address, uint8_t addressType)
{
    PEF_SNMP_DBG("formatPeerAddress address=" << address << " addressType="
                                              << static_cast<int>(addressType));
    if (address.empty())
    {
        PEF_SNMP_DBG("formatPeerAddress skip: empty address");
        return "";
    }

    if ((addressType == 1 && address == "0.0.0.0") ||
        (addressType == 2 &&
         address == "0000:0000:0000:0000:0000:0000:0000:0000"))
    {
        PEF_SNMP_DBG("formatPeerAddress skip: default/zero address");
        return "";
    }

    if (addressType == 2)
    {
        if (!address.empty() && address.front() != '[')
        {
            PEF_SNMP_DBG("formatPeerAddress using IPv6 bracket format");
            return "[" + address + "]:" + std::to_string(SNMP_TRAP_PORT);
        }
    }

    PEF_SNMP_DBG("formatPeerAddress using IPv4/plain format");
    return address + ":" + std::to_string(SNMP_TRAP_PORT);
}

std::map<std::string, bool> getSNMPDisableStatus()
{
    PEF_SNMP_DBG("Reading SNMP disable status from "
                 << PEF_SNMP_CONF_FILE_PATH);
    std::map<std::string, bool> disableStatus = {
        {"v1", false}, {"v2c", false}, {"v3", false}};

    std::ifstream snmpConfFileStream(PEF_SNMP_CONF_FILE_PATH);
    if (!snmpConfFileStream.is_open())
    {
        PEF_SNMP_DBG("SNMP config not found, using defaults");
        return disableStatus;
    }

    std::string line;
    while (std::getline(snmpConfFileStream, line))
    {
        std::istringstream lineStream(line);
        std::string key;
        std::string value;

        if (!(lineStream >> key >> value))
        {
            continue;
        }

        if (key == "disableSNMPv1")
        {
            key = "v1";
        }
        else if (key == "disableSNMPv2c")
        {
            key = "v2c";
        }
        else if (key == "disableSNMPv3")
        {
            key = "v3";
        }

        if ((key == "v1") || (key == "v2c") || (key == "v3"))
        {
            disableStatus[key] =
                (value == "1" || value == "true" || value == "yes");
            PEF_SNMP_DBG("disable status key="
                         << key << " value=" << disableStatus[key]);
        }
    }

    return disableStatus;
}

bool getTrapEnabled()
{
    bool snmpTrapStatus = false;
    std::ifstream snmpTrapStatusFileStream(PEF_SNMP_TRAP_STATUS_FILE_PATH,
                                           std::ios::in);
    if (!snmpTrapStatusFileStream.is_open())
    {
        PEF_SNMP_DBG("SnmpTrapStatus file not found");
        return false;
    }

    snmpTrapStatusFileStream >> std::boolalpha >> snmpTrapStatus;
    PEF_SNMP_DBG("SNMP trap enabled=" << snmpTrapStatus);
    return snmpTrapStatus;
}

bool loadSnmpV3UserFromDBus(sdbusplus::bus_t& bus, const std::string& userName,
                            std::string& algorithm, std::string& encryption,
                            std::string& password)
{
    PEF_SNMP_DBG("Loading SNMPv3 user from D-Bus user=" << userName);
    auto method = bus.new_method_call(
        SNMP_CONF_SERVICE,
        (std::string(SNMP_USER_MANAGER_ROOT) + userName).c_str(),
        "org.freedesktop.DBus.Properties", "GetAll");
    method.append(std::string(SNMP_USER_MANAGER_INTF));

    PropertyMap userProps;
    try
    {
        auto reply = bus.call(method);
        reply.read(userProps);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Failed to read SNMP user manager for user " << userName
                  << ": " << e.what() << '\n';
        return false;
    }

    try
    {
        algorithm = std::get<std::string>(userProps.at("Algorithm"));
        encryption = std::get<std::string>(userProps.at("Encryption"));
        auto encryptedPassword =
            std::get<std::string>(userProps.at("Password"));
        int outLen = 0;
        password = decryptString(encryptedPassword, &outLen);
        PEF_SNMP_DBG("Loaded SNMPv3 user properties user="
                     << userName << " algorithm=" << algorithm << " encryption="
                     << encryption << " passwordLen=" << password.size());
    }
    catch (const std::exception& e)
    {
        std::cerr << "Invalid SNMP user properties for user " << userName
                  << ": " << e.what() << '\n';
        return false;
    }

    if (password.empty())
    {
        PEF_SNMP_DBG(
            "SNMPv3 user password decrypt result empty for user=" << userName);
        return false;
    }

    return true;
}

std::vector<ManagerProperty> getManagers(
    const std::optional<uint8_t>& channelNoFilter,
    const std::optional<uint8_t>& destinationSelFilter)
{
    PEF_SNMP_DBG("Building manager list from PEF LAN config");
    std::vector<ManagerProperty> managers;
    auto bus = sdbusplus::bus::new_default();

    const auto ethMap = getEthChannelInterfaceMap(bus);
    PEF_SNMP_DBG("Eth channel map size=" << ethMap.size());

    if (!channelNoFilter.has_value())
    {
        PEF_SNMP_DBG("channelNoFilter not provided, skipping manager build");
        return managers;
    }

    const auto channelIt = ethMap.find(channelNoFilter.value());
    if (channelIt == ethMap.end())
    {
        PEF_SNMP_DBG("Filtered channel not found in eth map. channel="
                     << static_cast<int>(channelNoFilter.value()));
        return managers;
    }

    const auto channel = channelIt->first;
    const auto& iface = channelIt->second;
    PEF_SNMP_DBG("Processing LAN config for iface="
                 << iface << " channel=" << static_cast<int>(channel));

    // Read LAN config directly from JSON file instead of D-Bus GetAll
    // to avoid ELOOP error (this code runs inside the same service).
    Json lanData;
    {
        std::ifstream in(pefLanParamConfFile);
        if (!in.is_open())
        {
            PEF_SNMP_DBG("Cannot open LAN config file=" << pefLanParamConfFile);
            return managers;
        }
        auto mergedData = Json::parse(in, nullptr, false);
        if (mergedData.is_discarded())
        {
            PEF_SNMP_DBG("Failed to parse LAN config file");
            return managers;
        }
        if (mergedData.contains("Interfaces") &&
            mergedData["Interfaces"].is_object() &&
            mergedData["Interfaces"].contains(iface))
        {
            lanData = mergedData["Interfaces"][iface];
        }
        else if (mergedData.contains(iface))
        {
            lanData = mergedData[iface];
        }
    }

    if (lanData.is_null() || lanData.is_discarded() ||
        !lanData.contains("Config"))
    {
        PEF_SNMP_DBG("No config section for iface=" << iface);
        return managers;
    }

    try
    {
        auto& cfg = lanData["Config"];

        // Parse arrays from JSON config
        std::vector<uint8_t> type;
        if (cfg.contains("Type") && cfg["Type"].is_array())
        {
            for (const auto& v : cfg["Type"])
                type.push_back(static_cast<uint8_t>(v.get<uint32_t>()));
        }
        std::vector<uint8_t> addressType;
        if (cfg.contains("AddressType") && cfg["AddressType"].is_array())
        {
            for (const auto& v : cfg["AddressType"])
                addressType.push_back(static_cast<uint8_t>(v.get<uint32_t>()));
        }
        std::vector<std::string> ipv4;
        if (cfg.contains("IPv4") && cfg["IPv4"].is_array())
            ipv4 = cfg["IPv4"].get<std::vector<std::string>>();
        std::vector<std::string> ipv6;
        if (cfg.contains("IPv6") && cfg["IPv6"].is_array())
            ipv6 = cfg["IPv6"].get<std::vector<std::string>>();
        std::vector<std::string> userName;
        if (cfg.contains("UserName") && cfg["UserName"].is_array())
            userName = cfg["UserName"].get<std::vector<std::string>>();
        std::string community = cfg.value("CommunityString", std::string(""));

        const size_t entryCount = type.size();
        PEF_SNMP_DBG("LAN entryCount="
                     << entryCount << " addressTypeSize=" << addressType.size()
                     << " ipv4Size=" << ipv4.size() << " ipv6Size="
                     << ipv6.size() << " userNameSize=" << userName.size());

        if (!destinationSelFilter.has_value())
        {
            PEF_SNMP_DBG(
                "destinationSelFilter not provided, skipping manager build");
            return managers;
        }

        size_t selectedIndex =
            static_cast<size_t>(destinationSelFilter.value() - 1);
        if (selectedIndex >= entryCount)
        {
            PEF_SNMP_DBG("DestinationSel out of range for channel="
                         << static_cast<int>(channel) << " destinationSel="
                         << static_cast<int>(destinationSelFilter.value())
                         << " entryCount=" << entryCount);
            return managers;
        }

        PEF_SNMP_DBG("Applying destination filter channel="
                     << static_cast<int>(channel)
                     << " selectedIndex=" << selectedIndex);

        const uint8_t typeValue = type.at(selectedIndex);
        const uint8_t addressTypeValue = addressType.at(selectedIndex);
        PEF_SNMP_DBG("Entry idx="
                     << selectedIndex << " type=" << static_cast<int>(typeValue)
                     << " addressType=" << static_cast<int>(addressTypeValue));

        const char* authPath = "unknown";
        if (typeValue == 0 || typeValue == 1)
        {
            authPath = "community";
        }
        else if (typeValue == 2)
        {
            authPath = "user";
        }
        else if (typeValue == 3)
        {
            authPath = "smtp-skip";
        }
        PEF_SNMP_DBG("Entry idx=" << selectedIndex << " authPath=" << authPath);

        if (typeValue == 3)
        {
            PEF_SNMP_DBG("Entry idx=" << selectedIndex
                                      << " is SMTP only, skipping SNMP");
            return managers;
        }

        std::string rawAddress;
        if (addressTypeValue == 1)
        {
            rawAddress = ipv4.at(selectedIndex);
        }
        else if (addressTypeValue == 2)
        {
            rawAddress = ipv6.at(selectedIndex);
        }
        else
        {
            PEF_SNMP_DBG("Entry idx="
                         << selectedIndex << " skip: unsupported AddressType="
                         << static_cast<int>(addressTypeValue));
            return managers;
        }

        auto peer = formatPeerAddress(rawAddress, addressTypeValue);
        if (peer.empty())
        {
            PEF_SNMP_DBG(
                "Entry idx=" << selectedIndex << " invalid peer after format");
            return managers;
        }

        if (typeValue == 0 || typeValue == 1)
        {
            if (community.empty())
            {
                PEF_SNMP_DBG("Entry idx=" << selectedIndex
                                          << " skip: empty community string");
                return managers;
            }

            managers.push_back({peer, (typeValue == 0) ? "v1" : "v2c",
                                community, "", "", "", ""});
            PEF_SNMP_DBG("Added manager idx="
                         << selectedIndex << " peer=" << peer
                         << " version=" << ((typeValue == 0) ? "v1" : "v2c"));
        }
        else if (typeValue == 2)
        {
            const auto& selectedUserName = userName.at(selectedIndex);
            if (selectedUserName.empty())
            {
                PEF_SNMP_DBG("Entry idx=" << selectedIndex
                                          << " skip: empty/missing userName");
                return managers;
            }

            std::string algorithm;
            std::string encryption;
            std::string password;
            if (!loadSnmpV3UserFromDBus(bus, selectedUserName, algorithm,
                                        encryption, password))
            {
                PEF_SNMP_DBG("Entry idx=" << selectedIndex
                                          << " failed SNMPv3 user load");
                return managers;
            }

            managers.push_back({peer, "v3", "", selectedUserName, algorithm,
                                encryption, password});
            PEF_SNMP_DBG("Added manager idx="
                         << selectedIndex << " peer=" << peer << " version=v3"
                         << " user=" << selectedUserName);
        }
        else
        {
            PEF_SNMP_DBG("Entry idx="
                         << selectedIndex << " skip: unsupported Type="
                         << static_cast<int>(typeValue));
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Failed to parse LAN SNMP config for iface " << iface
                  << ": " << e.what() << '\n';
    }

    PEF_SNMP_DBG("Total managers prepared=" << managers.size());
    return managers;
}

uint32_t getSystemUptimeTicks()
{
    timespec ts{};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    {
        return 0;
    }

    const uint64_t ticks = (static_cast<uint64_t>(ts.tv_sec) * 100ULL) +
                           (static_cast<uint64_t>(ts.tv_nsec) / 10000000ULL);
    if (ticks > std::numeric_limits<uint32_t>::max())
    {
        return std::numeric_limits<uint32_t>::max();
    }
    return static_cast<uint32_t>(ticks);
}

} // namespace

bool Notification::addPDUVar(netsnmp_pdu& pdu, const OID& objID,
                             size_t objIDLen, u_char type, Value val)
{
    netsnmp_variable_list* varList = nullptr;

    switch (type)
    {
        case ASN_INTEGER:
        {
            auto value = std::get<int32_t>(val);
            varList = snmp_pdu_add_variable(&pdu, objID.data(), objIDLen, type,
                                            &value, sizeof(value));
            break;
        }
        case ASN_UNSIGNED:
        {
            auto value = std::get<uint32_t>(val);
            varList = snmp_pdu_add_variable(&pdu, objID.data(), objIDLen, type,
                                            &value, sizeof(value));
            break;
        }
        case ASN_OPAQUE_U64:
        {
            auto value = std::get<uint64_t>(val);
            varList = snmp_pdu_add_variable(&pdu, objID.data(), objIDLen, type,
                                            &value, sizeof(value));
            break;
        }
        case ASN_OCTET_STR:
        {
            const auto& value = std::get<std::string>(val);
            varList = snmp_pdu_add_variable(&pdu, objID.data(), objIDLen, type,
                                            value.c_str(), value.length());
            break;
        }
        default:
            varList = nullptr;
            break;
    }

    return (varList != nullptr);
}

bool Notification::sendTrap(const std::optional<uint8_t>& channelNoFilter,
                            const std::optional<uint8_t>& destinationSelFilter)
{
    PEF_SNMP_DBG("sendTrap start");
    if (!getTrapEnabled())
    {
        PEF_SNMP_DBG("sendTrap early exit: disabled");
        return false;
    }

    std::string bmcIPAddress;
    const std::string eventSubjectSN = getEventSubjectSN();
    const size_t hostSep = eventSubjectSN.rfind(':');
    bmcIPAddress = eventSubjectSN.substr(hostSep + 1);
    PEF_SNMP_DBG("sendTrap eventSubjectSN="
                 << eventSubjectSN << " extractedBmcIP=" << bmcIPAddress);

    bool trapSent = false;
    snmp_shutdown("pef-alert-manager");
    init_snmp("pef-alert-manager");

    const auto snmpDisableStatus = getSNMPDisableStatus();
    std::vector<ManagerProperty> managers;
    try
    {
        managers = getManagers(channelNoFilter, destinationSelFilter);
    }
    catch (const std::exception& e)
    {
        PEF_SNMP_DBG("sendTrap manager discovery exception=" << e.what());
        return false;
    }
    PEF_SNMP_DBG("sendTrap managerCount=" << managers.size());

    for (const auto& manager : managers)
    {
        PEF_SNMP_DBG("sendTrap manager peer="
                     << manager.ipaddress << " version=" << manager.version);
        if (snmpDisableStatus.contains(manager.version) &&
            snmpDisableStatus.at(manager.version))
        {
            PEF_SNMP_DBG("sendTrap skip: version disabled " << manager.version);
            continue;
        }

        netsnmp_session session{};
        snmp_sess_init(&session);
        session.peername = const_cast<char*>(manager.ipaddress.c_str());
        session.localname = const_cast<char*>(bmcIPAddress.c_str());
        PEF_SNMP_DBG("sendTrap using local source IP=" << bmcIPAddress);

        if (manager.version == "v1")
        {
            session.version = SNMP_VERSION_1;
            session.community = reinterpret_cast<u_char*>(
                const_cast<char*>(manager.community.c_str()));
            session.community_len = manager.community.length();
            session.callback = nullptr;
            session.callback_magic = nullptr;
        }
        else if (manager.version == "v2c")
        {
            session.version = SNMP_VERSION_2c;
            session.community = reinterpret_cast<u_char*>(
                const_cast<char*>(manager.community.c_str()));
            session.community_len = manager.community.length();
            session.callback = nullptr;
            session.callback_magic = nullptr;
        }
        else if (manager.version == "v3")
        {
            PEF_SNMP_DBG(
                "sendTrap configuring SNMPv3 user=" << manager.userName);
            session.version = SNMP_VERSION_3;
            session.securityName = const_cast<char*>(manager.userName.c_str());
            session.securityNameLen = manager.userName.size();

            struct group* gr = getgrnam("snmp");
            bool foundUser = false;

            if ((gr != nullptr) && (gr->gr_mem != nullptr))
            {
                int i = 0;
                while (gr->gr_mem[i] != nullptr)
                {
                    if (strcmp(session.securityName, gr->gr_mem[i]) == 0)
                    {
                        foundUser = true;
                        break;
                    }
                    i++;
                }
            }
            if (foundUser == false)
            {
                PEF_SNMP_DBG("User not found in snmp group"
                             << manager.userName);
                continue;
            }
            u_char engineId[SNMP_MAXBUF] = {0};
            size_t engineIdLen = snmpv3_get_engineID(engineId, SNMP_MAXBUF);
            session.securityEngineID = engineId;
            session.securityEngineIDLen = engineIdLen;
            session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;

            constexpr std::string_view SHA_384 = "SHA-384";
            constexpr std::string_view SHA_512 = "SHA-512";
            constexpr std::string_view AES_ENCRYPTION = "AES";

            if (manager.algorithm == SHA_384)
            {
                PEF_SNMP_DBG("SNMPv3 auth algorithm SHA-384");
                session.securityAuthProto = usmHMAC256SHA384AuthProtocol;
                session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
                session.securityAuthKeyLen = USM_AUTH_KU_LEN;
            }
            else if (manager.algorithm == SHA_512)
            {
                PEF_SNMP_DBG("SNMPv3 auth algorithm SHA-512");
                session.securityAuthProto = usmHMAC384SHA512AuthProtocol;
                session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
                session.securityAuthKeyLen = USM_AUTH_KU_LEN;
            }
            else
            {
                PEF_SNMP_DBG("SNMPv3 auth algorithm default");
                session.securityAuthProto = SNMP_DEFAULT_AUTH_PROTO;
                session.securityAuthProtoLen = SNMP_DEFAULT_AUTH_PROTOLEN;
                session.securityAuthKeyLen = USM_AUTH_KU_LEN;
            }

            u_char authKey[USM_AUTH_KU_LEN];
            std::memset(authKey, 0, sizeof(authKey));
            size_t authKeyLen = USM_AUTH_KU_LEN;
            int rc = generate_Ku(
                session.securityAuthProto, session.securityAuthProtoLen,
                reinterpret_cast<u_char*>(
                    const_cast<char*>(manager.password.c_str())),
                manager.password.length(), authKey, &authKeyLen);

            if (rc != SNMPERR_SUCCESS)
            {
                PEF_SNMP_DBG("SNMPv3 auth key generation failed");
                continue;
            }
            session.securityAuthKeyLen = authKeyLen;
            std::memcpy(session.securityAuthKey, authKey, authKeyLen);

            if (manager.encryption == AES_ENCRYPTION)
            {
                session.securityPrivProto = usmAES256PrivProtocol;
                session.securityPrivProtoLen =
                    OID_LENGTH(usmAES256PrivProtocol);
                session.securityPrivKeyLen = USM_PRIV_KU_LEN;
            }
            else
            {
                PEF_SNMP_DBG("SNMPv3 privacy encryption default");
                session.securityPrivProto = SNMP_DEFAULT_PRIV_PROTO;
                session.securityPrivProtoLen = SNMP_DEFAULT_PRIV_PROTOLEN;
                session.securityPrivKeyLen = USM_PRIV_KU_LEN;
            }

            u_char privKey[USM_PRIV_KU_LEN];
            std::memset(privKey, 0, sizeof(privKey));
            size_t privKeyLen = USM_PRIV_KU_LEN;
            rc = generate_Ku(session.securityAuthProto,
                             session.securityAuthProtoLen,
                             reinterpret_cast<u_char*>(
                                 const_cast<char*>(manager.password.c_str())),
                             manager.password.length(), privKey, &privKeyLen);
            if (rc != SNMPERR_SUCCESS)
            {
                PEF_SNMP_DBG("SNMPv3 privacy key generation failed");
                continue;
            }
            session.securityPrivKeyLen = privKeyLen;
            std::memcpy(session.securityPrivKey, privKey, privKeyLen);
        }
        else
        {
            continue;
        }

        // create the sessions
        auto ss = snmp_add(
            &session,
            netsnmp_transport_open_client("snmptrap", session.peername),
            nullptr, nullptr);
        if (!ss)
        {
            PEF_SNMP_DBG("Unable to get the snmp session: {SNMPMANAGER}"
                         << manager.ipaddress);
            continue;
        }
        PEF_SNMP_DBG("snmp_open success peer=" << manager.ipaddress);

        SessionPtr sessionPtr(ss, &::snmp_close);

        netsnmp_pdu* pdu = nullptr;
        if (manager.version == "v1")
        {
            pdu = snmp_pdu_create(SNMP_MSG_TRAP);
        }
        else
        {
            pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
        }

        if (!pdu)
        {
            PEF_SNMP_DBG("PDU create failed peer=" << manager.ipaddress);
            continue;
        }

        auto uptime = getSystemUptimeTicks();
        std::string uptimeStr = std::to_string(uptime);
        if (snmp_add_var(pdu, sysuptimeOID, sizeof(sysuptimeOID) / sizeof(oid),
                         't', uptimeStr.c_str()) != 0)
        {
            PEF_SNMP_DBG("add sysUpTime failed peer=" << manager.ipaddress);
            snmp_free_pdu(pdu);
            continue;
        }

        pdu->trap_type = SNMP_TRAP_ENTERPRISESPECIFIC;

        auto trapInfo = getTrapOID();
        if (!snmp_pdu_add_variable(pdu, SNMPTrapOID,
                                   sizeof(SNMPTrapOID) / sizeof(oid),
                                   ASN_OBJECT_ID, trapInfo.first.data(),
                                   trapInfo.second * sizeof(oid)))
        {
            PEF_SNMP_DBG("add snmpTrapOID failed peer=" << manager.ipaddress);
            snmp_free_pdu(pdu);
            continue;
        }

        const auto objectList = getFieldOIDList();
        bool allFieldsAdded = true;
        for (const auto& object : objectList)
        {
            if (!addPDUVar(*pdu, std::get<0>(object), std::get<1>(object),
                           std::get<2>(object), std::get<3>(object)))
            {
                PEF_SNMP_DBG("Failed to add the SNMP var");
                allFieldsAdded = false;
                break;
            }
        }

        if (!allFieldsAdded)
        {
            snmp_free_pdu(pdu);
            continue;
        }

        // pdu is freed by snmp_send
        auto retval = snmp_send(sessionPtr.get(), pdu);
        netsnmp_session* activeSession = sessionPtr.get();
        if (activeSession && activeSession->securityEngineID &&
            activeSession->securityEngineIDLen > 0 &&
            activeSession->securityName)
        {
            struct usmUser* usr =
                usm_get_user(activeSession->securityEngineID,
                             activeSession->securityEngineIDLen,
                             activeSession->securityName);
            if (usr)
            {
                usm_remove_user(usr);
                usm_free_user(usr);
            }
        }
        if (!retval)
        {
            continue;
        }
        trapSent = true;
    }
    if (trapSent == false)
    {
        PEF_SNMP_DBG("Failed to send the snmp trap for all managers.");
        return trapSent;
    }
    return trapSent;
}

bool sendOBMCErrorNotification(
    uint32_t id, const std::string& ts, const std::string& sev,
    const std::string& msg, const std::string& eventID,
    const std::string& eventStatus, const std::string& eventSubjectSN,
    const std::string& addData, const std::string& ip, uint8_t channelNo,
    uint8_t destinationSel)
{
    OBMCErrorNotification notification(id, ts, sev, msg, eventID, eventStatus,
                                       eventSubjectSN, addData, ip);
    return notification.sendTrap(channelNo, destinationSel);
}

} // namespace snmp
} // namespace network
} // namespace phosphor
