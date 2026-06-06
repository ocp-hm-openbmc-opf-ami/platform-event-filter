#pragma once

// net-snmp requires a specific header order.
// clang-format off
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
// clang-format on

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

#define PEF_SNMP_CONF_FILE_PATH "/etc/snmp/snmp.conf"
#define PEF_SNMP_TRAP_STATUS_FILE_PATH "/etc/snmp/SnmpTrapStatus"
#define PEF_SERVICE_BUS "xyz.openbmc_project.pef.alert.manager"
#define PEF_ROOT_OBJ_PATH "/xyz/openbmc_project/PefAlertManager"
#define PEF_LAN_PARAM_INTF "xyz.openbmc_project.pef.LanParamConfig"
#define SNMP_CONF_SERVICE "xyz.openbmc_project.Snmp.Conf"
#define SNMP_USER_MANAGER_INTF "xyz.openbmc_project.Snmp.UserManager"
#define SNMP_USER_MANAGER_ROOT "/xyz/openbmc_project/snmp/UserManager/"
#define SNMP_TRAP_PORT 162

namespace phosphor
{
namespace network
{
namespace snmp
{

using OID = std::array<oid, MAX_OID_LEN>;
using OID_LEN = size_t;
using Type = u_char;

using Value = std::variant<uint32_t, uint64_t, int32_t, std::string>;

constexpr oid SNMPTrapOID[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
constexpr oid sysuptimeOID[] = {1, 3, 6, 1, 2, 1, 1, 3, 0};

using Object = std::tuple<OID, OID_LEN, Type, Value>;

template <typename T>
u_char getASNType() = delete;

template <>
inline u_char getASNType<uint32_t>()
{
    return ASN_UNSIGNED;
}

template <>
inline u_char getASNType<uint64_t>()
{
    return ASN_OPAQUE_U64;
}

template <>
inline u_char getASNType<int32_t>()
{
    return ASN_INTEGER;
}

template <>
inline u_char getASNType<std::string>()
{
    return ASN_OCTET_STR;
}

class Notification
{
  public:
    Notification() = default;
    Notification(const Notification&) = delete;
    Notification(Notification&&) = default;
    Notification& operator=(const Notification&) = delete;
    Notification& operator=(Notification&&) = default;
    virtual ~Notification() = default;

    bool sendTrap(
        const std::optional<uint8_t>& channelNoFilter = std::nullopt,
        const std::optional<uint8_t>& destinationSelFilter = std::nullopt);

  protected:
    bool addPDUVar(netsnmp_pdu& pdu, const OID& objID, size_t objIDLen,
                   u_char type, Value val);

    virtual std::pair<OID, OID_LEN> getTrapOID() = 0;
    virtual std::vector<Object> getFieldOIDList() = 0;
    virtual std::string getEventSubjectSN() const
    {
        return "";
    }
};

class OBMCErrorNotification : public Notification
{
  private:
    uint32_t obmcErrorID = 0;
    std::string obmcErrorTimestamp;
    std::string obmcErrorSeverity;
    std::string obmcErrorMessage;
    std::string obmcEventID;
    std::string obmcEventStatus;
    std::string obmcEventSubjectSN;
    std::string obmcAddData;
    std::string obmcIP;

  public:
    OBMCErrorNotification() = delete;
    OBMCErrorNotification(const OBMCErrorNotification&) = delete;
    OBMCErrorNotification(OBMCErrorNotification&&) = default;
    OBMCErrorNotification& operator=(const OBMCErrorNotification&) = delete;
    OBMCErrorNotification& operator=(OBMCErrorNotification&&) = default;
    ~OBMCErrorNotification() = default;

    OBMCErrorNotification(uint32_t id, std::string ts, std::string sev,
                          std::string msg, std::string eventID,
                          std::string eventStatus, std::string eventSubjectSN,
                          std::string addData, std::string ip) :
        obmcErrorID(id), obmcErrorTimestamp(std::move(ts)),
        obmcErrorSeverity(std::move(sev)), obmcErrorMessage(std::move(msg)),
        obmcEventID(std::move(eventID)),
        obmcEventStatus(std::move(eventStatus)),
        obmcEventSubjectSN(std::move(eventSubjectSN)),
        obmcAddData(std::move(addData)), obmcIP(std::move(ip))
    {}

  protected:
    std::pair<OID, OID_LEN> getTrapOID() override
    {
        OID id = {1, 3, 6, 1, 4, 1, 49871, 1, 0, 0, 1};
        OID_LEN idLen = 11;
        return std::make_pair<OID, OID_LEN>(std::move(id), std::move(idLen));
    }

    std::vector<Object> getFieldOIDList() override
    {
        std::vector<Object> objectList;
        objectList.reserve(9);

        objectList.emplace_back(OID{1, 3, 6, 1, 4, 1, 49871, 1, 0, 1, 1}, 11,
                                getASNType<decltype(obmcErrorID)>(),
                                obmcErrorID);
        objectList.emplace_back(OID{1, 3, 6, 1, 4, 1, 49871, 1, 0, 1, 2}, 11,
                                getASNType<decltype(obmcErrorTimestamp)>(),
                                obmcErrorTimestamp);
        objectList.emplace_back(OID{1, 3, 6, 1, 4, 1, 49871, 1, 0, 1, 3}, 11,
                                getASNType<decltype(obmcEventID)>(),
                                obmcEventID);
        objectList.emplace_back(OID{1, 3, 6, 1, 4, 1, 49871, 1, 0, 1, 4}, 11,
                                getASNType<decltype(obmcErrorSeverity)>(),
                                obmcErrorSeverity);
        objectList.emplace_back(OID{1, 3, 6, 1, 4, 1, 49871, 1, 0, 1, 5}, 11,
                                getASNType<decltype(obmcErrorMessage)>(),
                                obmcErrorMessage);
        objectList.emplace_back(OID{1, 3, 6, 1, 4, 1, 49871, 1, 0, 1, 6}, 11,
                                getASNType<decltype(obmcIP)>(), obmcIP);
        objectList.emplace_back(OID{1, 3, 6, 1, 4, 1, 49871, 1, 0, 1, 7}, 11,
                                getASNType<decltype(obmcEventStatus)>(),
                                obmcEventStatus);
        objectList.emplace_back(OID{1, 3, 6, 1, 4, 1, 49871, 1, 0, 1, 8}, 11,
                                getASNType<decltype(obmcEventSubjectSN)>(),
                                obmcEventSubjectSN);
        objectList.emplace_back(OID{1, 3, 6, 1, 4, 1, 49871, 1, 0, 1, 9}, 11,
                                getASNType<decltype(obmcAddData)>(),
                                obmcAddData);

        return objectList;
    }

    std::string getEventSubjectSN() const override
    {
        return obmcEventSubjectSN;
    }
};

} // namespace snmp
} // namespace network
} // namespace phosphor
