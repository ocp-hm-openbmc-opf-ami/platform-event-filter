#pragma once

#include <cstdint>
#include <string>

namespace phosphor
{
namespace network
{
namespace snmp
{

bool sendOBMCErrorNotification(
    uint32_t id, const std::string& ts, const std::string& sev,
    const std::string& msg, const std::string& eventID,
    const std::string& eventStatus, const std::string& eventSubjectSN,
    const std::string& addData, const std::string& ip, uint8_t channelNo,
    uint8_t destinationSel);

} // namespace snmp
} // namespace network
} // namespace phosphor
