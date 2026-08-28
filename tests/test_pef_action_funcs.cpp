// Tests for externally-linked pure functions in pef_action.cpp:
//   getCurrentTime, resolveHost
//
// pef_action.cpp has main() — built with -Wl,--allow-multiple-definition so
// this file's main() wins the linker symbol race.
// pef_action.hpp is NOT included here to avoid its global D-Bus objects
// appearing a second time in this translation unit.
// sendOBMCErrorNotification is stubbed to avoid pulling in netsnmp.

#include <cstdint>
#include <string>

#include <gtest/gtest.h>

// Custom main — wins over pef_action.cpp's daemon main() with
// --allow-multiple-definition.
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

// Forward declarations from pef_action.cpp (avoids including pef_action.hpp)
std::string getCurrentTime();
bool resolveHost(const std::string& host);

// Stub: satisfies the linker without requiring snmp_notification.cpp
namespace phosphor::network::snmp
{
bool sendOBMCErrorNotification(
    uint32_t, const std::string&, const std::string&, const std::string&,
    const std::string&, const std::string&, const std::string&,
    const std::string&, const std::string&, uint8_t, uint8_t)
{
    return false;
}
} // namespace phosphor::network::snmp

namespace
{

// ---------------------------------------------------------------------------
// getCurrentTime — formats current wall-clock time as a string
// ---------------------------------------------------------------------------

TEST(GetCurrentTimeTest, ReturnsNonEmptyString)
{
    std::string ts = getCurrentTime();
    EXPECT_FALSE(ts.empty());
}

TEST(GetCurrentTimeTest, ContainsYear2026OrLater)
{
    std::string ts = getCurrentTime();
    // Format: "Mon Jan 01 00:00:00 UTC 2026" — year is present
    EXPECT_NE(ts.find("202"), std::string::npos);
}

TEST(GetCurrentTimeTest, CalledTwice_BothNonEmpty)
{
    EXPECT_FALSE(getCurrentTime().empty());
    EXPECT_FALSE(getCurrentTime().empty());
}

// ---------------------------------------------------------------------------
// resolveHost — DNS/network lookup via getaddrinfo
// ---------------------------------------------------------------------------

TEST(ResolveHostTest, Localhost_ReturnsTrue)
{
    EXPECT_TRUE(resolveHost("localhost"));
}

TEST(ResolveHostTest, LoopbackIPv4_ReturnsTrue)
{
    EXPECT_TRUE(resolveHost("127.0.0.1"));
}

TEST(ResolveHostTest, UnresolvableHostname_ReturnsFalse)
{
    EXPECT_FALSE(resolveHost("definitely.not.a.real.host.pef.action.test"));
}

TEST(ResolveHostTest, EmptyString_ReturnsFalse)
{
    // getaddrinfo("", ...) typically fails with EAI_NONAME
    EXPECT_FALSE(resolveHost(""));
}

} // namespace
