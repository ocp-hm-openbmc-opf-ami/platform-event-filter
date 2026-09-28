// Tests for externally-linked pure/IO functions in pef_config.cpp:
//   validateIPv4Address, validateIPv6Address, parseJSONConfig
//
// pef_config.cpp has main() — built with -Wl,--allow-multiple-definition so
// this file's main() wins the linker symbol race.
// sendOBMCErrorNotification is stubbed to avoid pulling in netsnmp.

#include <nlohmann/json.hpp>

#include <string>

#include <gtest/gtest.h>

// Custom main — wins over pef_config.cpp's daemon main() with
// --allow-multiple-definition.
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

// Forward declarations from pef_config.cpp
bool validateIPv4Address(const std::string& address);
bool validateIPv6Address(const std::string& address);
nlohmann::json parseJSONConfig(const std::string& configFile);

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

#include <filesystem>
#include <fstream>

namespace
{

// ---------------------------------------------------------------------------
// validateIPv4Address
// ---------------------------------------------------------------------------

TEST(ValidateIPv4AddressTest, EmptyAddress_ReturnsTrue)
{
    EXPECT_TRUE(validateIPv4Address(""));
}

TEST(ValidateIPv4AddressTest, LoopbackAddress_ReturnsTrue)
{
    EXPECT_TRUE(validateIPv4Address("127.0.0.1"));
}

TEST(ValidateIPv4AddressTest, ValidUnicastAddress_ReturnsTrue)
{
    EXPECT_TRUE(validateIPv4Address("192.168.1.100"));
    EXPECT_TRUE(validateIPv4Address("10.0.0.1"));
    EXPECT_TRUE(validateIPv4Address("255.255.255.255"));
}

TEST(ValidateIPv4AddressTest, AllZerosAddress_ReturnsTrue)
{
    EXPECT_TRUE(validateIPv4Address("0.0.0.0"));
}

TEST(ValidateIPv4AddressTest, PartialOctets_ReturnsFalse)
{
    // All digits+dots but not a valid IPv4 — rejected as incomplete
    EXPECT_FALSE(validateIPv4Address("10.0.0"));
    EXPECT_FALSE(validateIPv4Address("10.0"));
}

TEST(ValidateIPv4AddressTest, UnresolvableHostname_ReturnsFalse)
{
    EXPECT_FALSE(validateIPv4Address("definitely.not.a.real.host.pef.test"));
}

// ---------------------------------------------------------------------------
// validateIPv6Address
// ---------------------------------------------------------------------------

TEST(ValidateIPv6AddressTest, EmptyAddress_ReturnsTrue)
{
    EXPECT_TRUE(validateIPv6Address(""));
}

TEST(ValidateIPv6AddressTest, LoopbackIPv6_ReturnsTrue)
{
    EXPECT_TRUE(validateIPv6Address("::1"));
}

TEST(ValidateIPv6AddressTest, FullIPv6Address_ReturnsTrue)
{
    EXPECT_TRUE(validateIPv6Address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
}

TEST(ValidateIPv6AddressTest, CompressedIPv6_ReturnsTrue)
{
    EXPECT_TRUE(validateIPv6Address("fe80::1"));
}

TEST(ValidateIPv6AddressTest, PartialIPv6WithColon_ReturnsFalse)
{
    // Has colons + only hex chars → rejected as incomplete IPv6
    EXPECT_FALSE(validateIPv6Address("2001:db8"));
    EXPECT_FALSE(validateIPv6Address("2001:db8:1"));
}

TEST(ValidateIPv6AddressTest, UnresolvableHostname_ReturnsFalse)
{
    EXPECT_FALSE(validateIPv6Address("definitely.not.a.real.host.pef.test"));
}

// ---------------------------------------------------------------------------
// parseJSONConfig — reads a file and parses JSON
// ---------------------------------------------------------------------------

class ParseJSONConfigFixture : public ::testing::Test
{
  protected:
    std::filesystem::path jsonFilePath;

    void SetUp() override
    {
        jsonFilePath = std::filesystem::temp_directory_path() /
                       "pef_config_test_parseJSON.json";
        std::filesystem::remove(jsonFilePath);
    }

    void TearDown() override
    {
        std::filesystem::remove(jsonFilePath);
    }
};

TEST_F(ParseJSONConfigFixture, ValidJsonFile_ReturnsParsedObject)
{
    {
        std::ofstream out(jsonFilePath);
        out << R"({"PEFControl": 1, "EventFilterTable": []})";
    }

    auto result = parseJSONConfig(jsonFilePath.string());

    ASSERT_FALSE(result.is_discarded());
    EXPECT_EQ(result["PEFControl"], 1);
}

TEST_F(ParseJSONConfigFixture, NonExistentFile_ReturnsDiscarded)
{
    auto result = parseJSONConfig("/nonexistent/pef_cfg_test.json");
    EXPECT_TRUE(result.is_discarded());
}

TEST_F(ParseJSONConfigFixture, MalformedJson_ReturnsDiscarded)
{
    {
        std::ofstream out(jsonFilePath);
        out << "{ not valid json !!!";
    }

    auto result = parseJSONConfig(jsonFilePath.string());
    EXPECT_TRUE(result.is_discarded());
}

} // namespace
