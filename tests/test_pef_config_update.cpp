// Tests for static/free functions in include/pef_config_update.hpp:
//   findEntryNo, updateJsonFile, parseJsonData
//
// pef_config_update.hpp relies on sdbusplus and phosphor-logging being
// included first, and pefConfigFile being defined.

#include <boost/container/flat_map.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/message.hpp>

// Provide pefConfigFile so updateJsonFile / monitor functions compile
static constexpr const char* pefConfigFile = "/tmp/pef_test_update.json";

#include "pef_config_update.hpp"

#undef FAIL
#undef ERROR
#undef DEBUG

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

namespace
{

// ---------------------------------------------------------------------------
// findEntryNo — parses numeric suffix from a D-Bus object path component
// ---------------------------------------------------------------------------

TEST(FindEntryNoTest, PathWithNumericSuffix_ReturnsNumber)
{
    EXPECT_EQ(
        findEntryNo(
            "/xyz/openbmc_project/PefAlertManager/EventFilterTable/Entry5"),
        5);
}

TEST(FindEntryNoTest, EntryZeroSuffix_ReturnsZero)
{
    EXPECT_EQ(findEntryNo("/some/path/Entry0"), 0);
}

TEST(FindEntryNoTest, LargeEntryNumber_ReturnsThatNumber)
{
    EXPECT_EQ(findEntryNo("/path/Entry40"), 40);
}

TEST(FindEntryNoTest, NoDigitsInLastComponent_ReturnsZero)
{
    EXPECT_EQ(findEntryNo("/path/NoDigitsHere"), 0);
}

TEST(FindEntryNoTest, AlphaNumericMixed_ReturnsLeadingNumber)
{
    EXPECT_EQ(findEntryNo("/path/List1"), 1);
}

TEST(FindEntryNoTest, PolicyList_eth0_ReturnsZero)
{
    EXPECT_EQ(findEntryNo("/path/PolicyList_eth0"), 0);
}

TEST(FindEntryNoTest, SingleComponent_NoSlash_ReturnsParsedNumber)
{
    EXPECT_EQ(findEntryNo("Entry7"), 7);
}

// ---------------------------------------------------------------------------
// updateJsonFile — writes JSON to a file
// ---------------------------------------------------------------------------

TEST(UpdateJsonFileFixture, ValidJson_WrittenSuccessfully)
{
    nlohmann::json testData = {{"EventFilterTable", nlohmann::json::array()},
                               {"version", 1}};

    std::ofstream out(pefConfigFile);
    out << testData.dump(4);
    out.close();

    ASSERT_TRUE(updateJsonFile(testData));
    ASSERT_TRUE(std::filesystem::exists(pefConfigFile));

    std::ifstream in(pefConfigFile);
    ASSERT_TRUE(in.is_open());
    nlohmann::json readBack;
    in >> readBack;
    EXPECT_EQ(readBack["version"], 1);
}

TEST(UpdateJsonFileFixture, EmptyJson_WrittenSuccessfully)
{
    nlohmann::json emptyJson = nlohmann::json::object();
    EXPECT_TRUE(updateJsonFile(emptyJson));
}

// ---------------------------------------------------------------------------
// parseJsonData — reads a JSON file and parses it
// ---------------------------------------------------------------------------

class ParseJsonDataFixture : public ::testing::Test
{
  protected:
    std::filesystem::path jsonFilePath;

    void SetUp() override
    {
        jsonFilePath = std::filesystem::temp_directory_path() /
                       "pef_parse_json_test.json";
        std::filesystem::remove(jsonFilePath);
    }

    void TearDown() override
    {
        std::filesystem::remove(jsonFilePath);
    }
};

TEST_F(ParseJsonDataFixture, ValidJsonFile_ReturnsCorrectData)
{
    const nlohmann::json expected = {{"EventFilterTable", {{"entry", 1}}},
                                     {"PEFControl", 0x01}};
    {
        std::ofstream out(jsonFilePath);
        out << expected.dump(4);
    }

    nlohmann::json result = parseJsonData(jsonFilePath.string());

    ASSERT_FALSE(result.is_discarded());
    EXPECT_EQ(result["PEFControl"], 0x01);
}

TEST_F(ParseJsonDataFixture, NonExistentFile_ReturnsDiscardedJson)
{
    nlohmann::json result = parseJsonData("/nonexistent_pef/config.json");
    EXPECT_TRUE(result.is_discarded());
}

TEST_F(ParseJsonDataFixture, MalformedJson_ReturnsDiscardedJson)
{
    {
        std::ofstream out(jsonFilePath);
        out << "{ not valid json !!!";
    }

    nlohmann::json result = parseJsonData(jsonFilePath.string());
    EXPECT_TRUE(result.is_discarded());
}

TEST_F(ParseJsonDataFixture, ArrayJson_ParsedCorrectly)
{
    const nlohmann::json arr = nlohmann::json::array({1, 2, 3});
    {
        std::ofstream out(jsonFilePath);
        out << arr.dump();
    }

    nlohmann::json result = parseJsonData(jsonFilePath.string());
    ASSERT_FALSE(result.is_discarded());
    ASSERT_TRUE(result.is_array());
    EXPECT_EQ(result.size(), 3u);
}

} // namespace
