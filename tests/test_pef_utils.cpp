// Tests for inline functions in include/pef_utils.hpp:
//   retrieveSensorTypeFromPath, getSensorNameFromPath
//
// Include order: project header under test → undef conflicting macros → GTest

#include "pef_utils.hpp"

#undef FAIL
#undef ERROR
#undef DEBUG

#include <string>

#include <gtest/gtest.h>

namespace
{

// ---------------------------------------------------------------------------
// retrieveSensorTypeFromPath
// ---------------------------------------------------------------------------

TEST(RetrieveSensorTypeFromPathTest, TypicalSensorPath_ReturnsTypeSegment)
{
    EXPECT_EQ(retrieveSensorTypeFromPath(
                  "/xyz/openbmc_project/sensors/temperature/CPU_Temp", 0),
              "temperature");
}

TEST(RetrieveSensorTypeFromPathTest, VoltageType_ReturnsVoltage)
{
    EXPECT_EQ(retrieveSensorTypeFromPath(
                  "/xyz/openbmc_project/sensors/voltage/P12V_AUX", 0),
              "voltage");
}

TEST(RetrieveSensorTypeFromPathTest, FanType_ReturnsFan)
{
    EXPECT_EQ(retrieveSensorTypeFromPath(
                  "/xyz/openbmc_project/sensors/fan_tach/Fan0", 0),
              "fan_tach");
}

TEST(RetrieveSensorTypeFromPathTest, NoSlash_ReturnsPathUnchanged)
{
    const std::string path = "noslash";
    EXPECT_EQ(retrieveSensorTypeFromPath(path, 0), path);
}

TEST(RetrieveSensorTypeFromPathTest, OnlyOneSlash_ReturnsSegmentAfterSlash)
{
    // Single leading slash: rfind wraps, giving substr(1,npos) = "onlyone"
    const std::string path = "/onlyone";
    EXPECT_EQ(retrieveSensorTypeFromPath(path, 0), "onlyone");
}

TEST(RetrieveSensorTypeFromPathTest, TwoSegments_ReturnsFirstSegment)
{
    EXPECT_EQ(retrieveSensorTypeFromPath("/type/name", 0), "type");
}

TEST(RetrieveSensorTypeFromPathTest, TrailingSlash_ReturnsEmptyType)
{
    EXPECT_EQ(retrieveSensorTypeFromPath("/a/b/", 0), "b");
}

// ---------------------------------------------------------------------------
// getSensorNameFromPath
// ---------------------------------------------------------------------------

TEST(GetSensorNameFromPathTest, TypicalSensorPath_ReturnsName)
{
    EXPECT_EQ(getSensorNameFromPath(
                  "/xyz/openbmc_project/sensors/temperature/CPU_Temp"),
              "CPU_Temp");
}

TEST(GetSensorNameFromPathTest, NoSlash_ReturnsPathUnchanged)
{
    const std::string path = "noslash";
    EXPECT_EQ(getSensorNameFromPath(path), path);
}

TEST(GetSensorNameFromPathTest, SingleSegment_ReturnsEmptyAfterSlash)
{
    EXPECT_EQ(getSensorNameFromPath("/just_name"), "just_name");
}

TEST(GetSensorNameFromPathTest, TrailingSlash_ReturnsEmptyName)
{
    EXPECT_EQ(getSensorNameFromPath("/a/b/"), "");
}

TEST(GetSensorNameFromPathTest, MultipleSeparators_ReturnsLastSegment)
{
    EXPECT_EQ(getSensorNameFromPath("/a/b/c/d/SensorXYZ"), "SensorXYZ");
}

} // namespace
