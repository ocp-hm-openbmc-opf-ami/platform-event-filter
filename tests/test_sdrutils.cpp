// Tests for sdrutils.hpp:
//   CmpStrVersion::operator(), IPMIStatsEntry inline methods,
//   getSensorTypeStringFromPath, getSensorTypeFromPath,
//   getSensorEventTypeFromPath, sdrutils constants
//
// sdrutils.hpp relies on sdbusplus::asio and <iostream> being included first.

// clang-format off
#include <iostream>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include "sdrutils.hpp"
// clang-format on
#undef FAIL
#undef ERROR
#undef DEBUG

#include <string>

#include <gtest/gtest.h>

namespace
{

// ---------------------------------------------------------------------------
// CmpStrVersion — string version comparator used in SensorSubTree
// ---------------------------------------------------------------------------

TEST(CmpStrVersionTest, LesserVersion_ReturnsTrue)
{
    CmpStrVersion cmp;
    EXPECT_TRUE(cmp("1.0.0", "2.0.0"));
}

TEST(CmpStrVersionTest, GreaterVersion_ReturnsFalse)
{
    CmpStrVersion cmp;
    EXPECT_FALSE(cmp("2.0.0", "1.0.0"));
}

TEST(CmpStrVersionTest, EqualVersions_ReturnsFalse)
{
    CmpStrVersion cmp;
    EXPECT_FALSE(cmp("1.0.0", "1.0.0"));
}

TEST(CmpStrVersionTest, NumericSuffix_OrderedNumerically)
{
    CmpStrVersion cmp;
    // strverscmp orders "sensor9" < "sensor10" (numeric, not lexicographic)
    EXPECT_TRUE(cmp("sensor9", "sensor10"));
    EXPECT_FALSE(cmp("sensor10", "sensor9"));
}

TEST(CmpStrVersionTest, EmptyStrings_BothEmpty_ReturnsFalse)
{
    CmpStrVersion cmp;
    EXPECT_FALSE(cmp("", ""));
}

TEST(CmpStrVersionTest, EmptyLhs_ReturnsTrueWhenRhsNonEmpty)
{
    CmpStrVersion cmp;
    EXPECT_TRUE(cmp("", "a"));
}

// ---------------------------------------------------------------------------
// details::IPMIStatsEntry — inline methods in sdrutils.hpp
// ---------------------------------------------------------------------------

TEST(IPMIStatsEntryTest, DefaultName_IsEmpty)
{
    details::IPMIStatsEntry entry;
    EXPECT_TRUE(entry.getName().empty());
}

TEST(IPMIStatsEntryTest, UpdateName_Persists)
{
    details::IPMIStatsEntry entry;
    entry.updateName("CPU0_Temp");
    EXPECT_EQ(entry.getName(), "CPU0_Temp");
}

TEST(IPMIStatsEntryTest, UpdateNameTwice_UsesLatestName)
{
    details::IPMIStatsEntry entry;
    entry.updateName("old");
    entry.updateName("new");
    EXPECT_EQ(entry.getName(), "new");
}

TEST(IPMIStatsEntryTest, UpdateReading_InstrumentationOff_ReturnsFalse)
{
    // enableInstrumentation = false → updateReading always returns false
    details::IPMIStatsEntry entry;
    entry.updateName("VoltSensor");
    EXPECT_FALSE(entry.updateReading(3.3, 100));
    EXPECT_FALSE(
        entry.updateReading(std::numeric_limits<double>::quiet_NaN(), 0));
}

// ---------------------------------------------------------------------------
// sdrutils constants
// ---------------------------------------------------------------------------

TEST(SdrConstantsTest, MaxSensorsPerLUN_Is255)
{
    EXPECT_EQ(maxSensorsPerLUN, 255u);
}

TEST(SdrConstantsTest, MaxIPMISensors_IsThreeLUNs)
{
    EXPECT_EQ(maxIPMISensors, static_cast<uint16_t>(maxSensorsPerLUN * 3));
}

TEST(SdrConstantsTest, InvalidSensorNumber_Is0xFFFF)
{
    EXPECT_EQ(invalidSensorNumber, 0xFFFFu);
}

TEST(SdrConstantsTest, ReservedSensorNumber_Is0xFF)
{
    EXPECT_EQ(reservedSensorNumber, 0xFFu);
}

// ---------------------------------------------------------------------------
// getSensorTypeStringFromPath — inline in sdrutils.hpp
// ---------------------------------------------------------------------------

TEST(GetSensorTypeStringFromPathTest, TemperaturePath_ReturnsTemperature)
{
    EXPECT_EQ(getSensorTypeStringFromPath(
                  "/xyz/openbmc_project/sensors/temperature/CPU_Temp"),
              "temperature");
}

TEST(GetSensorTypeStringFromPathTest, VoltagePath_ReturnsVoltage)
{
    EXPECT_EQ(getSensorTypeStringFromPath(
                  "/xyz/openbmc_project/sensors/voltage/P12V"),
              "voltage");
}

TEST(GetSensorTypeStringFromPathTest, FanTachPath_ReturnsFanTach)
{
    EXPECT_EQ(getSensorTypeStringFromPath(
                  "/xyz/openbmc_project/sensors/fan_tach/Fan0"),
              "fan_tach");
}

TEST(GetSensorTypeStringFromPathTest, NoSlash_ReturnsPathUnchanged)
{
    const std::string path = "noslash";
    EXPECT_EQ(getSensorTypeStringFromPath(path), path);
}

TEST(GetSensorTypeStringFromPathTest, TwoSegments_ReturnsFirstSegment)
{
    EXPECT_EQ(getSensorTypeStringFromPath("/fan_tach/Fan0"), "fan_tach");
}

// ---------------------------------------------------------------------------
// getSensorTypeFromPath — looks up type code in sensorTypes map
// ---------------------------------------------------------------------------

TEST(GetSensorTypeFromPathTest, TemperaturePath_ReturnsTemperatureCode)
{
    EXPECT_EQ(getSensorTypeFromPath(
                  "/xyz/openbmc_project/sensors/temperature/CPU_Temp"),
              static_cast<uint8_t>(SensorTypeCodes::temperature)); // 0x01
}

TEST(GetSensorTypeFromPathTest, VoltagePath_ReturnsVoltageCode)
{
    EXPECT_EQ(
        getSensorTypeFromPath("/xyz/openbmc_project/sensors/voltage/P12V"),
        static_cast<uint8_t>(SensorTypeCodes::voltage)); // 0x02
}

TEST(GetSensorTypeFromPathTest, FanTachPath_ReturnsFanCode)
{
    EXPECT_EQ(
        getSensorTypeFromPath("/xyz/openbmc_project/sensors/fan_tach/Fan0"),
        static_cast<uint8_t>(SensorTypeCodes::fan)); // 0x04
}

TEST(GetSensorTypeFromPathTest, CpuPath_ReturnsProcessorCode)
{
    EXPECT_EQ(getSensorTypeFromPath("/xyz/openbmc_project/sensors/cpu/CPU0"),
              static_cast<uint8_t>(SensorTypeCodes::processor)); // 0x07
}

TEST(GetSensorTypeFromPathTest, UnknownType_ReturnsReserved)
{
    EXPECT_EQ(getSensorTypeFromPath(
                  "/xyz/openbmc_project/sensors/unknown_xyz/Sensor0"),
              static_cast<uint8_t>(SensorTypeCodes::reserved)); // 0x00
}

// ---------------------------------------------------------------------------
// getSensorEventTypeFromPath — looks up event type code in sensorTypes map
// ---------------------------------------------------------------------------

TEST(GetSensorEventTypeFromPathTest, TemperaturePath_ReturnsThreshold)
{
    EXPECT_EQ(getSensorEventTypeFromPath(
                  "/xyz/openbmc_project/sensors/temperature/CPU_Temp"),
              static_cast<uint8_t>(SensorEventTypeCodes::threshold)); // 0x01
}

TEST(GetSensorEventTypeFromPathTest, CpuPath_ReturnsSensorSpecified)
{
    EXPECT_EQ(
        getSensorEventTypeFromPath("/xyz/openbmc_project/sensors/cpu/CPU0"),
        static_cast<uint8_t>(SensorEventTypeCodes::sensorSpecified)); // 0x6f
}

} // namespace
