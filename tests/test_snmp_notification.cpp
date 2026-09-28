// Tests for snmp_notification.hpp + snmp_notification.cpp:
//   getASNType<> specializations (header)
//   OBMCErrorNotification::getTrapOID, getFieldOIDList, getEventSubjectSN
//   (inline) Notification::addPDUVar — all 4 type branches + default branch
//   Notification::sendTrap early-exit path

// clang-format off
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
// clang-format on

#include "snmp_notification.hpp"

#undef FAIL
#undef ERROR
#undef DEBUG

#include <cstdint>
#include <string>

#include <gtest/gtest.h>

namespace
{

using namespace phosphor::network::snmp;

// ---------------------------------------------------------------------------
// getASNType<> — template specialisations in snmp_notification.hpp
// ---------------------------------------------------------------------------

TEST(GetAsnTypeTest, Uint32_ReturnsASN_UNSIGNED)
{
    EXPECT_EQ(getASNType<uint32_t>(), static_cast<u_char>(ASN_UNSIGNED));
}

TEST(GetAsnTypeTest, Uint64_ReturnsASN_OPAQUE_U64)
{
    EXPECT_EQ(getASNType<uint64_t>(), static_cast<u_char>(ASN_OPAQUE_U64));
}

TEST(GetAsnTypeTest, Int32_ReturnsASN_INTEGER)
{
    EXPECT_EQ(getASNType<int32_t>(), static_cast<u_char>(ASN_INTEGER));
}

TEST(GetAsnTypeTest, String_ReturnsASN_OCTET_STR)
{
    EXPECT_EQ(getASNType<std::string>(), static_cast<u_char>(ASN_OCTET_STR));
}

// ---------------------------------------------------------------------------
// OBMCErrorNotification — expose protected inline methods via public subclass
// ---------------------------------------------------------------------------

class ExposedOBMCError final : public OBMCErrorNotification
{
  public:
    using OBMCErrorNotification::getEventSubjectSN;
    using OBMCErrorNotification::getFieldOIDList;
    using OBMCErrorNotification::getTrapOID;

    ExposedOBMCError() :
        OBMCErrorNotification(1u, "2026-08-17T00:00:00", "Critical",
                              "Test alert message", "EVT001", "Active",
                              "bmc-host:192.168.1.1", "key=value",
                              "192.168.1.1")
    {}
};

TEST(OBMCErrorNotificationTest, GetTrapOID_LenIs11)
{
    ExposedOBMCError notif;
    auto [oid, len] = notif.getTrapOID();
    EXPECT_EQ(len, 11u);
    EXPECT_EQ(oid[0], 1u);
}

TEST(OBMCErrorNotificationTest, GetFieldOIDList_HasNineFields)
{
    ExposedOBMCError notif;
    auto fields = notif.getFieldOIDList();
    EXPECT_EQ(fields.size(), 9u);
}

TEST(OBMCErrorNotificationTest, GetEventSubjectSN_ReturnsConstructedValue)
{
    ExposedOBMCError notif;
    EXPECT_EQ(notif.getEventSubjectSN(), "bmc-host:192.168.1.1");
}

// ---------------------------------------------------------------------------
// Notification::addPDUVar — all type branches (snmp_notification.cpp)
// ---------------------------------------------------------------------------

class TestNotification final : public Notification
{
  public:
    using Notification::addPDUVar;

    std::pair<OID, OID_LEN> getTrapOID() override
    {
        OID id = {1, 3, 6, 1, 4, 1, 49871, 1, 0, 0, 1};
        return {id, 11};
    }

    std::vector<Object> getFieldOIDList() override
    {
        return {};
    }
};

class AddPduVarFixture : public ::testing::Test
{
  protected:
    netsnmp_pdu* pdu = nullptr;

    void SetUp() override
    {
        pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
    }

    void TearDown() override
    {
        if (pdu != nullptr)
        {
            snmp_free_pdu(pdu);
        }
    }
};

TEST_F(AddPduVarFixture, Uint32Branch_ReturnsTrue)
{
    TestNotification notif;
    OID oid = {1, 3, 6, 1, 4, 1, 49871, 1, 0, 1, 1};
    EXPECT_TRUE(notif.addPDUVar(*pdu, oid, 11, ASN_UNSIGNED, uint32_t{42u}));
}

TEST_F(AddPduVarFixture, Uint64Branch_ExecutedWithoutCrash)
{
    TestNotification notif;
    OID oid = {1, 3, 6, 1, 4, 1, 49871, 1, 0, 1, 2};
    // ASN_OPAQUE_U64 support varies by netsnmp version; just verify no crash
    notif.addPDUVar(*pdu, oid, 11, ASN_OPAQUE_U64, uint64_t{9999u});
}

TEST_F(AddPduVarFixture, Int32Branch_ReturnsTrue)
{
    TestNotification notif;
    OID oid = {1, 3, 6, 1, 4, 1, 49871, 1, 0, 1, 3};
    EXPECT_TRUE(notif.addPDUVar(*pdu, oid, 11, ASN_INTEGER, int32_t{-7}));
}

TEST_F(AddPduVarFixture, StringBranch_ReturnsTrue)
{
    TestNotification notif;
    OID oid = {1, 3, 6, 1, 4, 1, 49871, 1, 0, 1, 4};
    EXPECT_TRUE(
        notif.addPDUVar(*pdu, oid, 11, ASN_OCTET_STR, std::string{"hello"}));
}

TEST_F(AddPduVarFixture, UnknownType_DefaultBranch_ReturnsFalse)
{
    TestNotification notif;
    OID oid = {1, 3, 6, 1};
    // ASN_BIT_STR hits the default branch → returns false
    EXPECT_FALSE(notif.addPDUVar(*pdu, oid, 4, ASN_BIT_STR, uint32_t{0u}));
}

// ---------------------------------------------------------------------------
// Notification::sendTrap — early-exit when trap status file is absent
// ---------------------------------------------------------------------------

TEST(SendTrapTest, TrapFileAbsent_ReturnsFalse)
{
    // /etc/snmp/SnmpTrapStatus not present in Docker test env → returns false
    ExposedOBMCError notif;
    EXPECT_FALSE(notif.sendTrap(std::nullopt, std::nullopt));
}

} // namespace
