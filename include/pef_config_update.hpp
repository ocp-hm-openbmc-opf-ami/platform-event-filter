#pragma once
#include <nlohmann/json.hpp>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <variant>
#include <vector>

using Json = nlohmann::json;

static bool updateJsonFile(const nlohmann::json& pefConfiguration)
{
    std::ofstream pefConfFile;
    pefConfFile.open(pefConfigFile, std::ios::trunc | std::ios::out);
    if (!pefConfFile)
    {
        std::cerr << "Failed to create file\n";
        return false;
    }
    pefConfFile << pefConfiguration.dump(4);
    pefConfFile.close();
    return true;
}

static int findEntryNo(std::string path)
{
    std::string entry;
    std::size_t found = path.find_last_of("/\\");
    entry = path.substr(found + 1);
    int i;
    for (i = 0; i < entry.length(); i++)
    {
        if (isdigit(entry[i]))
            break;
    }
    entry = entry.substr(i, entry.length() - i);
    int entryNo = atoi(entry.c_str());
    return entryNo;
}

Json parseJsonData(const std::string& configFile)
{
    std::ifstream jsonFile(configFile);
    if (!jsonFile.is_open())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "parseJSONConfig: Cannot open PEF config path");
    }
    auto data = Json::parse(jsonFile, nullptr, false);
    if (data.is_discarded())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "parseJSONConfig: readings JSON parser failure");
    }

    return data;
}

static sdbusplus::bus::match::match startEventFilterTableMonitor(
    std::shared_ptr<sdbusplus::asio::connection> conn)
{
    auto EventFilterEntryMatcherCallback = [conn](sdbusplus::message::message&
                                                      msg) {
        std::string pefConfIface;
        using EventFilterChangedValue =
            std::variant<uint8_t, uint16_t, std::vector<uint8_t>,
                         std::vector<uint16_t>>;
        boost::container::flat_map<std::string, EventFilterChangedValue>
            propertiesChanged;
        msg.read(pefConfIface, propertiesChanged);
        if (propertiesChanged.empty())
        {
            return;
        }

        std::string property = propertiesChanged.begin()->first;
        const auto& changedValue = propertiesChanged.begin()->second;
        std::string objPath;
        objPath = msg.get_path();

        // Determine which List group changed (List1=0, List2=1, etc.)
        std::optional<size_t> bucketIndex = std::nullopt;
        for (size_t idx = 0; idx < 4; ++idx)
        {
            const std::string listName = "List" + std::to_string(idx + 1);
            if (objPath.find(listName) != std::string::npos)
            {
                bucketIndex = idx;
                break;
            }
        }

        try
        {
            Json data = parseJsonData(pefConfigFile);
            auto& eventFilterTblData = data["EventFilterTable"];

            if (bucketIndex.has_value() &&
                std::holds_alternative<std::vector<uint8_t>>(changedValue))
            {
                const auto& values =
                    std::get<std::vector<uint8_t>>(changedValue);
                const size_t start = bucketIndex.value() * 10;
                const size_t maxCount =
                    (start < eventFilterTblData.size())
                        ? (eventFilterTblData.size() - start)
                        : 0;
                const size_t count = std::min(values.size(), maxCount);
                for (size_t i = 0; i < count; ++i)
                {
                    eventFilterTblData[start + i][property] =
                        static_cast<uint8_t>(values[i]);
                }
            }
            else if (bucketIndex.has_value() &&
                     std::holds_alternative<std::vector<uint16_t>>(
                         changedValue))
            {
                const auto& values =
                    std::get<std::vector<uint16_t>>(changedValue);
                const size_t start = bucketIndex.value() * 10;
                const size_t maxCount =
                    (start < eventFilterTblData.size())
                        ? (eventFilterTblData.size() - start)
                        : 0;
                const size_t count = std::min(values.size(), maxCount);
                for (size_t i = 0; i < count; ++i)
                {
                    eventFilterTblData[start + i][property] =
                        static_cast<uint16_t>(values[i]);
                }
            }
            else
            {
                // Legacy scalar fallback
                int entryVal = findEntryNo(objPath.c_str());
                for (auto& value : eventFilterTblData)
                {
                    int eventFilterEntry =
                        value.value("EventFilterTableEntry", 0);
                    if (entryVal == eventFilterEntry)
                    {
                        if (std::holds_alternative<uint16_t>(changedValue))
                        {
                            value[property] = std::get<uint16_t>(changedValue);
                        }
                        else if (std::holds_alternative<uint8_t>(changedValue))
                        {
                            value[property] = std::get<uint8_t>(changedValue);
                        }
                        break;
                    }
                }
            }

            updateJsonFile(data);
        }
        catch (nlohmann::json::exception& e)
        {
            std::cerr << "Error parsing config file";
            return;
        }
        catch (std::out_of_range& e)
        {
            std::cerr << "Error invalid type";
            return;
        }
    };
    sdbusplus::bus::match::match EventFilterEntryMatcher(
        static_cast<sdbusplus::bus::bus&>(*conn),
        "type='signal',interface='org.freedesktop.DBus.Properties',member='"
        "PropertiesChanged',arg0namespace='xyz.openbmc_project.pef."
        "EventFilterTable'",
        std::move(EventFilterEntryMatcherCallback));
    return EventFilterEntryMatcher;
}

static sdbusplus::bus::match::match startAlertPolicyTableMonitor(
    std::shared_ptr<sdbusplus::asio::connection> conn)
{
    auto AlertPolicyEntryMatcherCallback =
        [conn](sdbusplus::message::message& msg) {
            std::string pefConfIface;
            using AlertPolicyChangedValue =
                std::variant<uint8_t, uint16_t, std::vector<uint8_t>,
                             std::vector<std::string>>;
            boost::container::flat_map<std::string, AlertPolicyChangedValue>
                propertiesChanged;
            msg.read(pefConfIface, propertiesChanged);
            if (propertiesChanged.empty())
            {
                return;
            }

            std::string property = propertiesChanged.begin()->first;
            const auto& changedValue = propertiesChanged.begin()->second;
            std::string objPath;
            objPath = msg.get_path();

            std::optional<size_t> bucketIndex = std::nullopt;
            for (size_t idx = 0; idx < 4; ++idx)
            {
                const std::string policyListName =
                    "PolicyList_eth" + std::to_string(idx);
                if (objPath.find(policyListName) != std::string::npos)
                {
                    bucketIndex = idx;
                    break;
                }
            }

            try
            {
                Json data = parseJsonData(pefConfigFile);
                auto& alertPolicyTblData = data["AlertPolicyTable"];

                if (bucketIndex.has_value() &&
                    std::holds_alternative<std::vector<uint8_t>>(changedValue))
                {
                    const auto& values =
                        std::get<std::vector<uint8_t>>(changedValue);
                    const size_t start = bucketIndex.value() * 15;
                    const size_t maxCount =
                        (start < alertPolicyTblData.size())
                            ? (alertPolicyTblData.size() - start)
                            : 0;
                    const size_t count = std::min(values.size(), maxCount);
                    for (size_t idx = 0; idx < count; ++idx)
                    {
                        alertPolicyTblData[start + idx][property] =
                            static_cast<uint8_t>(values[idx]);
                    }
                }
                else if (bucketIndex.has_value() &&
                         std::holds_alternative<std::vector<std::string>>(
                             changedValue))
                {
                    const auto& values =
                        std::get<std::vector<std::string>>(changedValue);
                    const size_t start = bucketIndex.value() * 15;
                    const size_t maxCount =
                        (start < alertPolicyTblData.size())
                            ? (alertPolicyTblData.size() - start)
                            : 0;
                    const size_t count = std::min(values.size(), maxCount);
                    for (size_t idx = 0; idx < count; ++idx)
                    {
                        alertPolicyTblData[start + idx][property] =
                            static_cast<std::string>(values[idx]);
                    }
                }
                else
                {
                    uint8_t val = 0;
                    if (std::holds_alternative<uint8_t>(changedValue))
                    {
                        val = std::get<uint8_t>(changedValue);
                    }
                    else if (std::holds_alternative<uint16_t>(changedValue))
                    {
                        val = static_cast<uint8_t>(
                            std::get<uint16_t>(changedValue));
                    }
                    else
                    {
                        return;
                    }

                    int entryVal = 0;
                    entryVal = findEntryNo(objPath.c_str());
                    for (auto& value : alertPolicyTblData)
                    {
                        int alertPolicyEntry = 0;
                        if (value.contains("AlertPolicyTableEntry"))
                        {
                            alertPolicyEntry = value["AlertPolicyTableEntry"];
                            if (entryVal != alertPolicyEntry)
                            {
                                continue;
                            }
                        }
                        else if (entryVal > 0)
                        {
                            continue;
                        }

                        value[property] = static_cast<uint8_t>(val);
                        break;
                    }
                }

                Json dat = alertPolicyTblData;
                dat.merge_patch(data);
                updateJsonFile(dat);
            }
            catch (nlohmann::json::exception& e)
            {
                std::cerr << "Error parsing config file";
                return;
            }
            catch (std::out_of_range& e)
            {
                std::cerr << "Error invalid type";
                return;
            }
        };
    sdbusplus::bus::match::match AlertPolicyEntryMatcher(
        static_cast<sdbusplus::bus::bus&>(*conn),
        "type='signal',interface='org.freedesktop.DBus.Properties',member='"
        "PropertiesChanged',arg0namespace='xyz.openbmc_project.pef."
        "AlertPolicyTable'",
        std::move(AlertPolicyEntryMatcherCallback));
    return AlertPolicyEntryMatcher;
}

static sdbusplus::bus::match::match startPefConfInfoMonitor(
    std::shared_ptr<sdbusplus::asio::connection> conn)
{
    auto PefConfInfoMatcherCallback = [conn](sdbusplus::message::message& msg) {
        std::string pefConfIface;
        uint8_t val = 0;
        std::vector<std::string> rec;
        std::string subject;
        std::string message;
        uint16_t selId = 0;
        boost::container::flat_map<std::string,
                                   std::variant<uint8_t, uint16_t, std::string,
                                                std::vector<std::string>>>
            propertiesChanged;
        msg.read(pefConfIface, propertiesChanged);
        std::string property = propertiesChanged.begin()->first;
        if ((property == "LastSWProcessedEventID") ||
            (property == "LastBMCProcessedEventID"))
        {
            selId = std::get<uint16_t>(propertiesChanged.begin()->second);
        }

        else if (property == "Subject")
        {
            subject = std::get<std::string>(propertiesChanged.begin()->second);
        }
        else if (property == "Message")
        {
            message = std::get<std::string>(propertiesChanged.begin()->second);
        }

        else
        {
            val = std::get<uint8_t>(propertiesChanged.begin()->second);
        }
        std::string objPath;
        objPath = msg.get_path();
        try
        {
            Json data = parseJsonData(pefConfigFile);
            auto& pefConfData = data["PEFConfInfo"];
            for (auto& value : pefConfData)
            {
                if ((property == "LastSWProcessedEventID") ||
                    (property == "LastBMCProcessedEventID"))
                {
                    value[property] = static_cast<uint16_t>(selId);
                }

                else if (property == "Subject")
                {
                    value[property] = static_cast<std::string>(subject);
                }
                else if (property == "Message")
                {
                    value[property] = static_cast<std::string>(message);
                }

                else
                {
                    value[property] = static_cast<uint8_t>(val);
                }
            }
            Json data2 = pefConfData;
            data2.merge_patch(data);
            updateJsonFile(data2);
        }
        catch (nlohmann::json::exception& e)
        {
            std::cerr << "Error parsing config file";
            return;
        }
        catch (std::out_of_range& e)
        {
            std::cerr << "Error invalid type";
            return;
        }
    };
    sdbusplus::bus::match::match PefConfInfoEntryMatcher(
        static_cast<sdbusplus::bus::bus&>(*conn),
        "type='signal',interface='org.freedesktop.DBus.Properties',member='"
        "PropertiesChanged',arg0namespace='xyz.openbmc_project.pef."
        "PEFConfInfo'",
        std::move(PefConfInfoMatcherCallback));
    return PefConfInfoEntryMatcher;
}

static sdbusplus::bus::match::match startDestinationSelectorMonitor(
    std::shared_ptr<sdbusplus::asio::connection> conn)
{
    auto destinationSelectorCallback = [conn](
                                           sdbusplus::message::message& msg) {
        std::string interface;
        boost::container::flat_map<std::string, std::variant<uint8_t, uint16_t>>
            propertiesChanged;
        try
        {
            msg.read(interface, propertiesChanged);
        }
        catch (const std::exception& e)
        {
            std::cerr << "Failed to read DBus message: " << e.what() << "\n";
            return;
        }

        std::string objPath = msg.get_path();
        int entryVal = findEntryNo(objPath.c_str());

        try
        {
            Json data = parseJsonData(pefConfigFile);
            auto& dstSelectorTable = data["DestinationSelector"];

            for (const auto& [property, variantVal] : propertiesChanged)
            {
                for (auto& entry : dstSelectorTable)
                {
                    int entryNumber = entry["LanDestination"];
                    if (entryNumber == entryVal)
                    {
                        if (std::holds_alternative<uint8_t>(variantVal))
                        {
                            entry[property] = std::get<uint8_t>(variantVal);
                        }
                        else if (std::holds_alternative<uint16_t>(variantVal))
                        {
                            entry[property] = std::get<uint16_t>(variantVal);
                        }
                        break;
                    }
                }
            }

            updateJsonFile(data);
        }
        catch (nlohmann::json::exception& e)
        {
            std::cerr << "Error parsing config file";
            return;
        }
        catch (std::out_of_range& e)
        {
            std::cerr << "Error invalid type";
            return;
        }
    };

    sdbusplus::bus::match::match destinationSelectorMatcher(
        static_cast<sdbusplus::bus::bus&>(*conn),
        "type='signal',interface='org.freedesktop.DBus.Properties',"
        "member='PropertiesChanged',arg0namespace='xyz.openbmc_project.pef."
        "DestinationSelectorTable'",
        std::move(destinationSelectorCallback));

    return destinationSelectorMatcher;
}
