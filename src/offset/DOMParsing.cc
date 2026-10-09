#include "DOMParsing.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <istream>
#include <map>
#include <string>
#include <vector>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/istreamwrapper.h>
#include <rapidjson/schema.h>
#include <rapidjson/stringbuffer.h>


namespace
{

/**
 * Example:
 * {
 *     "offsets": {
 *         "UNKNOWN": null,
 *         "_MMVAD_SHORT": {
 *             "u1": {
 *                 "offset": 0,
 *                 "type": 406
 *             },
 *             "LeftChild": {
 *                 "offset": 8,
 *                 "type": 2147484421
 *             },
 *             "StartingVpn": {
 *                 "offset": 24,
 *                 "type": 0
 *             }
 *         }
 *     },
 *     "enums": { // this key is optional
 *         "ObTypeIndexTable": {
 *             "2": "Type",
 *             "3": "Directory"
 *         }
 *     }
 * }
 */
const char* const profileSchema = R"json(
{
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "required": ["offsets"],
    "properties": {
        "offsets": {
            "type": "object",
            "additionalProperties": {
                "type": ["object", "null"],
                "additionalProperties": {
                    "type": "object",
                    "required": ["offset", "type"],
                    "properties": {
                        "offset": {
                            "type": "integer",
                            "minimum": -2147483648,
                            "maximum": 2147483647
                        },
                        "type": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 4294967295
                        }
                    }
                }
            }
        },
        "enums": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "patternProperties": {
                    "^[0-9]{1,18}$": { "type": "string" }
                },
                "additionalProperties": {
                    "not": {},
                    "$comment": "RapidJSON 1.1.0 has a bug where the above is not correctly enforced"
                }
            }
        }
    }
}
)json";

const rapidjson::SchemaDocument GetProfileSchema()
{
    rapidjson::Document sd;
    sd.Parse(profileSchema);
    if (sd.HasParseError()) {
        // The schema is a compile-time constant; this is a programmer error.
        std::cerr << "Internal error: invalid profile schema at offset "
                  << sd.GetErrorOffset() << ": "
                  << rapidjson::GetParseError_En(sd.GetParseError()) << std::endl;
        std::abort();
    }
    return rapidjson::SchemaDocument(sd);
}

std::string Name(const rapidjson::Value& v)
{
    return std::string(v.GetString(), v.GetStringLength());
}

int64_t AsInt64(const rapidjson::Value& v)
{
    return v.IsInt64() ? v.GetInt64() : static_cast<int64_t>(v.GetUint64());
}

// The schema guarantees the shapes assumed below.
void ParseOffsets(const rapidjson::Value& offsets, Profile& p)
{
    for (const auto& type_entry : offsets.GetObject()) {
        const std::string type_name = Name(type_entry.name);

        std::map<std::string, std::pair<int, unsigned int>> member_map;
        if (type_entry.value.IsObject()) {
            for (const auto& member_entry : type_entry.value.GetObject()) {
                const auto& m = member_entry.value;
                member_map.emplace(
                    Name(member_entry.name),
                    std::make_pair(static_cast<int>(AsInt64(m["offset"])),
                                   static_cast<unsigned int>(AsInt64(m["type"]))));
            }
        }

        p.TRANSLATE[type_name] = static_cast<unsigned int>(p.OFFSET.size());
        p.OFFSET.push_back(std::move(member_map));
    }
}

void ParseEnums(const rapidjson::Value& enums, Profile& p)
{
    for (const auto& enum_entry : enums.GetObject()) {
        auto& ordinals = p.ENUM[Name(enum_entry.name)];
        for (const auto& ord_entry : enum_entry.value.GetObject()) {
            // Ordinal keys are stringified integers, e.g. "2".
            ordinals.emplace(std::stol(Name(ord_entry.name)), Name(ord_entry.value));
        }
    }
}

} // namespace

bool ParseProfile(std::istream& in, Profile& out)
{
    rapidjson::IStreamWrapper isw{in};
    rapidjson::SchemaDocument document = GetProfileSchema();
    rapidjson::SchemaValidatingReader<rapidjson::kParseDefaultFlags,
                                      rapidjson::IStreamWrapper, rapidjson::UTF8<>>
        reader(isw, document);

    rapidjson::Document doc;
    doc.Populate(reader);

    const rapidjson::ParseResult& result = reader.GetParseResult();
    if (!reader.IsValid() || !result) {
        if (!reader.IsValid()) {
            rapidjson::StringBuffer schema_ptr;
            rapidjson::StringBuffer doc_ptr;
            reader.GetInvalidSchemaPointer().StringifyUriFragment(schema_ptr);
            reader.GetInvalidDocumentPointer().StringifyUriFragment(doc_ptr);
            std::cerr << "Profile failed schema validation: keyword '"
                      << reader.GetInvalidSchemaKeyword() << "' at document location '"
                      << doc_ptr.GetString() << "' (schema location '"
                      << schema_ptr.GetString() << "')" << std::endl;
        } else {
            std::cerr << "JSON parse error at offset " << result.Offset() << ": "
                      << rapidjson::GetParseError_En(result.Code()) << std::endl;
        }
        return false;
    }

    Profile p;
    // The schema requires "offsets", so it is guaranteed to exist here.
    ParseOffsets(doc["offsets"], p);

    auto enums = doc.FindMember("enums");
    if (enums != doc.MemberEnd()) {
        ParseEnums(enums->value, p);
    }

    out = std::move(p);
    return true;
}
