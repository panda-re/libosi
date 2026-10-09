#pragma once

#include <istream>
#include <map>
#include <string>
#include <utility>
#include <vector>

/**
 * Result of parsing an offset profile (see exampleschema.json).
 */
struct Profile {
    std::map<std::string, unsigned int> TRANSLATE;
    std::vector<std::map<std::string, std::pair<int, unsigned int>>> OFFSET;
    std::map<std::string, std::map<long, std::string>> ENUM;
};

/**
 * @brief Populate an OS profile using a JSON document.
 *
 * Parses `in`, validating it against a profile
 * schema. Returns false (after logging the reason to stderr) on a syntax error or
 * schema violation; `out` is left untouched in that case.
 *
 * @param in the stream containing the JSON document.
 * @param out the profile to be filled in.
 */
bool ParseProfile(std::istream& in, Profile& out);
