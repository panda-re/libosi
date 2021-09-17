#include "iohal/memory/virtual_memory.h"
#include "offset/offset.h"
#include "wintrospection/wintrospection.h"
#include "gtest/gtest.h"
#include <set>
#include <unistd.h>

#include <dirent.h>
#include <iostream>
#include <map>
#include <vector>

// Include an internal header
#include "rapidjson/document.h"
#include "rapidjson/filereadstream.h"
#include "wintrospection/utils.h"

#include "config.h"

struct ModuleInfo {
    uint64_t base;
    uint32_t size;
    uint16_t loadcount;
    std::string path;
};

int MAX_BUFFER_SIZE = 65536;

void initialize_image_info(char* imageinfofile, std::string& g_profile, uint64_t& g_asid,
                           bool& g_pae, uint64_t& g_kdbg, uint64_t& g_kpcr,
                           int& g_pointer_width)
{
    rapidjson::Document document;
    const char* json = imageinfofile;

    FILE* fp = fopen(json, "r");

    char readBuffer[MAX_BUFFER_SIZE];
    rapidjson::FileReadStream is(fp, readBuffer, sizeof(readBuffer));
    document.ParseStream(is);

    assert(document.IsObject());
    rapidjson::Value& rows = document["rows"];
    assert(rows.IsArray());
    rapidjson::Value& rows_0 = rows[0];
    assert(rows_0.IsArray());
    assert(rows_0[4].IsNumber());

    g_profile = rows_0[0].GetString();
    g_asid = rows_0[4].GetUint64();
    g_kdbg = rows_0[5].GetUint64();
    g_kpcr = rows_0[8].GetUint64();

    std::string s_pae = rows_0[3].GetString();

    if (s_pae.compare("PAE") == 0)
        g_pae = true;
    else
        g_pae = false;

    if (g_profile.find("32") != std::string::npos)
        g_pointer_width = 4;
    else
        g_pointer_width = 8;

    fclose(fp);
}

void initialize_expected_results(
    char* dlllistfile,
    std::map<uint64_t, std::vector<struct ModuleInfo>>& EXPECTED_RESULTS)
{
    rapidjson::Document document;
    const char* json = dlllistfile;

    FILE* fp = fopen(json, "r");
    char readBuffer[MAX_BUFFER_SIZE];
    rapidjson::FileReadStream is(fp, readBuffer, sizeof(readBuffer));
    document.ParseStream(is);

    assert(document.IsObject());
    rapidjson::Value& rows = document["rows"];
    assert(rows.IsArray());

    for (rapidjson::Value::ConstValueIterator itr = rows.Begin(); itr != rows.End();
         ++itr) {
        assert((*itr).IsArray());

        uint64_t pid = (*itr)[0].GetUint64();
        auto it = EXPECTED_RESULTS.find(pid);

        if (strcmp((*itr)[4].GetString(), "Error reading PEB for pid") == 0) {
            if (it == EXPECTED_RESULTS.end()) {
                std::vector<struct ModuleInfo> vect;
                EXPECTED_RESULTS[pid] = vect;
            }
            continue;
        }

        struct ModuleInfo* mod = new struct ModuleInfo();
        mod->base = (*itr)[1].GetUint64();
        mod->size = (*itr)[2].GetUint();
        mod->loadcount = (*itr)[3].GetUint();
        mod->path = (*itr)[4].GetString();

        if (it != EXPECTED_RESULTS.end()) {
            (it->second).push_back((*mod));
        } else {
            std::vector<struct ModuleInfo> vect;
            vect.push_back((*mod));

            EXPECTED_RESULTS[pid] = vect;
        }
    }

    fclose(fp);
}

bool find_match(struct WindowsModuleEntry* me, std::vector<struct ModuleInfo>& mi)
{
    uint64_t base_addr = module_entry_get_base_address(me);
    for (auto& entry : mi) {
        if (base_addr == entry.base) {
            EXPECT_EQ(module_entry_get_modulesize(me), entry.size)
                << "ModuleSize mismatch";
            EXPECT_EQ(module_entry_get_loadcount(me), entry.loadcount)
                << "LoadCount mismatch";
            EXPECT_EQ(std::string(module_entry_get_dllpath(me)), entry.path)
                << "dllpath mismatch at address " << module_entry_get_base_address(me);
            return true;
        }
    }
    return false;
}

void handle_proces_modlist(
    struct WindowsKernelOSI* wintro, struct WindowsProcess* p,
    std::map<uint64_t, std::vector<struct ModuleInfo>> EXPECTED_RESULTS)
{
    auto pid = process_get_pid(p);
    auto candidate = EXPECTED_RESULTS.find(pid);

    if (candidate == EXPECTED_RESULTS.end()) {
        // fprintf(stderr, "Can't find pid %lu in dlllist\n", pid);
        auto modlist = get_module_list(wintro, p, MODULELIST_LOAD_ORDER);
        ASSERT_TRUE(!modlist) << "found modules that don't exist for PID" << pid;
        return;
    }

    auto& entry = candidate->second;

    uint32_t module_count = 0;
    auto modlist = get_module_list(wintro, p, MODULELIST_LOAD_ORDER);

    if (modlist) {
        auto me = module_list_next(modlist);
        while (me) {
            if (!find_match(me, entry))
                fprintf(stderr, "Did not find a match for %lu (possibly WOW64 module?)\n",
                        module_entry_get_base_address(me));
            module_count++;
            free_module_entry(me);
            me = module_list_next(modlist);
        }
    } else {
        ASSERT_TRUE(entry.size() == 0)
            << "Didn't find a module list where one was expected for PID: " << pid;
    }
    fprintf(stderr, "%u vs %lu for pid %lu\n", module_count, entry.size(), pid);
    ASSERT_TRUE(module_count >= entry.size()) << "Missing modules for PID: " << pid;
    free_module_list(modlist);
}

void delete_snapshot_dir()
{
    DIR* snapshotDir;

    if ((snapshotDir = opendir(TMP_SNAPSHOT_PATH)) != NULL) {
        std::string command = "rm -rf " + std::string(TMP_SNAPSHOT_PATH);
        std::system(command.c_str());
        closedir(snapshotDir);
    }
}

std::vector<std::string> unzip_snapshots(std::string snapshot_zip)
{
    DIR* snapshotDir;

    if ((snapshotDir = opendir(TMP_SNAPSHOT_PATH)) != NULL) {
        std::string command = "rm -rf " + std::string(TMP_SNAPSHOT_PATH);
        std::system(command.c_str());
        closedir(snapshotDir);
    }

    std::string command = "mkdir " + std::string(TMP_SNAPSHOT_PATH) + " && tar -xvzf " +
                          SNAPSHOTDIR + snapshot_zip + " -C " +
                          std::string(TMP_SNAPSHOT_PATH);
    fprintf(stderr, "Command: %s\n", command.c_str());
    std::system(command.c_str());

    struct dirent* dp;

    std::vector<std::string> snapshotNames;

    if ((snapshotDir = opendir(TMP_SNAPSHOT_PATH)) != NULL) {
        while ((dp = readdir(snapshotDir)) != NULL) {
            std::string snapshot_dir_name = dp->d_name;

            if (snapshot_dir_name.compare("..") != 0 &&
                snapshot_dir_name.compare(".") != 0) {
                DIR* snapshotDir2;
                struct dirent* dp_2;
                std::string snapshot_dir_path =
                    TMP_SNAPSHOT_PATH + std::string(dp->d_name);
                if ((snapshotDir2 = opendir(snapshot_dir_path.c_str())) != NULL) {
                    while ((dp_2 = readdir(snapshotDir2)) != NULL) {
                        std::string snapshot_name = dp_2->d_name;
                        if (snapshot_name.compare("..") != 0 &&
                            snapshot_name.compare(".") != 0) {
                            std::string full_snapshot_name =
                                snapshot_dir_path + "/" + std::string(dp_2->d_name);
                            fprintf(stderr, "Full Snapshot: %s\n",
                                    full_snapshot_name.c_str());
                            snapshotNames.push_back(full_snapshot_name.c_str());
                        }
                    }
                }
                closedir(snapshotDir2);
            }
        }
    }
    closedir(snapshotDir);
    return snapshotNames;
}

class TestMlist : public ::testing::TestWithParam<const char*>
{
};

TEST_P(TestMlist, snapshot)
{
    std::string snapshot_zip = GetParam();
    if (snapshot_zip.compare("..") == 0 || snapshot_zip.compare(".") == 0)
        return;

    std::vector<std::string> snapshots = unzip_snapshots(snapshot_zip);
    for (int i = 0; i < snapshots.size(); i++) {
        // Snapshot should follow form: "/path/to/snapshot.raw"
        std::string snapshot = snapshots[i];
        std::size_t found = snapshot.find_last_of("/");
        std::string snapshot_name =
            snapshot.substr(found + 1, snapshot.size() - (found + 1 + 4));

        std::string dlllist_path =
            std::string(DLLLISTDIR + snapshot_name + "_dlllist.json");
        std::string imageinfo_path =
            std::string(IMAGEINFODIR + snapshot_name + "_imageinfo.json");

        ASSERT_TRUE(snapshot.c_str()) << "Couldn't load input snapshot file!";
        ASSERT_TRUE(access(snapshot.c_str(), R_OK) == 0)
            << "Could not read input snapshot file";

        ASSERT_TRUE(dlllist_path.c_str()) << "Couldn't load input dlllist file!";
        ASSERT_TRUE(access(dlllist_path.c_str(), R_OK) == 0)
            << "Could not read input dlllist file";

        ASSERT_TRUE(imageinfo_path.c_str()) << "Couldn't load input imageinfo file!";
        ASSERT_TRUE(access(imageinfo_path.c_str(), R_OK) == 0)
            << "Could not read input imageinfo file";

        std::string g_profile;
        uint64_t g_kpcr = 0;
        uint64_t g_kdbg = 0;
        uint64_t g_asid = 0;
        int g_pointer_width = 0;
        bool g_pae = false;

        std::map<uint64_t, std::vector<struct ModuleInfo>> EXPECTED_RESULTS;

        initialize_image_info((char*)imageinfo_path.c_str(), g_profile, g_asid, g_pae,
                              g_kdbg, g_kpcr, g_pointer_width);
        // fprintf(stderr, "g_profile: %s\t asid: %lu\t kdbg: %lu\t kpcr: %lu\t
        // pointer_width: %i\n", g_profile.c_str(), g_asid, g_kdbg, g_kpcr,
        // g_pointer_width);
        initialize_expected_results((char*)dlllist_path.c_str(), EXPECTED_RESULTS);

        struct WindowsKernelDetails kdetails = {0};
        struct WindowsKernelOSI kosi = {0};
        kdetails.pointer_width = g_pointer_width;
        kdetails.kpcr = g_kpcr;
        kdetails.kdbg = g_kdbg;
        pm_addr_t asid = g_asid;
        bool pae = g_pae;

        kosi.pmem = load_physical_memory_snapshot(snapshot.c_str());
        kosi.kernel_tlib = load_type_library(g_profile.c_str());
        ASSERT_TRUE(kosi.pmem != nullptr) << "failed to load physical memory snapshot";
        ASSERT_TRUE(kosi.kernel_tlib != nullptr) << "failed to load type library";
        ASSERT_TRUE(initialize_windows_kernel_osi(&kosi, &kdetails, asid, pae, "windows"))
            << "Failed to initialize kernel osi";

        auto plist = get_process_list(&kosi);
        ASSERT_TRUE(plist != nullptr) << "Failed to get process list";
        int numProc = 0;

        auto process = process_list_next(plist);
        if (process == nullptr)
            numProc = 1; // represents system with pid = 4

        else {
            for (process; process != nullptr; process = process_list_next(plist)) {
                numProc++;
                handle_proces_modlist(&kosi, process, EXPECTED_RESULTS);
                free_process(process);
            }
        }

        ASSERT_TRUE(numProc >= EXPECTED_RESULTS.size())
            << "Mismatched number of processes, expecting " << EXPECTED_RESULTS.size()
            << " found " << numProc;

        free_process_list(plist);

        kosi.system_vmem.reset();
        kosi.pmem->free(kosi.pmem);
    }
    delete_snapshot_dir();
}

std::vector<const char*> getFiles(const char* snapshot_path)
{
    DIR* snapshotDir;
    struct dirent* dp;

    std::vector<const char*> snapshotNames;

    if ((snapshotDir = opendir(snapshot_path)) != NULL) {
        while ((dp = readdir(snapshotDir)) != NULL) {
            fprintf(stderr, "%s\n", dp->d_name);
            char* snapshot_name = new char[std::string(dp->d_name).length() + 1];
            strcpy(snapshot_name, dp->d_name);
            snapshotNames.push_back((const char*)snapshot_name);
        }
    }
    closedir(snapshotDir);
    return snapshotNames;
}

INSTANTIATE_TEST_CASE_P(Default, TestMlist, testing::ValuesIn(getFiles(SNAPSHOTDIR)));

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
