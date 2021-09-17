#include "offset/offset.h"
#include "wintrospection/pe.h"
#include "wintrospection/wintrospection.h"
#include "gtest/gtest.h"
#include <iohal/memory/virtual_memory.h>
#include <set>
#include <unistd.h>

#include <iostream>
#include <map>

#include <dirent.h>

#include "rapidjson/document.h"
#include "rapidjson/filereadstream.h"
#include "wintrospection/utils.h"

#include "config.h"

int MAX_BUFFER_SIZE = 65536;

struct ModuleInfo {
    uint64_t base;
    uint32_t size;
    uint16_t loadcount;
    std::string path;
};

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
            /*
            if (it == EXPECTED_RESULTS.end()) {
                std::vector<struct ModuleInfo> vect;
                EXPECTED_RESULTS[pid] = vect;
            }
            */
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

class TestMemPElist : public ::testing::TestWithParam<const char*>
{
};

TEST_P(TestMemPElist, snapshot)
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
        int numPESuccess = 0;
        int numPEFound = 0;

        for (auto const& x : EXPECTED_RESULTS) {
            WindowsProcessOSI* posi = (WindowsProcessOSI*)std::malloc(sizeof(WindowsProcessOSI));
            std::memset(posi, 0, sizeof(WindowsProcessOSI));
            ASSERT_TRUE(init_process_osi_from_pid(&kosi, posi, x.first))
                << "Failed to initialize process OSI object";
            // check if image is PE
            for (auto const& mod : x.second) {
                uint64_t pe_sign = 0;
                uint64_t nt_header_address = 0;
                uint64_t magic_val = 0;
                auto status = posi->vmem->read(mod.base, &magic_val, 2);

                if (!TRANSLATE_SUCCEEDED(status)) {
                    // fprintf(stderr, "DOS Header paged out\n");
                    continue;
                }

                if (magic_val != 0x5a4d) {
                    // fprintf(stderr, "Invalid MS-DOS header\n");
                    continue;
                }

                status = posi->vmem->read(mod.base + 0x3c, &nt_header_address, 4);
                if (!TRANSLATE_SUCCEEDED(status)) {
                    // fprintf(stderr, "DOS Header paged out\n");
                    continue;
                }

                ASSERT_TRUE(TRANSLATE_SUCCEEDED(
                    posi->vmem->read(mod.base + nt_header_address, &pe_sign, 4)))
                    << "Failed to read pe signature for base " << mod.base
                    << " and NT address " << nt_header_address << " for pid " << x.first
                    << "with asid " << posi->vmem->get_asid();

                ASSERT_EQ(pe_sign, 0x4550) << "Invalid pe signature " << pe_sign;
                numPEFound++;
                auto python_mem_pe = init_mem_pe(posi, mod.base, false);
                ASSERT_TRUE(python_mem_pe != nullptr) << "Failed to init mem_pe object";
                free_mem_pe(python_mem_pe);
                numPESuccess++;
            }

            uninit_process_osi(posi);
            delete posi;
        }

        kosi.system_vmem.reset();
        kosi.pmem->free(kosi.pmem);

        fprintf(stderr, "PEs identified vs PEs successfully parsed: %lu vs %lu\n",
                numPEFound, numPESuccess);
        ASSERT_EQ(numPEFound, numPESuccess)
            << "Number of PEs identified and parsed not equal";
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

INSTANTIATE_TEST_CASE_P(Default, TestMemPElist, testing::ValuesIn(getFiles(SNAPSHOTDIR)));

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
