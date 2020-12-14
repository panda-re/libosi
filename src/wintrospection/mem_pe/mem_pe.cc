#include "offset/windows_common.h"
#include "wintrospection/pe.h"
#include "wintrospection/wintrospection.h"
#include <cstring>

struct mem_pe {
    struct ProcessOSI* process_osi;
    uint64_t image_base;
    struct _IMAGE_DOS_HEADER dos_header;
    struct _IMAGE_NT_HEADERS nt_header;
    bool is32bit;
    union {
        _IMAGE_OPTIONAL_HEADER h32;
        _IMAGE_OPTIONAL_HEADER64 h64;
    } optional_header;

    bool parsed_exports;
    bool has_exports;
    bool parsed_debug;
    bool has_cv_entry;

    struct _IMAGE_DEBUG_DIRECTORY debug_table;
    struct _IMAGE_EXPORT_DIRECTORY export_table;
};

struct mem_pe* init_mem_pe(struct ProcessOSI* process_osi, uint64_t image_base,
                           bool force)
{
    auto mempe = (struct mem_pe*)std::calloc(1, sizeof(struct mem_pe));
    mempe->process_osi = process_osi;
    mempe->image_base = image_base;
    auto status = process_osi->vmem->read(image_base, &mempe->dos_header,
                                          sizeof(struct _IMAGE_DOS_HEADER));
    if (!TRANSLATE_SUCCEEDED(status)) {
        fprintf(stderr, "DOS Header is paged out %lx\n", image_base);
        std::free(mempe);
        return nullptr;
    }
    // Check this is a valid DOS header, ignoring mismatches if the
    // force flag is set
    if (!force && (mempe->dos_header.e_magic != 0x5a4d)) {
        fprintf(stderr, "_IMAGE_DOS_HEADER.e_magic = %x\n", mempe->dos_header.e_magic);
        std::free(mempe);
        return nullptr;
    }

    auto nt_header_address = image_base + mempe->dos_header.e_lfanew;
    status = process_vmem_read(process_osi, nt_header_address, &mempe->nt_header,
                               sizeof(struct _IMAGE_NT_HEADERS));
    if (!TRANSLATE_SUCCEEDED(status)) {
        fprintf(stderr, "Failed to read nt header at %lx\n", nt_header_address);
        std::free(mempe);
        return nullptr;
    }

    if (!force && (mempe->nt_header.Signature != 0x4550)) {
        fprintf(stderr, "_IMAGE_NT_HEADERS.Signature = %x\n", mempe->dos_header.e_magic);
        std::free(mempe);
        return nullptr;
    }

    mempe->is32bit = mem_pe_is_i386(mempe);
    auto optional_header =
        nt_header_address + sizeof(uint32_t) + sizeof(struct _IMAGE_FILE_HEADER);
    if (mempe->is32bit) {
        status = process_osi->vmem->read(optional_header, &mempe->optional_header.h32,
                                         sizeof(struct _IMAGE_OPTIONAL_HEADER));
    } else {
        status = process_osi->vmem->read(optional_header, &mempe->optional_header.h64,
                                         sizeof(struct _IMAGE_OPTIONAL_HEADER64));
    }
    if (!TRANSLATE_SUCCEEDED(status)) {
        fprintf(stderr, "Failed to read optional header at %lx\n", optional_header);
        std::free(mempe);
        return nullptr;
    }

    return mempe;
}

void free_mem_pe(struct mem_pe* pe)
{
    if (pe) {
        std::free(pe);
    }
}

uint16_t mem_pe_get_machine(struct mem_pe* mp)
{
    return mp->nt_header.FileHeader.Machine;
}

uint16_t mem_pe_get_numberofsections(struct mem_pe* mp)
{
    return mp->nt_header.FileHeader.NumberOfSections;
}

uint32_t mem_pe_get_timedatestamp(struct mem_pe* mp)
{
    return mp->nt_header.FileHeader.TimeDateStamp;
}

uint32_t mem_pe_get_pointertosymboltable(struct mem_pe* mp)
{
    return mp->nt_header.FileHeader.PointerToSymbolTable;
}

uint32_t mem_pe_get_numberofsymbols(struct mem_pe* mp)
{
    return mp->nt_header.FileHeader.NumberOfSymbols;
}

uint32_t mem_pe_get_sizeofoptionalheader(struct mem_pe* mp)
{
    return mp->nt_header.FileHeader.SizeOfOptionalHeader;
}

uint32_t mem_pe_get_characteristics(struct mem_pe* mp)
{
    return mp->nt_header.FileHeader.Characteristics;
}

bool mem_pe_is_i386(struct mem_pe* mp) { return mem_pe_get_machine(mp) == 0x014c; }

bool mem_pe_is_amd64(struct mem_pe* mp) { return mem_pe_get_machine(mp) == 0x8664; }

uint64_t mem_pe_get_baseofcode(struct mem_pe* mp)
{
    uint64_t base_addr = mp->image_base;
    if (mp->is32bit) {
        return base_addr + mp->optional_header.h32.BaseOfCode;
    } else {
        return base_addr + mp->optional_header.h64.BaseOfCode;
    }
}

uint64_t mem_pe_get_sizeofcode(struct mem_pe* mp)
{
    if (mp->is32bit) {
        return mp->optional_header.h32.SizeOfCode;
    } else {
        return mp->optional_header.h64.SizeOfCode;
    }
}

uint32_t mem_pe_get_sizeofimage(struct mem_pe* mp)
{
    if (mp->is32bit) {
        return mp->optional_header.h32.SizeOfImage;
    } else {
        return mp->optional_header.h64.SizeOfImage;
    }
}

uint32_t mem_pe_get_checksum(struct mem_pe* mp)
{
    if (mp->is32bit) {
        return mp->optional_header.h32.CheckSum;
    } else {
        return mp->optional_header.h64.CheckSum;
    }
}

uint32_t mem_pe_get_numberofrvaandsizes(struct mem_pe* mp)
{
    if (mp->is32bit) {
        return mp->optional_header.h32.NumberOfRvaAndSizes;
    } else {
        return mp->optional_header.h64.NumberOfRvaAndSizes;
    }
}

bool mem_pe_load_section_header(struct mem_pe* mp, struct _IMAGE_SECTION_HEADER* sechead,
                                uint16_t idx)
{
    uint16_t nsections = mem_pe_get_numberofsections(mp);
    if (idx >= nsections) {
        std::memset(sechead, 0, sizeof(_IMAGE_SECTION_HEADER));
        return false; // fail
    }

    auto nt_header_address = mp->image_base + mp->dos_header.e_lfanew;
    auto optional_header =
        nt_header_address + sizeof(uint32_t) + sizeof(struct _IMAGE_FILE_HEADER);
    auto section_table_address = optional_header + mem_pe_get_sizeofoptionalheader(mp);
    auto section_address =
        section_table_address + idx * sizeof(struct _IMAGE_SECTION_HEADER);

    auto status = mp->process_osi->vmem->read(section_address, sechead,
                                              sizeof(struct _IMAGE_SECTION_HEADER));
    if (!TRANSLATE_SUCCEEDED(status)) {
        fprintf(stderr, "Failed to read section header at %lx", section_address);
        std::memset(sechead, 0, sizeof(_IMAGE_SECTION_HEADER));
        return false;
    }
    return true;
}

bool mem_pe_load_section_header_by_section_number(struct mem_pe* mp,
                                                  struct _IMAGE_SECTION_HEADER* sechead,
                                                  uint16_t number)
{
    uint16_t nsections = mem_pe_get_numberofsections(mp);
    if ((number > nsections) || number == 0) {
        std::memset(sechead, 0, sizeof(_IMAGE_SECTION_HEADER));
        return false; // fail
    }

    return mem_pe_load_section_header(mp, sechead, number - 1);
}

bool parse_debug(struct mem_pe* mp)
{
    if (mp->parsed_debug) {
        return true;
    }

    uint64_t debug_table_address =
        (mp->is32bit
             ? mp->optional_header.h32.DataDirectory[IMAGE_DIRECTORY_ENTRY_TYPE_DEBUG]
                   .VirtualAddress
             : mp->optional_header.h64.DataDirectory[IMAGE_DIRECTORY_ENTRY_TYPE_DEBUG]
                   .VirtualAddress) +
        mp->image_base;

    uint32_t debug_table_size =
        mp->is32bit
            ? mp->optional_header.h32.DataDirectory[IMAGE_DIRECTORY_ENTRY_TYPE_DEBUG].Size
            : mp->optional_header.h64.DataDirectory[IMAGE_DIRECTORY_ENTRY_TYPE_DEBUG]
                  .Size;

    // fprintf(stderr, "[DEBUG] Parsing Debug Directory at %lx (size %x)\n",
    //                 debug_table_address, debug_table_size);

    mp->has_cv_entry = false;

    if (debug_table_size == 0) {
        // nothing to parse
        mp->parsed_debug = true;
        return true;
    }

    bool failed = false;
    uint64_t number_of_entries = debug_table_size / sizeof(_IMAGE_DEBUG_DIRECTORY);
    // fprintf(stderr, "[DEBUG] Number of debug entries: %lu\n", number_of_entries);
    for (size_t idx = 0; idx < number_of_entries; ++idx) {
        auto status = process_vmem_read(
            mp->process_osi,
            debug_table_address + idx * sizeof(struct _IMAGE_DEBUG_DIRECTORY),
            &(mp->debug_table), sizeof(struct _IMAGE_DEBUG_DIRECTORY));
        if (!TRANSLATE_SUCCEEDED(status)) {
            fprintf(stderr, "Failed to read _IMAGE_DEBUG_DIRECTORY at %lx\n",
                    debug_table_address + idx * sizeof(struct _IMAGE_DEBUG_DIRECTORY));
            std::memset(&(mp->debug_table), 0, sizeof(struct _IMAGE_DEBUG_DIRECTORY));
            failed = true;
            continue;
        }
        auto& dbg = mp->debug_table;
        if (dbg.Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
            // fprintf(stderr, "[DEBUG] Found code view entry\n");
            mp->has_cv_entry = true;
            break;
        } else if (dbg.Type == 3 /* fpo */) {
            //  pass
        } else {
            fprintf(stderr,
                    "[DEBUG] Unhandled debug info type _IMAGE_DEBUG_DIRECTORY.Type==%u\n",
                    dbg.Type);
        }
    }
    mp->parsed_debug = !failed;
    // fprintf(stderr, "[Debug] Was this parse a success? cv_entry=%u parsed_debug=%u\n",
    // mp->has_cv_entry, !failed);
    if (!mp->has_cv_entry) {
        // Everything parsed but didn't find a code view entry
        return mp->parsed_debug;
    }
    return true;
}

static inline std::string read_cstring(struct ProcessOSI* process_osi, uint64_t addr)
{
    std::string result = "";
    char working = '\0';
    uint32_t max_length = 4096;

    while (max_length > 0) {
        auto status = process_vmem_read(process_osi, addr, &working, 1);
        if (!TRANSLATE_SUCCEEDED(status)) {
            break;
        }
        if (working == '\0') {
            break;
        }
        result += working;
        max_length -= 1;
        addr += 1;
    }
    return result;
}

struct GUIDValue {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
};

static inline std::string mem_pe_get_cv_guid(struct mem_pe* mp)
{
    std::string result = "";
    if (!mp->has_cv_entry) {
        return result;
    }

    if (mp->debug_table.AddressOfRawData == 0) {
        fprintf(stderr, "debug information isn't mapped in\n");
        return result;
    }
    result.resize(64);

    uint32_t signature = 0;
    uint64_t dbg_info = mp->image_base + mp->debug_table.AddressOfRawData;
    auto status = process_vmem_read(mp->process_osi, dbg_info, &signature, 4);
    if (!TRANSLATE_SUCCEEDED(status)) {
        // fprintf(stderr, "Failed to read CV header at %lx for %lx\n", dbg_info,
        // mp->image_base);
        return result;
    }

    if (signature == 0x53445352) { // RSDS
        struct GUIDValue guid = {0};
        status = process_vmem_read(mp->process_osi, dbg_info + 4, &guid, 16);
        if (!TRANSLATE_SUCCEEDED(status)) {
            fprintf(stderr, "Failed to parse CV_INFO_PDB70\n");
            return result;
        }

        uint32_t age = 0;
        status = process_vmem_read(mp->process_osi, dbg_info + 0x14, &age, 4);
        if (!TRANSLATE_SUCCEEDED(status)) {
            fprintf(stderr, "Failed to parse GUID age\n");
            return result;
        }

        snprintf(&(result[0]), 64, "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
                 guid.data1, guid.data2, guid.data3, guid.data4[0], guid.data4[1],
                 guid.data4[2], guid.data4[3], guid.data4[4], guid.data4[5],
                 guid.data4[6], guid.data4[7], age);
        return result;
    } else if (signature == 0x3031424e) {
        uint32_t sig = 0;
        uint32_t age = 0;
        status = process_vmem_read(mp->process_osi, dbg_info + 8, &sig, 4);
        if (!TRANSLATE_SUCCEEDED(status)) {
            fprintf(stderr, "Failed to parse CV_INFO_PDB20\n");
            return result;
        }
        status = process_vmem_read(mp->process_osi, dbg_info + 0xc, &age, 4);
        if (!TRANSLATE_SUCCEEDED(status)) {
            fprintf(stderr, "Failed to parse CV_INFO_PDB20\n");
            return result;
        }

        snprintf(&(result[0]), 32, "%X%X", sig, age);
    }

    fprintf(stderr, "Unsupported PDB info type: %x\n", signature);
    return "";
}

std::string mem_pe_get_tds_guid(struct mem_pe* mp)
{
    std::string result = "";
    result.resize(16);
    snprintf(&(result[0]), 32, "%08X%08X", mem_pe_get_timedatestamp(mp),
             mem_pe_get_sizeofimage(mp));
    return result;
}

std::string mem_pe_get_guid(struct mem_pe* mp)
{
    if (!mp->parsed_debug) {
        (void)parse_debug(mp);
    }
    if (mp->has_cv_entry) {
        return mem_pe_get_cv_guid(mp);
    } else {
        return mem_pe_get_tds_guid(mp);
    }
}

std::string mem_pe_get_pdb_name(struct mem_pe* mp)
{
    if (!mp->parsed_debug) {
        (void)parse_debug(mp);
    }

    if (!mp->has_cv_entry) {
        return "";
    }

    if (mp->debug_table.AddressOfRawData == 0) {
        fprintf(stderr, "Debug information is not mapped in, skipping\n");
        return "";
    }

    uint32_t signature = 0;
    uint64_t dbg_info = mp->image_base + mp->debug_table.AddressOfRawData;

    auto status = process_vmem_read(mp->process_osi, dbg_info, &signature, 4);
    if (!TRANSLATE_SUCCEEDED(status)) {
        fprintf(stderr, "Failed to parse CV_HEADER for PDB name\n");
        return "";
    }

    if (signature == 0x53445352) { // RSDS
        return read_cstring(mp->process_osi, dbg_info + 0x18);
    } else if (signature == 0x3031424e) {
        return read_cstring(mp->process_osi, dbg_info + 0x10);
    }
    fprintf(stderr, "Unsupported CV type: %x, skipping\n", signature);
    return "";
}

bool parse_exports(struct mem_pe* mp)
{
    if (mp->parsed_exports) {
        return true;
    }

    uint64_t export_table_address =
        (mp->is32bit
             ? mp->optional_header.h32.DataDirectory[IMAGE_DIRECTORY_ENTRY_TYPE_EXPORT]
                   .VirtualAddress
             : mp->optional_header.h64.DataDirectory[IMAGE_DIRECTORY_ENTRY_TYPE_EXPORT]
                   .VirtualAddress) +
        mp->image_base;

    uint32_t export_table_size =
        mp->is32bit
            ? mp->optional_header.h32.DataDirectory[IMAGE_DIRECTORY_ENTRY_TYPE_EXPORT]
                  .Size
            : mp->optional_header.h64.DataDirectory[IMAGE_DIRECTORY_ENTRY_TYPE_EXPORT]
                  .Size;

    mp->has_exports = export_table_size != 0;

    if (!mp->has_exports) {
        // nothing to parse
        mp->parsed_exports = true;
        return true;
    }

    auto status =
        process_vmem_read(mp->process_osi, export_table_address, &(mp->export_table),
                          sizeof(struct _IMAGE_EXPORT_DIRECTORY));
    if (!TRANSLATE_SUCCEEDED(status)) {
        fprintf(stderr, "Export table isn't readable at %lx\n", export_table_address);
        std::memset(&(mp->export_table), 0, sizeof(_IMAGE_EXPORT_DIRECTORY));
        mp->parsed_exports = false;
        return false;
    }
    mp->parsed_exports = true;
    return true;
}

uint32_t mem_pe_export_table_get_numberoffunctions(struct mem_pe* mp)
{
    if (!(mp->parsed_exports)) {
        fprintf(stderr, "Tried to read exports before parsing\n");
        return 0;
    }

    if (!(mp->has_exports)) {
        return 0;
    }
    return mp->export_table.NumberOfFunctions;
}

std::string mem_pe_export_table_get_name(struct mem_pe* mp)
{
    if (!(mp->parsed_exports)) {
        return "<invalid_use_of_mempe>";
    }

    if (!(mp->has_exports)) {
        return "";
    }

    uint64_t name_addr = mp->image_base + mp->export_table.Name;
    const uint64_t max_size = 256;
    char buffer[max_size] = {0};

    for (uint64_t idx = 0; idx < max_size; ++idx) {
        auto status =
            process_vmem_read(mp->process_osi, name_addr + idx, buffer + idx, 1);
        if (!TRANSLATE_SUCCEEDED(status)) {
            buffer[idx] = '\0';
            break;
        }
        if (buffer[idx] == '\0') {
            break;
        }
    }
    return std::string(buffer);
}

bool namehelper_by_name_idx(struct mem_pe* mp, char* buffer, size_t* blen,
                            uint32_t name_idx)
{
    uint32_t rva = 0;
    auto name_address =
        mp->image_base + mp->export_table.AddressOfNames + name_idx * sizeof(uint32_t);
    auto status =
        process_vmem_read(mp->process_osi, name_address, &rva, sizeof(uint32_t));
    if (!TRANSLATE_SUCCEEDED(status)) {
        fprintf(stderr, "Failed to read export name rva: %lx -> %x\n", name_address, rva);
        return false;
    }

    uint64_t read_address = mp->image_base + rva;
    for (uint64_t idx = 0; idx < (*blen) - 1; ++idx) {
        auto status =
            process_vmem_read(mp->process_osi, read_address + idx, buffer + idx, 1);
        if (!TRANSLATE_SUCCEEDED(status)) {
            buffer[idx] = '\0';
            break;
        }
        if (buffer[idx] == '\0') {
            return true;
        }
    }
    buffer[*blen - 1] = '\0';
    return false;
}

bool mem_pe_export_table_get_name_by_table_idx(struct mem_pe* mp, char* buffer,
                                               size_t* buff_len, uint32_t target_idx)
{
    if (!mp->parsed_exports) {
        fprintf(stderr, "Attempted to read exports before parsing them\n");
        return false;
    }

    if (!(mp->has_exports)) {
        return false;
    }

    auto base_address = mp->image_base + mp->export_table.AddressOfNameOrdinals;
    for (uint64_t idx = 0; idx < mp->export_table.NumberOfNames; ++idx) {
        auto address = base_address + idx * sizeof(uint16_t);
        uint16_t candidate = 0;
        auto status = process_vmem_read(mp->process_osi, address, &candidate, 2);
        if (!TRANSLATE_SUCCEEDED(status)) {
            if (buffer) {
                buffer[0] = '\0';
            }
            *buff_len = 0;
            return false;
        }
        if (candidate == target_idx) {
            return namehelper_by_name_idx(mp, buffer, buff_len, idx);
        }
    }

    if (buffer != nullptr) {
        buffer[0] = '\0';
    }
    *buff_len = 0;
    return true;
}

uint64_t mem_pe_export_table_get_rva_by_table_idx(struct mem_pe* mp, uint32_t idx)
{
    if (!mp->parsed_exports) {
        fprintf(stderr, "Attempted to read exports before parsing them\n");
        return 0;
    }

    if (!(mp->has_exports)) {
        return 0;
    }

    uint32_t rva = 0;
    auto base_address =
        mp->image_base + mp->export_table.AddressOfFunctions + idx * sizeof(uint32_t);
    auto status =
        process_vmem_read(mp->process_osi, base_address, &rva, sizeof(uint32_t));
    if (!TRANSLATE_SUCCEEDED(status)) {
        return 0;
    }
    return rva;
}
