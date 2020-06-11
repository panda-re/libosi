#include "wintrospection/pe.h"
#include "wintrospection/wintrospection.h"
#include "offset/windows_common.h"

struct mem_pe
{
    struct ProcessOSI* process_osi;
    uint64_t image_base;
    struct _IMAGE_DOS_HEADER dos_header;
    struct _IMAGE_NT_HEADERS nt_header;
    bool is32bit;
    union {
        _IMAGE_OPTIONAL_HEADER h32;
        _IMAGE_OPTIONAL_HEADER64 h64;
    } optional_header;
};

struct mem_pe* init_mem_pe(struct ProcessOSI* process_osi,
                           uint64_t image_base, bool force)
{
    auto mempe = (struct mem_pe*) std::calloc(1, sizeof(struct mem_pe));
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
    status = process_osi->vmem->read(nt_header_address, &mempe->nt_header,
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
    auto optional_header = nt_header_address + sizeof(uint32_t) +
                         sizeof(struct _IMAGE_FILE_HEADER);
    if (mempe->is32bit) {
        status = process_osi->vmem->read(optional_header,
                                         &mempe->optional_header.h32,
                                         sizeof(struct _IMAGE_OPTIONAL_HEADER));
    } else {
        status = process_osi->vmem->read(optional_header,
                                         &mempe->optional_header.h64,
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


bool mem_pe_is_i386(struct mem_pe* mp)
{
    return mem_pe_get_machine(mp) == 0x014c;
}

bool mem_pe_is_amd64(struct mem_pe* mp)
{
    return mem_pe_get_machine(mp) == 0x8664;
}

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


