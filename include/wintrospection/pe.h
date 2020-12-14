#pragma once

#include "wintrospection/wintrospection.h"
#include <iohal/memory/virtual_memory.h>

// TODO descriptions from https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format

struct mem_pe;

struct mem_pe* init_mem_pe(struct ProcessOSI* process_osi, uint64_t image_base,
                           bool force);

// IMAGE_FILE_HEADER
uint16_t mem_pe_get_machine(struct mem_pe* mp);
uint16_t mem_pe_get_numberofsections(struct mem_pe* mp);
uint32_t mem_pe_get_timedatestamp(struct mem_pe* mp);
uint32_t mem_pe_get_pointertosymboltable(struct mem_pe* mp);
uint32_t mem_pe_get_numberofsymbols(struct mem_pe* mp);
uint32_t mem_pe_get_sizeofoptionalheader(struct mem_pe* mp);
uint32_t mem_pe_get_characteristics(struct mem_pe* mp);
bool mem_pe_is_i386(struct mem_pe* mp);
bool mem_pe_is_amd64(struct mem_pe* mp);

// IMAGE_OPTIONAL_HEADER
uint64_t mem_pe_get_sizeofcode(struct mem_pe* mp);

/**
 * image file checksum used for load-time validation
 */
uint32_t mem_pe_get_checksum(struct mem_pe* mp);

/**
 * The number of data directories in the optional header
 */
uint32_t mem_pe_get_numberofrvaandsizes(struct mem_pe* mp);

// NB: section numbers start indexing at 1, but this API starts at 0
//     be sure to adjust based on whether you want the index (starting at zero)
//     or the section number (starting at one)
bool mem_pe_load_section_header(struct mem_pe* mp, struct _IMAGE_SECTION_HEADER* sechead,
                                uint16_t idx);
bool mem_pe_load_section_header_by_section_number(struct mem_pe* mp,
                                                  struct _IMAGE_SECTION_HEADER* sechead,
                                                  uint16_t number);

// GUID functions
/**
 * Get the best GUID that is available
 */
std::string mem_pe_get_guid(struct mem_pe* mp);
std::string mem_pe_get_tds_guid(struct mem_pe* mp);
std::string mem_pe_get_pdb_name(struct mem_pe* mp);

// helper functions
bool parse_debug(struct mem_pe* pe);

bool parse_exports(struct mem_pe* pe);
std::string mem_pe_export_table_get_name(struct mem_pe* mp);
uint32_t mem_pe_export_table_get_base(struct mem_pe* mp);
uint32_t mem_pe_export_table_get_numberoffunctions(struct mem_pe* mp);

uint64_t mem_pe_export_table_get_rva_by_table_idx(struct mem_pe* mp, uint32_t idx);
bool mem_pe_export_table_get_name_by_table_idx(struct mem_pe* mp, char* buffer,
                                               size_t* buff_len, uint32_t idx);
uint32_t mem_pe_export_table_get_table_idx_by_ordinal(struct mem_pe* mp,
                                                      uint32_t ordinal);

void free_mem_pe(struct mem_pe* pe);
