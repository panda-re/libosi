#pragma once

#include <iohal/memory/virtual_memory.h>
#include "wintrospection/wintrospection.h"

struct mem_pe;

struct mem_pe* init_mem_pe(struct ProcessOSI* process_osi,
                           uint64_t image_base, bool force);

uint16_t mem_pe_get_machine(struct mem_pe* mp);
uint16_t mem_pe_get_numberofsections(struct mem_pe* mp);
uint32_t mem_pe_get_timedatestamp(struct mem_pe* mp);
uint32_t mem_pe_get_pointertosymboltable(struct mem_pe* mp);
uint32_t mem_pe_get_numberofsymbols(struct mem_pe* mp);
uint32_t mem_pe_get_sizeofoptionalheader(struct mem_pe* mp);
uint32_t mem_pe_get_characteristics(struct mem_pe* mp);

bool mem_pe_is_i386(struct mem_pe* mp);
bool mem_pe_is_amd64(struct mem_pe* mp);
uint64_t mem_pe_get_baseofcode(struct mem_pe* mp);
uint64_t mem_pe_get_sizeofcode(struct mem_pe* mp);

void free_mem_pe(struct mem_pe* pe);


