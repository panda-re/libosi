#ifndef __LIBINTRO_WINDOWS_HANDLE_TABLE_H
#define __LIBINTRO_WINDOWS_HANDLE_TABLE_H

#include "wintrospection/i_t.h"
#include "wintrospection/wintrospection.h"

osi::i_t resolve_handle_table_entry(struct WindowsProcessOSI* posi, uint64_t handle, bool x64);

#endif
