#ifndef __OSI_USTRING
#define __OSI_USTRING

#include <string>
#include <iostream>
#include <stdexcept>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <codecvt>
#include <locale>
#include <uchar.h>

#include <iohal/memory/virtual_memory.h>
#include <offset/offset.h>
#include "wintrospection/i_t.h"

#define MAX_STRING_LEN 4096

namespace osi {
    class ustring {
        private:
            i_t unicode_string;

            std::string read_utf16_string_as_utf8(uint64_t addr, uint64_t nbytes) {
                if (addr == 0 || nbytes <= 1) {
                    return std::string("");
                }

                if (nbytes > MAX_STRING_LEN) {
                    fprintf(stderr, "read_utf16_as_utf8 was asked to parse a string of len %lu\n",
                                    (uint64_t)nbytes);
                    return std::string("");
                }
                if ((nbytes % 2) == 1) {
                    fprintf(stderr, "Warning! UTF16 with odd length: %lu at %lx\n", (uint64_t) nbytes, (uint64_t)addr);
                    nbytes -= 1;
                }

                std::unique_ptr<char16_t[]> in_buf_p(new char16_t[nbytes]());
                auto vmem = unicode_string.get_virtual_memory();
                auto tstat = vmem->read(addr, (char16_t*) in_buf_p.get(), nbytes);

                if (tstat != TSTAT_SUCCESS) {
                    return "";
                }

                /* for debugging */
                /**
                printf("Processing %zu UTF-16 code units: [ ", nbytes);
                    for(size_t n = 0; n < nbytes; ++n) printf("%#x ", in_buf_p[n]);
                puts("]");
                **/

                std::u16string s(in_buf_p.get(), in_buf_p.get() + nbytes);
                std::wstring_convert<std::codecvt_utf8_utf16<char16_t>,char16_t> convert;
                std::string result = convert.to_bytes(s);

                return result;
            }

        public:
            ustring(i_t obj) {
                if (obj.get_type() != translate(obj.get_type_library(), "_UNICODE_STRING") &&
                    obj.get_type() != translate(obj.get_type_library(), "_UNICODE_STRING32")){
                    throw std::runtime_error("invalid ustring: not a _UNICODE_STRING or _UNICODE_STRING32");
                }
                unicode_string = obj;
            }

            uint16_t get_length() {
                return unicode_string["Length"].get16();
            }

            uint16_t get_maximum_length() {
                return unicode_string["MaximumLength"].get16();
            }

            std::string as_utf8() {
                uint16_t max_length = get_maximum_length();
                uint16_t length = get_length(); // Length is specified in bytes
                if (length == 0 && max_length == 1) {
                    return ""; // Sentinel
                }
                if (unicode_string.get_type() == translate(unicode_string.get_type_library(), "_UNICODE_STRING"))
                    return read_utf16_string_as_utf8(unicode_string("Buffer").get_address(), length);

                uint32_t bufferAddress = unicode_string["Buffer"].get32();
                return read_utf16_string_as_utf8(bufferAddress, length);
            };
    };
}

#endif // __OSI_USTRING
