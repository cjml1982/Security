/*
* create by Marty, move the common data from SecUser and SecControler 2017/07/11
* 
*
*
*
*
*/


#include <ndn-cpp/encrypt/SecCommon.hpp>

namespace pki {

void hexdump(
                FILE *f,
                const char *title,
                const unsigned char *s,
                int l)
{
    int n = 0;

    fprintf(f, "%s", title);
    for (; n < l; ++n) {
        if ((n % 16) == 0) {
                fprintf(f, "\n%04x", n);
        }
        fprintf(f, " %02x", s[n]);
    }

    fprintf(f, "\n");
}

}

