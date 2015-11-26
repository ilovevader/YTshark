#ifndef __Y_TSHARK_H__
#define __Y_TSHARK_H__

#include "ytmode.h"
int main(int argc, char *argv[])
{
    int ret = ytmodeMain(argc, argv);
    if (!firstTime) {
        epan_cleanup();
    }
    
    return ret;
}

void YtmodeReset()
{
    if (firstTime) {
        return;
    }

    optind = 1;
    prefs_reset();
}

#endif
