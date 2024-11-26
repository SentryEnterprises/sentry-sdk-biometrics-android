/* Copyright 2015, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#ifndef _UECC_PLATFORM_SPECIFIC_H_
#define _UECC_PLATFORM_SPECIFIC_H_

#include "stdint.h"
#include "uecc_types.h"
#include "time.h"
#include "sha.h"

static int64_t rNd_global=0x123456789089ULL;

int default_RNG(uint8_t *dest, uint16_t size)
{
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    uint8_t buf[300];
    uint8_t global_rnd_v[32];
    int r_size;
    int p = 0;
    
#ifndef _WINDOWS
    clock_gettime(CLOCK_REALTIME, &ts);
#endif
    
    rNd_global += (int64_t)(ts.tv_sec + ts.tv_nsec);
    do
    {
        rNd_global++;
        if (size > 32) r_size = 32; else r_size = size;
        rNd_global += (uint16_t)(ts.tv_nsec >> 16);
        buf[8] = (uint8_t)size;
        buf[0] = (uint8_t)(ts.tv_nsec);
        buf[1] = (uint8_t)(ts.tv_nsec >> 8);
        buf[2] = (uint8_t)(ts.tv_nsec >> 16);
        buf[3] = (uint8_t)(ts.tv_nsec >> 24);
        buf[4] = (uint8_t)(ts.tv_sec >> 24);
        buf[5] = (uint8_t)(ts.tv_sec >> 16);
        buf[6] = (uint8_t)(ts.tv_sec >> 8);
        buf[7] = (uint8_t)(ts.tv_sec >> 0);
        buf[10] = (uint8_t)(rNd_global >> 24);
        buf[12] = (uint8_t)(rNd_global >> 16);
        buf[14] = (uint8_t)(rNd_global >> 8);
        buf[16] = (uint8_t)(rNd_global >> 0);
        buf[18] = (uint8_t)(rNd_global >> 4);
        buf[19] = (uint8_t)(rNd_global >> 32);
        buf[20] = (uint8_t)(rNd_global >> 40);
        buf[22] = (uint8_t)(rNd_global >> 48);
        
        SHA256(buf, 300, global_rnd_v);


        for (uint16_t i = 0; i < r_size; i++)
        {
            dest[i+p] = global_rnd_v[i];
            rNd_global++;
        }
        size -= r_size;
        p += r_size;
    } while (size > 0);

    return 1;
}
#define default_RNG_defined 1


#endif /* _UECC_PLATFORM_SPECIFIC_H_ */
