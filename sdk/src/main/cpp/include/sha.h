#ifndef _SHA_H_
#define _SHA_H_

#include "stdint.h"


#define METHOD_SHA1   1
#define METHOD_SHA256 2

struct sha_ctx
{
    uint16_t hashsize;
    void (*transform)(struct sha_ctx*, uint32_t[]);
    uint32_t state[8];
    uint8_t data[64];
    uint32_t datalen;
};
void SHA256(uint8_t* msg, uint16_t msg_len, uint8_t* digest);
void SHA1(uint8_t* msg, uint16_t msg_len, uint8_t* digest);

int  sha_init(struct sha_ctx* ctx, uint16_t method);
void sha_update(struct sha_ctx* ctx, uint8_t* data, uint16_t len);
void sha_final(struct sha_ctx* ctx, uint8_t* digest);



#endif
