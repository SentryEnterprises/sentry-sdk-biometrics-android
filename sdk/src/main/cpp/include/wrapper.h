#ifndef __WRAPPER_C__
#include "stdint.h"


void wrap(uint8_t* apdu_in, uint32_t in_len, uint8_t* apdu_out, uint32_t* out_len, uint8_t* key_enc, uint8_t* key_cmac, uint8_t* inout_chaining_value, uint8_t* inout_encryption_counter);
int unwrap(uint8_t* apdu_in, uint32_t in_len, uint8_t* apdu_out, uint32_t* out_len, uint8_t* key_enc, uint8_t* key_rmac, uint8_t* chaining_value, uint8_t* encryption_counter);


#endif // !__WRAPPER_C__
