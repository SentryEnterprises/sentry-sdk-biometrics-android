#ifndef __secure_module_auth__
#include "stdint.h"

int lib_auth_init(uint8_t* o_ApduInternal, int *len, uint8_t* o_private_key, uint8_t* o_public_key, uint8_t* o_secret_shses);
int lib_auth_ecdh_kdf(uint8_t* PubKey, uint8_t* secret_shses, uint8_t* privateKey, uint8_t* o_KeyRespt, uint8_t* o_KeyENC, uint8_t* o_KeyCMAC, uint8_t* o_KeyRMAC, uint8_t* o_chaining_value);
int lib_auth_wrap(uint8_t* apdu_in, uint32_t in_len, uint8_t* apdu_out, uint32_t* out_len, uint8_t* keyENC, uint8_t* keyCMAC, uint8_t* inout_chaining_value, uint8_t* inout_encryption_counter);
int lib_auth_unwrap(uint8_t* wrapped_apdu_in, uint32_t in_len, uint8_t* unwrapped_apdu_out, uint32_t* out_len, uint8_t* keyENC, uint8_t* keyRMAC, uint8_t* chaining_value, uint8_t* encryption_counter);

#endif // !__secure_module_auth__

