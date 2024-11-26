#ifndef __lib_main_header__

#include "stdint.h"

#ifdef _WINDOWS
#define DllExport   __declspec( dllexport )
#define  _Export_ DllExport
#endif

#ifdef __ANDROID__
#define  _Export_ extern
#endif

#ifdef __APPLE__
#define  _Export_ extern
#endif

_Export_ int LibSecureChannelInit(uint8_t* out_apduCommand, int *out_commandLen, uint8_t* out_private_key, uint8_t* out_public_key, uint8_t* out_secret_shses);

_Export_ int LibCalcSecretKeys(uint8_t* pubKey, uint8_t* shses, uint8_t* privateKey, uint8_t* out_KeyRespt, uint8_t* out_KeyENC, uint8_t* out_KeyCMAC, uint8_t* out_KeyRMAC, uint8_t* out_chaining);

_Export_ int LibAuthWrap(uint8_t* apdu_in, uint32_t in_len, uint8_t* apdu_out, uint32_t* out_len, uint8_t* keyENC, uint8_t* keyCMAC, uint8_t* inout_chaining_value, uint8_t* inout_encryption_counter);

_Export_ int LibAuthUnwrap(uint8_t* wrapped_apdu_in, uint32_t in_len, uint8_t* unwrapped_apdu_out, uint32_t* out_len, uint8_t* keyENC, uint8_t* keyRMAC, uint8_t* chaining_value, uint8_t* encryption_counter);

#endif // !__lib_main_header__



