#include "stdint.h"
#include "string.h"
#include "stdio.h"

#include "libsdkmain.h"
#include "secure.h"

_Export_ int LibSecureChannelInit(uint8_t* out_apduCommand, int *out_commandLen, uint8_t *out_private_key, uint8_t *out_public_key, uint8_t *out_secret_shses)
{
    printf("\n\nLib Auth Init\n");
    int ret = lib_auth_init(out_apduCommand, out_commandLen, out_private_key, out_public_key, out_secret_shses);
    return ret;
}

_Export_ int LibCalcSecretKeys(uint8_t* pubKey, uint8_t* shses, uint8_t* privateKey, uint8_t* out_KeyRespt, uint8_t* out_KeyENC, uint8_t* out_KeyCMAC, uint8_t* out_KeyRMAC, uint8_t* out_chaining)
{
    int ret = lib_auth_ecdh_kdf(pubKey, shses, privateKey, out_KeyRespt, out_KeyENC, out_KeyCMAC, out_KeyRMAC, out_chaining);
    return ret;
}

_Export_ int LibAuthWrap(uint8_t* apdu_in, uint32_t in_len, uint8_t* apdu_out, uint32_t* out_len, uint8_t* keyENC, uint8_t* keyCMAC, uint8_t* inout_chaining_value, uint8_t* inout_encryption_counter)
{
    int ret = lib_auth_wrap(apdu_in, in_len, apdu_out, out_len, keyENC, keyCMAC, inout_chaining_value, inout_encryption_counter);
    return ret;
}

_Export_ int LibAuthUnwrap(uint8_t* wrapped_apdu_in, uint32_t in_len, uint8_t* unwrapped_apdu_out, uint32_t* out_len, uint8_t* keyENC, uint8_t* keyRMAC, uint8_t* chaining_value, uint8_t* encryption_counter)
{
    int ret = lib_auth_unwrap(wrapped_apdu_in, in_len, unwrapped_apdu_out, out_len, keyENC, keyRMAC, chaining_value, encryption_counter);
    return ret;
}