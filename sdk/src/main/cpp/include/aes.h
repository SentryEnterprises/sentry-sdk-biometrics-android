#ifndef __AES_C__

#include "stdint.h"

void AES_128(uint8_t* key, uint8_t* plaintext, uint8_t* ciphertext);
void AES_128_CBC_Encrypt(uint8_t* key, uint8_t* plaintext, uint8_t* ciphertext, uint32_t len, uint8_t* iv);
void AES_128_CBC_Decrypt(uint8_t* key, uint8_t* ciphertext, uint8_t* plaintext, uint32_t len, uint8_t* iv);


#endif // !__AES_C__

