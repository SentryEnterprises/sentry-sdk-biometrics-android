/* Copyright 2015, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#ifndef _UECC_TYPES_H_
#define _UECC_TYPES_H_


        #define uECC_ARM_USE_UMAAL 0
        #define uECC_WORD_SIZE 4

        #define SUPPORTS_INT128 0

        typedef int8_t wordcount_t;
        typedef int16_t bitcount_t;
        typedef int8_t cmpresult_t;


        typedef uint32_t uECC_word_t;
        typedef uint64_t uECC_dword_t;

        #define HIGH_BIT_SET 0x80000000
        #define uECC_WORD_BITS 32
        #define uECC_WORD_BITS_SHIFT 5
        #define uECC_WORD_BITS_MASK 0x01F


#endif /* _UECC_TYPES_H_ */
