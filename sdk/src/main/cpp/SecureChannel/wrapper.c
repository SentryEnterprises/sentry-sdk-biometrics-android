//
#include "stdint.h"
#include "string.h"
#include "aes.h"
#include "cmac.h"
//#include "secure.h"
#include "wrapper.h"

#include "stdio.h"
//
//uint8_t chaining_value[16];
//uint8_t encryption_counter[16];
//uint8_t apdu_new[264];
//
//SmartCardApduCallBack pSmartCardApduCallBack = NULL;
//int ApduIsSecureChannel = 0;
//
////----------------------------------------------------------------------------------------------------------------------
//int apdu_secure_channel(uint8_t* DataIn, uint32_t DataInLen, uint8_t* DataOut, uint32_t* DataOutLen)
//{
//    int Ret = 0;
//    uint32_t    wrap_out_len = 0;
//    uint8_t        wrap_apdu_out[300];
//    uint32_t    unwrap_out_len = 0;
//    uint8_t        unwrap_apdu_out[300];
//
//    if (ApduIsSecureChannel > 0)
//    {
//        if ((DataIn[0] & 0xF0) == 0x80)
//        {
//            DataIn[0] |= 0x04;
//        }
//
//        if ((DataIn[0] & 0xFF) != 0x84)
//        {
//            return pSmartCardApduCallBack(DataIn, DataInLen, DataOut, DataOutLen);
//        }
//    }
//
//
//    if (ApduIsSecureChannel == 0)
//    {
//        return pSmartCardApduCallBack(DataIn, DataInLen, DataOut, DataOutLen);
//    }
//    else
//    {
//        Ret = lib_auth_wrap(DataIn, DataInLen, wrap_apdu_out, &wrap_out_len);
//        if (Ret != 0) return Ret;
//        Ret = pSmartCardApduCallBack(wrap_apdu_out, wrap_out_len, unwrap_apdu_out, &unwrap_out_len);
//        if (Ret != 0) return Ret;
//
//        if (unwrap_out_len != 2)
//        {
//            Ret = lib_auth_unwrap(unwrap_apdu_out, unwrap_out_len, DataOut, DataOutLen);
//        }
//        else
//        {
//            memcpy(DataOut, unwrap_apdu_out, unwrap_out_len);
//            DataOutLen[0] = unwrap_out_len;
//
//        }
//
//    }
//
//    return Ret;
//
//}
//
//
////-----------------------------------------------------------------------------------------------------------
//void wrapper_init(uint8_t *chaining)
//{
//    memcpy(chaining_value, chaining,    16);
//    memset(encryption_counter, 0,        16);
//}
//
//-----------------------------------------------------------------------------------------------------------
void buffer_increment(uint8_t* encryption_counter)
{
    for (int i = 15; i > 0; i--)
    {
        if (encryption_counter[i] != 0xff)
        {
            encryption_counter[i]++;
            break;

        }
        else
        {
            encryption_counter[i] = 0;
        }

    }
}

//-----------------------------------------------------------------------------------------------------------
void wrap(uint8_t* apdu_in, uint32_t in_len, uint8_t* apdu_out, uint32_t*out_len, uint8_t *key_enc, uint8_t* key_cmac, uint8_t* inout_chaining_value, uint8_t* inout_encryption_counter)
{
    uint8_t cla = apdu_in[0];
    uint8_t ins = apdu_in[1];
    uint8_t p1 = apdu_in[2];
    uint8_t p2 = apdu_in[3];
    uint8_t lc = apdu_in[4];
    uint8_t lcenc = 0;
    
    uint8_t aes_buf[300];
    uint8_t cmac_buf[300];
    
    int p = 0;
    int pw = 0;
    
    int le = -1;
    if (in_len > (uint32_t) (lc + 5)) le = apdu_in[in_len - 1];
    
    buffer_increment(inout_encryption_counter);
    
    int i;
    printf("\nEncryption Counter:\n");
    for (i = 0; i < 16; i++)
    {
        if (i > 0) printf(", ");
        printf("0x%02X", inout_encryption_counter[i]);
    }
    printf("\n");

    
    if (lc > 0)
    {
        uint8_t iv[16];
        
        memset(aes_buf, 0, 300);
        //pad
        int total = ((lc / 16) + 1) * 16;
        memcpy(aes_buf, apdu_in + 5, lc);
        aes_buf[lc] = 0x80;
        AES_128(key_enc, inout_encryption_counter, iv);
        AES_128_CBC_Encrypt(key_enc, aes_buf, aes_buf, total, iv);
        lcenc = (uint8_t)total;
    }
    else
        if (lc == 0) lcenc = lc;
    
    memset(cmac_buf, 0, 300);
    
    p = 0;
    memcpy(cmac_buf, inout_chaining_value, 16); p += 16;
    cmac_buf[p] = cla; p++;
    cmac_buf[p] = ins; p++;
    cmac_buf[p] = p1; p++;
    cmac_buf[p] = p2; p++;
    cmac_buf[p] = lcenc + 8; p++;
    if (lc > 0) 
    {
        memcpy(cmac_buf + p, aes_buf, lcenc);
        p += lcenc;
    }
    
    AES_CMAC(key_cmac, cmac_buf, p, inout_chaining_value);
    
    pw = 0;
    apdu_out[pw] = cla; pw++;
    apdu_out[pw] = ins; pw++;
    apdu_out[pw] = p1; pw++;
    apdu_out[pw] = p2; pw++;
    apdu_out[pw] = lcenc + 8; pw++;
    
    if (lcenc > 0) { memcpy(apdu_out + pw, aes_buf, lcenc);  pw += lcenc; }
    memcpy(apdu_out + pw, inout_chaining_value, 8);  pw += 8;
    if (le != -1)  apdu_out[pw++] = (uint8_t)le;
    
    out_len[0] = pw;
}


//-----------------------------------------------------------------------------------------------------------
// encryption counter most likely has to match the values sent to wrap()
int unwrap(uint8_t* apdu_in, uint32_t in_len, uint8_t* apdu_out, uint32_t* out_len, uint8_t* key_enc, uint8_t* key_rmac, uint8_t* chaining_value, uint8_t* encryption_counter)
{
    uint8_t aes_buf[300];
    uint8_t cmac_buf[300];
    uint8_t tmp_chaining_value[16];
    int p = 0;
    int pw = 0;
    uint8_t sw1 = apdu_in[in_len - 2];
    uint8_t sw2 = apdu_in[in_len - 1];
    int lcenc = 0;
    int lcmac = 0;

    if (in_len < 10) return -1; //not RMAC

    lcmac = in_len - 10;
    memset(cmac_buf, 0, 300);

    p = 0;
    memcpy(cmac_buf, chaining_value, 16); p += 16;
    if (lcmac > 0) { memcpy(cmac_buf + p, apdu_in, lcmac); p += lcmac; }
    cmac_buf[p] = sw1; p++;
    cmac_buf[p] = sw2; p++;

    AES_CMAC(key_rmac, cmac_buf, p, tmp_chaining_value);
    if (memcmp(tmp_chaining_value, apdu_in + lcmac, 8) != 0) return -3;

    out_len[0] = 0;

    if (in_len > 16 + 8 + 1)
    {
        uint8_t iv[16];
        uint8_t ecn_cnt[16];

        lcenc = in_len - 10;
        if ((lcenc % 16) > 0) return -2;

        
        memcpy(ecn_cnt, encryption_counter, 16);
        ecn_cnt[0] = 0x80;
        memset(aes_buf, 0x88, 300);
        memcpy(aes_buf, apdu_in, lcenc);
        AES_128(key_enc, ecn_cnt, iv);
        AES_128_CBC_Decrypt(key_enc, aes_buf, aes_buf, lcenc, iv);
        for (p = lcenc - 1; p > 0; p--)
        {
            if (aes_buf[p] == 0x00) continue;
            if (aes_buf[p] == 0x80) break;
            return -3;
        }
        memcpy(apdu_out, aes_buf, p); pw = p;
    }

    apdu_out[pw++] = sw1;
    apdu_out[pw++] = sw2;
    out_len[0] = pw;
    return 0;

}
//-----------------------------------------------------------------------------------------------------------
