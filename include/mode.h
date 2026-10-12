#ifndef DEF_MODE
#define DEF_MODE

#include <stdint.h>

typedef enum 
{
    ECB,
    CBC,
    CFB
} mode_t;

uint8_t*  encryptEcb(const uint8_t* plain, const unsigned int plain_len, const uint32_t w[], int nr, unsigned int *cipher_len);
uint8_t* decryptEcb(const uint8_t* cipher, const unsigned int cipher_len, unsigned int *plain_len, const uint32_t w[], int nr);

uint8_t* encryptCbc(const uint8_t* plain, const unsigned int plain_len, const uint32_t w[], int nr, unsigned int *cipher_len);
uint8_t *decryptCbc(const uint8_t* cipher, const unsigned int cipher_len, unsigned int *plain_len, const uint32_t w[], int nr);

uint8_t* encryptCfb(const uint8_t* plain, const unsigned int plain_len, const uint32_t w[], int nr, unsigned int *cipher_len);
uint8_t *decryptCfb(const uint8_t* cipher, const unsigned int cipher_len, unsigned int *plain_len, const uint32_t w[], int nr);

#endif