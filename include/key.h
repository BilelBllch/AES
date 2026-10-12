#ifndef DEF_KEY
#define DEF_KEY
#include <stdint.h>

/*
FIPS page 14
"For the AES algorithm, the length of the Cipher Key, K, is 128, 192, or 256 bits. The key
length is represented by Nk = 4, 6, or 8, which reflects the number of 32-bit words (number of
columns) in the Cipher Key."

FIPS page 
For the AES algorithm, the number of rounds to be performed during the execution of the
algorithm is dependent on the key size. The number of rounds is represented by Nr, where Nr =
10 when Nk = 4, Nr = 12 when Nk = 6, and Nr = 14 when Nk = 8

On remarque que Nr = Nk+6
*/

#define Nk(len) ((len)/32)
#define Nb 4
#define Nr(len) (Nk(len) + 6)
#define W_SIZE(len) (Nb * (Nr(len) + 1))

typedef uint8_t word_t[4];

extern const uint8_t sbox[16][16];

void subbytesGeneric(uint8_t *tab, const uint8_t box[16][16], int len);
void keyExpansion(const uint8_t key[], uint32_t w[], uint8_t key_len);

#endif