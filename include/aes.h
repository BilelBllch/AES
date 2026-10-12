#ifndef DEF_AES
#define DEF_AES

#include <stdint.h>

#define BLOCK_SIZE 16

#define AES_128 128
#define AES_192 192
#define AES_256 256

/*
    On multiplie tout dans le corps fini GF(2^8)
    On a vu en TD et en TP des algorithmes de multiplications rapides
    On a que multiplier par 2 dans GF(2^8) revient a multiplier par X dans GF2[X]/(x^8+X^4+x^3+x+1)
    
    def multiplication_parX(pa):
        res = [0]*8
        if pa[7] == 0:
            res[0] = 0
            for i in range(7, 0, -1):
                res[i] = pa[i-1]
        else:
            res[7] = 0
            for i in range(7, 0, -1):
                res[i] = pa[i-1]
            res[0] += 1
            res[1] += 1
            res[3] += 1
            res[4] += 1
        return F2X(res)
        
    Clairement si le dernier bit par lequel on multiplie par X est 1,
    on a une permutation a gauche et une addition par x^4 + x^3 + x + 1
    car on a définit le corps fini comme le corps de rupture de x^8 + x^3 + x^3 + x + 1
    le polynome x^4 + x^3 + x + 1 correspond a 00011011 donc a 0x1B
*/
#define XTIME_IRRED_RETENUE 0x1B




typedef uint8_t state_t[BLOCK_SIZE];

extern const uint8_t sbox[16][16];
extern const uint8_t inv_sbox[16][16];
extern const uint8_t mixColMat[4][4];


void encryptBlock(const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE], const uint32_t w[], int nr);
void decryptBlock(const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE], const uint32_t w[], int nr);
void printState(state_t s);
void printHex(const char* label, const uint8_t* data, int length);

#endif