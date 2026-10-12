#include "key.h"

#include <string.h>
// Logiquement, le nombre de tour de boucle sur le tableau rcon est Nb*(Nr(len)+1)
// Mais d'après:
// https://en.wikipedia.org/wiki/AES_key_schedule
// "AES uses up to rcon10 for AES-128 (as 11 round keys are needed), up to rcon8 for AES-192, and up to rcon7 for AES-256."
// On défini donc directemeent rcon de taille 11 et de modifier les bornes de parcours du tableau selon la taille de la clé
static const uint8_t rcon[11] = {
    0x00, // padding
    0x01, 0x02,0x04,0x08,0x10,0x20, 0x40, 0x80, 0x1b, 0x36 // les premieres valeurs sont juste un xtimes(0x01) répété i-1 fois
};

void subbytesGeneric(uint8_t *tab, const uint8_t box[16][16], int len)
{
    for(int i = 0; i < len; i++)
    {
        uint8_t ligne = tab[i] >> 4;
        uint8_t col = tab[i] & 0x0F;
        tab[i] = box[ligne][col];
    }
}

static void rotWord(word_t w)
{
    uint8_t tmp = w[0];
    w[0] = w[1];
    w[1] = w[2];
    w[2] = w[3];
    w[3] = tmp;
}

static void subWord(word_t w)
{
    subbytesGeneric(w, sbox, 4);
}

void keyExpansion(const uint8_t key[], uint32_t w[], uint8_t key_len)
{
    int nk = Nk(key_len);
    int nr = Nr(key_len);

    uint32_t temp;
    int i = 0;
    while(i < nk)
    {
        // supposons que key[4*i] = 0xAA, key[4*i+1] = 0xBB, key[4i+2] = 0xCC et key[4*i+3] = 0xDD
        // key[4*i] << 24 : on ajoute 24 bits nuls (donc trois octets nuls donc trois "00") a la suite de 0xAA on obtient donc 0xAA 00 00 00 
        // key[4*i+1] << 16 : on ajoute 16 bits nuls (donc deux octets nuls donc deux "00") a la suite [...]
        // key[4*i+1] << 8 : on ajoute 8 bits nuls donc un octet nuls [...]
        // on calcule ensuite : 0xAA 00 00 00 | 0x00 BB 00 00 | 0x00 00 CC 00 | 0x00 00 00 DD
        // Le | permet la fusion par octet, on obtient alors OxAA BB CC DD
        w[i] = ((uint32_t)key[4*i] << 24) | ((uint32_t)key[4*i+1] << 16) | ((uint32_t)key[4*i+2] << 8) | (uint32_t)key[4*i+3];
        i++;
    }
    // i = nk
    while(i < Nb*(nr+1))
    {
        //memcpy(temp, w[i-1], 4);
        temp = w[i-1];
        word_t temp_word = {(temp >> 24)&0xff, (temp >> 16)&0xff, (temp >> 8)&0xff, temp&0xff};
        if(i%nk == 0)
        {
            rotWord(temp_word);
            subWord(temp_word);
            
            temp_word[0] ^= rcon[i/nk];
        }
        else if (nk > 6 && i % nk == 4)
        {
            subWord(temp_word);
        }
        temp = ((uint32_t)temp_word[0] << 24) | ((uint32_t)temp_word[1] << 16) | ((uint32_t)temp_word[2] << 8) | (uint32_t)temp_word[3];
        w[i] = w[i-nk]^temp;
        i++;
    }
}

