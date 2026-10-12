#include "mode.h"

#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>

/*
    J'ai pas souvenir qu'on ait vu un padding particulier
    En lisant de la documentation, des pages wikipedia et 
    en discutant avec des camarades,
    j'ai décidé d'implémenté la méthode pkcs#7
    https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
    https://datatracker.ietf.org/doc/html/rfc5652#section-6.3

    The value of each added byte is the number of bytes that are added, i.e. N bytes, each of value N are added. 
    The number of bytes added will depend on the block boundary to which the message needs to be extended.
    The padding will be one of:
    01
    02 02
    03 03 03
    04 04 04 04
    05 05 05 05 05
    06 06 06 06 06 06

    uint8_t test1[32] = "bilel"; //5 lettre = 5 octets
    for(int i = 0; i < 5; i++)
    {
        printf("%02X ", test1[i]);
    }
    puts("");
    int padded_len1;
    uint8_t *test1_padded = paddingPkcs7(test1, 5, &padded_len1);
    
    printf("%u\n", padded_len1);
    for(int i = 0; i < padded_len1; i++)
    {
        printf("%02X ", test1_padded[i]);
    }
    printf("\n");
    free(test1_padded);
*/

static  uint8_t* paddingPkcs7(const uint8_t* topad, const unsigned int current_size, unsigned int *padded_len)
{
    uint8_t padded_val = BLOCK_SIZE - (current_size%BLOCK_SIZE);
    *padded_len = current_size + padded_val;
    uint8_t *padded_data = malloc(sizeof(uint8_t)*(*padded_len));
    if(padded_data == NULL)
    {
        return NULL;
    }
    memcpy(padded_data, topad, current_size);
    for(int i = 0; i < padded_val; i++)
    {
        padded_data[current_size+i] = padded_val;
    }
    return padded_data;
}


uint8_t* encryptEcb(const uint8_t* plain, const unsigned int plain_len, const uint32_t w[], int nr, unsigned int *cipher_len)
{
    uint8_t *padded_plain = paddingPkcs7(plain, plain_len, cipher_len);
    if(padded_plain == NULL)
    {
        warn("[ENCRYPT ECB] Fatal error: could'nt allocate memory for the padding \n");
        return NULL;
    }
    uint8_t *cipher = malloc(sizeof(uint8_t)*(*cipher_len));
    if(cipher == NULL)
    {
        free(padded_plain);
        warn("[ENCRYPT ECB] Fatal error: could'nt allocate memory for the cipher text\n");
        return NULL;
    }
    for(unsigned int i = 0; i < *cipher_len; i+=BLOCK_SIZE)
    {
        encryptBlock(padded_plain+i, cipher+i, w, nr);
    }
    free(padded_plain);
    return cipher;
}

uint8_t *decryptEcb(const uint8_t* cipher, const unsigned int cipher_len, unsigned int *plain_len, const uint32_t w[], int nr)
{
    uint8_t *padded_decipher= malloc(sizeof(uint8_t)*cipher_len);
    if(padded_decipher == NULL)
    {
        warn("[DECRYPT ECB]  Fatal error: could'nt allocate memory for the padded deciphered");
        return NULL;
    }
    for(unsigned int i = 0; i < cipher_len; i+=BLOCK_SIZE)
    {
        decryptBlock(cipher+i, padded_decipher+i, w, nr);
    }

    // Il faut maintenant retirer le padding
    // On sait que la longueur du padding est donné par la valeur v du dernier octet
    // Ce v occupe les derniers octets du texte clair initial
    // Mais il a été ensuite chiffré via AES
    // On a donc une constante v' = AES(v)
    // D'où v = AES^{-1}(v') = dernier octet du dechiffré
    uint8_t padded_val = padded_decipher[cipher_len-1];
    
    // Il faut verifier que le padding est correct
    // Pour cela, il faut verifier que les octets précédents valent bien padded_val
    for(int i = 1; i < padded_val; i++)
    {
        if(padded_decipher[cipher_len - i] != padded_val)
        {
            warn("[DECRYPT ECB] probleme de padding");
            return NULL;
        }
    }
    *plain_len = cipher_len - padded_val;
    padded_decipher= realloc(padded_decipher, *plain_len);
    return padded_decipher;
}

// On a discuté en cours d'OPS ou en crypto que les fonctions classiques rand() sont pas sûres
// J'ai donc cherché un peu https://en.wikipedia.org/wiki//dev/random
// "In Unix-like operating systems, /dev/random and /dev/urandom are special files that provide
// random numbers from a cryptographically secure pseudorandom number generator (CSPRNG)"
static int generateIV(uint8_t iv[BLOCK_SIZE])
{
    FILE* random_file = fopen("/dev/urandom", "rb");
    if(random_file == NULL)
    {
        warn("[GENERATE IV] could'not read /dev/urandom\n");
        return -1;
    }
    int read = fread(iv, 1, BLOCK_SIZE, random_file);
    if(read != BLOCK_SIZE)
    {
        warn("[GENERATE IV] could not read enough random data in /dev/urandom ?\n");
        return -1;
    }
    
    read = fclose(random_file);
    if(read != 0)
    {
        warn("[GENERATE IV] problem closing /dev/urandom\n");
        return -1;
    }
    return 0;
}

// On applique le padding puis on chiffre en chainant : la sortie d'un block chiffré devient mon entrée
// le premier block c'est l'IV xoré avec le premier block de message
uint8_t* encryptCbc(const uint8_t* plain, const unsigned int plain_len, const uint32_t w[], int nr, unsigned int *cipher_len)
{
    uint8_t iv[16] = {0};
    if(generateIV(iv) == -1)
    {
        return NULL;
    }
    unsigned int padded_len;
    uint8_t *padded_plain = paddingPkcs7(plain, plain_len, &padded_len);
    if(padded_plain == NULL)
    {
        warn("[ENCRYPT CBC] Fatal error: could'nt allocate memory for the padding \n");
        return NULL;
    }
    *cipher_len = padded_len + BLOCK_SIZE; // il faut aussi transmettre l'IV en plus
    uint8_t *cipher = malloc(sizeof(uint8_t)*(*cipher_len));
    if(cipher == NULL)
    {
        free(padded_plain);
        warn("[ENCRYPT CBC] Fatal error: could'nt allocate memory for the cipher text\n");
        return NULL;
    }
    memcpy(cipher, iv, BLOCK_SIZE);
    
    uint8_t *prev_block = cipher;
    for(unsigned int i = 0; i < padded_len; i+=BLOCK_SIZE)
    {
        uint8_t in[BLOCK_SIZE];
        for(int j = 0; j < BLOCK_SIZE; j++)
        {
            in[j] = prev_block[j]^padded_plain[i+j];
        }
        encryptBlock(in, cipher+BLOCK_SIZE+i, w, nr); // on decale pas seulement de i mais de i + BLOCK_SIZE pour avoir le decalage et conservé l'IV dans le chiffré 
        prev_block = cipher + BLOCK_SIZE +i;
    }
    free(padded_plain);
    return cipher;
}


uint8_t *decryptCbc(const uint8_t* cipher, const unsigned int cipher_len, unsigned int *plain_len, const uint32_t w[], int nr)
{
    unsigned int real_cipher_len = cipher_len - BLOCK_SIZE; // on retire la taille prise par l'iv

    uint8_t *padded_decipher= malloc(sizeof(uint8_t)*real_cipher_len);
    if(padded_decipher == NULL)
    {
        warn("[DECRYPT CBC]  Fatal error: could'nt allocate memory for the padded deciphered");
        return NULL;
    }

    
    const uint8_t *prev_block = cipher;
    // puréeeeeeeeeeeeeeeeeeeeee
    for(unsigned int i = BLOCK_SIZE; i < cipher_len; i+=BLOCK_SIZE)
    {
        uint8_t decrypted_block[BLOCK_SIZE];
        decryptBlock(cipher+i, decrypted_block, w, nr);
        for(int j = 0; j < BLOCK_SIZE; j++)
        {
            padded_decipher[i+j-BLOCK_SIZE] = decrypted_block[j] ^ prev_block[j];
        }
        prev_block = cipher+i;
    }

    uint8_t padded_val = padded_decipher[real_cipher_len-1];
    for(int i = 1; i <= padded_val; i++)
    {
        if(padded_decipher[real_cipher_len - i] != padded_val)
        {
            warn("[DECRYPT CBC] Padding not defined properly");
            return NULL;
        }
    }
    *plain_len = real_cipher_len - padded_val;
    padded_decipher= realloc(padded_decipher, *plain_len);
    return padded_decipher;
}

// On s'appuie enormément sur les diapo du cours
// on prend r = n 
uint8_t* encryptCfb(const uint8_t* plain, const unsigned int plain_len, const uint32_t w[], int nr, unsigned int *cipher_len)
{
    uint8_t iv[BLOCK_SIZE] = {0};
    if(generateIV(iv) == -1)
    {
        return NULL;
    }

    *cipher_len = plain_len + BLOCK_SIZE; //pour l'IV
    uint8_t *cipher = malloc(sizeof(uint8_t)*(*cipher_len));
    if(cipher == NULL)
    {
        warn("[ENCRYPT CFB]  Fatal error: could'nt allocate memory to encrypt\n");
        return NULL;
    }
    memcpy(cipher, iv, BLOCK_SIZE);
    uint8_t I[BLOCK_SIZE];
    memcpy(I, iv, BLOCK_SIZE);
    uint8_t O[BLOCK_SIZE];
    for(unsigned int i = 0; i < plain_len; i+=BLOCK_SIZE)
    {
        // O_j = E(I_j)
        encryptBlock(I, O, w, nr);

        // on verifie si on est "au milieu" du message a chiffré ou a la fin (si on est a la fin, currentBlockSize = plain_len-i)
        unsigned int currentBlockSize = (plain_len - i < BLOCK_SIZE) ? plain_len-i : BLOCK_SIZE;
        for(unsigned int j = 0; j < currentBlockSize; j++)
        {
            //c_j = m_j xor t_j (t_j = les r premiers blocs de Oj, mais on part du principe que r=n = 128)
            cipher[BLOCK_SIZE + i + j] = plain[i+j] ^ O[j];
        }
        if(currentBlockSize == BLOCK_SIZE)
        {
            memcpy(I, cipher+i+BLOCK_SIZE, BLOCK_SIZE);
        }
    }
    return cipher;
}


uint8_t *decryptCfb(const uint8_t* cipher, const unsigned int cipher_len, unsigned int *plain_len, const uint32_t w[], int nr)
{
    *plain_len = cipher_len - BLOCK_SIZE; // on retire l'iv
    uint8_t *plain = malloc(sizeof(uint8_t)*(*plain_len));
    if(plain == NULL)
    {
        warn("[DECRYPT CFB]  Fatal error: could'nt allocate memory to decipher\n");
        return NULL;
    }
    uint8_t I[BLOCK_SIZE];
    memcpy(I, cipher, BLOCK_SIZE);
    uint8_t O[BLOCK_SIZE];

    for(unsigned int i = 0; i < *plain_len; i+=BLOCK_SIZE)
    {
        encryptBlock(I, O, w, nr); // le dechiffrement en CFB reutilise la fonction de chiffrement
        unsigned int currentBlockSize = (*plain_len - i < BLOCK_SIZE) ? *plain_len-i : BLOCK_SIZE;
        for(unsigned int j = 0; j < currentBlockSize; j++)
        {
            plain[i + j] = cipher[BLOCK_SIZE+i+j] ^ O[j];
        }
        if(currentBlockSize == BLOCK_SIZE)
        {
            memcpy(I, cipher+BLOCK_SIZE + i, BLOCK_SIZE);
        }
    }

    return plain;
}