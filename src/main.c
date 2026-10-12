#include "aes.h"
#include "key.h"
#include "mode.h"
#include "io.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <getopt.h>
#include <err.h>
#include <stdbool.h>


const char *mode_str[3] = {"ECB", "CBC", "CFB"};

static void help()
{
    puts("Usage:\taes [options] [path]");
    puts("Crypt or decrypt a file using AES");
    puts("Options:");
    puts("\t-h, --help\t\t\t\t Display this help message");
    puts("\t-e [FILE], --encrypt [FILE]\t\t Encrypt the file given as input and following the key size and mode set");
    puts("\t-d [FILE], --decrypt [FILE]\t\t Decrypt the file given as input and following the key size and mode set");
    puts("\t-o [FILE], --output [FILE]\t\t Set the output file");
    puts("\t-b, --benchmark\t\t\t\t Launch a benchmarking test");

    puts("\t-k, --key=hexstring\t\t\t Set the key (the size must be 128 or 192 or 256) [default = 000102030405060708090a0b0c0d0e0f]");
    puts("\t-m, --mode=MODE\t\t\t\t Set the mode (ECB, CBC, CFB) [default = ECB]");
}

static void benchmark()
{

    puts("=== BENCHMARK (100 iterations) ===");
    puts("The benchmark will do every step of the typical usage of AES-128 ECB :\n\t1) encryption\n\t2)decryption");
    puts("It will do so 100 times.");
    const uint8_t defaultkey[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint32_t w[W_SIZE(AES_128)];
    keyExpansion(defaultkey, w, AES_128);
    int nr = Nr(AES_128);

    unsigned int plain_len;
    uint8_t *plain_data = readFile("alice.sage", &plain_len);
    
    unsigned int cipher_len;
    unsigned int restored_len;
    
    uint8_t *cipher_data = NULL;
    uint8_t *restored_data = NULL;

    
    clock_t start = clock();
    
    for(int i = 0; i < 100; i++) 
    {
        if (cipher_data) 
        {
            free(cipher_data);
        }
        if (restored_data) 
        {
            free(restored_data);
        }

        cipher_data = encryptEcb(plain_data, plain_len, w, nr, &cipher_len);
        restored_data = decryptEcb(cipher_data, cipher_len, &restored_len, w, nr);
    }
    
    clock_t end = clock();
    
    free(plain_data);
    free(cipher_data);
    free(restored_data);

    double cpu_time_used = (double) (end-start)/CLOCKS_PER_SEC;
    printf("Time to cipher and decipher 100 times: %f\nAverage time to crypt and decrypt: %f\n", cpu_time_used, cpu_time_used/100);
}


static int hexchar_to_int(char hex)
{
    // https://www.ascii-code.com/fr
    // En fait les caractères sont justes des abstractions numériques de l'ascii
    // 'a' = 97, ..., 'z' = 122
    // '0' = 48, ..., '9' = 57
    // on peut donc reconstruire les valeurs des chiffres hexadecimaux en faisant des translations par les bonnes valeurs
    if (hex >= '0' && hex <= '9') 
    {
        return hex - '0';
    }
    if (hex >= 'a' && hex <= 'f') 
    {
        return hex - 'a' + 10;
    }
    if (hex >= 'A' && hex <= 'F') 
    {
        return hex - 'A' + 10;
    }
    return -1; 
}

static int keyParse(const char hexstring[], int *key_size, uint8_t key[])
{
    unsigned int len = strlen(hexstring);
    if(len == 32)
    {
        *key_size = AES_128;
    }
    else if(len == 48)
    {
        *key_size = AES_192;
    }
    else if(len == 64)
    {
        *key_size = AES_256;
    }
    else
    {
        return -1;
    }
    // On lit 2 caractères par 2 caractères
    // on recupere d'abord le nombre "le plus à gauche" (high) puis "le plus à droite" (low)
    // on fait ensuite simplement la reconstruction du nombre
    for(unsigned int i = 0; i < len; i+=2)
    {
        int high = hexchar_to_int(hexstring[i]);
        int low  = hexchar_to_int(hexstring[i+1]);
        if(high == -1 || low == -1)
        {
            return -1;
        }
        // on decale high de 4 bits vers la gauche et on fait un OU avec low
        // exemple:
        // high = c = 12 = 1100
        // low = 3 = 0011
        // high << 4 = 1100 0000
        // (high <<< 4) | low = 1100 0000 | 0000 0011 = 1100 0011 = 0xc3 
        uint8_t v = (uint8_t) ((high << 4) | low);
        key[i/2] = v;
    }
    return 0;
}

static int encrypt(const uint8_t key[], int key_size, mode_t mode, const char input[], const char output[])
{
    unsigned int plain_len = 0;
    unsigned int cipher_len = 0;
    uint8_t *cipher_data = NULL;
    
    uint8_t *plain_data = readFile(input, &plain_len);
    if (plain_data == NULL) 
    {
        warnx("Could not read file '%s'.\n", input);
        return -1;
    }

    uint32_t w[60]; 
    keyExpansion(key, w, key_size);
    int nr = Nr(key_size);

    switch (mode) 
    {
        case ECB:
            cipher_data = encryptEcb(plain_data, plain_len, w, nr, &cipher_len);
            break;
        case CBC:
            cipher_data = encryptCbc(plain_data, plain_len, w, nr, &cipher_len);
            break;
        case CFB:
            cipher_data = encryptCfb(plain_data, plain_len, w, nr, &cipher_len);
            break;
        default:
            warnx("Unknown mode\n");
            free(plain_data);
            return -1;
    }

    if (cipher_data == NULL) 
    {
        warnx("Encryption failed\n");
        free(plain_data);
        return -1;
    }
    writeFile(output, cipher_data, cipher_len);
    
    printf("Encryption done: %u bytes written in '%s'.\n", cipher_len, output);

    free(plain_data);
    free(cipher_data);

    return 0;
}

static int decrypt(const uint8_t key[], int key_size, mode_t mode, const char input[], const char output[])
{
    unsigned int cipher_len = 0;
    unsigned int plain_len = 0;
    uint8_t *plain_data = NULL;
    
    uint8_t *cipher_data = readFile(input, &cipher_len);
    if (cipher_data == NULL) 
    {
        warnx("Error, could read '%s'\n", input);
        return -1;
    }
    uint32_t w[60]; 
    keyExpansion(key, w, key_size);
    int nr = Nr(key_size);
    switch (mode) 
    {
        case ECB:
            plain_data = decryptEcb(cipher_data, cipher_len, &plain_len, w, nr);
            break;
        case CBC:
            plain_data = decryptCbc(cipher_data, cipher_len, &plain_len, w, nr);
            break;
        case CFB:
            plain_data = decryptCfb(cipher_data, cipher_len, &plain_len, w, nr);
            break;
        default:
            warnx("Unknown mode\n");
            free(cipher_data);
            return -1;
    }

    if (plain_data == NULL) 
    {
        warnx("Decryption failed");
        free(cipher_data);
        return -1;
    }

    writeFile(output, plain_data, plain_len);
    
    printf("Decryption done : %u bytes in '%s'.\n", plain_len, output);

    free(cipher_data);
    free(plain_data);

    return 0;
}

int main(int argc, char *argv[])
{
    static const struct option long_opts[] = {
        {"help",      no_argument,       NULL, 'h'},
        {"encrypt",   required_argument, NULL, 'e'}, 
        {"decrypt",   required_argument, NULL, 'd'},
        {"output",    required_argument, NULL, 'o'},
        {"key",   required_argument, NULL, 'k'},
        {"mode",      required_argument, NULL, 'm'},
        {"benchmark", no_argument,       NULL, 'b'},
        {NULL, 0, NULL, 0} 
    };

    bool encrypting = false;
    bool decrypting = false;
    bool benchmarking = false;
    
    mode_t mode = ECB;

    char *key_hexstring = "000102030405060708090a0b0c0d0e0f"; // par defaut
    int key_size = 0;
    char input[1024] = "";
    char output[1024] = "";
    

    int opt;
    while((opt = getopt_long(argc, argv, "he:d:o:k:m:b", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'h':
            help();
            return EXIT_SUCCESS;
            break;
        case 'e':
            encrypting = true;
            strncpy(input, optarg, sizeof(input) - 1);
            input[sizeof(input) - 1] = '\0';
            break;  
        case 'd':
            decrypting = true;
            strncpy(input, optarg, sizeof(input) - 1);
            input[sizeof(input) - 1] = '\0';
            break;
        case 'o':
            strncpy(output, optarg, sizeof(output) - 1);
            output[sizeof(output) - 1] = '\0';
            break;
        case 'k':
            key_hexstring = optarg;
            break;
        case 'm':
            if(strncmp(optarg, "ECB", 4) == 0)
            {
                mode = ECB;
            }
            else if(strncmp(optarg, "CBC", 4) == 0)
            {
                mode = CBC;
            }
            else if(strncmp(optarg, "CFB", 4) == 0)
            {
                mode = CFB;
            }
            else
            {
                errx(EXIT_FAILURE, "Invalid mode, it must be ECB or CBC or CFB\n");
            }
            break;
        case 'b':
            benchmarking = true;
            break;
        default:
            errx(EXIT_FAILURE, "Invalid option\n");
        }
    }
    if ((encrypting && decrypting) || (encrypting && benchmarking) || (decrypting && benchmarking))
    {
        errx(EXIT_FAILURE, "Wrong combination of -b, -d and -e. \n");
    }
    else if(benchmarking)
    {
       benchmark();
    }
    
    if(encrypting)
    {
        if(strlen(input) <= 1)
        {
            errx(EXIT_FAILURE, "In encryption mode, an input file must be set\n");
        }
        uint8_t key[32];
        if(keyParse(key_hexstring, &key_size, key) != 0)
        {
            errx(EXIT_FAILURE, "Invalid key format\n");
        }
        printf("Encrypting file %s with mode %s with a %u bits key %s", input, mode_str[mode], key_size, key_hexstring);
        if(encrypt(key, key_size, mode, input, output) != 0)
        {
            errx(EXIT_FAILURE, "Encryption failed\n");
        }
    }
    else if(decrypting)
    {
        if(strlen(input) <= 1)
        {
            errx(EXIT_FAILURE, "In decryption mode, an input file must be set\n");
        }
        uint8_t key[32];
        if(keyParse(key_hexstring, &key_size, key) != 0)
        {
            errx(EXIT_FAILURE, "Invalid key format\n");
        }
        
        if(decrypt(key, key_size, mode, input, output) != 0)
        {
            errx(EXIT_FAILURE, "Decryption failed\n");
        }
    }
}
