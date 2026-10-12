#include "io.h"
#include <stdio.h>
#include <stdlib.h>
#include <err.h>


uint8_t* readFile(const char* filename, unsigned int* out_size)
{
    FILE *file = fopen(filename, "rb");
    if (file == NULL) 
    {
        warnx("[PARSER] couldnot read %s\n", filename);
        return NULL;
    }
    // On déplace le curseur à la toute fin du fichier
    // On recupere la position du curseur
    // On remet le curseur au tout début
    // Comme ca on peut retrouver la taille du fichier selon les positions successives du curseur
    fseek(file, 0, SEEK_END);          
    long size = ftell(file);           
    rewind(file);                      

    *out_size = (unsigned int)size;

    uint8_t *buffer = (uint8_t*) malloc(*out_size);
    if (buffer == NULL) 
    {
        printf("[PARSER] : memory allocation.\n");
        fclose(file);
        return NULL;
    }

    if(fread(buffer, 1, *out_size, file) != *out_size)
    {
        warnx("[PARSER] : problem reading file %s\n", filename);
        fclose(file);
        return NULL;
    }
    fclose(file);

    return buffer; 
}

void writeFile(const char* filename, const uint8_t* data, unsigned int size) 
{
    FILE *file = fopen(filename, "wb");
    if (file == NULL)
    {
        warnx("[PARSER] : could not open %s\n", filename);
        return;
    }

    if(fwrite(data, 1, size, file) != size)
    {
        warnx("[PARSER] : problem writing file %s\n", filename);
    }
    fclose(file);
}