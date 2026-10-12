#ifndef DEF_PARSER
#define DEF_PARSER

#include <stdint.h>

uint8_t* readFile(const char* filename, unsigned int* out_size);

void writeFile(const char* filename, const uint8_t* data, unsigned int size);

#endif