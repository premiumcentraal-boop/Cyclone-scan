#ifndef DT_SHA256_H
#define DT_SHA256_H
#include <stddef.h>
#include <stdint.h>
void dt_sha256(const unsigned char *data, size_t size, unsigned char out[32]);
#endif
