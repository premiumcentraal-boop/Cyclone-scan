#ifndef DT_IO_H
#define DT_IO_H
#include <stddef.h>
int dt_read(const char *, char *, size_t, size_t *);
int dt_exists(const char *);
#endif
