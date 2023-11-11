
#ifndef SEA_IO_H
#define SEA_IO_H

#include <stdio.h>

char *readFile(const char *file);

#define streq(a, b) (strcmp(a, b) == 0)

int simple_repl(FILE *stream, size_t cap, int callback(char *, void*), void *args);

int strsw(const char *str, const char *prefix);


#endif // SEA_IO_H
