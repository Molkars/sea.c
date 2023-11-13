
#include "util.h"
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

char *readFile(const char *path) {
    FILE *f;
    f = fopen(path, "r");

    if (!f || fseek(f, 0, SEEK_END)) {
        return NULL;
    }

    ssize_t length = ftell(f);
    if (length == -1) return NULL;
    rewind(f);
    size_t len = (size_t) length;
    if (len >= SIZE_MAX) {
        return NULL;
    }

    char *buffer = calloc(len + 1, sizeof(char));
    if (buffer == NULL || fread(buffer, 1, len, f) != len) {
        free(buffer);
        return NULL;
    }

    buffer[len] = '\0';
    return buffer;
}

int simple_repl(FILE *stream, size_t cap, int callback(char *, void*), void *args) {
	if (stream == NULL) return 0xFF01;
	if (callback == NULL) return 0xFF02;
	if (cap == 0) return 0xFF03;

	char *buffer = calloc(cap, sizeof(char));
	char nl[] = "\n";

	size_t line_len = 0;
	size_t line_cap = cap;
	char *line = calloc(line_cap, sizeof(char));
    
    printf(" ::> ");
    fflush(stdout);
	while (fgets(buffer, cap, stdin) != NULL) {
		size_t i = strcspn(buffer, nl);

		char *end;
		if (line_len > 0) {
			end = line + line_len;
		} else {
			end = line;
		}

		line_len += i;
		if (line_len >= line_cap) {
			if (i < cap - 1) {
				line_cap = line_len += 1;
			} else {
				line_cap *= 2;
			}
			line = realloc(line, sizeof(char) * line_cap);
		}
		strncpy(end, buffer, i);


		if (i < cap - 1) {
			int result = callback(line, args);
			if (result != -1) {
                free(buffer);
				return result;
			}

			line_len = 0;
			line_cap = cap;
			line = calloc(line_cap, sizeof(char));
            printf(" ::> ");
            fflush(stdout);
		}
	}

	return 0xFF04;
#undef CAP
}

int strsw(const char *str, const char *prefix) {
	if (!str || !prefix) return 0;
	size_t slen = strlen(str);
	size_t plen = strlen(prefix);

	return plen <= slen && strncmp(str, prefix, plen) == 0;
}
