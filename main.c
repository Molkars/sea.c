
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "sea.h"

void _usage(void) {
    printf("usage: seac [command] ...args\n");
    printf("command:\n");
    printf(" - tokenize <file-path>\n");
    printf(" - comiple <file-path>\n");
}

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

int main(int argc, char **argv) {
    if (argc < 2) {
        _usage();
        return 1;
    }

    sea_tokens tokens;

    char *command = argv[1];
    if (strcmp(command, "tokenize") == 0) {
        if (argc != 3) {
            printf("tokenize: expected <file-path>\n");
            _usage();
            return 1;
        }

        char *filepath = argv[2];
        printf("tokenize: tokenizing %s\n", filepath);

        const char *src = readFile(filepath);
        if (!src) {
            printf("tokenize: unable to read file: %s\n", filepath);
            return 1;
        }

        printf("== source ==\n");
        printf("%s\n", src);

        if (!sea_tokenize(src, &tokens)) {
            printf("tokenize: unable to tokenize file\n");
            return 1;
        }

        printf("#tokens: %ld\n", vec_sea_token_size(tokens.inner));
        for (size_t i = 0; i < vec_sea_token_size(tokens.inner); i++) {
            sea_token *token = vec_sea_token_get(tokens.inner, i);
            printf("#%ld | %2ld:%2ld (%0.3ld %0.3ld) %s\n", i, 
                    token->line, token->column, token->index, token->length,
                    token->lex);
        }
    } else if (strcmp(command, "compile") == 0) {
        if (argc != 3) {
            printf("compile: expected <file-path>\n");
            _usage();
            return 1;
        }

        char *filepath = argv[2];
        printf("compile: compiling %s\n", filepath);
    } else {
        printf("unknown command: %s\n", command);
        _usage();
        return 1;
    }

    return 0;
}
