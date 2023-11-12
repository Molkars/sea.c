
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "sea.h"
#include "util.h"
#include <malloc.h>

#define defer_return(value) do { out = value; goto defer; } while (0);

void _usage(void) {
    printf("usage: seac [command] ...args\n");
    printf("command:\n");
    printf(" - tokenize <file-path>\n");
    printf(" - parse <file-path>\n");
	printf(" - repl\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        _usage();
        return 1;
    }

#define CMD2(name, msg) int name(int, char**); if (strcmp(command, msg) == 0) return name(argc, argv);
#define CMD(name) CMD2(name, #name)

	const char *command = argv[1];
	CMD(tokenize)
    CMD(repl);

#undef CMD2
#undef CMD

	printf("unknown command: %s\n", command);
	_usage();
	return 1;
}

int tokenize(int argc, char **argv) {
	char *src = NULL;
	sea_tokens tokens;
	sea_tokens_init(&tokens);
	int out = 0;

	if (argc != 3) {
		printf("tokenize: expected <file-path>\n");
		_usage();
		defer_return(1);
	}

	char *filepath = argv[2];
	printf("tokenize: tokenizing %s\n", filepath);

	src = readFile(filepath);
	if (!src) {
		printf("tokenize: unable to read file: %s\n", filepath);
		defer_return(1);
	}

	printf("== source ==\n");
	printf("%s\n", src);

	if (!sea_tokenize(src, &tokens)) {
		printf("tokenize: unable to tokenize file\n");
		defer_return(1);
	}

	printf("#tokens: %ld\n", vec_sea_token_size(tokens.inner));
	for (size_t i = 0; i < vec_sea_token_size(tokens.inner); i++) {
		sea_token *token = vec_sea_token_get(tokens.inner, i);
		printf("#%ld | %2ld:%2ld (%0.3ld %0.3ld) %s\n", i, 
				token->line, token->column, token->index, token->length,
				token->lex);
	}

defer:
	free(src);
	sea_tokens_free(&tokens);
	return out;
}

void display_error(const char *line, sea_error_t *error) {
    sea_token *start = error->start;
    sea_token *end = error->end;
    if (!start || !end) {
        printf("error has neither start or end tokens!\n");
        return;
    }
    printf(" |  %s\n", line);
    printf(" |  ");
    for (size_t i = 0; i < start->index; i++) {
        printf(" ");
    }
    for (size_t i = start->index; i < end->index + end->length; i++) {
        printf("^");
    }
    printf(" <-- at %lu:%lu - %lu:%lu\n",
            start->line, start->column,
            end->line, end->column);
    printf(" |  %s\n", error->message);
}

int repl_worker(char *line, void *arg) {
    (void) arg;
	sea_tokens tokens;
	sea_tokens_init(&tokens);
    sea_stmt *stmt = NULL;
    sea_expr *expr = NULL;
    int out = -1;

    if (streq(line, "exit")) {
        defer_return(0);
    }

	if (!sea_tokenize(line, &tokens)) {
		printf("tokenize: unable to tokenize file\n");
		defer_return(-1);
	}

    sea_parser parser;
    
    sea_parser_init(&parser, &tokens);
    stmt = sea_parse_stmt(&parser);

    if (stmt) {
        vec_sea_error_t errors;
        vec_sea_error_init(errors);
        sea_stmt_collect_errors(stmt, errors);
        if (vec_sea_error_size(errors) > 0) {
            printf("found errors in stmt!\n");
            for (size_t i = 0; i < vec_sea_error_size(errors); i++) {
                sea_error_t *error = vec_sea_error_get(errors, i);
                display_error(line, error);
            }
            defer_return(-1);
        }

        defer_return(-1);
    }

    sea_parser_init(&parser, &tokens);
    expr = sea_parse_expr(&parser);
    if (expr) {
        if (sea_parser_more(&parser)) {
            printf( "  unable to parse entire expression!\n"
                    "    current token: '%s'\n"
                    "    at %lu:%lu\n",
                    sea_parser_peek(&parser)->lex,
                    sea_parser_line(&parser), sea_parser_column(&parser));

            defer_return(-1);
        }

        printf("  ");
        sea_expr_display(stdout, expr);
        printf("\n");
        defer_return(-1);
    }

    printf("  unable to parse anything\n");
    defer_return(-1);

defer:
    free(line);
    sea_tokens_free(&tokens);
    sea_stmt_free(stmt);
    sea_expr_free(expr);
    return out;
}

int repl(int argc, char **argv) {
    (void) argc;
    (void) argv;

    struct mallinfo2 info1;
    info1 = mallinfo2();
    printf("hblkind = %lu\n", info1.hblkhd);
    printf("uordblks = %lu\n", info1.uordblks);

	int out = simple_repl(stdin, 1024, repl_worker, NULL);

    struct mallinfo2 info;
    info = mallinfo2();
    printf("hblkind = %lu\n", info.hblkhd);
    printf("  %lu\n", info.hblkhd - info1.hblkhd);
    printf("uordblks = %lu\n", info.uordblks);
    printf("  %lu\n", info.uordblks - info1.uordblks);

    return out;
}


