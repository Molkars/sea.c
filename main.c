
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "sea.h"
#include "util.h"

#define defer_return(value) do { out = value; goto defer; } while (0);

void _usage(void) {
    printf("usage: seac [command] ...args\n");
    printf("command:\n");
    printf(" - tokenize <file-path>\n");
    printf(" - compile <file-path>\n");
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
	CMD(compile)
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


int compile(int argc, char **argv) {
	char *src = NULL;
	int out = 0;

	if (argc != 3) {
		printf("compile: expected <file-path>\n");
		_usage();
		defer_return(1);
	}

	char *filepath = argv[2];
	printf("compile: compiling %s\n", filepath);


defer:
	free(src);
	return out;
}

int testExpr(int argc, char **argv) {
	char *src = NULL;
	sea_tokens tokens;
	sea_tokens_init(&tokens);
	int out = 0;

	if (argc != 3) {
		printf("test-expr: expected <file-path>\n");
		_usage();
		defer_return(1);
	}

	char *filepath = argv[2];
	printf("test-expr: testing %s\n", filepath);

	src = readFile(filepath);
	if (!src) {
		printf("tokenize: unable to read file: %s\n", filepath);
		defer_return(1);
	}

	printf("== source ==\n");
	printf("%s\n", src);

	if (!sea_tokenize(src, &tokens)) {
		printf("test-expr: unable to tokenize file\n");
		defer_return(1);
	}

	sea_parser parser;
	sea_parser_init(&parser, &tokens);
	sea_expr expr;
	vec_sea_expr_t exprs;
	vec_sea_expr_init(exprs);

	while (sea_parser_more(&parser)) {
		if (!sea_parse_expr(&parser, &expr)) {
			size_t line, col;
			line = sea_parser_line(&parser);
			col = sea_parser_column(&parser);

			printf("test-expr: unable to parse expression at %lu:%lu\n", line, col);
		}
		vec_sea_expr_append(exprs, expr);
	}
	if (sea_parser_more(&parser)) {
		printf("test-expr: incomplete expressions in file!!");
	}
defer:
	free(src);
	sea_tokens_free(&tokens);
	return out;	
}

int repl_worker(char *line, void *args) {
	sea_tokens tokens;
	sea_tokens_init(&tokens);
	sea_decl decl;
	memset(&decl, 0, sizeof(sea_decl));
	sea_stmt stmt;
	memset(&stmt, 0, sizeof(sea_stmt));
	sea_expr expr;
	memset(&expr, 0, sizeof(sea_expr));
	int out = -1;

	printf("read line: %s\n", line);

	if (streq(line, "exit") || streq(line, "quit")) defer_return(0);

	if (!sea_tokenize(line, &tokens)) {
		printf("unable to tokenize: todo(errors)\n");
		defer_return(-1);
	}

	sea_parser parser;
	sea_parser_init(&parser, &tokens);
	if (!sea_parse_decl(&parser, &decl)) {
		if (decl.type == SEA_DECL_ERROR) {
			sea_error_print((sea_error_t *) decl.item);
			defer_return(-1);
		}
	} else {
		printf("got decl!\n");
		defer_return(-1);
	}

	sea_parser_init(&parser, &tokens);
	if (!sea_parse_expr(&parser, &expr)) {
		if (expr.type == SEA_EXPR_ERROR) {
			sea_error_print((sea_error_t *) expr.item);	
			defer_return(-1);
		}
	} else if (sea_parser_more(&parser)) {
		sea_token *tok = sea_parser_peek(&parser);
		printf("unable to parse entire expression\n"
				"  current token is: %s\n"
				"  at %lu:%lu\n",
				tok->lex, tok->line, tok->column);
	} else {
		printf("got expr!\n");
		defer_return(-1);
	}

defer:
	free(line);
	sea_decl_free(decl);
	sea_stmt_free(stmt);
	sea_expr_free(expr);
	return out;
}

int repl(int _argc, char **_argv) {
	return simple_repl(stdin, 1024, repl_worker, NULL);
}


