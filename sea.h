
#ifndef SEA_H
#define SEA_H

#include <sys/types.h>

#define Arg(x) do { \
    void *___arg = (void *) x; \
    if (___arg == NULL) { \
        printf("[%s %s:%ld] argument %s was null", \
                __FUNCTION__, __FILE__, __LINE__, #x); \
        exit(1); \
    } \
while (0);

typedef struct sea_token {
    size_t line, column, length, index;
    char *lex;
} sea_token;

void sea_token_free(sea_token *token);
sea_token *sea_token_clone(sea_token *token);

#define VECTOR_TYPE sea_token *
#define VECTOR_NAME sea_token
#define VECTOR_FREE sea_token_free
#include "vec.h"

/// TOKENZING

typedef struct sea_tokens {
    vec_sea_token_t inner;
    char *source;
} sea_tokens;

void sea_tokens_init(sea_tokens *tokens);
void sea_tokens_free(sea_tokens *tokens);

void *sea_tokenize(const char *source, sea_tokens *out);

int sea_token_is_word(const sea_token *token);
int sea_token_is_int(const sea_token *token);

/// AST:EXPR

typedef struct sea_parser {
    sea_tokens *tokens;
    size_t index;
} sea_parser;


int sea_parser_init(sea_parser *parser, sea_tokens *tokens);

int sea_parser_more(const sea_parser *parser);
size_t sea_parser_line(const sea_parser *parser);
size_t sea_parser_column(const sea_parser *parser);

typedef struct sea_error_t {
	char *message;
	sea_token *token;
	struct sea_error_t *parent;
} sea_error_t;

typedef struct sea_type_lit {
    sea_token *token;
} sea_type_lit;

int sea_parse_type_lit(sea_parser *parser, sea_type_lit *out);

typedef enum sea_expr_type {
    SEA_EXPR_INT,
    SEA_EXPR_SYM,
    SEA_EXPR_ADD,
    SEA_EXPR_SUB,
	SEA_EXPR_ERROR,
} sea_expr_type;

typedef struct sea_expr {
    sea_expr_type type;
    void *item;
} sea_expr;

int sea_parse_expr(sea_parser *parser, sea_expr *expr);

#define VECTOR_TYPE sea_expr 
#define VECTOR_NAME sea_expr
#include "vec.h"

typedef struct sea_bin_expr {
    sea_expr left;
    sea_expr right;
} sea_bin_expr;

typedef struct sea_call_expr {
	sea_token *name;
	vec_sea_expr_t args;
} sea_call_expr;

/// AST:STMT

typedef enum sea_stmt_type {
    SEA_STMT_BLOCK,
    SEA_STMT_IF,
    SEA_STMT_FOR,
    SEA_STMT_WHILE,

    // Psuedo-Statements
    SEA_STMT_CALL,
    SEA_STMT_ASSIGN,
} sea_stmt_type;

typedef struct sea_stmt {
    sea_stmt_type type;
    void *item;
} sea_stmt;

int sea_parse_stmt(sea_parser *parser, sea_stmt *out);

#define VECTOR_TYPE sea_stmt
#define VECTOR_NAME sea_stmt
#include "vec.h"

typedef struct sea_stmt_block {
    vec_sea_stmt_t inner;
} sea_stmt_block;

/// AST:DECL

typedef struct sea_func_param {
    sea_type_lit type;
    sea_token *name;
} sea_func_param;

#define VECTOR_TYPE sea_func_param
#define VECTOR_NAME sea_func_param
#include "vec.h"

int sea_parse_func_param(sea_parser *parser, sea_func_param *out);

typedef enum sea_decl_type {
    SEA_DECL_EXTERN,
    SEA_DECL_FUNC,
    SEA_DECL_GLOBAL,
	SEA_DECL_ERROR,
} sea_decl_type;

typedef struct sea_decl {
    sea_decl_type type;
    void *item;
} sea_decl;

int sea_parse_decl(sea_parser *parser, sea_decl *out);

typedef struct sea_decl_extern {
    sea_type_lit type;
    sea_token *name;
    vec_sea_func_param_t params;
} sea_decl_extern;

typedef struct sea_decl_function {
    sea_decl_type type;
    sea_token *name;
    vec_sea_func_param_t params;
    sea_stmt body;
} sea_decl_function;

#define VECTOR_TYPE sea_decl
#define VECTOR_NAME sea_decl
#include "vec.h"

/// AST:PROGRAM

typedef struct sea_program {
    vec_sea_decl_t decls;
} sea_program;

int sea_parse_program(sea_parser *parser, sea_program *out);

#endif // SEA_H

