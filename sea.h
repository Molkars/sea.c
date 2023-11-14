
#ifndef SEA_H
#define SEA_H

#include <sys/types.h>
#include <stdio.h>

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
sea_token *sea_parser_peek(const sea_parser *parser);
sea_token *sea_parser_prev(const sea_parser *parser);
sea_token *sea_parser_last(const sea_parser *parser);

typedef struct sea_error_t {
	char *message;
	sea_token *start;
    sea_token *end;
} sea_error_t;

void sea_error_print(sea_error_t *error);
void sea_error_free(sea_error_t *error);

#define VECTOR_TYPE sea_error_t *
#define VECTOR_NAME sea_error
#include "vec.h"

typedef struct sea_type_lit {
    sea_token *token;
} sea_type_lit;

sea_type_lit *sea_parse_type_lit(sea_parser *parser);
void sea_type_lit_free(sea_type_lit *item);

typedef enum sea_expr_type {
    SEA_EXPR_INT,
    SEA_EXPR_SYM,
    SEA_EXPR_CALL,

    SEA_EXPR_NOT,
    SEA_EXPR_NEGATE,

    SEA_EXPR_MUL,
    SEA_EXPR_DIV,
    SEA_EXPR_REM,

    SEA_EXPR_ADD,
    SEA_EXPR_SUB,
    
    SEA_EXPR_LT,
    SEA_EXPR_GT,
    SEA_EXPR_LE,
    SEA_EXPR_GE,

    SEA_EXPR_EQ,
    SEA_EXPR_NE,

    SEA_EXPR_ASSIGN,

    SEA_EXPR_ERROR,
} sea_expr_type;

typedef struct sea_expr {
    sea_expr_type type;
    void *item;
    sea_error_t *error;
} sea_expr;

sea_expr *sea_parse_expr(sea_parser *parser);
void sea_expr_free(sea_expr *expr);
int sea_expr_display(FILE *fd, const sea_expr *expr);
void sea_expr_collect_errors(const sea_expr *expr, vec_sea_error_t vec);

#define VECTOR_TYPE sea_expr *
#define VECTOR_NAME sea_expr
#define VECTOR_FREE sea_expr_free
#include "vec.h"

typedef struct sea_expr_bin {
    sea_expr *left;
    sea_expr *right;
} sea_expr_bin;

void sea_expr_bin_free(sea_expr_bin *expr);

typedef struct sea_expr_call {
	sea_token *name;
	vec_sea_expr_t args;
} sea_expr_call;

void sea_expr_call_free(sea_expr_call *expr);

/// AST:STMT

typedef enum sea_stmt_type {
    SEA_STMT_BLOCK,
    SEA_STMT_IF,
    SEA_STMT_FOR,
    SEA_STMT_WHILE,
    SEA_STMT_VAR,

    // Psuedo-Statements
    SEA_STMT_EXPR,

    SEA_STMT_ERROR,
} sea_stmt_type;

typedef struct sea_stmt {
    sea_stmt_type type;
    void *item;
    sea_error_t *error;
} sea_stmt;

sea_stmt *sea_parse_stmt(sea_parser *parser);
void sea_stmt_free(sea_stmt *stmt);
void sea_stmt_collect_errors(const sea_stmt *stmt, vec_sea_error_t vec);

#define VECTOR_TYPE sea_stmt *
#define VECTOR_NAME sea_stmt
#define VECTOR_FREE sea_stmt_free
#include "vec.h"

typedef struct sea_stmt_if {
    sea_expr *condition;
    sea_stmt *body;
    sea_stmt *else_branch;
} sea_stmt_if;

void sea_stmt_if_free(sea_stmt_if *stmt);

typedef struct sea_stmt_block {
    vec_sea_stmt_t inner;
} sea_stmt_block;

void sea_stmt_block_free(sea_stmt_block *stmt);

typedef struct sea_stmt_for {
    sea_stmt *initializer;
    sea_expr *condition;
    sea_expr *incrementer;
    sea_stmt *body;
} sea_stmt_for;

void sea_stmt_for_free(sea_stmt_for *stmt);

typedef struct sea_stmt_while {
    sea_expr *condition;
    sea_stmt *body;
} sea_stmt_while;

void sea_stmt_while_free(sea_stmt_while *stmt);

typedef struct sea_stmt_var {
    sea_type_lit *type;
    sea_token *name;
    sea_expr *value;
} sea_stmt_var;

void sea_stmt_var_free(sea_stmt_var *stmt);

/// AST:DECL

typedef struct sea_func_param {
    sea_type_lit *type;
    sea_token *name;
} sea_func_param;

void sea_func_param_free(sea_func_param param);

#define VECTOR_TYPE sea_func_param
#define VECTOR_NAME sea_func_param
#define VECTOR_FREE sea_func_param_free
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
	sea_error_t *error;
} sea_decl;

sea_decl *sea_parse_decl(sea_parser *parser);
void sea_decl_free(sea_decl *decl);

#define VECTOR_TYPE sea_decl *
#define VECTOR_NAME sea_decl
#define VECTOR_FREE sea_decl_free
#include "vec.h"

typedef struct sea_decl_extern {
    sea_type_lit *type;
    sea_token *name;
    vec_sea_func_param_t params;
} sea_decl_extern;

sea_decl *sea_parse_extern(sea_parser *parser);
void sea_decl_extern_free(sea_decl_extern *decl);

typedef struct sea_decl_function {
    sea_type_lit *type;
    sea_token *name;
    vec_sea_func_param_t params;
    sea_stmt *body;
} sea_decl_function;

sea_decl *sea_parse_function(sea_parser *parser);
void sea_decl_function_free(sea_decl_function *decl);

typedef struct sea_decl_global {
    sea_type_lit *type;
    sea_token *name;
    sea_expr *value;
} sea_decl_global;

sea_decl *sea_parse_global(sea_parser *parser);
void sea_decl_global_free(sea_decl_global *decl);

/// AST:PROGRAM

typedef struct sea_program {
    vec_sea_decl_t decls;
} sea_program;

sea_program *sea_parse_program(sea_parser *parser);

void sea_program_free(sea_program *program);

#endif // SEA_H

