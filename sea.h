
#ifndef SEA_H
#define SEA_H

#define Arg(x) do { \
    void *___arg = (void *) x; \
    if (___arg == NULL) { \
        printf("[%s %s:%ld] argument %s was null", __FUNCTION__, __FILE__, __LINE__, #x); \
        exit(1); \
    } \
while (0);

typedef struct sea_token {
    size_t line, column, length, index;
    const char *lex;
} sea_token;

#define VECTOR_TYPE sea_token
#define VECTOR_NAME sea_token
#include "vec.h"

/// TOKENZING

typedef struct sea_tokens {
    vec_sea_token_t inner;
    const char *source;
} sea_tokens;

sea_tokens sea_tokenize(const char *source);

/// AST:EXPR

typedef struct sea_type_lit {
    sea_token *token;
} sea_type_lit;

typedef enum sea_expr_type {
    SEA_EXPR_INT,
    SEA_EXPR_ADD,
    SEA_EXPR_SUB,
} sea_expr_type;

typedef struct sea_expr {
    sea_expr_type type;
    void *item;
} sea_expr;

typedef struct sea_bin_expr {
    sea_expr left;
    sea_expr right;
} sea_bin_expr;

/// AST:STMT

typedef enum sea_stmt_type {
    SEA_STMT_BLOCK,
    SEA_STMT_IF,
    SEA_STMT_FOR,
    SEA_STMT_WHILE,

    // Psuedo-Statements
    SEA_STMT_INVOKE,
    SEA_STMT_ASSIGN,
} sea_stmt_type;

typedef struct sea_stmt {
    sea_stmt_type type;
    void *item;
} sea_stmt;

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

typedef enum sea_decl_type {
    SEA_DECL_EXTERN,
    SEA_DECL_FUNC,
    SEA_DECL_GLOBAL,
} sea_decl_type;

typedef struct sea_decl {
    sea_decl_type type;
    void *item;
} sea_decl;

typedef struct sea_decl_extern {
    sea_decl_type type;
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

#endif // SEA_H

