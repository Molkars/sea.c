
#include "sea.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

typedef struct {
    size_t index;
    size_t line, column;
    const char *source;
    size_t source_len;
} src_t;

int src_more(const src_t *source) {
    return source->index < source->source_len;
}

int src_matchc(const src_t *src, char token) {
    if (src_more(src)) {
        return src->source[src->index] == token;
    }
    return 0;
}

char src_adv(src_t *source) {
    if (!src_more(source)) return 0;
    char c = source->source[source->index];
    if (c == '\n') {
        source->index += 1;
        source->line += 1;
        source->column = 1;
    } else {
        source->index += 1;
        source->column += 1;
    }
    return c;
}

int src_takec(src_t *src, char token) {
    if (src_matchc(src, token)) {
        src_adv(src);
        return 1;
    }
    return 0;
}

char src_peek(const src_t *src) {
    if (!src_more(src)) return 0;
    return src->source[src->index];
}


void *sea_tokenize(const char *source, sea_tokens *out) {
    src_t src;
    src.index = 0;
    src.line = 1;
    src.column = 1;
    src.source = source;
    src.source_len = strlen(source);

    out->source = source;
    vec_sea_token_init(out->inner);

    sea_token token;
    size_t start;
    while (src_more(&src)) {
        start = src.index;

        char c = src_adv(&src);
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            continue;
        }

        if (c == '=' || c == '<' || c == '>' || c == '!') {
            src_takec(&src, '=');
        } else if (c == '(' || c == ')' || c == '{' || c == '}' || c == ';'
                || c == '+' || c == '-' || c == '*' || c == '%' || c == ';') 
        {
            // no-op
        } else if (c == '/') {
            if (src_takec(&src, '/')) {
                while (src_more(&src) && !src_matchc(&src, '\n')) {
                    src_adv(&src);
                }
            }
        } else if (isalpha((int) c)) {
            for (
                int d = (int) src_peek(&src);
                src_more(&src) && (isalpha(d) || isdigit(d));
                d = (int) src_peek(&src)
            ) {
               src_adv(&src); 
            }
        } else if (isdigit((int) c)) {
            while (src_more(&src) && isdigit((int) src_peek(&src))) {
                src_adv(&src);
            }
        } else {
            printf("sea_tokenize: got unknown char: '%c' %d at %lu:%lu\n",
                    c, (int) c, src.line, src.column);
            return NULL;
        }

        token.index = start;
        token.length = src.index - start;
        token.line = src.line;
        token.column = src.column - token.length;

        char *lex = calloc(token.length + 1, sizeof(char));
        strncpy(lex, source + token.index, token.length);
        lex[token.length] = '\0';
        token.lex = lex;

        vec_sea_token_append(out->inner, token);
    }

    return out;
}

int sea_token_is_word(const sea_token *token) {
    if (!token) return 0;

    size_t len = strlen(token->lex);
    if (len == 0) return 0;

    if (!isalpha((int) token->lex[0])) return 0;
    for (size_t i = 1; i < len; i++) {
        int d = (int) token->lex[i];
        if (!isalpha(d) && !isdigit(d)) return 0;
    }
    return 1;
}

int sea_token_is_int(const sea_token *token) {
    if (!token) return 0;

    size_t len = strlen(token->lex);
    for (size_t i = 0; i < len; i++) {
        int d = (int) token->lex[i];
        if (!isdigit(d)) return 0;
    }
    return 1;
}


/// PARSER

typedef struct sea_parser {
    sea_tokens *tokens;
    size_t index;
} sea_parser;

int sea_parser_more(const sea_parser *parser) {
    return parser->index < vec_sea_token_size(parser->tokens->inner);
}

sea_token *sea_parser_peek(const sea_parser *parser) {
    if (sea_parser_more(parser)) {
        return vec_sea_token_get(parser->tokens->inner, parser->index);
    } else {
        return NULL;
    }
}

sea_token *sea_parser_adv(sea_parser *parser) {
    sea_token *token = sea_parser_peek(parser);
    if (token == NULL) return NULL;
    parser->index += 1;
    return token;
}

int sea_parser_match(const sea_parser *parser, const char *tok) {
    sea_token *token = sea_parser_peek(parser);
    if (token == NULL) return 0;
    return strcmp(token->lex, tok) == 0;
}


int sea_parser_matchw(const sea_parser *parser) {
    sea_token *token = sea_parser_peek(parser);
    if (!token) return 0;
    return sea_token_is_word(token);
}

int sea_parser_matchi(const sea_parser *parser) {
    sea_token *token = sea_parser_peek(parser);
    return sea_token_is_int(token);
}

int sea_parser_expect(sea_parser *parser, const char *tok, const char *msg) {
    if (!sea_parser_more(parser)) {
        printf("%s\n", msg);
    }
    sea_token *token = sea_parser_adv(parser);
    if (strcmp(token->lex, tok) != 0) {
        printf("%s\n", msg);
        return 0;
    }
    return 1;
}

int sea_parse_type_lit(sea_parser *parser, sea_type_lit *out) {
    if (sea_parser_match(parser, "int") || sea_parser_match(parser, "void")) {
        out->token = sea_parser_adv(parser);
        return 1;
    }
    return 0;
}

int sea_parse_expr_primary(sea_parser *parser, sea_expr *out) {
    if (sea_parser_matchw(parser)) {
        out->type = SEA_EXPR_SYM;
        out->item = sea_parser_adv(parser);
        return 1;
    }

    if (sea_parser_matchi(parser)) {
        out->type = SEA_EXPR_INT;
        out->item = sea_parser_adv(parser);
        return 1;
    }

    if (sea_parser_match(parser, "(")) {
        sea_token *lparen = sea_parser_adv(parser);
        if (!sea_parse_expr(parser, out)) {
            printf("expected expression after '('\n  at %lu:%lu\n",
                    lparen->line, lparen->column);
            return 0;
        }
        if (!sea_parser_expect(parser, ")", "expected ')' after expression")) {
            return 0;
        }
        return 1;
    }

    return 0;
}

int sea_parse_expr(sea_parser *parser, sea_expr *out) {

    return 1;
}


