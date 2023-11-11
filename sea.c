
#include "sea.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "util.h"

void sea_token_free(sea_token token) {
	free(token.lex);
}

void sea_token_free_ptr(sea_token *token) {
	if (!token) return;
	sea_token_free(*token);
	free(token);
}

sea_token *sea_token_clone(sea_token *token) {
	sea_token *out = malloc(sizeof(sea_token));
	memcpy(out, token, sizeof(sea_token));
	return out;
}

typedef struct {
    size_t index;
    size_t line, column;
    char *source;
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

void sea_tokens_init(sea_tokens *tokens) {
	if (tokens == NULL) return;
	tokens->source = NULL;
	vec_sea_token_init(tokens->inner);
}

void sea_tokens_free(sea_tokens *tokens) {
	if (!tokens) return;
	free(tokens->source);
	vec_sea_token_free(tokens->inner);
}

void *sea_tokenize(const char *source, sea_tokens *out) {
    src_t src;
    src.index = 0;
    src.line = 1;
    src.column = 1;
    src.source = calloc(strlen(source) + 1, sizeof(char));
	strcpy(src.source, source);
    src.source_len = strlen(source);

    out->source = src.source; 

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
                || c == '+' || c == '-' || c == '*' || c == '%' || c == ';'
				|| c == ',') 
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

		sea_token *tok = malloc(sizeof(sea_token));
		memcpy(tok, &token, sizeof(sea_token));
        vec_sea_token_append(out->inner, tok);
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

int sea_parser_init(sea_parser *parser, sea_tokens *tokens) {
	if (!parser || !tokens) return 0;
	parser->tokens = tokens;
	parser->index = 0;
	return 1;
}

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

sea_token *sea_parser_last(const sea_parser *parser) {
	size_t len = vec_sea_token_size(parser->tokens->inner);
	if (len > 0) {
		return vec_sea_token_get(parser->tokens->inner, len - 1);
	} else {
		return NULL;
	}
}

sea_token *sea_parser_previous(const sea_parser *parser) {
	if (parser->index <= 0 || parser->index > vec_sea_token_size(parser->tokens->inner)) {
		return NULL;
	}
	return vec_sea_token_get(parser->tokens->inner, parser->index - 1);
}

size_t sea_parser_line(const sea_parser *parser) {
	sea_token *tok;

	tok = sea_parser_peek(parser);
	if (!tok) {
		tok = sea_parser_last(parser);
	}

	size_t out;
	if (!tok) {
		out = 0;
	} else {
		out = tok->line;
	}
	return out;
}

size_t sea_parser_column(const sea_parser *parser) {
	sea_token *tok = sea_parser_peek(parser);
	if (!tok) {
		size_t len = vec_sea_token_size(parser->tokens->inner);
		if (len == 0) return 0;
		tok = vec_sea_token_get(parser->tokens->inner, len - 1);
	}
	return tok->column;
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

sea_error_t *sea_make_error(const char *msg, sea_token *token) {
    sea_error_t *out = malloc(sizeof(sea_error_t));
    out->message = calloc(strlen(msg) + 1, sizeof(char));
    strcpy(out->message, msg);
    out->token = token;
    return out;
}

sea_expr *sea_parse_primary(sea_parser *parser) {
    sea_token *token = sea_parser_adv(parser);
    if (!token) return NULL;

    sea_expr *out = malloc(sizeof(sea_expr));

    if (sea_token_is_int(token)) {
        out->type = SEA_EXPR_INT;
        out->item = sea_token_clone(token);
        out->error = NULL;
    } else if (sea_token_is_word(token)) {
        if (!sea_parser_match(parser, "(")) {
            out->type = SEA_EXPR_SYM;
            out->item = sea_token_clone(token);
            out->error = NULL;
        } else {
            sea_call_expr *call = malloc(sizeof(sea_call_expr));
            call->name = sea_token_clone(token);

            sea_parser_adv(parser); // (
            vec_sea_expr_ptr_init(call->args);

            sea_expr *arg;
            while (sea_parser_more(parser) && !sea_parser_match(parser, ")")) {
                arg = sea_parse_expr(parser);
                vec_sea_expr_ptr_append(call->args, arg);

                if (!sea_parser_match(parser, ",")) {
                    break;
                } else {
                    sea_parser_adv(parser);
                }
            }

            out->type = SEA_EXPR_CALL;
            out->item = call;
            if (!sea_parser_match(parser, ")")) {
                out->error = sea_make_error(
                        "Expected ')' after call arguments",
                        sea_parser_adv(parser));
            } else {
                sea_parser_adv(parser);
                out->error = NULL;
            }
        }
    } else {
        free(out);
        out = NULL;
    }

    return out;
}

sea_expr *sea_parse_unary(sea_parser *parser) {
    sea_expr *out = NULL;

    if (sea_parser_match(parser, "-") || sea_parser_match(parser, "!")) {
        sea_token *token = sea_parser_adv(parser);
        sea_expr *inner = sea_parse_primary(parser);

        if (inner) {
            out = malloc(sizeof(sea_expr));
            if (streq(token->lex, "!")) {
                out->type = SEA_EXPR_NOT;
            } else {
                out->type = SEA_EXPR_NEGATE;
            }
            out->item = inner;
            out->error = NULL;
        }
    } else {
        out = sea_parse_primary(parser);
    }

    return out;
}

sea_expr *sea_parse_term(sea_parser *parser) {
    sea_expr *out = sea_parse_unary(parser);
    if (!out) return NULL;

    sea_bin_expr *expr;
    sea_expr *right;
    while (sea_parser_match(parser, "*") || sea_parser_match(parser, "/")
            || sea_parser_match(parser, "%"))
    {
        sea_token *token = sea_parser_adv(parser);
        right = sea_parse_unary(parser);


        expr = malloc(sizeof(sea_bin_expr));
        expr->left = out;
        expr->right = right;

        out = malloc(sizeof(sea_expr));
        out->item = expr;
        if (streq(token->lex, "*")) {
            out->type = SEA_EXPR_MUL;
        } else if (streq(token->lex, "/")) {
            out->type = SEA_EXPR_DIV;
        } else {
            out->type = SEA_EXPR_REM;
        }
        if (!right) {
            out->error = sea_make_error(
                    "Expected expression after term operator",
                    sea_parser_adv(parser));
        } else {
            out->error = NULL;
        }
    }

    return out;
}

sea_expr *sea_parse_additive(sea_parser *parser) {
    sea_expr *out = sea_parse_term(parser);
    if (!out) return NULL;

    sea_bin_expr *expr;
    sea_expr *right;
    while (sea_parser_match(parser, "+") || sea_parser_match(parser, "-")) {
        sea_token *token = sea_parser_adv(parser);
        right = sea_parse_term(parser);

        expr = malloc(sizeof(sea_bin_expr));
        expr->left = out;
        expr->right = right;

        out = malloc(sizeof(sea_expr));
        out->item = expr;
        if (streq(token->lex, "+")) {
            out->type = SEA_EXPR_ADD;
        } else {
            out->type = SEA_EXPR_SUB;
        }
        if (!right) {
            out->error = sea_make_error(
                    "expected expression after additive operator",
                    sea_parser_adv(parser));
        } else {
            out->error = NULL;
        }
    }

    return out;
}

sea_expr *sea_parse_ordinal(sea_parser *parser) {
    sea_expr *out = sea_parse_additive(parser);
    if (!out) return NULL;

    sea_bin_expr *expr;
    sea_expr *right;
    while (sea_parser_match(parser, "<=") || sea_parser_match(parser, ">=")
            || sea_parser_match(parser, "<") || sea_parser_match(parser, ">")) {
        sea_token *token = sea_parser_adv(parser);
        right = sea_parse_additive(parser);

        expr = malloc(sizeof(sea_bin_expr));
        expr->left = out;
        expr->right = right;

        out = malloc(sizeof(sea_expr));
        out->item = expr;
        if (streq(token->lex, "<")) {
            out->type = SEA_EXPR_LT;
        } else if (streq(token->lex, ">")) {
            out->type = SEA_EXPR_GT;
        } else if (streq(token->lex, "<=")) {
            out->type = SEA_EXPR_LE;
        } else {
            out->type = SEA_EXPR_GE;
        }
        if (!right) {
            out->error = sea_make_error(
                    "expected expression after ordinal operator",
                    sea_parser_adv(parser));
        } else {
            out->error = NULL;
        }
    }

    return out;
}

sea_expr *sea_parse_equality(sea_parser *parser) {
    sea_expr *out = sea_parse_ordinal(parser);
    if (!out) return NULL;

    sea_bin_expr *expr;
    sea_expr *right;
    while (sea_parser_match(parser, "==") || sea_parser_match(parser, "!=")) {
        sea_token *token = sea_parser_adv(parser);
        right = sea_parse_ordinal(parser);

        expr = malloc(sizeof(sea_bin_expr));
        expr->left = out;
        expr->right = right;

        out = malloc(sizeof(sea_expr));
        out->item = expr;
        if (streq(token->lex, "==")) {
            out->type = SEA_EXPR_EQ;
        } else {
            out->type = SEA_EXPR_NE;
        }
        if (!right) {
            out->error = sea_make_error(
                    "expected expression after equality operator",
                    sea_parser_adv(parser));
        } else {
            out->error = NULL;
        }
    }

    return out;
}

sea_expr *sea_parse_expr(sea_parser* parser) {
    sea_expr *out = sea_parse_equality(parser);
    if (!out) return NULL;

    if (sea_parser_match(parser, "=")) {
        sea_parser_adv(parser);
        sea_bin_expr *bin = malloc(sizeof(sea_bin_expr));
        bin->left = out;
        bin->right = sea_parse_expr(parser);

        out = malloc(sizeof(sea_expr));
        out->type = SEA_EXPR_ASSIGN;
        out->item = bin;
        if (!bin->right) {
            out->error = sea_make_error(
                    "Expected expression after assignment operator",
                    sea_parser_adv(parser));
        }
    }

    return out;
}

int sea_expr_display(FILE *fd, const sea_expr *expr) {
    if (!expr) return 0;

    int ct = 0;
    if (expr->type == SEA_EXPR_INT) {
        sea_token *tok = (sea_token *) expr->item;
        ct += fprintf(fd, "%s", tok->lex);
    } else if (expr->type == SEA_EXPR_SYM) {
        sea_token *tok = (sea_token *) expr->item;
        ct += fprintf(fd, "%s", tok->lex);
    } else if (expr->type == SEA_EXPR_CALL) {
        sea_call_expr *inner = (sea_call_expr *) expr->item;
        ct += fprintf(fd, "%s(", inner->name->lex);
        for (size_t i = 0; i < vec_sea_expr_ptr_size(inner->args); i++) {
            if (i > 0) {
                ct += fprintf(fd, ", ");
            }
            ct += sea_expr_display(fd, vec_sea_expr_ptr_get(inner->args, i));
        }
        ct += fprintf(fd, ")");
    } else if (expr->type == SEA_EXPR_NEGATE) {
        sea_expr *inner = (sea_expr *) expr->item;
        ct += fprintf(fd, "-");
        ct += sea_expr_display(fd, inner);
    } else if (expr->type == SEA_EXPR_NOT) {
        sea_expr *inner = (sea_expr *) expr->item;
        ct += fprintf(fd, "!");
        ct += sea_expr_display(fd, inner);
    } else if (expr->type == SEA_EXPR_MUL) {
        sea_bin_expr *inner = (sea_bin_expr *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " * ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_DIV) {
        sea_bin_expr *inner = (sea_bin_expr *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " / ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_REM) {
        sea_bin_expr *inner = (sea_bin_expr *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " %% ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_ADD) {
        sea_bin_expr *inner = (sea_bin_expr *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " + ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_SUB) {
        sea_bin_expr *inner = (sea_bin_expr *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " - ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_LT) {
        sea_bin_expr *inner = (sea_bin_expr *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " < ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_GT) {
        sea_bin_expr *inner = (sea_bin_expr *) expr->item;
        ct += sea_expr_display(fd, inner->left);;
        ct += fprintf(fd, " > ");;
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_LE) {
        sea_bin_expr *inner = (sea_bin_expr *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " <= ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_GE) {
        sea_bin_expr *inner = (sea_bin_expr *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " >= ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_EQ) {
        sea_bin_expr *inner = (sea_bin_expr *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " == ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_NE) {
        sea_bin_expr *inner = (sea_bin_expr *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " != ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_ASSIGN) {
        sea_bin_expr *inner = (sea_bin_expr *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " = ");
        ct += sea_expr_display(fd, inner->right);
    } else {
        fprintf(stderr, "invalid expression type: %d\n", expr->type);
        ct = 0;
    }

    return ct;
}

#undef SEA_ERROR
#undef SEA_EXPECT
