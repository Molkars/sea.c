
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

int sea_parser_expect(sea_parser *parser, const char *tok, const char *msg) {
    if (!sea_parser_more(parser)) {
        printf("%s\n", msg);
		return 0;
    }
    sea_token *token = sea_parser_adv(parser);
    if (strcmp(token->lex, tok) != 0) {
        printf("%s\n", msg);
        return 0;
    }
    return 1;
}

void sea_parser_recover(sea_parser *parser) {
	while (sea_parser_more(parser) && !sea_parser_match(parser, ";")) {
		sea_parser_adv(parser);
	}
	if (sea_parser_match(parser, ";")) {
		sea_parser_adv(parser);
	}
}

#define SEA_ERROR(expr, msg, tok) do {\
	(expr) = malloc(sizeof(sea_error_t)); \
	((sea_error_t *) expr)->message = msg; \
	((sea_error_t *) expr)->token = tok; \
	sea_parser_recover(parser); \
} while (0);

int sea_parse_type_lit(sea_parser *parser, sea_type_lit *out) {
	if (sea_parser_match(parser, "int") || sea_parser_match(parser, "void")) {
		out->token = sea_token_clone(sea_parser_adv(parser));
		return 1;
	} else {
		return 0;
	}
}

void sea_type_lit_free(sea_type_lit item) {
	sea_token_free(*item.token);
	free(item.token);
}

int sea_parse_func_param(sea_parser *parser, sea_func_param *out) {
	if (!sea_parse_type_lit(parser, &out->type)) {
		return 0;
	}

	if (sea_parser_matchw(parser)) {
		out->name = sea_token_clone(sea_parser_adv(parser));
	} else {
		out->name = NULL;
	}

	return 1;
}

sea_error_t *sea_parser_make_error(const char *msg, sea_token *token, sea_error_t *parent) {
	sea_error_t *out = malloc(sizeof(sea_error_t));
	
	size_t len = strlen(msg);
	out->message = calloc(len + 1, sizeof(char));
	strncpy(out->message, msg, len);
	out->message[len] = '\0';

	out->token = token;
	out->parent = parent;
	return out;
}

void sea_error_print(sea_error_t *error) {
	while (error) {
		size_t line, col;
		if (error->token) {
			line = error->token->line;
			col = error->token->column;
		} else {
			line = 1;
			col = 0;
		}
		printf(
				"> %s\n" 
			   	">  at %lu:%lu\n", 
				error->message, line, col);
		error = error->parent;
	}
}


int sea_parse_primary(sea_parser *parser, sea_expr *expr) {
	if (!sea_parser_more(parser)) return 0;

	sea_token *token = sea_parser_adv(parser);

	if (sea_token_is_int(token)) {
		expr->type = SEA_EXPR_INT;
		expr->item = sea_token_clone(token);
		return 1;
	}

	if (sea_token_is_word(token)) {
		if (!sea_token_match(parser, "(")) {
			expr->type = SEA_EXPR_SYM;
			expr->item = sea_token_clone(token);
			return 1;
		}
		sea_parser_adv(parser);

		sea_call_expr *call = malloc(sizeof(sea_call_expr));
		call->name = sea_token_clone(token);
		vec_sea_expr_init(call->args);
		sea_expr arg;
		while (sea_parser_more(parser) && !sea_parser_match(parser, ")")) {
			if (!sea_parse_expr(parser, &arg)) {
				if (arg.type == SEA_EXPR_ERROR && !sea_parser_match(parser, ",")) {
					expr->type = SEA_EXPR_ERROR;

				}
			}

			vec_sea_expr_append(call->args, arg);
			if (!sea_parser_match(parser, ",")) {
				break;
			} else {
				sea_parser_adv(parser);
			}
		}

		expr->type = SEA_EXPR_CALL;
		expr->item = call;
	}

	if (streq("(", token->lex)) {
		if (!sea_parse_expr(parser, expr)) {
			expr->type = SEA_EXPR_ERROR;
			expr->item = sea_parser_make_error(
					"Expected expression after group token: '('",
					sea_token_clone(token),
					expr->type == SEA_EXPR_ERROR ? (sea_error_t *) expr->item : NULL);
			return 0;
		}

		if (!sea_parser_match(parser, ")")) {
			expr->type = SEA_EXPR_ERROR;
			expr->item = sea_parser_make_error(
					"Expected ')' after grouped expression",
					sea_token_clone(sea_parser_previous(parser)),
					NULL);
			return 0;
		}

		return 1;
	}

	return 0;
}

int sea_parse_expr(sea_parser *parser, sea_expr *expr) {
	return sea_parse_primary(parser, expr);
}

// DECL

int sea_parse_decl(sea_parser *parser, sea_decl *out) {
	if (sea_parser_match(parser, "extern")) {
		sea_parser_adv(parser);
		sea_decl_extern item;

		if (!sea_parse_type_lit(parser, &item.type)) {
			SEA_ERROR(out->item, "expected return type after 'extern' keyword", sea_parser_adv(parser));
			out->type = SEA_DECL_ERROR;
			return 0;
		}

		if (!sea_parser_matchw(parser)) {
			SEA_ERROR(out->item, "expected extern function name", sea_parser_adv(parser));
			out->type = SEA_DECL_ERROR;
			return 0;
		}
		item.name = sea_parser_adv(parser);

		if (!sea_parser_match(parser, "(")) {
			SEA_ERROR(out->item, "expected '(' after extern function name", sea_parser_adv(parser));
			out->type = SEA_DECL_ERROR;
			return 0;
		}
		sea_parser_adv(parser);

		vec_sea_func_param_init(item.params);
		sea_func_param param;
		while (sea_parser_more(parser) && !sea_parser_match(parser, ")")) {
			if (!sea_parse_func_param(parser, &param)) {
				SEA_ERROR(out->item, "expected function param", sea_parser_adv(parser));
				out->type = SEA_DECL_ERROR;
				return 0;
			}
			vec_sea_func_param_append(item.params, param);

			if (sea_parser_match(parser, ",")) {
				sea_parser_adv(parser);
			} else {
				break;
			}
		}

		out->type = SEA_DECL_EXTERN;
		out->item = malloc(sizeof(sea_decl_extern));
		memcpy(out->item, &item, sizeof(sea_decl_extern));
		return 1;
	}

	return 0;
}

void sea_decl_free(sea_decl decl) {

	if (decl.type == SEA_DECL_EXTERN) {
		sea_decl_extern *item = (sea_decl_extern *) decl.item;
		if (item) {
			sea_type_lit_free(item->type);
			sea_token_free(*item->name);
			free(item->name);
			vec_sea_func_param_free(item->params);
			free(item);
		}
	} else {
		printf("free: unimpl %s\n", __FUNCTION__);
	}
}

void sea_stmt_free(sea_stmt stmt) {
	// todo
}

void sea_expr_free(sea_expr expr) {
	// todo
}

#undef SEA_ERROR
#undef SEA_EXPECT
