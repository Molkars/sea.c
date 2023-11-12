
#include "sea.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "util.h"

void sea_token_free(sea_token *token) {
	if (!token) return;
    free(token->lex);
	free(token);
}

sea_token *sea_token_clone(sea_token *token) {
	sea_token *out = malloc(sizeof(sea_token));
    out->line = token->line;
    out->column = token->column;
    out->length = token->length;
    out->index = token->index;
    out->lex = calloc(strlen(token->lex) + 1, sizeof(char));
    strcpy(out->lex, token->lex);
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
    // fancy for: parser.tokens[parser.index] -> Option[E]
    if (sea_parser_more(parser)) {
        return vec_sea_token_get(parser->tokens->inner, parser->index);
    } else {
		return NULL;
    }
}

sea_token *sea_parser_prev(const sea_parser *parser) {
    // fancy for: parser.tokens[parser.index - 1] -> Option[E]
    if (parser->index == 0 || parser->index > vec_sea_token_size(parser->tokens->inner)) {
        return NULL;
    } else {
        return vec_sea_token_get(parser->tokens->inner, parser->index - 1);
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


int sea_parser_match_word(const sea_parser *parser) {
    sea_token *token = sea_parser_peek(parser);
    if (!token) return 0;
    return sea_token_is_word(token);
}

int sea_parser_matchi(const sea_parser *parser) {
    sea_token *token = sea_parser_peek(parser);
    return sea_token_is_int(token);
}

sea_error_t *sea_make_error(const char *msg, sea_token *start, sea_token *end) {
    sea_error_t *out = malloc(sizeof(sea_error_t));
    out->message = calloc(strlen(msg) + 1, sizeof(char));
    strcpy(out->message, msg);
    out->start = sea_token_clone(start);
    out->end = sea_token_clone(end);
    return out;
}

void sea_error_free(sea_error_t *error) {
    if (!error) return;
    free(error->message);
    sea_token_free(error->start);
    sea_token_free(error->end);
    free(error);
}

sea_type_lit *sea_parse_type_lit(sea_parser *parser) {
    sea_type_lit *out = NULL;


    if (sea_parser_match(parser, "int") || sea_parser_match(parser, "void")) {
        out = malloc(sizeof(sea_type_lit));
        out->token = sea_token_clone(sea_parser_adv(parser));
    }

    return out;
}

void sea_type_lit_free(sea_type_lit *item) {
    if (item) {
        sea_token_free(item->token);
        free(item);
    }
}

sea_expr *sea_parse_primary(sea_parser *parser) {
    sea_token *token = sea_parser_peek(parser);
    if (!token) return NULL;

    sea_expr *out = malloc(sizeof(sea_expr));

    if (sea_token_is_int(token)) {
        sea_parser_adv(parser);
        out->type = SEA_EXPR_INT;
        out->item = sea_token_clone(token);
        out->error = NULL;
    } else if (sea_token_is_word(token)) {
        sea_parser_adv(parser);

        if (!sea_parser_match(parser, "(")) {
            out->type = SEA_EXPR_SYM;
            out->item = sea_token_clone(token);
            out->error = NULL;
        } else {
            sea_expr_call *call = malloc(sizeof(sea_expr_call));
            call->name = sea_token_clone(token);

            sea_parser_adv(parser); // (
            vec_sea_expr_init(call->args);

            sea_expr *arg;
            sea_token *start;
            while (sea_parser_more(parser) && !sea_parser_match(parser, ")")) {
                start = sea_parser_peek(parser);
                arg = sea_parse_expr(parser);
                if (!arg) {
                    arg = malloc(sizeof(sea_expr));
                    arg->type = SEA_EXPR_ERROR;
                    arg->item = sea_token_clone(sea_parser_adv(parser));
                    arg->error = sea_make_error("Expected expression as argument",
                            start, arg->item);
                }
                vec_sea_expr_append(call->args, arg);

                if (!sea_parser_match(parser, ",")) {
                    break;
                } else {
                    sea_parser_adv(parser);
                }
            }

            out->type = SEA_EXPR_CALL;
            out->item = call;
            if (!sea_parser_match(parser, ")")) {
                sea_token *rparen_token = sea_parser_adv(parser);
                out->error = sea_make_error(
                        "Expected ')' after call arguments",
                        rparen_token, rparen_token);
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

    sea_expr_bin *expr;
    sea_token *start;
    sea_expr *right;
    while (sea_parser_match(parser, "*") || sea_parser_match(parser, "/")
            || sea_parser_match(parser, "%"))
    {
        sea_token *token = sea_parser_adv(parser);
        start = sea_parser_peek(parser);
        right = sea_parse_unary(parser);

        expr = malloc(sizeof(sea_expr_bin));
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
                    start, sea_parser_adv(parser));
        } else {
            out->error = NULL;
        }
    }

    return out;
}

sea_expr *sea_parse_additive(sea_parser *parser) {
    sea_expr *out = sea_parse_term(parser);
    if (!out) return NULL;

    sea_expr_bin *expr;
    sea_token *start;
    sea_expr *right;
    while (sea_parser_match(parser, "+") || sea_parser_match(parser, "-")) {
        sea_token *token = sea_parser_adv(parser);
        start = sea_parser_peek(parser);
        right = sea_parse_term(parser);

        expr = malloc(sizeof(sea_expr_bin));
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
                    start, sea_parser_adv(parser));
        } else {
            out->error = NULL;
        }
    }

    return out;
}

sea_expr *sea_parse_ordinal(sea_parser *parser) {
    sea_expr *out = sea_parse_additive(parser);
    if (!out) return NULL;

    sea_expr_bin *expr;
    sea_token *start;
    sea_expr *right;
    while (sea_parser_match(parser, "<=") || sea_parser_match(parser, ">=")
            || sea_parser_match(parser, "<") || sea_parser_match(parser, ">")) {
        sea_token *token = sea_parser_adv(parser);
        start = sea_parser_peek(parser);
        right = sea_parse_additive(parser);

        expr = malloc(sizeof(sea_expr_bin));
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
                    start, sea_parser_adv(parser));
        } else {
            out->error = NULL;
        }
    }

    return out;
}

sea_expr *sea_parse_equality(sea_parser *parser) {
    sea_expr *out = sea_parse_ordinal(parser);
    if (!out) return NULL;

    sea_expr_bin *expr;
    sea_token *start;
    sea_expr *right;
    while (sea_parser_match(parser, "==") || sea_parser_match(parser, "!=")) {
        sea_token *token = sea_parser_adv(parser);
        start = sea_parser_peek(parser);
        right = sea_parse_ordinal(parser);

        expr = malloc(sizeof(sea_expr_bin));
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
                    start, sea_parser_adv(parser));
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

        sea_expr_bin *bin = malloc(sizeof(sea_expr_bin));
        sea_token *start;

        bin->left = out;
        start = sea_parser_peek(parser);
        bin->right = sea_parse_expr(parser);

        out = malloc(sizeof(sea_expr));
        out->type = SEA_EXPR_ASSIGN;
        out->item = bin;

        if (!bin->right) {
            out->error = sea_make_error(
                    "Expected expression after assignment operator",
                    start, sea_parser_adv(parser));
        }
    }

    return out;
}

void sea_expr_free(sea_expr *expr) {
    if (!expr) return;

    switch (expr->type) {
        case SEA_EXPR_INT:
        case SEA_EXPR_SYM:
        {
            sea_token *tok = (sea_token *) expr->item;
            sea_token_free(tok);
            break;
        }
        case SEA_EXPR_CALL:
        {
            sea_expr_call *inner = (sea_expr_call *) expr->item;
            sea_expr_call_free(inner);
            break;
        }
        case SEA_EXPR_NEGATE:
        case SEA_EXPR_NOT:
        {
            sea_expr *inner = (sea_expr *) expr->item;
            sea_expr_free(inner);
            break;
        }
        case SEA_EXPR_MUL:
        case SEA_EXPR_DIV:
        case SEA_EXPR_REM:
        case SEA_EXPR_ADD:
        case SEA_EXPR_SUB:
        case SEA_EXPR_LT:
        case SEA_EXPR_GT:
        case SEA_EXPR_LE:
        case SEA_EXPR_GE:
        case SEA_EXPR_EQ:
        case SEA_EXPR_NE:
        case SEA_EXPR_ASSIGN:
        {
            sea_expr_bin *inner = (sea_expr_bin *) expr->item;
            sea_expr_bin_free(inner);
            break;
        }
        case SEA_EXPR_ERROR:
        {
            sea_token_free(expr->item);
            break;
        }
        default:
        {
            fprintf(stderr, "unable to free expr: %d\n", expr->type);
            break;
        }
    }

    sea_error_free(expr->error);
    free(expr);
}

void sea_expr_call_free(sea_expr_call *expr) {
    if (!expr) return;
    sea_token_free(expr->name);
    vec_sea_expr_free(expr->args);
    free(expr);
}

void sea_expr_bin_free(sea_expr_bin *expr) {
    if (!expr) return;
    sea_expr_free(expr->left);
    sea_expr_free(expr->right);
    free(expr);
}

void sea_expr_collect_errors(const sea_expr *expr, vec_sea_error_t vec) {
    if (!expr) return;

    if (expr->error) {
        vec_sea_error_append(vec, expr->error);
    }

    switch (expr->type) {
        case SEA_EXPR_INT:
        case SEA_EXPR_SYM:
        case SEA_EXPR_ERROR:
            break;
        case SEA_EXPR_CALL:
        {
            sea_expr_call *inner = (sea_expr_call *) expr->item;
            for (size_t i = 0; i < vec_sea_expr_size(inner->args); i++) {
                sea_expr *arg = vec_sea_expr_get(inner->args, i);
                sea_expr_collect_errors(arg, vec);
            }
            break;
        }
        case SEA_EXPR_NEGATE:
        case SEA_EXPR_NOT:
        {
            sea_expr *inner = (sea_expr *) expr->item;
            sea_expr_collect_errors(inner, vec);
            break;
        }
        case SEA_EXPR_MUL:
        case SEA_EXPR_DIV:
        case SEA_EXPR_REM:
        case SEA_EXPR_ADD:
        case SEA_EXPR_SUB:
        case SEA_EXPR_LT:
        case SEA_EXPR_GT:
        case SEA_EXPR_LE:
        case SEA_EXPR_GE:
        case SEA_EXPR_EQ:
        case SEA_EXPR_NE:
        case SEA_EXPR_ASSIGN:
        {
            sea_expr_bin *inner = (sea_expr_bin *) expr->item;
            sea_expr_collect_errors(inner->left, vec);
            sea_expr_collect_errors(inner->right, vec);
            break;
        }
        default:
        {
            fprintf(stderr, "unable to collect errors for expr: %d\n", expr->type);
            break;
        }
    }
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
        sea_expr_call *inner = (sea_expr_call *) expr->item;
        ct += fprintf(fd, "%s(", inner->name->lex);
        for (size_t i = 0; i < vec_sea_expr_size(inner->args); i++) {
            if (i > 0) {
                ct += fprintf(fd, ", ");
            }
            ct += sea_expr_display(fd, vec_sea_expr_get(inner->args, i));
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
        sea_expr_bin *inner = (sea_expr_bin *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " * ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_DIV) {
        sea_expr_bin *inner = (sea_expr_bin *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " / ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_REM) {
        sea_expr_bin *inner = (sea_expr_bin *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " %% ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_ADD) {
        sea_expr_bin *inner = (sea_expr_bin *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " + ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_SUB) {
        sea_expr_bin *inner = (sea_expr_bin *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " - ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_LT) {
        sea_expr_bin *inner = (sea_expr_bin *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " < ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_GT) {
        sea_expr_bin *inner = (sea_expr_bin *) expr->item;
        ct += sea_expr_display(fd, inner->left);;
        ct += fprintf(fd, " > ");;
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_LE) {
        sea_expr_bin *inner = (sea_expr_bin *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " <= ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_GE) {
        sea_expr_bin *inner = (sea_expr_bin *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " >= ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_EQ) {
        sea_expr_bin *inner = (sea_expr_bin *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " == ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_NE) {
        sea_expr_bin *inner = (sea_expr_bin *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " != ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_ASSIGN) {
        sea_expr_bin *inner = (sea_expr_bin *) expr->item;
        ct += sea_expr_display(fd, inner->left);
        ct += fprintf(fd, " = ");
        ct += sea_expr_display(fd, inner->right);
    } else if (expr->type == SEA_EXPR_ERROR) {
        sea_token *start = expr->error->start;
        sea_token *end = expr->error->end;
        ct += fprintf(fd, "<error (%lu:%lu - %lu:%lu) - %s>",
                start ? start->line : 0, start ? start->column : 0,
                end ? end->line : 0, end ? end->column : 0,
                expr->error->message);
    } else {
        fprintf(stderr, "invalid expression type: %d\n", expr->type);
        ct = 0;
    }

    return ct;
}

sea_stmt *sea_parse_if_stmt(sea_parser *parser) {
    if (!sea_parser_match(parser, "if")) {
        return NULL;
    }
    sea_parser_adv(parser);

    sea_stmt_if *stmt = malloc(sizeof(sea_stmt_if));
    stmt->condition = NULL;
    stmt->body = NULL;
    stmt->else_branch = NULL;

    sea_stmt *out = malloc(sizeof(sea_stmt));
    out->type = SEA_STMT_IF;
    out->item = stmt;
    out->error = NULL;

    if (!sea_parser_match(parser, "(")) {
        sea_token *token = sea_parser_adv(parser);
        out->error = sea_make_error("Expected '(' after 'if'", token, token);
        return out;
    }
    sea_parser_adv(parser);

    sea_token *condition_token = sea_parser_peek(parser);
    sea_expr *condition = sea_parse_expr(parser);
    if (!condition) {
        out->error = sea_make_error("Expected condition expression",
                condition_token, sea_parser_adv(parser));
        return out;
    } else {
        stmt->condition = condition;
    }

    if (!sea_parser_match(parser, ")")) {
        sea_token *token = sea_parser_adv(parser);
        out->error = sea_make_error("Expected ')' after if condition", token, token);
        return out;
    }
    sea_parser_adv(parser);

    sea_token *body_token = sea_parser_peek(parser);
    sea_stmt *body = sea_parse_stmt(parser);
    if (!body) {
        out->error = sea_make_error("Expected statement as if-body",
                body_token, sea_parser_adv(parser));
        return out;
    } else {
        stmt->body = body;
    }

    if (sea_parser_match(parser, "else")) {
        sea_token *else_branch_token = sea_parser_peek(parser);
        sea_stmt *else_branch = sea_parse_stmt(parser);
        if (!else_branch) {
            out->error = sea_make_error("Expected statement as else-body",
                    else_branch_token, sea_parser_adv(parser));
            return out;
        } else {
            stmt->else_branch = else_branch;
        }
    }

    return out;
}

sea_stmt *sea_parse_block_stmt(sea_parser *parser) {
    if (!sea_parser_match(parser, "{")) return NULL;
    sea_parser_adv(parser);
    
    sea_stmt_block *stmt = malloc(sizeof(sea_stmt_block));
    vec_sea_stmt_init(stmt->inner);

    sea_stmt *out = malloc(sizeof(sea_stmt));
    out->type = SEA_STMT_BLOCK;
    out->item = stmt;
    out->error = NULL;

    sea_stmt *item;
    sea_token *start_token;
    while (sea_parser_more(parser) && !sea_parser_match(parser, "}")) {
        start_token = sea_parser_peek(parser);

        item = sea_parse_stmt(parser);
        if (!item) {
            item = malloc(sizeof(sea_stmt));
            item->type = SEA_STMT_ERROR;
            item->item = sea_token_clone(start_token);
            item->error = sea_make_error(
                    "Expected statement in block!",
                    start_token, sea_parser_adv(parser));
        }

        vec_sea_stmt_append(stmt->inner, item);

        if (!sea_parser_match(parser, ";")) {
            break;
        } else {
            sea_parser_adv(parser);
        }
    }

    if (!sea_parser_match(parser, "}")) {
        sea_token *token = sea_parser_adv(parser);
        out->error = sea_make_error(
                "Expected '}' after block expression!",
                token, token);
    }

    return out;
}

sea_stmt *sea_parse_var_stmt(sea_parser *parser) {
    sea_type_lit *type = sea_parse_type_lit(parser);
    if (!type) {
        return NULL;
    }

    sea_stmt_var *stmt = malloc(sizeof(sea_stmt_var));
    stmt->type = type;
    stmt->name = NULL;
    stmt->value = NULL;
    
    sea_stmt *out = malloc(sizeof(sea_stmt));
    out->type = SEA_STMT_VAR;
    out->item = stmt;
    out->error = NULL;

    if (!sea_parser_match_word(parser)) {
        sea_token *token = sea_parser_adv(parser);
        out->error = sea_make_error(
                "Expected variable name after return type!",
                token, token);
        return out;
    }
    stmt->name = sea_token_clone(sea_parser_adv(parser));

    if (sea_parser_match(parser, "=")) {
        sea_parser_adv(parser);

        sea_token *token = sea_parser_peek(parser);
        stmt->value = sea_parse_expr(parser);
        if (!stmt->value) {
            out->error = sea_make_error(
                    "Expected expression after '=' in variable statement",
                    token, sea_parser_adv(parser));
            return out;
        }
    }

    return out;
}

sea_stmt *sea_parse_expr_stmt(sea_parser *parser) {
    sea_expr *expr = sea_parse_expr(parser);
    if (!expr) {
        return NULL;
    }
    sea_stmt *out = malloc(sizeof(sea_stmt));
    out->type = SEA_STMT_EXPR;
    out->item = expr;
    out->error = NULL;

    return out;
}

sea_stmt *sea_parse_for_stmt(sea_parser *parser) {
    if (!sea_parser_match(parser, "for")) {
        return NULL;
    }
    sea_parser_adv(parser);

    sea_stmt_for *stmt = malloc(sizeof(sea_stmt_for));
    stmt->initializer = NULL;
    stmt->condition = NULL;
    stmt->incrementer = NULL;
    stmt->body = NULL;

    sea_stmt *out = malloc(sizeof(sea_stmt));
    out->type = SEA_STMT_FOR;
    out->item = stmt;
    out->error = NULL;

    if (!sea_parser_match(parser, "(")) {
        sea_token *token = sea_parser_adv(parser);
        out->error = sea_make_error(
                "Expected '(' after 'for' keyword",
                token, token);
        return out;
    }
    sea_parser_adv(parser);

    stmt->initializer = sea_parse_var_stmt(parser);
    if (!stmt->initializer) {
        stmt->initializer = sea_parse_expr_stmt(parser);
    }
    
    if (!sea_parser_match(parser, ";")) {
        sea_token *token = sea_parser_adv(parser);
        out->error = sea_make_error(
                "Expected ';' after 'for' initializer",
                token, token);
        return out;
    }
    sea_parser_adv(parser);

    stmt->condition = sea_parse_expr(parser);

    if (!sea_parser_match(parser, ";")) {
        sea_token *token = sea_parser_adv(parser);
        out->error = sea_make_error(
                "Expected ';' after 'for' condition",
                token, token);
        return out;
    }
    sea_parser_adv(parser);

    stmt->incrementer = sea_parse_expr(parser);
    
    if (!sea_parser_match(parser, ")")) {
        sea_token *token = sea_parser_adv(parser);
        out->error = sea_make_error(
                "Expected ')' after 'for' loop definitions",
                token, token);
        return out;
    }
    sea_parser_adv(parser);
    
    sea_token *body_token = sea_parser_peek(parser);
    stmt->body = sea_parse_stmt(parser);
    if (!stmt->body) {
        out->error = sea_make_error(
                "'for' loop needs a body!",
                body_token, sea_parser_adv(parser));
        return out;
    }

    return out;
}

sea_stmt *sea_parse_while_stmt(sea_parser *parser) {
    if (!sea_parser_match(parser, "while")) {
        return NULL;
    }
    sea_parser_adv(parser);

    sea_stmt_while *stmt = malloc(sizeof(sea_stmt_while));
    stmt->condition = NULL;
    stmt->body = NULL;

    sea_stmt *out = malloc(sizeof(sea_stmt));
    out->type = SEA_STMT_WHILE;
    out->item = stmt;
    out->error = NULL;

    if (!sea_parser_match(parser, "(")) {
        sea_token *token = sea_parser_adv(parser);
        out->error = sea_make_error(
                "Expected '(' after 'while' keyword",
                token, token);
        return out;
    }
    sea_parser_adv(parser);

    sea_token *condition_token = sea_parser_peek(parser);
    stmt->condition = sea_parse_expr(parser);
    if (!stmt->condition) {
        out->error = sea_make_error(
                "Expected condition for while loop",
                condition_token, sea_parser_adv(parser));
        return out;
    }

    if (!sea_parser_match(parser, ")")) {
        sea_token *token = sea_parser_adv(parser);
        out->error = sea_make_error(
                "Expected ')' after 'while' condition",
                token, token);
        return out;
    }
    sea_parser_adv(parser);

    stmt->body = sea_parse_stmt(parser);
    if (!stmt->body) {
        out->error = sea_make_error(
                "while loop needs a body!",
                condition_token, sea_parser_adv(parser));
        return out;
    }

    return out;
}

sea_stmt *sea_parse_stmt(sea_parser *parser) {
    sea_stmt *out;

    if ((out = sea_parse_if_stmt(parser))) {
        return out;
    }

    if ((out = sea_parse_block_stmt(parser))) {
        return out;
    }

    if ((out = sea_parse_for_stmt(parser))) {
        return out;
    }

    if ((out = sea_parse_while_stmt(parser))) {
        return out;
    }

    if ((out = sea_parse_var_stmt(parser))) {
        return out;
    }

    if ((out = sea_parse_expr_stmt(parser))) {
        return out;
    }

    return NULL;
}

void sea_stmt_if_free(sea_stmt_if *stmt) {
    if (!stmt) return;
    sea_expr_free(stmt->condition);
    sea_stmt_free(stmt->body);
    sea_stmt_free(stmt->else_branch);
    free(stmt);
}

void sea_stmt_block_free(sea_stmt_block *stmt) {
    if (!stmt) return;
    vec_sea_stmt_free(stmt->inner);
    free(stmt);
}

void sea_stmt_for_free(sea_stmt_for *stmt) {
    if (!stmt) return;
    sea_stmt_free(stmt->initializer);
    sea_expr_free(stmt->condition);
    sea_expr_free(stmt->incrementer);
    sea_stmt_free(stmt->body);
    free(stmt);
}

void sea_stmt_while_free(sea_stmt_while *stmt) {
    if (stmt) {
        sea_expr_free(stmt->condition);
        sea_stmt_free(stmt->body);
        free(stmt);
    }
}

void sea_stmt_var_free(sea_stmt_var *stmt) {
    if (stmt) {
        sea_type_lit_free(stmt->type);
        sea_token_free(stmt->name);
        sea_expr_free(stmt->value);
        free(stmt);
    }
}

void sea_stmt_free(sea_stmt *stmt) {
    if (!stmt) return;

    switch (stmt->type) {
        case SEA_STMT_IF:
        {
            sea_stmt_if_free(stmt->item);
            break;
        }
        case SEA_STMT_BLOCK:
        {
            sea_stmt_block_free(stmt->item);
            break;
        }
        case SEA_STMT_FOR:
        {
            sea_stmt_for_free(stmt->item);
            break;
        }
        case SEA_STMT_WHILE:
        {
            sea_stmt_while_free(stmt->item);
            break;
        }
        case SEA_STMT_VAR:
        {
            sea_stmt_var_free(stmt->item);
            break;
        }
        case SEA_STMT_EXPR:
        {
            sea_expr_free(stmt->item);
            break;
        }
        case SEA_STMT_ERROR:
        {
            sea_token_free(stmt->item);
            break;
        }
        default:
        {
            fprintf(stderr, "unable to free stmt: %d\n", stmt->type);
            break;
        }
    }

    sea_error_free(stmt->error);
    free(stmt);
}

void sea_stmt_collect_errors(const sea_stmt *item, vec_sea_error_t vec) {
    if (!item) return;

    if (item->error) {
        vec_sea_error_append(vec, item->error);
    }

    switch (item->type) {
        case SEA_STMT_IF:
        {
            sea_stmt_if *stmt = item->item;
            sea_expr_collect_errors(stmt->condition, vec);
            sea_stmt_collect_errors(stmt->body, vec);
            sea_stmt_collect_errors(stmt->else_branch, vec);
            break;
        }
        case SEA_STMT_BLOCK:
        {
            sea_stmt_block *stmt = item->item;
            for (size_t i = 0; i < vec_sea_stmt_size(stmt->inner); i++) {
                sea_stmt *inner = vec_sea_stmt_get(stmt->inner, i);
                sea_stmt_collect_errors(inner, vec);
            }
            break;
        }
        case SEA_STMT_FOR:
        {
            sea_stmt_for *stmt = item->item;
            sea_stmt_collect_errors(stmt->initializer, vec);
            sea_expr_collect_errors(stmt->condition, vec);
            sea_expr_collect_errors(stmt->incrementer, vec);
            sea_stmt_collect_errors(stmt->body, vec);
            break;
        }
        case SEA_STMT_WHILE:
        {
            sea_stmt_while *stmt = item->item;
            sea_expr_collect_errors(stmt->condition, vec);
            sea_stmt_collect_errors(stmt->body, vec);
            break;
        }
        case SEA_STMT_VAR:
        {
            sea_stmt_var *stmt = item->item;
            sea_expr_collect_errors(stmt->value, vec);
            break;
        }
        case SEA_STMT_EXPR:
        {
            sea_expr *expr = item->item;
            sea_expr_collect_errors(expr, vec);
            break;
        }
        case SEA_STMT_ERROR:
        {
            break;
        }
        default:
        {
            fprintf(stderr, "unable to collect errors on stmt: %d\n", item->type);
            break;
        }
    }
}


#undef SEA_ERROR
#undef SEA_EXPECT

#undef SEA_ERROR
#undef SEA_EXPECT
