#ifdef VM

#include <stdio.h>
#include <core.h>
#include "chunk.h"
#include "debug.h"

int main(int argc, char *argv[]) {
    Chunk chunk = {0};
    initChunk(&chunk);
    int constant = addConstant(&chunk, 1.2);
    writeChunk(&chunk, OP_CONSTANT, 123);
    writeChunk(&chunk, constant, 123);
    writeChunk(&chunk, OP_RETURN, 123);
    disassembleChunk(&chunk, "test chunk");
    freeChunk(&chunk);
    return 0;
}

#else
// haikal@hkNode:Token:s
// haikal@hkList:Token:s
#include <core.h>
#include <bstrlib.h>

bool haderror = false;
char const source[] = "var x: i32 = 0;";
i32 start = 0;
i32 current = 0;
i32 line = 0;

void error(i32 line, char const *message) {
    printf("error: line: %d, mesage: %s\n", line, message);
}

void crash() {
    exit(1);
}


enumdef(TokenType) {
    tk_lparen, tk_rparen, tk_lbrace, tk_rbrace,
    tk_comma, tk_dot, tk_minus, tk_plus, tk_semicolon, tk_slash, tk_star,
    tk_bang, tk_bangeq, tk_eq, tk_eqeq, tk_gt, tk_gte, tk_lt, tk_lte,
    tk_ident, tk_string, tk_number,
    tk_and, tk_or, tk_if, tk_elif, tk_else, tk_true, tk_false,
    tk_print, tk_ret, tk_var, tk_for, tk_while, tk_struct, tk_proc,
    tk_eof, tk_tokencount,
};

structdef(Token) {
    TokenType tokentype;
    char const *lexeme;
    void *literal;
    i32 line;
};

bool Token_eq(Token a, Token b) {
    return a.literal == b.literal &&
        a.tokentype == b.tokentype &&
        a.line == b.line &&
        a.lexeme == b.lexeme;
}

bstring tokenToString(Token *token) {
    // char const *result = "";
    bstring result = bfromcstr("");
    // bcatcstr(result, token->tokentype);
    bcatcstr(result, token->lexeme);
    bcatcstr(result, " ");
    bcatcstr(result, token->literal);
    return result;
}

#include <hkNode.h>
#include <hkList.h>

structdef(Scanner) {
    bstring source;
    hkList_Token *tokens;
};

bool scannerIsAtEnd(Scanner *scanner) {
    return current >= scanner->source->mlen;
}

char scannerAdvance(Scanner *scanner) {
    return scanner->source->data[current++];
}

void addToken(TokenType type) {
}

void scannerScanToken(Scanner *scanner) {
    char c = scannerAdvance(scanner);
    switch (c) {
        case '(': addToken(tk_lparen); break;
        case ')': addToken(tk_rparen); break;
        case '{': addToken(tk_lbrace); break;
        case '}': addToken(tk_rbrace); break;
        case ',': addToken(tk_comma); break;
        case '.': addToken(tk_dot); break;
        case '-': addToken(tk_minus); break;
        case '+': addToken(tk_plus); break;
        case ';': addToken(tk_semicolon); break;
        case '*': addToken(tk_star); break;
    }
}

void scannerScanTokens(Scanner *scanner) {
    while(!scannerIsAtEnd(scanner)) {
        start = current;
        scanToken();
    }
    hkList_Token_append(scanner->tokens, (Token) {.tokentype = tk_eof, .lexeme = "", .literal = NULL, .line = 0});
};

i32 main(i32 argc, char *argv[]) {
    for (i32 i = 0; i < sizeofarray(source); ++i) {
        printf("%c, ", source[i]);
    }
    Scanner scanner = {
        .source = bfromcstr(source),
        .tokens = (hkList_Token *) hkList_Token_create(),
    };
}
#include <hkNode.c>
#include <hkList.c>

#endif
