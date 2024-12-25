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
// haikal@hkNode:TokenPayload:s
// haikal@hkList:TokenPayload:s
// haikal@hkHashMap:TokenType:e
#include <core.h>
#include <bstrlib.h>

bool haderror = false;
// char const source[] = "var x: i32 = 0;";
char const source[] = "var x : int = 0;";
i32 start = 0;
i32 current = 0;
i32 line = 0;

void error(i32 line, char const *message) {
    printf("error: line: %d, message: %s\n", line, message);
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

char const *getNameFromToken(TokenType tokentype) {
    switch (tokentype) {
    case tk_lparen: return "tk_lparen"; break;
    case tk_rparen: return "tk_rparen"; break;
    case tk_lbrace: return "tk_lbrace"; break;
    case tk_rbrace: return "tk_rbrace"; break;
    case tk_comma: return "tk_comma"; break;
    case tk_dot: return "tk_dot"; break;
    case tk_minus: return "tk_minus"; break;
    case tk_plus: return "tk_plus"; break;
    case tk_semicolon: return "tk_semicolon"; break;
    case tk_slash: return "tk_slash"; break;
    case tk_star: return "tk_star"; break;
    case tk_bang: return "tk_bang"; break;
    case tk_bangeq: return "tk_bangeq"; break;
    case tk_eq: return "tk_eq"; break;
    case tk_eqeq: return "tk_eqeq"; break;
    case tk_gt: return "tk_gt"; break;
    case tk_gte: return "tk_gte"; break;
    case tk_lt: return "tk_lt"; break;
    case tk_lte: return "tk_lte"; break;
    case tk_ident: return "tk_ident"; break;
    case tk_string: return "tk_string"; break;
    case tk_number: return "tk_number"; break;
    case tk_and: return "tk_and"; break;
    case tk_or: return "tk_or"; break;
    case tk_if: return "tk_if"; break;
    case tk_elif: return "tk_elif"; break;
    case tk_else: return "tk_else"; break;
    case tk_true: return "tk_true"; break;
    case tk_false: return "tk_false"; break;
    case tk_print: return "tk_print"; break;
    case tk_ret: return "tk_ret"; break;
    case tk_var: return "tk_var"; break;
    case tk_for: return "tk_for"; break;
    case tk_while: return "tk_while"; break;
    case tk_struct: return "tk_struct"; break;
    case tk_proc: return "tk_proc"; break;
    case tk_eof: return "tk_eof"; break;
    // case tk_tokencount:
    default: break;
    }
    return "";
}

structdef(TokenPayload) {
    TokenType tokentype;
    char const *lexeme;
    void *literal;
    i32 line;
};

bool TokenPayload_eq(TokenPayload a, TokenPayload b) {
    return a.literal == b.literal &&
        a.tokentype == b.tokentype &&
        a.line == b.line &&
        a.lexeme == b.lexeme;
}

bstring tokenToString(TokenPayload *token) {
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
#include <hkHashMap.h>

structdef(Scanner) {
    bstring source;
    hkList_TokenPayload *tokens;
    hkHashMap_TokenType *map;
};

bool scannerIsAtEnd(Scanner *scanner) {
    return current >= scanner->source->mlen;
}

char peek(Scanner *scanner) {
    if (scannerIsAtEnd(scanner)) {
        return '\0';
    }
    return scanner->source->data[current];
}

char peekNext(Scanner *scanner) {
    if (current + 1 >= scanner->source->mlen) {
        return '\0';
    }
    return scanner->source->data[current + 1];
}

char scannerAdvance(Scanner *scanner) {
    return scanner->source->data[current++];
}

void scannerAddTokenPayload(Scanner *scanner, TokenType type, void *literal) {
    bstring text = bmidstr(scanner->source, start, current - start);
    hkList_TokenPayload_append(scanner->tokens, (TokenPayload){.tokentype = type, .lexeme = bdata(text), .literal = literal, line});
}

void addToken(Scanner *scanner, TokenType type) {
    scannerAddTokenPayload(scanner, type, NULL);
}

bool scannerMatch(Scanner *scanner, char expected) {
    if (scannerIsAtEnd(scanner)) {
        return false;
    }
    if (scanner->source->data[current] != expected) {
        return false;
    }
    current += 1;
    return true;
}

char scannerPeak(Scanner *scanner) {
    if (scannerIsAtEnd(scanner)) {
        return '\0';
    }
    return scanner->source->data[current];
}

bool isDigit(char c) {
    return c >= '0' && c <= '9';
}

bool isAlpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c == '_');
}

bool isAlphaNumberic(char c) {
    return isAlpha(c) || isDigit(c);
}

void scannerNumber(Scanner *scanner) {
    while (isDigit(peek(scanner))) {
        scannerAdvance(scanner);
    }
    if (peek(scanner) == '.' && isDigit(peekNext(scanner))) {
        scannerAdvance(scanner);
        while (isDigit(peek(scanner))) {
            scannerAdvance(scanner);
        }
    }
    bstring result = bmidstr(scanner->source, start, current - start);
    scannerAddTokenPayload(scanner, tk_number, result);
}

void scannerIdentifier(Scanner *scanner) {
    while (isAlphaNumberic(peek(scanner))) {
        scannerAdvance(scanner);
    }
    bstring text = bmidstr(scanner->source, start, current - start);
    TokenType *type = hkHashMap_TokenType_get(scanner->map, bdata(text));
    if (!type) {
        // type = &(TokenType){tk_ident};
        addToken(scanner, tk_ident);
        return;
    }
    addToken(scanner, *type);
}

void scannerScanToken(Scanner *scanner) {
    char c = scannerAdvance(scanner);
    switch (c) {
        case '(': addToken(scanner, tk_lparen); break;
        case ')': addToken(scanner, tk_rparen); break;
        case '{': addToken(scanner, tk_lbrace); break;
        case '}': addToken(scanner, tk_rbrace); break;
        case ',': addToken(scanner, tk_comma); break;
        case '.': addToken(scanner, tk_dot); break;
        case '-': addToken(scanner, tk_minus); break;
        case '+': addToken(scanner, tk_plus); break;
        case ';': addToken(scanner, tk_semicolon); break;
        case '*': addToken(scanner, tk_star); break;
        case '!': addToken(scanner, scannerMatch(scanner, '=') ? tk_bangeq : tk_bang); break;
        case '=': addToken(scanner, scannerMatch(scanner, '=') ? tk_eqeq : tk_eq); break;
        case '<': addToken(scanner, scannerMatch(scanner, '=') ? tk_lte : tk_lt); break;
        case '>': addToken(scanner, scannerMatch(scanner, '=') ? tk_gte : tk_gt); break;
        case '/':
            if (scannerMatch(scanner, '/')) {
                while (scannerPeak(scanner) != '\n' && !scannerIsAtEnd(scanner)) {
                    scannerAdvance(scanner);
                } 
            } else {
                addToken(scanner, tk_slash);
            }
        break;
        case ' ':
        case '\r':
        case '\t':
            break;
        case '\n':
            line += 1;
            break;
        default: 
            if (isDigit(c)) {
                scannerNumber(scanner);
            } else if (isAlpha(c)) {
                scannerIdentifier(scanner);
            } else {
                error(line, "Unexpected character.\n"); 
            }
            break;
    }
}

void scannerScanTokens(Scanner *scanner) {
    while(!scannerIsAtEnd(scanner)) {
        start = current;
        scannerScanToken(scanner);
    }
    hkList_TokenPayload_append(scanner->tokens, (TokenPayload) {.tokentype = tk_eof, .lexeme = "", .literal = NULL, .line = 0});
};

i32 main(i32 argc, char *argv[]) {
    for (i32 i = 0; i < sizeofarray(source); ++i) {
        printf("%c, ", source[i]);
    }
    Scanner scanner = {
        .source = bfromcstr(source),
        .tokens = (hkList_TokenPayload *) hkList_TokenPayload_create(),
        .map = hkHashMap_TokenType_create(),
    };
    hkHashMap_TokenType_set(scanner.map, "and", tk_and);
    hkHashMap_TokenType_set(scanner.map, "or", tk_or);
    hkHashMap_TokenType_set(scanner.map, "true", tk_true);
    hkHashMap_TokenType_set(scanner.map, "false", tk_false);
    hkHashMap_TokenType_set(scanner.map, "if", tk_if);
    hkHashMap_TokenType_set(scanner.map, "else", tk_else);
    hkHashMap_TokenType_set(scanner.map, "elif", tk_elif);
    hkHashMap_TokenType_set(scanner.map, "print", tk_print);
    hkHashMap_TokenType_set(scanner.map, "ret", tk_ret);
    hkHashMap_TokenType_set(scanner.map, "var", tk_var);
    hkHashMap_TokenType_set(scanner.map, "for", tk_for);
    hkHashMap_TokenType_set(scanner.map, "while", tk_while);
    hkHashMap_TokenType_set(scanner.map, "struct", tk_struct);
    hkHashMap_TokenType_set(scanner.map, "proc", tk_proc);
    scannerScanTokens(&scanner);
    // hkList_Token_print(scanner.tokens);
    hkNode_TokenPayload *iter = scanner.tokens->head; 
    printf("scanner.tokens.length: %llu\n", scanner.tokens->length); 
    while (iter) { 
        // printf("scanner.tokens: {%s, %p}\n", getTokenPayloadName(iter->data.literal), iter->next); 
        printf("scanner.tokens: {%s, %s, %p}\n", iter->data.lexeme, getNameFromToken(iter->data.tokentype), iter->next); 
        iter = iter->next; 
    }
}
#include <hkNode.c>
#include <hkList.c>
#include <hkHashMap.c>

#endif
