// haikal@Node:TokenPayload:s
// haikal@List:TokenPayload:s
// haikal@Map:TokenType:e
#include <core.h>
#include <bstrlib.h>
#include <stdio.h>

bool haderror = false;
i32 start = 0;
i32 current = 0;
i32 line = 0;

void error(i32 line, char const *message) {
    printf("error: line: %d, message: %s\n", line, message);
}

void crash() {
    exit(1);
}

//--------------------------------
// tokenizer
//--------------------------------
typedef enum TokenType TokenType;
enum TokenType {
    tk_lparen, tk_rparen, tk_lbrace, tk_rbrace,
    tk_comma, tk_dot, tk_minus, tk_plus, tk_colon, tk_semicolon, tk_slash, tk_star,
    tk_bang, tk_bangeq, tk_eq, tk_eqeq, tk_gt, tk_gte, tk_lt, tk_lte,
    tk_ident, tk_string, tk_number,
    tk_and, tk_or, tk_if, tk_elif, tk_else, tk_true, tk_false,
    tk_print, tk_ret, tk_var, tk_for, tk_while, tk_struct, tk_proc,
    tk_eof,
    tk_tokencount,
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
        case tk_colon: return "tk_colon"; break;
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

typedef struct TokenPayload TokenPayload;
struct TokenPayload {
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
    bcatcstr(result, "'");
    bcatcstr(result, token->lexeme);
    bcatcstr(result, "'");
    bcatcstr(result, " ");
    bcatcstr(result, token->literal);
    return result;
}

#include <Node.h>
#include <List.h>
#include <Map.h>

//--------------------------------
// scanner
//--------------------------------

typedef struct Scanner Scanner;
struct Scanner {
    bstring source;
    List_TokenPayload *tokens;
    Map_TokenType *map;
};

bool scannerIsAtEnd(Scanner *scanner) {
    return current >= scanner->source->slen;
}

char peek(Scanner *scanner) {
    if (scannerIsAtEnd(scanner)) {
        return '\0';
    }
    return scanner->source->data[current];
}

char peekNext(Scanner *scanner) {
    if (current + 1 >= scanner->source->slen) {
        return '\0';
    }
    return scanner->source->data[current + 1];
}

char scannerAdvance(Scanner *scanner) {
    return scanner->source->data[current++];
}

void scannerAddTokenPayload(Scanner *scanner, TokenType type, void *literal) {
    bstring text = bmidstr(scanner->source, start, current - start);
    List_TokenPayload_append(scanner->tokens, (TokenPayload){.tokentype = type, .lexeme = bdata(text), .literal = literal, line});
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
    TokenType *type = Map_TokenType_get(scanner->map, bdata(text));
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
        case '+': addToken(scanner, tk_plus); break;
        case '*': addToken(scanner, tk_star); break;
        case '!': addToken(scanner, scannerMatch(scanner, '=') ? tk_bangeq : tk_bang); break;
        case '=': addToken(scanner, scannerMatch(scanner, '=') ? tk_eqeq : tk_eq); break;
        case '<': addToken(scanner, scannerMatch(scanner, '=') ? tk_lte : tk_lt); break;
        case '>': addToken(scanner, scannerMatch(scanner, '=') ? tk_gte : tk_gt); break;
        case '-': addToken(scanner, scannerMatch(scanner, '>') ? tk_ret : tk_minus); break;
        case ';': addToken(scanner, tk_semicolon); break;
        case ':': addToken(scanner, tk_colon); break;
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
        case '\0':
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
                printf("error: line: %d, message: Unexpected character: '%c'.\n", line, c);
            }
            break;
    }
}

void scannerScanTokens(Scanner *scanner) {
    while (!scannerIsAtEnd(scanner)) {
        start = current;
        scannerScanToken(scanner);
    }
    List_TokenPayload_append(scanner->tokens, (TokenPayload) {.tokentype = tk_eof, .lexeme = "", .literal = NULL, .line = 0});
};

#define source_max_buffer_size 1024 * 1024
char source[source_max_buffer_size];
size_t source_size;

i32 compile() {
    u64 line_count = 1;
    printf("line %04llu:    ", line_count);
    for (i32 i = 0; i < source_size; ++i) {
            if (source[i] == '\n') {
                printf("\nline %04llu:    ", line_count);
                line_count += 1;
            }
            else {
                printf("%c", source[i]);
            }
        if (source[i] == 0) {
            printf("EOF\n");
            break;
        }
    }
    // printf("source:\n%s", source);
    Scanner scanner = {
        .source = bfromcstr(source),
        .tokens = List_TokenPayload_create(),
        .map = Map_TokenType_create(),
    };
    Map_TokenType_set(scanner.map, "and", tk_and);
    Map_TokenType_set(scanner.map, "or", tk_or);
    Map_TokenType_set(scanner.map, "true", tk_true);
    Map_TokenType_set(scanner.map, "true", tk_true);
    Map_TokenType_set(scanner.map, "false", tk_false);
    Map_TokenType_set(scanner.map, "if", tk_if);
    Map_TokenType_set(scanner.map, "elif", tk_elif);
    Map_TokenType_set(scanner.map, "else", tk_else);
    Map_TokenType_set(scanner.map, "print", tk_print);
    Map_TokenType_set(scanner.map, "ret", tk_ret);
    Map_TokenType_set(scanner.map, "var", tk_var);
    Map_TokenType_set(scanner.map, "for", tk_for);
    Map_TokenType_set(scanner.map, "while", tk_while);
    Map_TokenType_set(scanner.map, "struct", tk_struct);
    Map_TokenType_set(scanner.map, "proc", tk_proc);
    scannerScanTokens(&scanner);
    // List_Token_print(scanner.tokens);
    Node_TokenPayload *iter = scanner.tokens->head; 
    printf("scanner.tokens.length: %llu\n", scanner.tokens->length); 
    while (iter) { 
        // printf("scanner.tokens: {%s, %p}\n", getTokenPayloadName(iter->data.literal), iter->next); 
        printf("scanner.tokens: {%s, %s, %p}\n", iter->data.lexeme, getNameFromToken(iter->data.tokentype), iter->next); 
        iter = iter->next; 
    }
    return 0;
}

i32 main(i32 argc, char *argv[]) {
    if (argc == 1) {
        printf("Error: Invalid Input! Please specify a file to compile.");
        return 1;
    }
    else {
        FILE *input;
        if (fopen_s(&input, argv[1], "r") != 0) {
            printf("Error: File %s not found!\n", argv[1]);
            return 1;
        }
        fseek(input, 0, SEEK_END);
        source_size = (size_t)ftell(input);
        rewind(input);

        if (source_size == -1L) {
            printf("Error: ftell failed.\n");
            return 1;
        }
        printf("Found %llu bytes in file: %s.\n", source_size, argv[1]);
        size_t read_bytes = fread_s(source, source_max_buffer_size, sizeof(char), source_size, input);
        if (read_bytes != (size_t)source_size) {
            if (feof(input)) {
                printf("Unexpected end of file reached.\n");
            } else if (ferror(input)) {
                perror("Error reading from file");
            } else {
                printf("Warning: Only %zu bytes read out of %zu.\n", read_bytes, source_size);
            }
        }
        source_size = read_bytes;
        source[source_size-1] = '\0';
        fclose(input);
    }
    compile();
    return 0;
}

#include <Node.c>
#include <List.c>
#include <Map.c>
