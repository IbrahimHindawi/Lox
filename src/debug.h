#pragma once
#include "chunk.h"
#include "value.h"

void disassembleChunk(Chunk *chunk, const char *name);

static int simpleInstruction(const char *name, int offset) {
  printf("%s\n", name);
  return offset + 1;
}

static int constantInstruction(const char *name, Chunk *chunk, int offset) {
    uint8_t constant = chunk->code[offset + 1];
    printf("%-16s %4d '", name, constant);
    printValue(chunk->constants.values[constant]);
    printf("'\n");
    return offset + 2;
}

i32 disassembleInstruction(Chunk *chunk, i32 offset);
