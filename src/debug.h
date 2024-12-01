#pragma once
#include "chunk.h"

void disassembleChunk(Chunk *chunk, const char *name);

static int simpleInstruction(const char* name, int offset) {
  printf("%s\n", name);
  return offset + 1;
}

i32 disassembleInstruction(Chunk *chunk, i32 offset);
