#pragma once
#include "core.h"
#include "memory.h"

enumdef(OpCode) {
    OP_RETURN,
};

structdef(Chunk) {
    u8 *code;
    i32 capacity;
    i32 count;
};

void initChunk(Chunk *chunk);
void writeChunk(Chunk *chunk, u8 byte);
void freeChunk(Chunk *chunk);
