#pragma once
#include "core.h"
#include "memory.h"
#include "value.h"

enumdef(OpCode) {
    OP_RETURN,
    OP_CONSTANT,
};

structdef(Chunk) {
    u8 *code;
    i32 *lines;
    i32 capacity;
    i32 count;
    ValueArray constants;
};

void initChunk(Chunk *chunk);
void writeChunk(Chunk *chunk, u8 byte, i32 line);
i32 addConstant(Chunk *chunk, Value value);
void freeChunk(Chunk *chunk);
