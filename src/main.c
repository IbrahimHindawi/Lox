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

#include <core.h>
i32 main(i32 argc, char *argv[]) {
}

#endif
