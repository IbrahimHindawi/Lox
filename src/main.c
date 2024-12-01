#include <stdio.h>
#include "core.h"
#include "chunk.h"
#include "debug.h"

int main(int argc, char *argv[]) {
    Chunk chunk = {0};
    initChunk(&chunk);
    writeChunk(&chunk, OP_RETURN);
    disassembleChunk(&chunk, "test chunk");
    freeChunk(&chunk);
    return 0;
}
