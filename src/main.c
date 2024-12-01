#include <stdio.h>
#include "core.h"
#include "chunk.h"

int main(int argc, char *argv[]) {
    Chunk chunk = {0};
    initChunk(&chunk);
    writeChunk(&chunk, OP_RETURN);
    freeChunk(&chunk);
    return 0;
}
