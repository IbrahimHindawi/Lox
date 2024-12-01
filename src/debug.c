#include "debug.h"

void disassembleChunk(Chunk *chunk, const char *name) {
  printf("== %s ==\n", name);

  for (int offset = 0; offset < chunk->count;) {
    offset = disassembleInstruction(chunk, offset);
  }
}

i32 disassembleInstruction(Chunk *chunk, i32 offset) {

  printf("%04d ", offset);
  if (offset > 0 && chunk->lines[offset] == chunk->lines[offset - 1]) {
    printf("   | ");
  } else {
    printf("%4d ", chunk->lines[offset]);
  }
  uint8_t instruction = chunk->code[offset];
  switch (instruction) {
    case OP_RETURN:
      return simpleInstruction("OP_RETURN", offset);
    case OP_CONSTANT:
      return constantInstruction("OP_CONSTANT", chunk, offset);
    default:
      printf("Unknown opcode %d\n", instruction);
      return offset + 1;
  }
}
