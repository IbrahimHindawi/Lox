#pragma once

#include "core.h"

typedef f64 Value;

structdef(ValueArray) {
    Value *values;
    i32 capacity;
    i32 count;
};

void initValueArray(ValueArray *array);
void writeValueArray(ValueArray *array, Value value);
void freeValueArray(ValueArray *array);
void printValue(Value value);
