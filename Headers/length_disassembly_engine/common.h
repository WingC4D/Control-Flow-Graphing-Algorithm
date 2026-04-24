#pragma once
#include "instruction/length_context.h"

struct LdeCommon { using enum inst::Context::Status;
    inst::Context         currContext;
    inst::Context::Status status            = success;
    BYTE                  instruction_count = 0;
};