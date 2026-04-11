#include "block.h"
using namespace block;

TraceResults Block::trace(_Out_ std::vector<const BYTE*>& NewFunctionsVec) const { using enum TraceResults;
    switch (ldeState->traceBlock(landmarksPtr->root, NewFunctionsVec)) {
        case reachedJump:
            landmarksPtr->end = landmarksPtr->root + ldeState->getLastInstHeadOffset();
            return reachedJump;

        case reachedConditionalJump:
            landmarksPtr->end = landmarksPtr->root + ldeState->getLastInstHeadOffset();
            return reachedConditionalJump;

        case reachedReturn:
            landmarksPtr->end = landmarksPtr->root + ldeState->getLastInstHeadOffset();
            return reachedReturn;

        case noNewBlock:
        case reachedCall:
        case failed:
            break;
    }
    return failed;
}

TraceResults Block::LdeState::traceBlock(const BYTE* block_root, std::vector<const BYTE*>& NewFunctionsVec) {
    while (instruction_count < MAX_INSTRUCTIONS && status == success) {
        status = currContext.map(block_root + size);
        switch (currContext.checkForNewBlock(block_root + size)) {
            case reachedJump:
                handleEnfOfTrace();
                return reachedJump;

            case reachedConditionalJump:
                handleEnfOfTrace();
                return reachedConditionalJump;

            case reachedReturn:
                handleEnfOfTrace();
                return reachedReturn;

            case reachedCall:
                addResolvedCall(NewFunctionsVec, currContext.resolveJump(block_root + size));

            case noNewBlock:
                break;

            case failed:
                return failed;
            }
        prepareNextStep();
    }
    return failed;
}

BOOLEAN Block::isInRange(const BYTE* candidate_address) const {
    if (!landmarksPtr->end)
        return false;
    if (landmarksPtr->root > candidate_address)
        return false;
    if (landmarksPtr->end < candidate_address)
        return false;
    return true;
}

BOOLEAN Block::isInstructionHead(const LPBYTE candidate_address) const {
    if (!landmarksPtr->end)
        return false;
    for (DWORD accumulated_length = 0; auto& Context: ldeState->contextsArray) {
        if (landmarksPtr->root + accumulated_length == candidate_address)
            return true;
        accumulated_length += Context.getLength();
    }
    return false;
}

void Block::findNewEnd(const BYTE* interlacing_root_ptr) const {
    DWORD accumulated_length = 0;
    for (BYTE last_instruction_length = 0, new_instruction_count = 0; inst::Context& InstructionCtx: ldeState->contextsArray) {
        if (landmarksPtr->root + accumulated_length == interlacing_root_ptr) {
            if (new_instruction_count)
                resize(new_instruction_count, interlacing_root_ptr - last_instruction_length, accumulated_length);
            return;
        }
        last_instruction_length = InstructionCtx.getLength();
        accumulated_length     += last_instruction_length;
        new_instruction_count++;
    }
}

void Block::resize(const BYTE new_instruction_count, const BYTE* new_end_address, DWORD new_size) const {
    if (!new_instruction_count || !new_end_address)
        return;
    landmarksPtr->end           = const_cast<BYTE*>(new_end_address);
    ldeState->size              = new_size;
    ldeState->instruction_count = new_instruction_count;
    ldeState->contextsArray.resize(new_instruction_count);
}

void Block::logIndex() const {//Logs index dynamically
    if (idx & COND_MASK)
        return idx & COND_TAKEN_MASK ?
            std::println("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Conditional Jump Taken)\n", idx & MAX_INDEX, height) :
            std::println("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Conditional Jump Not Taken)\n", idx & MAX_INDEX, height);

    return height ?
        std::println("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Non Conditional)\n", idx & MAX_INDEX, height) :
        std::println("[!] Analysing Root Branch (Non Conditional)\n");
}

void Block::print() const {
    if (!landmarksPtr->end) {
        std::println("[!] This Branch Is Not Traced Yet.");
        return;
    }
    for (DWORD accumulated_length = 0, instruction_count = 0; inst::Context Context : ldeState->contextsArray) {
        Context.log_addr_idx(landmarksPtr->root + accumulated_length, static_cast<BYTE>(instruction_count));
        accumulated_length += Context.getLength();
        if (instruction_count >= MAX_INSTRUCTIONS) {
            std::println("Hit an error while printing Block #{:03d}", idx);
            return;
        }
        instruction_count++;
    }
}

