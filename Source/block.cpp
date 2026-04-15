#include "block.h"
using namespace block;

// A wrapping dispatcher around LdeState::traceBlock().
TraceResults Block::trace(std::vector<const BYTE*>& NewFunctionsVec) { using enum TraceResults;
    switch (lde.traceBlock(root, NewFunctionsVec)) {
        case reachedJump:
            end = root + lde.getLastInstHeadOffset();
            return reachedJump;

        case reachedConditionalJump:
            end = root + lde.getLastInstHeadOffset();
            return reachedConditionalJump;

        case reachedReturn:
            end = root + lde.getLastInstHeadOffset();
            return reachedReturn;

        case noNewBlock:
        case reachedCall:
        case failed:
            break;
    }
    return failed;
}

// A loop wrapped around inst::Context::map() & inst::Context::checkForNewBlock(), looking for redirecting jumps.
TraceResults Block::LdeState::traceBlock(const BYTE* block_root, std::vector<const BYTE*>& NewFunctionsVec) {
    while (instruction_count < MAX_INSTRUCTIONS) {
        if ((status = currContext.map(block_root + size)) != success && status != reached_end_of_function)
            return failed;

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

            case failed:
                return failed;

            case reachedCall:
                addResolvedCall(NewFunctionsVec, currContext.resolveJump(block_root + size));
                break;

            case noNewBlock:
                break;
        }
        prepareNextStep();
    }
    return failed;
}

BOOLEAN Block::isInRange(const BYTE* candidate_address) const {
    if (!end)
        return false;

    if (root > candidate_address)
        return false;

    if (end < candidate_address)
        return false;
    return true;
}

// Ensures that the passed address is valid, and is a valid instruction head within the calling block's range and that the block was traced, then resizes the block to the preceding instruction head
void Block::findNewEnd(const BYTE* interlacing_root_ptr) {
    if (!interlacing_root_ptr || !lde.instruction_count)
        return;
    DWORD accumulated_length = 0;
    for (BYTE last_instruction_length = 0, new_instruction_count = 0; inst::Context& Context: lde.contextsArray) {
        if (root + accumulated_length == interlacing_root_ptr) {
            if (accumulated_length)
                return resize(new_instruction_count, interlacing_root_ptr - last_instruction_length, accumulated_length);
        }
        last_instruction_length = Context.getLength();
        accumulated_length     += last_instruction_length;
        new_instruction_count++;
    }
}

void Block::resize(const BYTE new_instruction_count, const BYTE* new_end_address, const DWORD new_size) {
    if (!new_instruction_count || !new_end_address)
        return;

    lde.contextsArray.resize(new_instruction_count);
    end                   = new_end_address;
    lde.size              = new_size;
    lde.instruction_count = new_instruction_count;
}

void Block::logIndex() const {
    if (idx & COND_MASK)
        return idx & COND_TAKEN_MASK ?
            std::println("[i] Analyzing Block Of Linear Index {:#06x} & Of Height: {:#04x} (Conditional Jump Taken)", idx & MAX_INDEX, height) :
            std::println("[i] Analyzing Block Of Linear Index {:#06x} & Of Height: {:#04x} (Conditional Jump Not Taken)", idx & MAX_INDEX, height);

    return height ?
        std::println("[!] Analyzing Block Of Linear Index {:#06x} & Of Height: {:#04x} (Non-Conditional)", idx & MAX_INDEX, height) :
        std::println("[!] Analyzing The Root Block (Non-Conditional)");
}

void Block::logInstructionBytesAndAddresses() const {
    if (!end) {
        std::println("[!] This block is empty.");
        return;
    }
    for (DWORD accumulated_length = 0, instruction_count = 0; inst::Context Context : lde.contextsArray) {
        Context.log(root + accumulated_length, static_cast<BYTE>(instruction_count));
        accumulated_length += Context.getLength();
        if (instruction_count >= MAX_INSTRUCTIONS) {
            std::println("Hit an error while printing Block #{:06X}", idx);
            return;
        }
        instruction_count++;
    }
    std::println();
}


void Block::logFromAndToVectors() const {
    if (!flowFromVec.empty()) {
        std::print("[i] This block flows from: ");
        QWORD parent = 0,
              size   = flowFromVec.size() - 1;
        for (;  parent < size; parent++)
            std::print("{:#05x}, ", flowFromVec[parent]);
        std::println("{:#05x}", flowFromVec[parent]);
    } else {
        std::println("[i] This is a root block.");
    }
    if (!flowToVec.empty()) {
        std::print("[i] this block flows to:   ");
        QWORD child = 0,
            size = flowToVec.size() - 1;
        for (; child < size; child++)
            std::print("{:#05x}, ", flowToVec[child]);
        std::println("{:#05x}", flowToVec[child]);
    } else {
        std::println("[i] This is a leaf block.");
    }
    std::println();
}