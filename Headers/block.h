#pragma once
#include <vector>
#include "lde_common.h"

namespace block {
    constexpr BYTE  MAX_INSTRUCTIONS = 0xA0;
    constexpr DWORD MAX_INDEX        = 0X3FFFFFFF,
                    COND_MASK        = 0X80000000,
                    COND_TAKEN_MASK  = 0X40000000,
                    INVALID_INDEX    = 0xFFFFFFFF;

    enum TraceResults : BYTE;
}

struct Block {
    struct LdeState: LdeCommon {
        std::vector<inst::Context> contextsArray;

        LdeState() : contextsArray(block::MAX_INSTRUCTIONS) {}

        void prepareNextStep() {
            size                            += currContext.getLength();
            contextsArray[instruction_count] = currContext;
            currContext.clear();
            instruction_count++;
        }

        void handleEnfOfTrace() {
            prepareNextStep();
            contextsArray.resize(instruction_count);
        }

        block::TraceResults traceBlock(const BYTE* block_root, std::vector<const BYTE*>& NewFunctionsVec);

        DWORD getLastInstHeadOffset() const {
            return size - contextsArray.back().getLength();
        }

        const BYTE* resolveJumpLastInstruction(const BYTE* const last_instruction_head) {
            return contextsArray.back().resolveJump(last_instruction_head);
        }
    };

    const BYTE* const                root,
              *                      end = nullptr;
    DWORD                            idx,
                                     height;
    LdeState                         lde{};
    std::vector<DWORD>               flowFromVec{};
    std::vector<DWORD>               flowToVec{};

    Block(const BYTE* root_address, DWORD parent_index = block::INVALID_INDEX, DWORD index = 0, DWORD block_height = 0) : root(root_address) {
        if (parent_index != block::INVALID_INDEX)
            flowFromVec.emplace_back(parent_index);
        idx    = index;
        height = block_height;
    }

    void logInstructionBytesAndAddresses() const;

    void logIndex() const;

    void findNewEnd(const BYTE* interlacing_root_ptr);

    block::TraceResults trace(std::vector<const BYTE*>& NewFunctionsVec);

    BOOLEAN isInRange(const BYTE* candidate_address) const;

    DWORD getIndex() const {
        return idx & block::MAX_INDEX;
    }

    const BYTE* getNextInstruction() const {
        return root + lde.size;
    }

    const BYTE* resolveEndAsJump() {
        return lde.contextsArray.back().resolveJump(end);
    }

    inline void resize(BYTE new_instruction_count, const BYTE* new_end_address, DWORD new_size);

    static void addResolvedCall(std::vector<const BYTE*>& NewFunctionVec, const BYTE* resolved_address) {
        for (const BYTE* stored_func_address : NewFunctionVec)
            if (stored_func_address == resolved_address)
                return;

        NewFunctionVec.emplace_back(resolved_address);
    }
};