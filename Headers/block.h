#pragma once
#include <memory>
#include <vector>
#include "lde_common.h"

namespace block {
    constexpr BYTE  MAX_INSTRUCTIONS = 0xA0;

    constexpr DWORD MAX_INDEX       = 0X1FFFFFFF,
                    COND_MASK       = 0X80000000,
                    COND_TAKEN_MASK = 0X40000000,
                    INVALID_INDEX   = 0xFFFFFFFF;

    enum TraceResults : BYTE;

    

}

struct BlockLandmarks {
    const BYTE* const root,
        * end;

    BlockLandmarks(const BYTE* const root_address, const BYTE* end_address = nullptr) : root(root_address) {
        end = end_address;
    }
};

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

    std::unique_ptr<BlockLandmarks>  landmarksPtr;
    DWORD                            idx;
    DWORD                            height;
    std::unique_ptr<LdeState>        ldeState;
    std::vector<DWORD>               flowFromVec;
    std::vector<DWORD>               flowToVec;

    Block(const BYTE* root_address, DWORD parent_index, DWORD index, DWORD blk_height) :
        landmarksPtr(std::make_unique<BlockLandmarks>(root_address)), ldeState(std::make_unique<LdeState>()), flowFromVec(0), flowToVec(0) {
        if (parent_index != block::INVALID_INDEX)
            flowFromVec.emplace_back(parent_index);
        idx     = index;
        height = blk_height;
    }

    void print() const;

    void logIndex() const;

    void findNewEnd(const BYTE* interlacing_root_ptr) const;

    BOOLEAN isInstructionHead(LPBYTE candidate_address) const;

    block::TraceResults trace(std::vector<const BYTE*>& NewFunctionsVec) const;

    BOOLEAN isInRange(const BYTE* candidate_address) const;

    DWORD getIndex() const {
        return idx & block::MAX_INDEX;
    }

    const BYTE* getNextInstruction() const {
        return landmarksPtr->root + ldeState->size;
    }

    const BYTE* resolveEndAsJump() const {
        return ldeState->contextsArray.back().resolveJump(landmarksPtr->end);
    }

    inline void resize(BYTE new_instruction_count, const BYTE* new_end_address, DWORD new_size) const;

    static void addResolvedCall(std::vector<const BYTE*>& NewFunctionVec, const BYTE* resolved_address) {
        for (const BYTE* stored_func_address : NewFunctionVec)
            if (stored_func_address == resolved_address)
                return;

        NewFunctionVec.emplace_back(resolved_address);
    }
};