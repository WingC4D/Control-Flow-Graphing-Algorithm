#pragma once
#include <map>
#include "block.h"
constexpr WORD  BASE_BLOCK_RESERVE_SIZE = 0x0400,
                NEW_FUNCTIONS_BASE_SIZE = 0x0004;



struct ConditionalJumpCtx {
    const BYTE* shallow_ptr,
              * deep_ptr;
	DWORD	    shallowIdx,
			    deepIdx;
};

namespace block {
    enum TraceResults: BYTE;
}

class FunctionTree {
public:
    enum ErrorCode : BYTE {
        success,
        failed
    };
    FunctionTree(LPVOID lpFunctionRoot) : root(static_cast<BYTE*>(lpFunctionRoot)) {
        blocksVec.reserve(BASE_BLOCK_RESERVE_SIZE);
        blocksVec.emplace_back(root, block::INVALID_INDEX, 0, 0);
        newFunctionsVec.reserve(NEW_FUNCTIONS_BASE_SIZE);
    }

    ErrorCode trace();

    void print() const {
        for (auto& block : blocksVec) {
            block.logIndex();
            block.logInstructionBytesAndAddresses();
            std::println();
        }
    }

private:
    const BYTE*              root;
	std::vector<Block>       blocksVec;
	std::vector<const BYTE*> newFunctionsVec;
	std::vector<DWORD>		 leavesVec{};

    struct TraceContext {
        std::map<const BYTE*, DWORD> rootsMap;
        std::vector<DWORD>           explorationVec;
        DWORD                        blocksCount,
                                     currIndex;
        block::TraceResults          result;

        TraceContext(const BYTE* root_address) : rootsMap(std::map{ std::pair{ root_address, static_cast<DWORD>(0) } }), explorationVec(1) {
            explorationVec.reserve(BASE_BLOCK_RESERVE_SIZE);
            currIndex    = 0;
            blocksCount  = 1;
            result       = block::TraceResults::noNewBlock;
        }
    };


    enum AddBlock : BYTE {
        was_traced = 0,
        added = 1,
        split = 2
    };

    BOOLEAN splitBlock(DWORD to_split_idx, const BYTE* splitting_address, TraceContext& TraceCtx);

	AddBlock addBlock(const BYTE *address_to_add, DWORD index, TraceContext& Context);

	void transferUniqueChildren(DWORD old_parent_idx, DWORD new_parent_idx);

	inline BOOLEAN checkIfTraced(TraceContext& Context);

	void handleJump(const BYTE* resolved_address, DWORD new_block_idx, TraceContext& Context);
};