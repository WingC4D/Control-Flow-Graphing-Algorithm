#pragma once
#include <map>
#include "block.h"
constexpr WORD  BASE_BLOCK_RESERVE_SIZE = 0x0400;

constexpr DWORD NEW_FUNCTIONS_BASE_SIZE = 0x00,
                ENDS_UNCOND_JUMP        = 0x20000000,
                COND_BLOCK_MASK         = 0X80000000,
                C_JUMP_TAKEN_MASK       = 0X40000000,
				
				INVALID_BLOCK_INDEX	    = 0xFFFFFFFF;

enum AddBlock: BYTE {
	was_traced = 0,
	added	   = 1,
	split	   = 2
};

struct ConditionalJumpCtx {
    const BYTE* shallow_ptr,
              * deep_ptr;
	DWORD	    shallowIdx,
			    deepIdx;
};
namespace fnt {
	enum ErrorCode: BYTE {
		success,
		failed
	};
}

struct FunctionTree {
    const BYTE*              root;
	std::vector<Block>       blocksVec;
	std::vector<const BYTE*> newFunctionsVec;
	std::vector<DWORD>		 leavesVec;

    struct TraceContext {
        std::map<const BYTE*, DWORD> rootsMap;
        ;
        std::vector<DWORD>           explorationVec;
        DWORD                        blocksCount,
                                     currentIdx;

        TraceContext(const BYTE* root_address) : rootsMap(std::map{ std::pair{ root_address, static_cast<DWORD>(0) } }), explorationVec(1) {
            explorationVec.reserve(BASE_BLOCK_RESERVE_SIZE);
            currentIdx   = 0;
            blocksCount  = 1;
        }
    };

	FunctionTree(LPVOID lpFunctionRoot): root(static_cast<BYTE*>(lpFunctionRoot)), newFunctionsVec(NEW_FUNCTIONS_BASE_SIZE), leavesVec(0) {
        blocksVec.reserve(BASE_BLOCK_RESERVE_SIZE);
        blocksVec.emplace_back(root, block::INVALID_INDEX, 0, 0);
	}

	fnt::ErrorCode trace();

    BOOLEAN splitBlock(Block& BlockToSplit, const BYTE* splitting_address, std::map<const BYTE*, DWORD>& RootsMap);

	AddBlock addBlock(const BYTE *address_to_add, DWORD index, TraceContext& Context);

	void transferUniqueChildren(Block& OldParent, DWORD NewParentIdx);

	inline BOOLEAN checkIfTraced(TraceContext& Context);

	void handleJump(const BYTE* resolved_address, DWORD new_block_idx, TraceContext& Context);

	void print() const {
		for (auto& block: blocksVec) {
			block.logIndex();
			block.print();
			std::println();
		}
	}
};