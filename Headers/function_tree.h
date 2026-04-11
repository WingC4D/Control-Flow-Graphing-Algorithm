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
    /*
    ConditionalJumpCtx(const BYTE* resolved_jump, const BYTE* next_instruction, DWORD blocks_count) {
        shallowIdx = blocks_count | COND_MASK;
        deepIdx    = 1 + (blocks_count | COND_MASK);

        if (resolved_jump < next_instruction)  {
            shallow_ptr = resolved_jump;
            shallowIdx |= COND_TAKEN_MASK;
            deep_ptr    = next_instruction;
        }

        else  {
            deep_ptr    = resolved_jump;
            deepIdx    |= COND_TAKEN_MASK;
            shallow_ptr = next_instruction;
            
        }
    }
    */
};
namespace fnt {
	enum ErrorCode: BYTE {
		success,
		failed
	};
}

struct FunctionTree {
    const BYTE*                         root;
	std::vector<Block>                  blocksVec;
	std::vector<const BYTE*>			newFunctionsVec;
	std::vector<DWORD>					leavesVec;

    struct TraceContext {
        std::map<const BYTE*, Block*> rootsMap;
        Block*                        currentBlock;
        std::vector<DWORD>            explorationVec;
        DWORD                         blocksCount;

        TraceContext(const BYTE* root_address, Block* root_block_ptr) : rootsMap(std::map{ std::pair{root_address, root_block_ptr} }), explorationVec(1) {
            explorationVec.reserve(BASE_BLOCK_RESERVE_SIZE);
            currentBlock = root_block_ptr;
            blocksCount  = 1;
        }
    };

	FunctionTree(LPVOID lpFunctionRoot): root(static_cast<BYTE*>(lpFunctionRoot)), newFunctionsVec(NEW_FUNCTIONS_BASE_SIZE), leavesVec(0) {
        blocksVec.reserve(BASE_BLOCK_RESERVE_SIZE);
        blocksVec.emplace_back(root, block::INVALID_INDEX, 0, 0);
	}

	fnt::ErrorCode trace();

    BOOLEAN splitBlock(Block& BlockToSplit, const BYTE* splitting_address, std::map<const BYTE*, Block*>& RootsMap);

	AddBlock addBlock(const BYTE *address_to_add, DWORD index, TraceContext& Context);

	void transferUniqueChildren(Block& OldParent, Block* NewParent);

	inline BOOLEAN checkIfTraced(TraceContext& Context);

	void handleJump(const BYTE* resolved_address, DWORD new_block_idx, TraceContext& TraceContext);

	void print() const {
		for (auto& block: blocksVec) {
			block.logIndex();
			block.print();
			std::println();
		}
	}
};