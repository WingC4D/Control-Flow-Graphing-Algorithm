#pragma once
#include <Windows.h>
#include <map>
#include <vector>
#include <memory>
#include<iostream>
#include <print>
#include "Lde.h"


class  Lde;
struct LdeState;


constexpr WORD  BASE_BLOCK_RESERVE_SIZE = 0x0400;

constexpr DWORD NEW_FUNCTIONS_BASE_SIZE = 0x00,
                ENDS_UNCOND_JUMP        = 0x20000000,
                COND_BLOCK_MASK         = 0X80000000,
                C_JUMP_TAKEN_MASK       = 0X40000000,
				MAX_BRANCH_INDEX        = 0X1FFFFFFF,
				INVALID_BLOCK_INDEX	    = 0xFFFFFFFF;

struct BlockPrerequisites {
	LPBYTE root;
	DWORD  idx,
           parent_idx,
           height;

	BlockPrerequisites(const LPBYTE candidate_address, const DWORD index, const DWORD parent_index, const DWORD prq_height) {
        root       = candidate_address;
        idx        = index;
        parent_idx = parent_index;
        height     = prq_height;
	}
};

struct BlockLandmarks { 
    const BYTE* const root,
              * end;

	BlockLandmarks(const BYTE* const root_address, const BYTE*end_address = nullptr): root(root_address) {
        end = end_address;
	}
};


struct Block {
	std::unique_ptr<BlockLandmarks> landmarksPtr;
	DWORD                           idx;
	DWORD                           height;
	std::unique_ptr<LdeState>       ldeState;
	std::vector<DWORD>              flowFromVec;
	std::vector<DWORD>              flowToVec;

	Block(const BYTE* root_address, DWORD parent_index, DWORD index, DWORD blk_height):
	landmarksPtr(std::make_unique<BlockLandmarks>(root_address)), ldeState(std::make_unique<LdeState>()), flowFromVec(0), flowToVec(0) {
		if (parent_index != 0xFFFFFFFF)
			flowFromVec.emplace_back(parent_index);
		idx    = index;
		height = blk_height;
	}

	void print() const; 

	void logIndex() const;

	void findNewEnd(const BYTE *interlacing_root_ptr) const;

	BOOLEAN isInstructionHead(LPBYTE candidate_address) const;

    block::TraceResults trace(std::vector<const BYTE*>& NewFunctionsVec) const;

    block::TraceResults traceUntil(std::vector<const BYTE*>& NewFunctionsVec, LPBYTE until_address);

	BOOLEAN isInRange(const BYTE* candidate_address) const;

	DWORD getIndex() const {
        return idx & MAX_BRANCH_INDEX;
    }

    const BYTE * getNextInstruction() const {
        return landmarksPtr->root + ldeState->size;
	}

    inline const BYTE* resolveEndAsJump() const;

	inline void resize(BYTE new_instruction_count, const BYTE *new_end_address) const;

	void handleEndOfTrace(const BYTE* current_address, LdeState& State);

	static void addResolvedCall(std::vector<const BYTE*>& NewFunctionVec, const BYTE* resolved_address) {
        for (const BYTE* stored_func_address : NewFunctionVec)
            if (stored_func_address == resolved_address) 
                return;

        NewFunctionVec.emplace_back(resolved_address);
	}
};

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
        shallowIdx = blocks_count | COND_BLOCK_MASK;
        deepIdx    = 1 + (blocks_count | COND_BLOCK_MASK);

        if (resolved_jump < next_instruction)  {
            shallow_ptr = resolved_jump;
            shallowIdx |= C_JUMP_TAKEN_MASK;
            deep_ptr    = next_instruction;
        }

        else  {
            deep_ptr    = resolved_jump;
            deepIdx    |= C_JUMP_TAKEN_MASK;
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
	std::vector<Block> blocksVec;
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
        blocksVec.emplace_back(root, 0xFFFFFFFF, 0, 0);
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