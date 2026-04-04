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

namespace blk {
	enum TraceResults: BYTE {
		noNewBlock,
		reachedReturn,
		reachedConditionalJump,
		reachedNonConditionalJump,
		reachedCall,
		failed
	};
}
constexpr DWORD NEW_FUNCTIONS_BASE_SIZE = 0x00,

			    ENDS_UNCOND_JUMP		= 0x20000000,
				COND_BLOCK_MASK		    = 0X80000000,
				C_JUMP_TAKEN_MASK		= 0X40000000,
				MAX_BRANCH_INDEX		= 0X1FFFFFFF,
				INVALID_BLOCK_INDEX		= 0xFFFFFFFF;

struct BlockPrerequisites {
	LPBYTE root;
	DWORD  index,
		   parentIndex,
		   height;

	BlockPrerequisites(LPBYTE candidate_address, DWORD new_index, DWORD parent_index, DWORD height):
	root(candidate_address),
	index(new_index),
	parentIndex(parent_index),
	height(height) {
	}
};

struct BlockLandmarks { 
	BYTE* const root;
	BYTE *end;

	BlockLandmarks(LPBYTE root_address, LPBYTE end_address = nullptr):
	root(root_address),
	end(end_address){
	}
	BYTE* getRoot() const {
		return root;
	}
};

struct Block {
	std::unique_ptr<BlockLandmarks> landmarksPtr;
	DWORD							idx;
	DWORD							height;
	std::unique_ptr<LdeState>		ldeState;
	std::vector<DWORD>				flowFromVec;
	std::vector<DWORD>				flowToVec;



	Block(LPBYTE root_address, DWORD parent_index, DWORD index, DWORD height_):
	landmarksPtr(std::make_unique<BlockLandmarks>(root_address)), ldeState(std::make_unique<LdeState>()),
	flowFromVec(0), flowToVec(0) {
		idx    = index;
		height = height_;
		if (parent_index != 0xFFFFFFFF) {
			flowFromVec.emplace_back(parent_index);
		}
	}
	void print() const; 

	void logIndex() const;

	void findNewEnd(LPBYTE interlacing_root_ptr) const;

	BOOLEAN isInstructionHead(LPBYTE candidate_address) const;

	blk::TraceResults trace(std::vector<LPBYTE>& NewFunctionsVec);

	blk::TraceResults traceUntil(std::vector<LPBYTE>& NewFunctionsVec, LPBYTE until_address);

	BOOLEAN isInRange(LPBYTE candidate_address) const;

	inline DWORD getIndex() const;
	
	inline void resize(BYTE new_size, LPBYTE new_end_address) const;

	void handleEndOfTrace(LPBYTE current_address, LdeState& State);

	inline static void addResolvedCall(std::vector<LPBYTE>& NewFunctionVec, LPBYTE resolved_address);

};

enum AddBlock: BYTE {
	was_traced = 0,
	added	   = 1,
	split	   = 2
};

struct FunctionTreeTraceCtx {
	std::map<BYTE*, Block*>& rootsMap;
	Block&				     currentBlock;
	std::vector<DWORD>&		 explorationVec;
	
};

struct ConditionalJumpCtx {
	LPBYTE  shallowPtr,
	        deepPtr;
	DWORD	shallowIdx,
			deepIdx;
};
namespace fTree {
	enum ErrorCode : BYTE {
		success,
		failed
	};
}
struct FunctionTree {
	
	std::vector<std::unique_ptr<Block>> blocksVec;
	std::vector<BYTE*> newFunctionsVec;
	LPBYTE const root;
	std::vector<DWORD>leavesVec;

	FunctionTree(LPVOID lpFunctionRoot): blocksVec(0), newFunctionsVec(NEW_FUNCTIONS_BASE_SIZE), root(static_cast<BYTE*>(lpFunctionRoot)), leavesVec(0) {
		blocksVec.emplace_back(std::make_unique<Block>(root, 0xFFFFFFFF, 0, 0));
	}

	fTree::ErrorCode trace();

	inline BOOLEAN splitBlock(Block& BlockToSplit, LPBYTE splitting_address, std::map<BYTE*, Block*>& RootsMap);

	AddBlock addBlock(LPBYTE address_to_add, DWORD new_block_index, DWORD parent_index, DWORD height, std::map<BYTE*, Block*>& RootsMap);

	void transferUniqueChildren(Block& OldParentBlock, Block& NewParentBlock) const;

	inline BOOLEAN checkIfTraced(Block& JustTracedBlock, std::map<BYTE*, Block*>& RootsMap) const;

	void handleJump(LPBYTE resolved_address, DWORD new_block_idx, const FunctionTreeTraceCtx& TraceContext);

	void print() {
		for (std::unique_ptr<Block>& block: blocksVec) {
			block->logIndex();
			block->print();
			std::println();
		}
	}
};
