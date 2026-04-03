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
enum IsNewBranch : BYTE {
	no,
	no_reached_ret,
	yes_reached_conditional_branch,
	yes_reached_non_conditional_branch,
	yes_is_call,
	algorithm_failed
};
constexpr DWORD NEW_FUNCTIONS_BASE_SIZE = 0x00,

			    ENDS_UNCOND_JUMP		= 0x20000000,
				COND_BLOCK_MASK		    = 0X80000000,
				C_JUMP_TAKEN_MASK		= 0X40000000,
				MAX_BRANCH_INDEX		= 0X1FFFFFFF,
				INVALID_BLOCK_INDEX		= 0xFFFFFFFF;

struct NEW_BRANCH_PREREQ {
	LPBYTE root;
	DWORD  index,
		   parentIndex,
		   height;

	NEW_BRANCH_PREREQ(LPBYTE candidate_address, DWORD new_index, DWORD parent_index, DWORD height):
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

struct BLOCK {
	std::unique_ptr<BlockLandmarks> landmarksPtr;
	DWORD							idx;
	DWORD							height;
	std::unique_ptr<LdeState>		ldeState;
	std::vector<DWORD>				flowFromVec;
	std::vector<DWORD>				flowToVec;



	BLOCK(LPBYTE root_address, DWORD parent_index, DWORD index, DWORD height_):
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

	IsNewBranch trace(std::vector<LPBYTE>& NewFunctionsVec);

	IsNewBranch TraceUntil(std::vector<LPBYTE>& NewFunctionsVec, LPBYTE until_address);

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
	std::map<BYTE*, BLOCK*>& rootsMap;
	BLOCK&				     currentBlock;
	std::vector<DWORD>&		 explorationVec;
	
};

struct ConditionalJumpCtx {
	LPBYTE  lpShallowAddress,
	        lpDeepAddress;
	DWORD	dwShallowIndex,
			dwDeepIndex;
};

struct FunctionTree {
	enum ErrorCode: BYTE {
		success,
		failed
	};

	std::vector<std::unique_ptr<BLOCK>> blocksVec;
	std::vector<BYTE*> newFunctionsVec;
	const LPBYTE root;
	std::vector<DWORD>leavesVec;

	FunctionTree(const LPBYTE& lpFunctionRoot):
	blocksVec(0),
	newFunctionsVec(NEW_FUNCTIONS_BASE_SIZE),
	root(lpFunctionRoot),
	leavesVec(NULL) {
		blocksVec.emplace_back(std::make_unique<BLOCK>(lpFunctionRoot, 0xFFFFFFFF, 0, 0));
	}

	ErrorCode Trace();

	inline BOOLEAN splitBlock(BLOCK& SplitBlock, LPBYTE splitting_address, std::map<BYTE*, BLOCK*>& RootsMap);

	AddBlock addBlock(LPBYTE address_to_add, DWORD new_block_index, DWORD parent_index, DWORD height, std::map<BYTE*, BLOCK*>& RootsMap);

	void transferUniqueChildren(BLOCK& OldParentBlock, BLOCK& NewParentBlock) const;

	inline BOOLEAN checkIfTraced(BLOCK& JustTracedBlock, std::map<BYTE*, BLOCK*>& RootsMap) const;

	void handleJump(LPBYTE resolved_address, DWORD new_block_idx, const FunctionTreeTraceCtx& TraceContext);

	void print() {
		for (std::unique_ptr<BLOCK>& block: blocksVec) {
			block->logIndex();
			block->print();
			std::println();
		}
	}
};
