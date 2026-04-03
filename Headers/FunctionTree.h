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
	LPBYTE lpRoot;
	DWORD  dwIndex,
		   dwParentIdx,
		   dwHeight;

	NEW_BRANCH_PREREQ(LPBYTE lpCandidate, DWORD dwNewBranchIndex, DWORD dwParentBranchIndex, DWORD dwNewBranchHeight):
	lpRoot(lpCandidate),
	dwIndex(dwNewBranchIndex),
	dwParentIdx(dwParentBranchIndex),
	dwHeight(dwNewBranchHeight) {
	}
};

struct BLOCK_LANDMARKS { 
	const BYTE* lpRoot;
	BYTE *lpEnd;

	BLOCK_LANDMARKS(LPBYTE lpRootAddress, LPBYTE lpEndAddress):
	lpRoot(lpRootAddress),
	lpEnd(lpEndAddress){
	}
	const BYTE* getRoot() const {
		return lpRoot;
	}
};

struct BLOCK {
	std::unique_ptr<BLOCK_LANDMARKS> lpLandmarks;
	DWORD							 dwIndex;
	DWORD							 dwHeight;
	std::unique_ptr<LdeState>		 ldeState;
	std::vector<DWORD>				 flowFromVec;
	std::vector<DWORD>				 flowToVec;



	BLOCK(LPBYTE lpStartAddress, DWORD dwParentIdx, DWORD dwBranchIdx, DWORD dwBranchHeight):
	lpLandmarks(std::make_unique<BLOCK_LANDMARKS>(lpStartAddress, nullptr)),
	ldeState(std::make_unique<LdeState>()), flowFromVec(0), flowToVec(0) {
		dwIndex  = dwBranchIdx;
		dwHeight = dwBranchHeight;
		if (dwParentIdx != 0xFFFFFFFF) {
			flowFromVec.emplace_back(dwParentIdx);
		}
	}
	void print() const; 

	void logIndex() const;

	void findNewEnd(LPBYTE lpInterlacingRoot) const;

	BOOLEAN isInstructionHead(LPBYTE lpCandidate) const;

	IsNewBranch trace(std::vector<BYTE*>& NewFunctionsVec);

	IsNewBranch TraceUntil(std::vector<BYTE*>& NewFunctionsVec, const unsigned char * until_address);

	inline BOOLEAN isInRange(LPBYTE CandidateLandmarks_t) const;

	inline DWORD getIndex(void) const;
	
	inline void resize(BYTE sNewSize, LPBYTE lpNewEndAddress) const;

	void handleEndOfTrace(LPBYTE lpCurrentAddress, LdeState& state);

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
	const LPBYTE lpRoot;
	std::vector<DWORD>vLeafs;
	DWORD dwNewFunctionsCount;

	FunctionTree(const LPBYTE& lpFunctionRoot):
	blocksVec(0),
	newFunctionsVec(NEW_FUNCTIONS_BASE_SIZE),
	lpRoot(lpFunctionRoot),
	vLeafs(NULL) {
		using namespace std;
		blocksVec.emplace_back(make_unique<BLOCK>(lpFunctionRoot, 0xFFFFFFFF, 0, 0));
		dwNewFunctionsCount = 0;
	}

	ErrorCode Trace();

	inline BOOLEAN splitBlock(BLOCK& SplitBlock, LPBYTE lpSplittingAddress, std::map<BYTE*, BLOCK*>& RootsMap);

	AddBlock addBlock(LPBYTE lpToAdd, DWORD dwIndex, DWORD dwParentIndex, DWORD dwHeight, std::map<BYTE*, BLOCK*>& RootsMap);

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
