#pragma once
#include <Windows.h>
#include <map>
#include <vector>
#include <memory>
#include <iostream>
#include "LDE.h"

enum IS_NEW_BRANCH: BYTE;
class  LDE;
struct LDE_STATE;
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
	BYTE* lpEnd;

	BLOCK_LANDMARKS(LPBYTE lpRootAddress, LPBYTE lpEndAddress):
	lpRoot(lpRootAddress),
	lpEnd(lpEndAddress){
	}

};

struct BLOCK {
	std::unique_ptr<BLOCK_LANDMARKS> lpLandmarks;
	DWORD							 dwIndex;
	DWORD							 dwHeight;
	std::unique_ptr<LDE_STATE>		 ldeState;
	std::vector<DWORD>				 flowFromVec;
	std::vector<DWORD>				 flowToVec;

	BLOCK(LPBYTE lpStartAddress, DWORD dwParentIdx, DWORD dwBranchIdx, DWORD dwBranchHeight):
	lpLandmarks(std::make_unique<BLOCK_LANDMARKS>(lpStartAddress, nullptr)),
	ldeState(std::make_unique<LDE_STATE>()), flowFromVec(0), flowToVec(0) {
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

	IS_NEW_BRANCH Trace(std::vector<BYTE*>& NewFunctionsVec);

	IS_NEW_BRANCH TraceUntil(std::vector<BYTE*>& vNewFunctionsVec, LPBYTE lpUntilAddress);

	inline BOOLEAN isInRange(LPBYTE CandidateLandmarks_t) const;

	inline DWORD getIndex(void) const;
	
	inline void resize(BYTE sNewSize, LPBYTE lpNewEndAddress) const;

	inline void handleEndOfTrace(LPBYTE lpCurrentAddress, LDE_STATE& state);

	inline static void addResolvedCall(std::vector<LPBYTE>& NewFunctionVec, LPBYTE lpResolvedAddress);

};

enum add_block: BYTE {
	was_traced = 0,
	added	   = 1,
	split	   = 2
};

struct FUNCTION_TREE_TRACE_CTX {
	std::map<BYTE*, BLOCK*>& rootsMap;
	BLOCK&				     currentBlock;
	std::vector<DWORD>&		 explorationVec;
	
};

struct CONDITIONAL_JUMP_CTX {
	LPBYTE  lpShallowAddress,
	        lpDeepAddress;
	DWORD	dwShallowIndex,
			dwDeepIndex;
};

struct FUNCTION_TREE {
	enum ErrorCode: BYTE {
		success,
		failed
	};

	std::vector<std::unique_ptr<BLOCK>> blocksVec;
	std::vector<BYTE*> newFunctionsVec;
	const LPBYTE lpRoot;
	std::vector<DWORD>vLeafs;
	DWORD dwNewFunctionsCount;

	FUNCTION_TREE(const LPBYTE& lpFunctionRoot):
	blocksVec(0),
	newFunctionsVec(NEW_FUNCTIONS_BASE_SIZE),
	lpRoot(lpFunctionRoot),
	vLeafs(NULL) {
		using namespace std;
		blocksVec.emplace_back(make_unique<BLOCK>(lpFunctionRoot, 0xFFFFFFFF, NULL, NULL));
		dwNewFunctionsCount = NULL;
	}

	ErrorCode Trace();

	inline BOOLEAN splitBlock(BLOCK& SplitBlock, LPBYTE lpSplittingAddress, std::map<BYTE*, BLOCK*>& RootsMap);

	add_block addBlock(LPBYTE lpToAdd, DWORD dwIndex, DWORD dwParentIndex, DWORD dwHeight, std::map<BYTE*, BLOCK*>& RootsMap);

	void TransferUniqueChildren(BLOCK& OldParentBlock, BLOCK& NewParentBlock) const;

	inline BOOLEAN checkIfTraced(BLOCK& JustTracedBlock, std::map<BYTE*, BLOCK*>& RootsMap) const;

	void handleJump(LPBYTE lpResolvedJump, DWORD dwNewBlockIndex, const FUNCTION_TREE_TRACE_CTX& TraceContext);

	void Print() { using namespace std;
		for (unique_ptr<BLOCK>& block: blocksVec) {
			block->logIndex();
			block->print();
			cout << '\n';
		}
	}
};
