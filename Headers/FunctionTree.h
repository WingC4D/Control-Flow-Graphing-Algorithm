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
				CONDITIONAL_BRANCH_MASK = 0X80000000,
				C_JUMP_TAKEN_MASK		= 0X40000000,
				MAX_BRANCH_INDEX		= 0X1FFFFFFF,
				INVALID_BLOCK_INDEX		= 0xFFFFFFFF;

struct NEW_BRANCH_PREREQ {
	LPBYTE  lpRoot;
	DWORD  dwIndex,
				  dwParentIdx,
				  dwHeight;

	NEW_BRANCH_PREREQ(const LPBYTE& lpCandidate, const DWORD& dwNewBranchIndex, const DWORD& dwParentBranchIndex, const DWORD& dwNewBranchHeight):
	lpRoot(const_cast<BYTE*>(lpCandidate)),
	dwIndex(dwNewBranchIndex),
	dwParentIdx(dwParentBranchIndex),
	dwHeight(dwNewBranchHeight) {
	}
};

struct BLOCK_LANDMARKS {
	const BYTE* lpRoot;
	BYTE* lpEnd;

	BLOCK_LANDMARKS(const LPBYTE& lpRootAddress, const LPBYTE& lpEndAddress):
	lpRoot(lpRootAddress),
	lpEnd(lpEndAddress){
	}

};

struct BLOCK {
	std::unique_ptr<BLOCK_LANDMARKS> lpLandmarks;
	DWORD							  dwIndex;
	DWORD							  dwHeight;
	std::unique_ptr<LDE_STATE>		  ldeState;
	std::vector<DWORD>				  flowFromVec;
	std::vector<DWORD>				  flowToVec;

	BLOCK(const LPBYTE& lpStartAddress, const DWORD dwParentIdx, const DWORD& dwBranchIdx, const DWORD& dwBranchHeight):
	lpLandmarks(std::make_unique<BLOCK_LANDMARKS>(lpStartAddress, nullptr)),
	ldeState(std::make_unique<LDE_STATE>()),
	flowFromVec(NULL), flowToVec(NULL) {
		dwIndex = dwBranchIdx;
		dwHeight = dwBranchHeight;
		if (dwParentIdx != 0xFFFFFFFF) 
			flowFromVec.emplace_back(dwParentIdx);
		
	}

	IS_NEW_BRANCH Trace(std::vector<BYTE*>& NewFunctionsVec);

	IS_NEW_BRANCH TraceUntil(std::vector<BYTE*>& vNewFunctionsVec,  const LPBYTE& lpUntilAddress);

	void print() const; 

	void logIndex() const;

	inline BOOLEAN isInRange(const LPBYTE& CandidateLandmarks_t) const;

	BOOLEAN isInstructionHead(const LPBYTE& lpCandidate) const;

	void findNewEnd(const LPBYTE& lpInterlacingRoot) const;

	inline DWORD getIndex(void) const;
	
	inline void resize(const BYTE& sNewSize, const LPBYTE& lpNewEndAddress) const;
};

enum add_block : BYTE
{
	was_traced = 0,
	added	   = 1,
	split	   = 2
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
		blocksVec.insert(blocksVec.begin(),  make_unique<BLOCK>(lpFunctionRoot, 0xFFFFFFFF, NULL, NULL));
		dwNewFunctionsCount = NULL;
	}

	ErrorCode Trace();

	inline BOOLEAN splitBlock(BLOCK& Block, const LPBYTE& lpSplittingAddress, std::map<BYTE*, BLOCK*>& RootsMap, std::map<BYTE*, BLOCK*>& EndsMap);

	add_block addBlock(const NEW_BRANCH_PREREQ& NewBranchCtx, std::map<BYTE*, BLOCK*>& RootsMap, std::map<BYTE*, BLOCK*>& EndsMap);

	void TransferUniqueChildren(BLOCK& OldParentBlock, BLOCK& NewParentBlock) const;

	inline DWORD checkIfTraced(BLOCK& CandidateBlock, std::map<BYTE*, BLOCK*>& RootsMap, std::map<BYTE*, BLOCK*>& EndsMap) const;

	void handleConditionalJump(const LPBYTE& lpShallowAddress, const LPBYTE& lpDeepAddress, std::map<LPBYTE, BLOCK*>&RootsMap, std::map<LPBYTE, BLOCK*>&EndsMap, std::vector<DWORD>&explorationVec, BLOCK& CurrentBlock_t);

	void Print() { using namespace std;
		for (unique_ptr<BLOCK>& block: blocksVec) {
			block->logIndex();
			block->print();
			cout << '\n';
		}
	}
};
