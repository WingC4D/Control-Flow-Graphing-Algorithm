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
				MAX_BRANCH_INDEX		= 0X1FFFFFFF;
enum ADD_BRANCH: BYTE {
	added = 0,
	split = 1,
	was_traced = 2
};
struct BLOCK_LANDMARKS;
struct NEW_BRANCH_PREREQ {
	const LPBYTE& lpRoot;
	const DWORD&  dwIndex,
				  dwParentIdx,
				  dwHeight;

	NEW_BRANCH_PREREQ(const LPBYTE& lpCandidate, const DWORD& dwNewBranchIndex, const DWORD& dwParentBranchIndex, const DWORD& dwNewBranchHeight):
	lpRoot(lpCandidate),
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

	BOOLEAN operator < (const BLOCK_LANDMARKS& other) const {
		return lpRoot < other.lpRoot;
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
	flowFromVec(0), flowToVec(0) {
		dwIndex = dwBranchIdx;
		dwHeight = dwBranchHeight;
		if (dwParentIdx != 0xFFFFFFFF) 
			flowFromVec.emplace_back(dwParentIdx);
		
	}

	BOOLEAN operator <(const BLOCK& other) const {
		return this->lpLandmarks < other.lpLandmarks;
	}

	IS_NEW_BRANCH Trace(std::vector<BYTE*>& vNewFunctionsVec);

	IS_NEW_BRANCH TraceUntil(std::vector<BYTE*>& vNewFunctionsVec,  const LPBYTE& lpUntilAddress);

	void Print() const; 

	void LogIndex() const;

	inline BOOLEAN IsLargeBlockHead() const;

	inline BOOLEAN isInRange(const LPBYTE& CandidateLandmarks_t) const;

	BOOLEAN IsInstructionHead(const LPBYTE& lpCandidate) const;

	void FindNewEnd(const LPBYTE& lpInterlacingRoot) const;

	inline DWORD GetIndex(void) const;
	
	inline void Resize(const BYTE& sNewSize, const LPBYTE& lpNewEndAddress) const;
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

	FUNCTION_TREE(const LPBYTE lpFunctionStartingAddress):
	blocksVec(0),
	newFunctionsVec(NEW_FUNCTIONS_BASE_SIZE),
	lpRoot(lpFunctionStartingAddress),
	vLeafs(0) {
		using namespace std;
		blocksVec.emplace_back(make_unique<BLOCK>(lpFunctionStartingAddress, 0xFFFFFFFF, 0, 0));
		dwNewFunctionsCount = NULL;
	}

	ErrorCode Trace();

	std::vector<DWORD> GetFullParentBlock(DWORD dwBlockIdx);

	inline static BOOLEAN DidJumpForward(const LPBYTE& lpJumpRoot, const LPBYTE& lpContinueRoot);

	inline BOOLEAN SplitBlock(BLOCK& Block, const LPBYTE& lpSplittingAddress, std::map<BYTE*, BLOCK*>& RootsMap, std::map<BYTE*, BLOCK*>& EndsMap);

	ADD_BRANCH AddBranch(const NEW_BRANCH_PREREQ& NewBranchCtx, std::map<BYTE*, BLOCK*>& RootsMap, std::map<BYTE*, BLOCK*>& EndsMap);

	void TransferUniqueChildren(BLOCK& OldParentBlock, BLOCK& NewParentBlock) const;

	inline DWORD CheckIfAlreadyTraced(BLOCK& CandidateBlock, std::map<BYTE*, BLOCK*>& RootsMap, std::map<BYTE*, BLOCK*>& EndsMap);

	void Print() {
		using namespace std;
		for (unique_ptr<BLOCK>& block: blocksVec) {
			block->LogIndex();
			block->Print();
			cout << '\n';
		}
	}
};
