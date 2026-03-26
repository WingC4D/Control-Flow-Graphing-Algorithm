#include "FunctionTree.h"

BOOLEAN BLOCK::isInRange(const LPBYTE& CandidateLandmarks_t) const {
	if (!lpLandmarks->lpEnd) {
		return FALSE;
	}
	if (lpLandmarks->lpRoot > CandidateLandmarks_t) {
		return FALSE;
	}
	if (lpLandmarks->lpEnd  < CandidateLandmarks_t) {
		return FALSE;
	}
	return TRUE;
}

BOOLEAN BLOCK::isInstructionHead(const LPBYTE& lpCandidate) const {
	if (!lpLandmarks->lpEnd) return FALSE;
	DWORD dwAccumulatedLength = NULL;
	BYTE ucInstructionIdx	  = NULL;
	for (BYTE Context: ldeState->contextsArray) {
		if (lpLandmarks->lpRoot + dwAccumulatedLength == lpCandidate) {
			return TRUE;
		}
		dwAccumulatedLength += LDE::GetInstructionLenCtx(Context);
		ucInstructionIdx++;
	}
	return FALSE;
}

void BLOCK::resize(const BYTE& sNewSize, const LPBYTE& lpNewEndAddress) const {
	lpLandmarks->lpEnd		   = lpNewEndAddress;
	ldeState->instructionCount = sNewSize;
	ldeState->contextsArray.resize(sNewSize);
	ldeState->prefixCountArray.resize(sNewSize);
}

void BLOCK::findNewEnd(const LPBYTE& lpInterlacingRoot) const {
	DWORD dwAccumulatedLength   = NULL;
	BYTE  ucLastInstructionLen  = NULL,
	      cbNewInstructionCount = NULL;
	for (BYTE Context: ldeState->contextsArray) {
		if (const_cast<BYTE*>(lpLandmarks->lpRoot) + dwAccumulatedLength == lpInterlacingRoot) {
			if (cbNewInstructionCount) {
				resize(cbNewInstructionCount, const_cast<BYTE*>(lpInterlacingRoot) - ucLastInstructionLen);
			}
			return;
		}
		ucLastInstructionLen = LDE::GetInstructionLenCtx(Context);
		dwAccumulatedLength += ucLastInstructionLen;
		cbNewInstructionCount++;
	}
}

BOOLEAN FUNCTION_TREE::splitBlock(BLOCK& Block, const LPBYTE& lpSplittingAddress, std::map<BYTE*, BLOCK*>& RootsMap, std::map<BYTE*, BLOCK*>& EndsMap) {
	using namespace std;
	if (!Block.isInRange(lpSplittingAddress)) 
		return FALSE;
	DWORD dwNewIndex = static_cast<DWORD>(blocksVec.size()),
		  dwAccumulatedLength			= NULL;
	BYTE  ucLastInstructionLen			= NULL,
		  i								= NULL,
	      ucOriginalInstructionCount	= Block.ldeState->instructionCount;
	for (BYTE Context: Block.ldeState->contextsArray) {
		if (Block.lpLandmarks->lpRoot + dwAccumulatedLength == lpSplittingAddress) {
			if (i) {
				blocksVec.emplace_back(make_unique<BLOCK>(lpSplittingAddress, Block.getIndex(), dwNewIndex, Block.dwHeight + 1));
				BLOCK& NewBlock					= *blocksVec[dwNewIndex];
				BYTE   NewBlockInstructionCount = NULL;
				for (; i + NewBlockInstructionCount < ucOriginalInstructionCount; NewBlockInstructionCount++) {
					NewBlock.ldeState->contextsArray[NewBlockInstructionCount]	  = Block.ldeState->contextsArray[NewBlockInstructionCount + i];
					NewBlock.ldeState->prefixCountArray[NewBlockInstructionCount] = Block.ldeState->prefixCountArray[NewBlockInstructionCount + i];
				}
				NewBlock.resize(NewBlockInstructionCount, Block.lpLandmarks->lpEnd);
				TransferUniqueChildren(Block, NewBlock);
				Block.resize(i, lpSplittingAddress - ucLastInstructionLen);
				RootsMap[const_cast<BYTE*>(NewBlock.lpLandmarks->lpRoot)] = blocksVec[NewBlock.getIndex()].get();
				EndsMap[NewBlock.lpLandmarks->lpEnd]					  = blocksVec[NewBlock.getIndex()].get();
				EndsMap[Block.lpLandmarks->lpEnd]						  = blocksVec[Block.getIndex()].get();
			}
			break;
		}
		ucLastInstructionLen = LDE::GetInstructionLenCtx(Context);
		dwAccumulatedLength += ucLastInstructionLen;
		i++;
	}
	if (i == ucOriginalInstructionCount) {
		return FALSE;
	}
	return TRUE;
}

add_block FUNCTION_TREE::addBlock(const NEW_BRANCH_PREREQ& NewBranchCtx, std::map<BYTE*, BLOCK*>& RootsMap, std::map<BYTE*, BLOCK*>& EndsMap) {
	if (RootsMap.contains(NewBranchCtx.lpRoot)) {
		return  was_traced;
	}
	auto upper_bound = RootsMap.upper_bound(NewBranchCtx.lpRoot);
	if (upper_bound != RootsMap.begin()) {
		BLOCK& block = *(--upper_bound)->second;
		if (block.isInRange(NewBranchCtx.lpRoot)) {
			if (splitBlock(block, NewBranchCtx.lpRoot, RootsMap, EndsMap)) {
				return split;
			}
		}
	}
	blocksVec.emplace_back(std::make_unique<BLOCK>(NewBranchCtx.lpRoot, NewBranchCtx.dwParentIdx, NewBranchCtx.dwIndex, NewBranchCtx.dwHeight));
	return added;
}

FUNCTION_TREE::ErrorCode FUNCTION_TREE::Trace() {
	std::vector<DWORD>       explorationVec(1);
	std::map<LPBYTE, BLOCK*> RootsRefMap,
						     EndsRefMap;
	LPBYTE				     lpReference = lpRoot;
	RootsRefMap[const_cast<LPBYTE>(blocksVec[0]->lpLandmarks->lpRoot)] = blocksVec[0].get();

	while (!explorationVec.empty()) {
		DWORD		  dwCurrIdx	     =  explorationVec[explorationVec.size() - 1],
					  dwVecSize	     =  static_cast<DWORD>(blocksVec.size());
		BLOCK&		  CurrentBlock_t = *blocksVec[dwCurrIdx];

		if (dwVecSize == MAX_BRANCH_INDEX) 
			return failed;
		
		explorationVec.pop_back();

		if (CurrentBlock_t.lpLandmarks->lpEnd) 
			continue; 

		IS_NEW_BRANCH trace_result = CurrentBlock_t.Trace(newFunctionsVec);

		if (checkIfTraced(CurrentBlock_t, RootsRefMap,  EndsRefMap)) 
			continue; 

		switch (trace_result) {
			case yes_reached_non_conditional_branch: {
				lpReference		 = CurrentBlock_t.lpLandmarks->lpEnd;
				lpReference		 = LDE::ResolveJump(lpReference);
				add_block result = addBlock(NEW_BRANCH_PREREQ{ lpReference, dwVecSize,CurrentBlock_t.getIndex(), CurrentBlock_t.dwHeight + 1 }, RootsRefMap, EndsRefMap);
				if (result == added) {
					CurrentBlock_t.flowToVec.emplace_back(dwVecSize);
					explorationVec.push_back(dwVecSize);
					RootsRefMap[lpReference] = blocksVec[dwVecSize].get();
				} else if (result == was_traced) 
					RootsRefMap.at(lpReference)->flowFromVec.emplace_back(CurrentBlock_t.getIndex());
				break;
			}
			case yes_reached_conditional_branch: {
				lpReference					= CurrentBlock_t.lpLandmarks->lpEnd;
				BYTE     *lpNextInstruction = lpReference + LDE::GetInstructionLenCtx(CurrentBlock_t.ldeState->contextsArray[CurrentBlock_t.ldeState->instructionCount - 1]),
					     *lpResolvedJump	= LDE::ResolveJump(lpReference);
				BOOLEAN   bAdded			= FALSE;
				
				if (lpNextInstruction < lpResolvedJump) {
					handleConditionalJump(lpNextInstruction, lpResolvedJump, RootsRefMap, EndsRefMap, explorationVec, CurrentBlock_t);
				}
				else {
					handleConditionalJump(lpResolvedJump, lpNextInstruction, RootsRefMap, EndsRefMap, explorationVec, CurrentBlock_t);
				}
				break;
			}
			case no_reached_ret: {
				vLeafs.push_back(CurrentBlock_t.getIndex());
				break;
			}
			case yes_is_call:
			case algorithm_failed:
			case no: {
				return failed;
			}
		}
 	}
	Print();
 	return success;
}

void BLOCK::logIndex() const {
	using namespace std;
	if ((dwIndex & ENDS_UNCOND_JUMP)) {
		cout << "* ";
	}
	if (dwIndex & CONDITIONAL_BRANCH_MASK) {
		if (dwIndex & C_JUMP_TAKEN_MASK) { cout << format("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Conditional Jump Taken)\n\n", dwIndex & MAX_BRANCH_INDEX, dwHeight); }
		else { cout << format("[!] Analysing Branch #{:2d} & Of Height: #{:02d} (Conditional Jump Not Taken)\n\n", dwIndex & MAX_BRANCH_INDEX, dwHeight); }
	} else {
		if (!dwHeight) { cout << "[!] Analysing Root Branch (Non Conditional)\n\n";}
		else { cout << format("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Non Conditional)\n\n", dwIndex & 0x00FFFFFF, dwHeight); }
	}
}

IS_NEW_BRANCH BLOCK::Trace(_Out_ std::vector<BYTE *>& NewFunctionsVec) {
	LPBYTE	  lpReference = const_cast<BYTE*>(lpLandmarks->lpRoot);
	LDE_STATE state;
	while (state.instructionCount < ROOT_BRANCH_INSTRUCTION_COUNT) {
		BYTE ucInstructionLen = LDE::MapInstructionLen(lpReference, state);
		if (!ucInstructionLen) {
			return algorithm_failed;
		}
		switch (LDE::checkForNewBlock(state, lpReference)) {
			case yes_reached_non_conditional_branch: {
				lpLandmarks->lpEnd = lpReference;
				LDE::prepareForNextStep(state);
				state.contextsArray.resize(state.instructionCount);
				state.prefixCountArray.resize(state.instructionCount);
				ldeState = std::make_unique<LDE_STATE>(state);
				return yes_reached_non_conditional_branch;
			}
			case yes_reached_conditional_branch: {
				lpLandmarks->lpEnd = lpReference;
				LDE::prepareForNextStep(state);
				state.contextsArray.resize(state.instructionCount);
				state.prefixCountArray.resize(state.instructionCount);
				ldeState = std::make_unique<LDE_STATE>(state);
				return yes_reached_conditional_branch;
			}
			case yes_is_call: {
				NewFunctionsVec.push_back(LDE::ResolveJump(lpReference));
				break;
			}
			case no: {
				break;
			}
			case no_reached_ret: {
				lpLandmarks->lpEnd = lpReference;
				LDE::prepareForNextStep(state);
				state.contextsArray.resize(state.instructionCount);
				state.prefixCountArray.resize(state.instructionCount);
				ldeState = std::make_unique<LDE_STATE>(state);
				return no_reached_ret;
			}
			case algorithm_failed: {
				return algorithm_failed;
			}
		}
		LDE::prepareForNextStep(state);
		lpReference += ucInstructionLen;
	}
	return algorithm_failed;
}

IS_NEW_BRANCH BLOCK::TraceUntil(_Out_ std::vector<BYTE*>& vNewFunctionsVec, const LPBYTE& lpUntilAddress) {
	using namespace  std;
	LPBYTE	  lpReference = const_cast<BYTE*>(lpLandmarks->lpRoot);
	LDE_STATE state;
	//logIndex();
	BYTE ucInstructionLen = 0;
	while (state.instructionCount < ROOT_BRANCH_INSTRUCTION_COUNT && lpUntilAddress <= lpLandmarks->lpRoot) {
		if (lpReference == lpUntilAddress && ucInstructionLen) {
			lpLandmarks->lpEnd = lpReference - ucInstructionLen;
			ldeState = make_unique<LDE_STATE>(state);
			return no;
		}
		ucInstructionLen = LDE::MapInstructionLen(lpReference, state);
		//LDE::logInstructionAndAddress(lpReference, state);

		switch (LDE::checkForNewBlock(state, lpReference)) {
			case yes_reached_non_conditional_branch: {
				lpLandmarks->lpEnd = lpReference;
				LDE::prepareForNextStep(state);
				ldeState = make_unique<LDE_STATE>(state);
				return yes_reached_non_conditional_branch;
			}
			case yes_reached_conditional_branch: {
				lpLandmarks->lpEnd = lpReference;
				LDE::prepareForNextStep(state);
				ldeState = make_unique<LDE_STATE>(state);
				return yes_reached_conditional_branch;
			}
			case yes_is_call: {
				vNewFunctionsVec.push_back(LDE::ResolveJump(lpReference));
				break;
			}
			case no: { break; }
			case no_reached_ret: {
				lpLandmarks->lpEnd = lpReference;
				LDE::prepareForNextStep(state);
				ldeState = make_unique<LDE_STATE>(state);
				return no_reached_ret;
			}

			case algorithm_failed: { return algorithm_failed; }
		}
		LDE::prepareForNextStep(state);
		lpReference += ucInstructionLen;
	}
	return algorithm_failed;
}

DWORD FUNCTION_TREE::checkIfTraced(BLOCK& CandidateBlock, std::map<BYTE*, BLOCK*>& RootsMap, std::map<BYTE*, BLOCK*>& EndsMap) const {
	auto prevBlock = RootsMap.upper_bound(const_cast<BYTE*>(CandidateBlock.lpLandmarks->lpRoot));
	if (prevBlock != RootsMap.end()) {
		BLOCK& CloseBlock = *prevBlock->second;
		if (CandidateBlock.isInRange(const_cast<BYTE*>(CloseBlock.lpLandmarks->lpRoot)) && CandidateBlock.dwIndex != CloseBlock.dwIndex) {
			CandidateBlock.findNewEnd(const_cast<BYTE*>(CloseBlock.lpLandmarks->lpRoot));
			TransferUniqueChildren(CandidateBlock, CloseBlock);
			EndsMap[CandidateBlock.lpLandmarks->lpEnd] = blocksVec[CandidateBlock.getIndex()].get();
			EndsMap[CloseBlock.lpLandmarks->lpEnd]	   = blocksVec[CloseBlock.getIndex()].get();
			return TRUE;
		}
	}
	EndsMap[CandidateBlock.lpLandmarks->lpEnd] = blocksVec[CandidateBlock.getIndex()].get();
	return FALSE;

}

void BLOCK::print(void) const {
	using namespace std;
	if (!lpLandmarks->lpEnd) { cout << "[!] This Branch Is Not Traced Yet."; }
	DWORD dwAccumulatedLength = 0;
	for (BYTE i = 0; i < ldeState->instructionCount; i++) {
		LDE::logInstructionAndAddressCtx(const_cast<LPBYTE>(lpLandmarks->lpRoot) + dwAccumulatedLength, ldeState->contextsArray[i], i);
		dwAccumulatedLength += LDE::GetInstructionLenCtx(ldeState->contextsArray[i]);
	}
}

DWORD BLOCK::getIndex(void) const {
	return dwIndex & MAX_BRANCH_INDEX;
}


void FUNCTION_TREE::TransferUniqueChildren(BLOCK& OldParentBlock, BLOCK& NewParentBlock) const {
	if (OldParentBlock.flowToVec.empty()) {
		OldParentBlock.flowToVec.push_back(NewParentBlock.getIndex());
		NewParentBlock.flowFromVec.push_back(OldParentBlock.getIndex());
		return;
	}
	DWORD   outer_idx = NULL;
	BOOLEAN g_state   = FALSE;
	for (DWORD  child_idx: OldParentBlock.flowToVec) {
		BOOLEAN state = FALSE;
		BLOCK&  ChildBlock = *blocksVec[child_idx];
		BYTE    parents_idx = 0;
		for (DWORD dwParentIndex: ChildBlock.flowFromVec) {
			if (dwParentIndex == OldParentBlock.getIndex()) {
				ChildBlock.flowFromVec[parents_idx] = NewParentBlock.getIndex();
				break;
			}
			parents_idx++;
		}
		for (DWORD inner_idx = outer_idx; inner_idx < static_cast<DWORD>(NewParentBlock.flowToVec.size()); inner_idx++) {
			if (inner_idx == child_idx) {
				state = TRUE;
				break;
			}
		}
		if (state) {
			outer_idx++;
			continue;
		}
		g_state = TRUE;
		NewParentBlock.flowToVec.push_back(child_idx);
		outer_idx++;
	}
	if (g_state) {
		OldParentBlock.flowToVec.clear();
		OldParentBlock.flowToVec.push_back(NewParentBlock.getIndex());
	}
}

void FUNCTION_TREE::handleConditionalJump(const LPBYTE& lpShallowAddress, const LPBYTE& lpDeepAddress, std::map<LPBYTE, BLOCK*>&RootsMap, std::map<LPBYTE, BLOCK*>&EndsMap, std::vector<DWORD>&explorationVec, BLOCK& CurrentBlock_t) {
	BOOLEAN   bAdded = FALSE;
	DWORD	  dwVecSize = static_cast<DWORD>(blocksVec.size());
	
	add_block  result = addBlock(NEW_BRANCH_PREREQ{ lpShallowAddress, dwVecSize | CONDITIONAL_BRANCH_MASK,CurrentBlock_t.getIndex(), CurrentBlock_t.dwHeight + 1 },
		RootsMap, EndsMap);
	if (result == added) {
		CurrentBlock_t.flowToVec.emplace_back(dwVecSize);
		explorationVec.push_back(dwVecSize);
		RootsMap[lpShallowAddress] = blocksVec[dwVecSize].get();
		bAdded = TRUE;
	}
	else if (result == was_traced) RootsMap.at(lpShallowAddress)->flowFromVec.emplace_back(CurrentBlock_t.getIndex());

	result = addBlock(NEW_BRANCH_PREREQ{ lpDeepAddress, bAdded + (dwVecSize | CONDITIONAL_BRANCH_MASK | C_JUMP_TAKEN_MASK),CurrentBlock_t.getIndex(), CurrentBlock_t.dwHeight + 1 },
		RootsMap, EndsMap);
	if (result == added) {
		CurrentBlock_t.flowToVec.emplace_back(dwVecSize + bAdded);
		explorationVec.push_back(dwVecSize + bAdded);
		RootsMap[lpDeepAddress] = blocksVec[dwVecSize + bAdded].get();
	}
	else if (result == was_traced)
		RootsMap.at(lpDeepAddress)->flowFromVec.emplace_back(CurrentBlock_t.getIndex());
	
}