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

BOOLEAN FUNCTION_TREE::splitBlock(BLOCK& SplitBlock, LPBYTE lpSplittingAddress, std::map<BYTE*, BLOCK*>& RootsMap) {
	if (!SplitBlock.isInRange(lpSplittingAddress)) 
		return FALSE;
	DWORD dwNewIndex = static_cast<DWORD>(blocksVec.size()),
		  dwAccumulatedLength			= NULL;
	BYTE  ucLastInstructionLen			= NULL,
		  i								= NULL,
	      ucOriginalInstructionCount	= SplitBlock.ldeState->instructionCount;
	for (BYTE Context: SplitBlock.ldeState->contextsArray) {
		if (SplitBlock.lpLandmarks->lpRoot + dwAccumulatedLength == lpSplittingAddress) {
			if (i) {
				blocksVec.emplace_back(std::make_unique<BLOCK>(lpSplittingAddress, SplitBlock.getIndex(), dwNewIndex, SplitBlock.dwHeight + 1));
				BLOCK& NewBlock					= *blocksVec[dwNewIndex];
				BYTE   NewBlockInstructionCount = NULL;
				for (; i + NewBlockInstructionCount < ucOriginalInstructionCount; NewBlockInstructionCount++) {
					NewBlock.ldeState->contextsArray[NewBlockInstructionCount]	  = SplitBlock.ldeState->contextsArray[NewBlockInstructionCount + i];
					NewBlock.ldeState->prefixCountArray[NewBlockInstructionCount] = SplitBlock.ldeState->prefixCountArray[NewBlockInstructionCount + i];
				}
				NewBlock.resize(NewBlockInstructionCount, SplitBlock.lpLandmarks->lpEnd);
				TransferUniqueChildren(SplitBlock, NewBlock);
				SplitBlock.resize(i, lpSplittingAddress - ucLastInstructionLen);
				RootsMap[const_cast<BYTE*>(NewBlock.lpLandmarks->lpRoot)] = blocksVec[NewBlock.getIndex()].get();
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

add_block FUNCTION_TREE::addBlock(LPBYTE lpToAdd, DWORD dwIndex, DWORD dwParentIndex, DWORD dwHeight, std::map<BYTE*, BLOCK*>& RootsMap) {
	if (RootsMap.contains(lpToAdd)) {
		return  was_traced;
	}
	auto upper_bound = RootsMap.upper_bound(lpToAdd);
	if (upper_bound != RootsMap.begin()) {
		BLOCK& block = *(--upper_bound)->second;
		if (block.isInRange(lpToAdd)) {
			if (splitBlock(block, lpToAdd, RootsMap)) {
				return split;
			}
		}
	}
	blocksVec.emplace_back(std::make_unique<BLOCK>(lpToAdd, dwParentIndex, dwIndex, dwHeight));
	return added;
}

FUNCTION_TREE::ErrorCode FUNCTION_TREE::Trace() {
	std::vector<DWORD>       explorationVec(1);
	std::map<LPBYTE, BLOCK*> RootsRefMap;
	RootsRefMap[const_cast<LPBYTE>(lpRoot)] = blocksVec[0].get();

	while (!explorationVec.empty()) {
		DWORD  dwCurrIdx	=  explorationVec[explorationVec.size() - 1],
			   dwVecSize	=  static_cast<DWORD>(blocksVec.size());
		BLOCK& CurrentBlock = *blocksVec[dwCurrIdx];
		if (dwVecSize == MAX_BRANCH_INDEX) {
			return failed;
		}
		explorationVec.pop_back();
		if (CurrentBlock.lpLandmarks->lpEnd) {
			continue;
		} 
		IS_NEW_BRANCH trace_result = CurrentBlock.Trace(newFunctionsVec);
		if (checkIfTraced(CurrentBlock, RootsRefMap)) {
			continue;
		}
		FUNCTION_TREE_TRACE_CTX trace_ctx = { .rootsMap = RootsRefMap, .currentBlock = CurrentBlock, .explorationVec = explorationVec };
		switch (trace_result) {
			case yes_reached_non_conditional_branch: {
				handleJump(LDE::ResolveJump(CurrentBlock.lpLandmarks->lpEnd), dwVecSize, trace_ctx);
				break;
			}
			case yes_reached_conditional_branch: {
				LPBYTE					   lpResolvedJump	 = LDE::ResolveJump(CurrentBlock.lpLandmarks->lpEnd),
										   lpNextInstruction = CurrentBlock.lpLandmarks->lpEnd + LDE::GetInstructionLenCtx(CurrentBlock.ldeState->contextsArray[CurrentBlock.ldeState->instructionCount - 1]);
				CONDITIONAL_JUMP_CTX cond_jump_ctx;
				lpNextInstruction < lpResolvedJump ?
					cond_jump_ctx = { .lpShallowAddress = lpNextInstruction, .lpDeepAddress = lpResolvedJump, .dwShallowIndex = dwVecSize | COND_BLOCK_MASK, .dwDeepIndex = dwVecSize + 1 | COND_BLOCK_MASK | C_JUMP_TAKEN_MASK }:
					cond_jump_ctx = { .lpShallowAddress = lpResolvedJump, .lpDeepAddress = lpNextInstruction, .dwShallowIndex = dwVecSize | COND_BLOCK_MASK | C_JUMP_TAKEN_MASK, .dwDeepIndex = dwVecSize + 1 | COND_BLOCK_MASK };

				handleJump(cond_jump_ctx.lpShallowAddress, cond_jump_ctx.dwShallowIndex ,trace_ctx);
				handleJump(cond_jump_ctx.lpDeepAddress, cond_jump_ctx.dwDeepIndex, trace_ctx);
				break;
			}
			case no_reached_ret: {
				vLeafs.push_back(CurrentBlock.getIndex());
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
	if (dwIndex & ENDS_UNCOND_JUMP) {
		std::cout << "* ";
	}
	if (dwIndex & COND_BLOCK_MASK) {
		dwIndex & C_JUMP_TAKEN_MASK ?
			std::cout << std::format("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Conditional Jump Taken)\n\n", dwIndex & MAX_BRANCH_INDEX, dwHeight):
			std::cout << std::format("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Conditional Jump Not Taken)\n\n", dwIndex & MAX_BRANCH_INDEX, dwHeight);
	} else {
		dwHeight ?
			std::cout << std::format("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Non Conditional)\n\n", dwIndex & 0x00FFFFFF, dwHeight):
			std::cout << "[!] Analysing Root Branch (Non Conditional)\n\n";
	}
}


void BLOCK::addResolvedCall(std::vector<LPBYTE>& NewFunctionVec, const LPBYTE& lpResolvedAddress) {
	bool was_added = false;
	for (LPBYTE lpStoredFunction: NewFunctionVec) {
		if (lpStoredFunction == lpResolvedAddress) {
			was_added = true;
			break;
		}
	}
	if (!was_added) {
		NewFunctionVec.emplace_back(lpResolvedAddress);
	}
}

void BLOCK::handleEndOfTrace(const LPBYTE& lpCurrentAddress, LDE_STATE& state) {
	state.contextsArray.resize(state.instructionCount);
	state.prefixCountArray.resize(state.instructionCount);
	ldeState		   = std::make_unique<LDE_STATE>(state);
	lpLandmarks->lpEnd = lpCurrentAddress;
}

IS_NEW_BRANCH BLOCK::Trace(_Out_ std::vector<BYTE *>& NewFunctionsVec) {
	LPBYTE	  lpReference = const_cast<BYTE*>(lpLandmarks->lpRoot);
	LDE_STATE state;
	while (state.instructionCount < ROOT_BRANCH_INSTRUCTION_COUNT) {
		BYTE ucInstructionLen = LDE::MapInstructionLen(lpReference, state);
		if (!ucInstructionLen) {
			return algorithm_failed;
		}
		LDE::prepareForNextStep(state);
		switch (LDE::checkForNewBlock(state, lpReference)) {
			case yes_reached_non_conditional_branch: {
				handleEndOfTrace(lpReference, state);
				return yes_reached_non_conditional_branch;
			}
			case yes_reached_conditional_branch: {
				handleEndOfTrace(lpReference, state);
				return yes_reached_conditional_branch;
			}
			case yes_is_call: {
				addResolvedCall(NewFunctionsVec, LDE::ResolveJump(lpReference));
				break;
			}
			case no_reached_ret: {
				handleEndOfTrace(lpReference, state);
				return no_reached_ret;
			}
			case algorithm_failed: {
				return algorithm_failed;
			}
			case no: {
				break;
			}
		}
		lpReference += ucInstructionLen;
	}
	return algorithm_failed;
}

IS_NEW_BRANCH BLOCK::TraceUntil(_Out_ std::vector<BYTE*>& vNewFunctionsVec, const LPBYTE& lpUntilAddress) {
	LPBYTE	  lpReference = const_cast<BYTE*>(lpLandmarks->lpRoot);
	LDE_STATE state;
	//logIndex();
	BYTE ucInstructionLen = 0;
	while (state.instructionCount < ROOT_BRANCH_INSTRUCTION_COUNT && lpUntilAddress <= lpLandmarks->lpRoot) {
		if (lpReference == lpUntilAddress && ucInstructionLen) {
			handleEndOfTrace(lpReference, state);
			return no;
		}
		ucInstructionLen = LDE::MapInstructionLen(lpReference, state);
		//LDE::logInstructionAndAddress(lpReference, state);
		LDE::prepareForNextStep(state);
		switch (LDE::checkForNewBlock(state, lpReference)) {
			case yes_reached_non_conditional_branch: {
				handleEndOfTrace(lpReference, state);
				return yes_reached_non_conditional_branch;
			}
			case yes_reached_conditional_branch: {
				handleEndOfTrace(lpReference, state);
				return yes_reached_conditional_branch;
			}
			case yes_is_call: {
				addResolvedCall(vNewFunctionsVec, LDE::ResolveJump(lpReference));
				break;
			}
			case no: { break; }
			case no_reached_ret: {
				handleEndOfTrace(lpReference, state);
				return no_reached_ret;
			}
			case algorithm_failed: { return algorithm_failed; }
		}
		lpReference += ucInstructionLen;
	}
	return algorithm_failed;
}

BOOLEAN FUNCTION_TREE::checkIfTraced(BLOCK& CandidateBlock, std::map<BYTE*, BLOCK*>& RootsMap) const {
	std::map<BYTE*, BLOCK*>::iterator prevBlock = RootsMap.upper_bound(const_cast<BYTE*>(CandidateBlock.lpLandmarks->lpRoot));
	if (prevBlock != RootsMap.end()) {
		BLOCK& CloseBlock = *prevBlock->second;
		if (CandidateBlock.isInRange(const_cast<BYTE*>(CloseBlock.lpLandmarks->lpRoot)) && CandidateBlock.dwIndex != CloseBlock.dwIndex) {
			CandidateBlock.findNewEnd(const_cast<BYTE*>(CloseBlock.lpLandmarks->lpRoot));
			TransferUniqueChildren(CandidateBlock, CloseBlock);
			return TRUE;
		}
	}
	return FALSE;
}

void BLOCK::print(void) const {
	if (!lpLandmarks->lpEnd) {
		std::cout << "[!] This Branch Is Not Traced Yet.";
	}
	DWORD dwAccumulatedLength = 0;
	BYTE i = 0;
	for (BYTE Context: ldeState->contextsArray) {
		LDE::logInstructionAndAddressCtx(const_cast<LPBYTE>(lpLandmarks->lpRoot) + dwAccumulatedLength, Context, i);
		dwAccumulatedLength += LDE::GetInstructionLenCtx(Context);
		i++;
	}
}

DWORD BLOCK::getIndex(void) const {
	return dwIndex & MAX_BRANCH_INDEX;
}

void FUNCTION_TREE::TransferUniqueChildren(BLOCK& OldParentBlock, BLOCK& NewParentBlock) const {
	if (OldParentBlock.flowToVec.empty()) {
		OldParentBlock.flowToVec.emplace_back(NewParentBlock.getIndex());
		NewParentBlock.flowFromVec.emplace_back(OldParentBlock.getIndex());
		return;
	}
	BOOLEAN g_state = FALSE;
	for (DWORD  child_idx: OldParentBlock.flowToVec) {
		BYTE parents_idx = 0;
		for (DWORD dwParentIndex: blocksVec[child_idx]->flowFromVec) {
			if (dwParentIndex == OldParentBlock.getIndex()) {
				blocksVec[child_idx]->flowFromVec[parents_idx] = NewParentBlock.getIndex();
				break;
			}
			parents_idx++;
		}
		g_state = TRUE;
		NewParentBlock.flowToVec.emplace_back(child_idx);
	}
	if (g_state) {
		OldParentBlock.flowToVec.clear();
		OldParentBlock.flowToVec.emplace_back(NewParentBlock.getIndex());
	}
}

void FUNCTION_TREE::handleJump(LPBYTE lpResolvedJump, DWORD dwNewBlockIndex, const FUNCTION_TREE_TRACE_CTX& TraceContext) {
	DWORD dwVecSize = static_cast<DWORD>(blocksVec.size());
	switch (addBlock(lpResolvedJump, dwNewBlockIndex, TraceContext.currentBlock.getIndex(), TraceContext.currentBlock.dwHeight + 1, TraceContext.rootsMap)) {
		case added:{
			TraceContext.currentBlock.flowToVec.emplace_back(dwVecSize);
			TraceContext.explorationVec.emplace_back(dwVecSize);
			TraceContext.rootsMap[lpResolvedJump] = blocksVec[dwVecSize].get();
			break;
		}
		case was_traced: {
			TraceContext.rootsMap.at(lpResolvedJump)->flowFromVec.emplace_back(TraceContext.currentBlock.getIndex());
			break;
		}
		case split: {
			break;
		}
	}
}