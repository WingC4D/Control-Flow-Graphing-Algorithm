#include "FunctionTree.h"

BOOLEAN BLOCK::isInRange(LPBYTE CandidateLandmarks_t) const {
	if (!lpLandmarks->lpEnd) {
		return false;
	}
	if (lpLandmarks->lpRoot > CandidateLandmarks_t) {
		return false;
	}
	if (lpLandmarks->lpEnd  < CandidateLandmarks_t) {
		return false;
	}
	return true;
}

BOOLEAN BLOCK::isInstructionHead(LPBYTE lpCandidate) const {
	if (!lpLandmarks->lpEnd) {
		return false;
	}
	
	for (DWORD dwAccumulatedLength = 0; BYTE Context: ldeState->contextsArray) {
		if (lpLandmarks->lpRoot + dwAccumulatedLength == lpCandidate) {
			return true;
		}
		dwAccumulatedLength += LDE::GetInstructionLenCtx(Context);
	}
	return false;
}

void BLOCK::resize(BYTE sNewSize, LPBYTE lpNewEndAddress) const {
	if (sNewSize && lpNewEndAddress) {
		lpLandmarks->lpEnd		   = lpNewEndAddress;
		ldeState->instructionCount = sNewSize;
		ldeState->contextsArray.resize(sNewSize);
		ldeState->prefixCountArray.resize(sNewSize);
	}
}

void BLOCK::findNewEnd(LPBYTE lpInterlacingRoot) const {
	DWORD dwAccumulatedLength   = 0;
	BYTE  ucLastInstructionLen  = 0,
	      cbNewInstructionCount = 0;
	for (BYTE Context: ldeState->contextsArray) {
		if (const_cast<BYTE*>(lpLandmarks->lpRoot) + dwAccumulatedLength == lpInterlacingRoot) {
			if (cbNewInstructionCount) {
				resize(cbNewInstructionCount, lpInterlacingRoot - ucLastInstructionLen);
			}
			return;
		}
		ucLastInstructionLen = LDE::GetInstructionLenCtx(Context);
		dwAccumulatedLength += ucLastInstructionLen;
		cbNewInstructionCount++;
	}
}

BOOLEAN FUNCTION_TREE::splitBlock(BLOCK& SplitBlock, LPBYTE lpSplittingAddress, std::map<BYTE*, BLOCK*>& RootsMap) {
	if (!SplitBlock.isInRange(lpSplittingAddress)) {
		return false;
	}
	DWORD dwNewIndex					= static_cast<DWORD>(blocksVec.size()),
		  dwAccumulatedLength			= 0;
	BYTE  ucLastInstructionLen			= 0,
		  ucIteratedInstructions		= 0,
	      ucOriginalInstructionCount	= SplitBlock.ldeState->instructionCount;
	for (BYTE Context: SplitBlock.ldeState->contextsArray) {
		if (SplitBlock.lpLandmarks->lpRoot + dwAccumulatedLength == lpSplittingAddress) {
			if (ucIteratedInstructions) {
				blocksVec.emplace_back(std::make_unique<BLOCK>(lpSplittingAddress, SplitBlock.getIndex(), dwNewIndex, SplitBlock.dwHeight + 1));
				BLOCK& NewBlock					= *blocksVec[dwNewIndex];
				BYTE   NewBlockInstructionCount = 0;
				for (; ucIteratedInstructions + NewBlockInstructionCount < ucOriginalInstructionCount; NewBlockInstructionCount++) {
					NewBlock.ldeState->contextsArray[NewBlockInstructionCount]	  = SplitBlock.ldeState->contextsArray[NewBlockInstructionCount + ucIteratedInstructions];
					NewBlock.ldeState->prefixCountArray[NewBlockInstructionCount] = SplitBlock.ldeState->prefixCountArray[NewBlockInstructionCount + ucIteratedInstructions];
				}
				NewBlock.resize(NewBlockInstructionCount, SplitBlock.lpLandmarks->lpEnd);
				TransferUniqueChildren(SplitBlock, NewBlock);
				SplitBlock.resize(ucIteratedInstructions, lpSplittingAddress - ucLastInstructionLen);
				RootsMap[lpSplittingAddress] = blocksVec[dwNewIndex].get();
			}
			break;
		}
		ucLastInstructionLen = LDE::GetInstructionLenCtx(Context);
		dwAccumulatedLength += ucLastInstructionLen;
		ucIteratedInstructions++;
	}
	if (ucIteratedInstructions == ucOriginalInstructionCount) {
		return false;
	}
	return true;
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
				LPBYTE				 lpResolvedJump	   = LDE::ResolveJump(CurrentBlock.lpLandmarks->lpEnd),
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
	if (dwIndex & COND_BLOCK_MASK) {
		dwIndex & C_JUMP_TAKEN_MASK ?
			std::println("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Conditional Jump Taken)\n", dwIndex & MAX_BRANCH_INDEX, dwHeight):
			std::println("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Conditional Jump Not Taken)\n", dwIndex & MAX_BRANCH_INDEX, dwHeight);
	} else {
		dwHeight ?
			std::println("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Non Conditional)\n", dwIndex & 0x00FFFFFF, dwHeight):
			std::println("[!] Analysing Root Branch (Non Conditional)\n");
	}
}


void BLOCK::addResolvedCall(std::vector<LPBYTE>& NewFunctionVec, LPBYTE lpResolvedAddress) {
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

void BLOCK::handleEndOfTrace(LPBYTE lpCurrentAddress, LDE_STATE& state) {
	state.contextsArray.resize(state.instructionCount);
	state.prefixCountArray.resize(state.instructionCount);
	ldeState		   = std::make_unique<LDE_STATE>(state);
	lpLandmarks->lpEnd = lpCurrentAddress;
}

IS_NEW_BRANCH BLOCK::Trace(_Out_ std::vector<BYTE *>& NewFunctionsVec) {
	LPBYTE	  lpReference = const_cast<BYTE*>(lpLandmarks->lpRoot);
	LDE_STATE state;
	while (state.instructionCount < ROOT_BRANCH_INSTRUCTION_COUNT && state.ecStatus == success) {
		BYTE ucInstructionLen = LDE::mapInstructionLen(lpReference, state.curr_instruction_ctx, state.ecStatus, state.prefixCountArray[state.instructionCount]);
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

IS_NEW_BRANCH BLOCK::TraceUntil(_Out_ std::vector<BYTE*>& vNewFunctionsVec, LPBYTE lpUntilAddress) {
	LPBYTE	  lpReference = const_cast<BYTE*>(lpLandmarks->lpRoot);
	LDE_STATE state;
#ifdef DEBUG
	logIndex();
#endif
	BYTE ucInstructionLen = 0;
	while (state.instructionCount < ROOT_BRANCH_INSTRUCTION_COUNT && lpUntilAddress <= lpLandmarks->lpRoot) {
		if (lpReference == lpUntilAddress && ucInstructionLen) {
			handleEndOfTrace(lpReference, state);
			return no;
		}
		ucInstructionLen = LDE::mapInstructionLen(lpReference, state.curr_instruction_ctx, state.ecStatus, state.prefixCountArray[state.instructionCount]);
#ifdef DEBUG
		LDE::logInstructionAndAddress(lpReference, state);
#endif
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

BOOLEAN FUNCTION_TREE::checkIfTraced(BLOCK& JustTracedBlock, std::map<BYTE*, BLOCK*>& RootsMap) const {
	std::map<BYTE*, BLOCK*>::iterator itNextBlock = RootsMap.upper_bound(const_cast<BYTE*>(JustTracedBlock.lpLandmarks->lpRoot));
	if (itNextBlock == RootsMap.end()) {
		return false;
	}
	if (JustTracedBlock.dwIndex == itNextBlock->second->dwIndex) {
		return false;
	}
	if (!JustTracedBlock.isInRange(const_cast<BYTE*>(itNextBlock->second->lpLandmarks->lpRoot))) {
		return false;
	}
	JustTracedBlock.findNewEnd(const_cast<BYTE*>(itNextBlock->second->lpLandmarks->lpRoot));
	TransferUniqueChildren(JustTracedBlock, *itNextBlock->second);
	return true;
}

void BLOCK::print(void) const {
	if (!lpLandmarks->lpEnd) {
		std::println("[!] This Branch Is Not Traced Yet.");
	}
	for (DWORD dwAccumulatedLength = 0, i = 0; BYTE Context: ldeState->contextsArray) {
		LDE::logInstructionAndAddressCtx(const_cast<LPBYTE>(lpLandmarks->lpRoot) + dwAccumulatedLength, Context, static_cast<BYTE>(i));
		dwAccumulatedLength += LDE::GetInstructionLenCtx(Context);
		if (i == 0xFF) {
			std::println("Hit an error while printing Block #{:03d}", dwIndex);
			return;
		}
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
	bool g_state = false;
	for (BYTE parents_idx = 0; DWORD  child_idx: OldParentBlock.flowToVec) {
		for (DWORD dwParentIndex: blocksVec[child_idx]->flowFromVec) {
			if (dwParentIndex == OldParentBlock.getIndex()) {
				blocksVec[child_idx]->flowFromVec[parents_idx] = NewParentBlock.getIndex();
				break;
			}
			parents_idx++;
		}
		g_state = true;
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