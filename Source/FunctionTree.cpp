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
		dwAccumulatedLength += Lde::getInstructionLengthCtx(Context);
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
		ucLastInstructionLen = Lde::getInstructionLengthCtx(Context);
		dwAccumulatedLength += ucLastInstructionLen;
		cbNewInstructionCount++;
	}
}

BOOLEAN FunctionTree::splitBlock(BLOCK& SplitBlock, LPBYTE lpSplittingAddress, std::map<BYTE*, BLOCK*>& RootsMap) {
	if (!SplitBlock.isInRange(lpSplittingAddress)) {
		return false;
	}
	DWORD dwNewIndex					= static_cast<DWORD>(blocksVec.size()),
		  dwAccumulatedLength			= 0;
	BYTE  ucLastInstructionLen			= 0,
		  ucIteratedInstructions		= 0,
	      ucOriginalInstructionCount	= SplitBlock.ldeState->instructionCount;
	for (BYTE Context: SplitBlock.ldeState->contextsArray) {
		if (const_cast<BYTE*>(SplitBlock.lpLandmarks->lpRoot) + dwAccumulatedLength == lpSplittingAddress) {
			if (ucIteratedInstructions) {
				blocksVec.emplace_back(std::make_unique<BLOCK>(lpSplittingAddress, SplitBlock.getIndex(), dwNewIndex, SplitBlock.dwHeight + 1));
				BLOCK& NewBlock					= *blocksVec[dwNewIndex];
				BYTE   NewBlockInstructionCount = 0;
				for (; ucIteratedInstructions + NewBlockInstructionCount < ucOriginalInstructionCount; NewBlockInstructionCount++) {
					NewBlock.ldeState->contextsArray[NewBlockInstructionCount]	  = SplitBlock.ldeState->contextsArray[NewBlockInstructionCount + ucIteratedInstructions];
					NewBlock.ldeState->prefixCountArray[NewBlockInstructionCount] = SplitBlock.ldeState->prefixCountArray[NewBlockInstructionCount + ucIteratedInstructions];
				}
				NewBlock.resize(NewBlockInstructionCount, SplitBlock.lpLandmarks->lpEnd);
				transferUniqueChildren(SplitBlock, NewBlock);
				SplitBlock.resize(ucIteratedInstructions, lpSplittingAddress - ucLastInstructionLen);
				RootsMap[lpSplittingAddress] = blocksVec[dwNewIndex].get();
			}
			break;
		}
		ucLastInstructionLen = Lde::getInstructionLengthCtx(Context);
		dwAccumulatedLength += ucLastInstructionLen;
		ucIteratedInstructions++;
	}
	if (ucIteratedInstructions == ucOriginalInstructionCount) {
		return false;
	}
	return true;
}

AddBlock FunctionTree::addBlock(LPBYTE lpToAdd, DWORD dwIndex, DWORD dwParentIndex, DWORD dwHeight, std::map<BYTE*, BLOCK*>& RootsMap) {
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

FunctionTree::ErrorCode FunctionTree::Trace() {
	std::vector<DWORD>       ExplorationVec(1);
	std::map<LPBYTE, BLOCK*> RootsRefMap;
	RootsRefMap[const_cast<LPBYTE>(lpRoot)] = blocksVec[0].get();
	while (!ExplorationVec.empty()) {
		DWORD  dwCurrIdx	=  ExplorationVec[ExplorationVec.size() - 1],
			   dwVecSize	=  static_cast<DWORD>(blocksVec.size());
		BLOCK& CurrentBlock = *blocksVec[dwCurrIdx];
		if (dwVecSize == MAX_BRANCH_INDEX) {
			return failed;
		}
		ExplorationVec.pop_back();
		if (CurrentBlock.lpLandmarks->lpEnd) {
			continue;
		} 
		IsNewBranch trace_result = CurrentBlock.trace(newFunctionsVec);
		if (checkIfTraced(CurrentBlock, RootsRefMap)) {
			continue;
		}
		FunctionTreeTraceCtx TraceContext = { .rootsMap = RootsRefMap, .currentBlock = CurrentBlock, .explorationVec = ExplorationVec };
		switch (trace_result) {
			case IsNewBranch::yes_reached_non_conditional_branch: {
				handleJump(Lde::resolveJump(CurrentBlock.lpLandmarks->lpEnd), dwVecSize, TraceContext);
				break;
			}
			case IsNewBranch::yes_reached_conditional_branch: {
				LPBYTE				 lpResolvedJump	   = Lde::resolveJump(CurrentBlock.lpLandmarks->lpEnd),
									 lpNextInstruction = CurrentBlock.lpLandmarks->lpEnd + Lde::getInstructionLengthCtx(CurrentBlock.ldeState->contextsArray[CurrentBlock.ldeState->instructionCount - 1]);
				ConditionalJumpCtx   ConditionalJumpContext;
				lpNextInstruction < lpResolvedJump ?
					ConditionalJumpContext = { .lpShallowAddress = lpNextInstruction, .lpDeepAddress = lpResolvedJump, .dwShallowIndex = dwVecSize | COND_BLOCK_MASK, .dwDeepIndex = dwVecSize + 1 | COND_BLOCK_MASK | C_JUMP_TAKEN_MASK }:
					ConditionalJumpContext = { .lpShallowAddress = lpResolvedJump, .lpDeepAddress = lpNextInstruction, .dwShallowIndex = dwVecSize | COND_BLOCK_MASK | C_JUMP_TAKEN_MASK, .dwDeepIndex = dwVecSize + 1 | COND_BLOCK_MASK };

				handleJump(ConditionalJumpContext.lpShallowAddress, ConditionalJumpContext.dwShallowIndex ,TraceContext);
				handleJump(ConditionalJumpContext.lpDeepAddress, ConditionalJumpContext.dwDeepIndex, TraceContext);
				break;
			}
			case IsNewBranch::no_reached_ret: {
				vLeafs.push_back(CurrentBlock.getIndex());
				break;
			}
			case IsNewBranch::yes_is_call:
			case IsNewBranch::algorithm_failed:
			case IsNewBranch::no: {
				return failed;
			}
		}
 	}
	print();
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

void BLOCK::addResolvedCall(std::vector<unsigned char *>& NewFunctionVec, unsigned char *resolved_address) {
	bool was_added = false;
	for (unsigned char * stored_func_address: NewFunctionVec) {
		if (stored_func_address == resolved_address) {
			was_added = true;
			break;
		}
	}
	if (!was_added) {
		NewFunctionVec.emplace_back(resolved_address);
	}
}

void BLOCK::handleEndOfTrace(LPBYTE lpCurrentAddress, LdeState& state) {
	state.contextsArray.resize(state.instructionCount);
	state.prefixCountArray.resize(state.instructionCount);
	ldeState		   = std::make_unique<LdeState>(state);
	lpLandmarks->lpEnd = lpCurrentAddress;
}

IsNewBranch BLOCK::trace(_Out_ std::vector<BYTE *>& NewFunctionsVec) {
	LPBYTE	  lpReference = const_cast<BYTE*>(lpLandmarks->lpRoot);
	LdeState state;
	while (state.instructionCount < ROOT_BRANCH_INSTRUCTION_COUNT && state.status == success) {
		BYTE ucInstructionLen = Lde::mapInstructionLength(lpReference, state.currInstructionContext, state.status, state.prefixCountArray[state.instructionCount]);
		if (!ucInstructionLen) {
			return algorithm_failed;
		}
		Lde::prepareForNextStep(state);
		switch (Lde::checkForNewBlock(state, lpReference)) {
			case yes_reached_non_conditional_branch: {
				handleEndOfTrace(lpReference, state);
				return yes_reached_non_conditional_branch;
			}
			case yes_reached_conditional_branch: {
				handleEndOfTrace(lpReference, state);
				return yes_reached_conditional_branch;
			}
			case yes_is_call: {
				addResolvedCall(NewFunctionsVec, Lde::resolveJump(lpReference));
				break;
			}
			case no_reached_ret: {
				handleEndOfTrace(lpReference, state);
				return no_reached_ret;
			}
			default:
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

IsNewBranch BLOCK::TraceUntil(_Out_ std::vector<unsigned char*>& NewFunctionsVec, _In_ const unsigned char* until_address) {
	unsigned char* reference_ptr	  = const_cast<unsigned char*>(lpLandmarks->lpRoot),
				   instruction_length = 0;
	LdeState State;
#ifdef DEBUG
	logIndex();
#endif
	while (State.instructionCount < ROOT_BRANCH_INSTRUCTION_COUNT && until_address > reference_ptr) {
		if (reference_ptr == until_address && instruction_length) {
			handleEndOfTrace(reference_ptr, State);
			return IsNewBranch::no;
		}
		instruction_length = Lde::mapInstructionLength(reference_ptr, State.currInstructionContext, State.status, State.prefixCountArray[State.instructionCount]);
#ifdef DEBUG
		Lde::logInstructionAndAddress(reference_ptr, State);
#endif
		Lde::prepareForNextStep(State);
		switch (Lde::checkForNewBlock(State, reference_ptr)) {
			case IsNewBranch::yes_reached_non_conditional_branch: {
				handleEndOfTrace(reference_ptr, State);
				return IsNewBranch::yes_reached_non_conditional_branch;
			}
			case IsNewBranch::yes_reached_conditional_branch: {
				handleEndOfTrace(reference_ptr, State);
				return IsNewBranch::yes_reached_conditional_branch;
			}
			case IsNewBranch::yes_is_call: {
				addResolvedCall(NewFunctionsVec, Lde::resolveJump(reference_ptr));
				break;
			}
			case IsNewBranch::no: {
				break;
			}
			case IsNewBranch::no_reached_ret: {
				handleEndOfTrace(reference_ptr, State);
				return IsNewBranch::no_reached_ret;
			}
			default:
			case IsNewBranch::algorithm_failed: {
				return IsNewBranch::algorithm_failed;
			}
		}
		reference_ptr += instruction_length;
	}
	return IsNewBranch::algorithm_failed;
}

BOOLEAN FunctionTree::checkIfTraced(BLOCK& JustTracedBlock, std::map<BYTE*, BLOCK*>& RootsMap) const {
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
	transferUniqueChildren(JustTracedBlock, *itNextBlock->second);
	return true;
}

void BLOCK::print() const {
	if (!lpLandmarks->lpEnd) {
		std::println("[!] This Branch Is Not Traced Yet.");
	}
	for (DWORD dwAccumulatedLength = 0, i = 0; BYTE Context: ldeState->contextsArray) {
		Lde::logInstructionAndAddressCtx(const_cast<LPBYTE>(lpLandmarks->lpRoot) + dwAccumulatedLength, Context, static_cast<BYTE>(i));
		dwAccumulatedLength += Lde::getInstructionLengthCtx(Context);
		if (i == 0xFF) {
			std::println("Hit an error while printing Block #{:03d}", dwIndex);
			return;
		}
		i++;
	}
}

DWORD BLOCK::getIndex() const {
	return dwIndex & MAX_BRANCH_INDEX;
}

void FunctionTree::transferUniqueChildren(BLOCK& OldParentBlock, BLOCK& NewParentBlock) const {
	if (OldParentBlock.flowToVec.empty()) {
		OldParentBlock.flowToVec.emplace_back(NewParentBlock.getIndex());
		NewParentBlock.flowFromVec.emplace_back(OldParentBlock.getIndex());
		return;
	}
	BOOLEAN transferred_parent = false;
	for (DWORD  child_idx: OldParentBlock.flowToVec) {
		for (BYTE parents_idx = 0; DWORD dwParentIndex: blocksVec[child_idx]->flowFromVec) {
			if (dwParentIndex == OldParentBlock.getIndex()) {
				blocksVec[child_idx]->flowFromVec[parents_idx] = NewParentBlock.getIndex();
				break;
			}
			parents_idx++;
		}
		transferred_parent = true;
		NewParentBlock.flowToVec.emplace_back(child_idx);
	}
	if (transferred_parent) {
		OldParentBlock.flowToVec.clear();
		OldParentBlock.flowToVec.emplace_back(NewParentBlock.getIndex());
	}
}

void FunctionTree::handleJump(const LPBYTE resolved_address, const DWORD new_block_idx, const FunctionTreeTraceCtx& TraceContext) {
	DWORD vector_size = static_cast<DWORD>(blocksVec.size());
	switch (addBlock(resolved_address, new_block_idx, TraceContext.currentBlock.getIndex(), TraceContext.currentBlock.dwHeight + 1, TraceContext.rootsMap)) {
		case added: {
			TraceContext.currentBlock.flowToVec.emplace_back(vector_size);
			TraceContext.explorationVec.emplace_back(vector_size);
			TraceContext.rootsMap[resolved_address] = blocksVec[vector_size].get();
			break;
		}
		case was_traced: {
			TraceContext.rootsMap.at(resolved_address)->flowFromVec.emplace_back(TraceContext.currentBlock.getIndex());
			break;
		}
		case split: {
			break;
		}
	}
}