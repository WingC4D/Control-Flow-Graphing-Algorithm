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

BOOLEAN BLOCK::IsInstructionHead(const LPBYTE& lpCandidate) const {
	if (!lpLandmarks->lpEnd) return FALSE;
	DWORD dwAccumulatedLength = NULL;
	BYTE ucInstructionIdx	  = NULL;
	for (BYTE Context: ldeState->contexts_arr) {
		if (lpLandmarks->lpRoot + dwAccumulatedLength == lpCandidate) {
			return TRUE;
		}
		dwAccumulatedLength += LDE::GetInstructionLenCtx(Context);
		ucInstructionIdx++;
	}
	return FALSE;
}

void BLOCK::Resize(const BYTE& sNewSize, const LPBYTE& lpNewEndAddress) const {
	lpLandmarks->lpEnd				   = lpNewEndAddress;
	ldeState->cb_count_of_instructions = sNewSize;
	ldeState->contexts_arr.resize(sNewSize);
	ldeState->prefix_count_arr.resize(sNewSize);
}

void BLOCK::FindNewEnd(const LPBYTE& lpInterlacingRoot) const {
	DWORD dwAccumulatedLength   = NULL;
	BYTE  ucLastInstructionLen  = NULL,
	      cbNewInstructionCount = NULL;
	for (BYTE Context: ldeState->contexts_arr) {
		if (const_cast<BYTE*>(lpLandmarks->lpRoot) + dwAccumulatedLength == lpInterlacingRoot) {
			if (cbNewInstructionCount) {
				Resize(cbNewInstructionCount, const_cast<BYTE*>(lpInterlacingRoot) - ucLastInstructionLen);
			}
			return;
		}
		ucLastInstructionLen = LDE::GetInstructionLenCtx(Context);
		dwAccumulatedLength += ucLastInstructionLen;
		cbNewInstructionCount++;
	}
}

BOOLEAN FUNCTION_TREE::SplitBlock(BLOCK& Block, const LPBYTE& lpSplittingAddress, std::map<BYTE*, BLOCK*>& RootsMap, std::map<BYTE*, BLOCK*>& EndsMap) {
	using namespace std;
	if (!Block.isInRange(lpSplittingAddress)) 
		return FALSE;
	DWORD dwNewIndex = static_cast<DWORD>(blocksVec.size()),
		  dwAccumulatedLength			= NULL;
	BYTE  ucLastInstructionLen			= NULL,
		  i								= NULL,
	      ucOriginalInstructionCount	= Block.ldeState->cb_count_of_instructions;
	for (BYTE Context: Block.ldeState->contexts_arr) {
		if (Block.lpLandmarks->lpRoot + dwAccumulatedLength == lpSplittingAddress) {
			if (i) {
				blocksVec.emplace_back(make_unique<BLOCK>(lpSplittingAddress, Block.GetIndex(), dwNewIndex, Block.dwHeight + 1));
				BLOCK& NewBlock					= *blocksVec[dwNewIndex];
				BYTE   NewBlockInstructionCount = NULL;
				for (; i + NewBlockInstructionCount < ucOriginalInstructionCount; NewBlockInstructionCount++) {
					NewBlock.ldeState->contexts_arr[NewBlockInstructionCount]	   = Block.ldeState->contexts_arr[NewBlockInstructionCount + i];
					NewBlock.ldeState->prefix_count_arr[NewBlockInstructionCount] = Block.ldeState->prefix_count_arr[NewBlockInstructionCount + i];
				}
				NewBlock.Resize(NewBlockInstructionCount, Block.lpLandmarks->lpEnd);
				TransferUniqueChildren(Block, NewBlock);
				Block.Resize(i, lpSplittingAddress - ucLastInstructionLen);
				RootsMap[const_cast<BYTE*>(NewBlock.lpLandmarks->lpRoot)] = *reinterpret_cast<BLOCK**>(&blocksVec[NewBlock.GetIndex()]);
				EndsMap[NewBlock.lpLandmarks->lpEnd]					  = *reinterpret_cast<BLOCK**>(&blocksVec[NewBlock.GetIndex()]);
				EndsMap[Block.lpLandmarks->lpEnd]						  = *reinterpret_cast<BLOCK**>(&blocksVec[Block.GetIndex()]);
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

ADD_BRANCH FUNCTION_TREE::AddBranch(const NEW_BRANCH_PREREQ& NewBranchCtx, std::map<BYTE*, BLOCK*>& RootsMap, std::map<BYTE*, BLOCK*>& EndsMap) { using namespace std;
	auto lpBlock = --RootsMap.upper_bound(NewBranchCtx.lpRoot);
	if (lpBlock->second->isInRange(NewBranchCtx.lpRoot)) {
		if (SplitBlock(*lpBlock->second, NewBranchCtx.lpRoot, RootsMap, EndsMap)) {
			return split;
		}
	}
	blocksVec.push_back(make_unique<BLOCK>(NewBranchCtx.lpRoot, NewBranchCtx.dwParentIdx, NewBranchCtx.dwIndex, NewBranchCtx.dwHeight));
	return added;
}

FUNCTION_TREE::ErrorCode FUNCTION_TREE::Trace() { using namespace std;
	vector<DWORD> explorationVec(1);
	map<LPBYTE, BLOCK*> RootsRefMap,
						EndsRefMap;
	LPBYTE				lpReference = lpRoot;
	RootsRefMap[const_cast<LPBYTE>(blocksVec[0]->lpLandmarks->lpRoot)] = *reinterpret_cast<BLOCK**>(&blocksVec[0]);

	while (!explorationVec.empty()) {
		DWORD		  dwCurrIdx	     =  explorationVec[explorationVec.size() - 1],
					  dwVecSize	     =  static_cast<DWORD>(blocksVec.size());
		BLOCK&		  CurrentBlock_t = *blocksVec[dwCurrIdx];
		if (!dwVecSize) {
			return failed;
		}
		if (CurrentBlock_t.lpLandmarks->lpEnd) {
			explorationVec.pop_back();
			continue;
		}
		IS_NEW_BRANCH trace_result = CurrentBlock_t.Trace(newFunctionsVec);

		if (CheckIfAlreadyTraced(CurrentBlock_t, RootsRefMap,  EndsRefMap)) {
			explorationVec.pop_back();
			continue;
		}

		switch (trace_result) {
			case yes_reached_non_conditional_branch: {
				lpReference = CurrentBlock_t.lpLandmarks->lpEnd;
				lpReference = LDE::ResolveJump(lpReference);
				explorationVec.pop_back();
				if (!RootsRefMap.contains(lpReference)) {
					if (added == AddBranch(NEW_BRANCH_PREREQ{ lpReference, dwVecSize,
						CurrentBlock_t.GetIndex(), CurrentBlock_t.dwHeight + 1 },  RootsRefMap, EndsRefMap)) {
						CurrentBlock_t.flowToVec.emplace_back(dwVecSize);
						explorationVec.push_back(dwVecSize);
						RootsRefMap[lpReference] = *reinterpret_cast<BLOCK**>(&blocksVec[dwVecSize]);
					}
				}
				break;
			}
			case yes_reached_conditional_branch: {
				explorationVec.pop_back();
				lpReference				  = CurrentBlock_t.lpLandmarks->lpEnd;
				BYTE* lpNextInstruction   = lpReference + LDE::GetInstructionLenCtx(CurrentBlock_t.ldeState->contexts_arr[CurrentBlock_t.ldeState->cb_count_of_instructions - 1]);
				BYTE* lpResolvedJump	  = LDE::ResolveJump(lpReference);
				BOOLEAN bAdded			  = FALSE;
				if (lpNextInstruction < lpResolvedJump) {
					if (!RootsRefMap.contains(lpNextInstruction)) {
						if (added == AddBranch(NEW_BRANCH_PREREQ{ lpNextInstruction, dwVecSize | CONDITIONAL_BRANCH_MASK,
							CurrentBlock_t.GetIndex(), CurrentBlock_t.dwHeight + 1 }, RootsRefMap, EndsRefMap)) {
							CurrentBlock_t.flowToVec.emplace_back(dwVecSize);
							explorationVec.push_back(dwVecSize);
							RootsRefMap[lpNextInstruction] = *reinterpret_cast<BLOCK**>(&blocksVec[dwVecSize]);
							bAdded						   = TRUE;
						}
					} else {
						RootsRefMap.at(lpNextInstruction)->flowFromVec.emplace_back(CurrentBlock_t.GetIndex());
					}
					if (!RootsRefMap.contains(lpResolvedJump)) {
						if (added == AddBranch(NEW_BRANCH_PREREQ{ lpResolvedJump, bAdded + (dwVecSize | CONDITIONAL_BRANCH_MASK | C_JUMP_TAKEN_MASK),
							CurrentBlock_t.GetIndex(), CurrentBlock_t.dwHeight + 1 }, RootsRefMap,  EndsRefMap)) {
							CurrentBlock_t.flowToVec.emplace_back(dwVecSize + bAdded);
							explorationVec.push_back(dwVecSize + bAdded);
							RootsRefMap[lpResolvedJump] = *reinterpret_cast<BLOCK**>(&blocksVec[dwVecSize + bAdded]);
						}
					} else {
						RootsRefMap.at(lpResolvedJump)->flowFromVec.emplace_back(CurrentBlock_t.GetIndex());
					}
				} else {
					if (!RootsRefMap.contains(lpResolvedJump)) {
						if (added == AddBranch(NEW_BRANCH_PREREQ{ lpResolvedJump, dwVecSize | CONDITIONAL_BRANCH_MASK,
							CurrentBlock_t.GetIndex(), CurrentBlock_t.dwHeight + 1 }, RootsRefMap, EndsRefMap)) {
							CurrentBlock_t.flowToVec.emplace_back(dwVecSize);
							explorationVec.push_back(dwVecSize);
							RootsRefMap[lpResolvedJump] = *reinterpret_cast<BLOCK**>(&blocksVec[dwVecSize]);
							bAdded						= TRUE;
						}
					} else {
						RootsRefMap.at(lpResolvedJump)->flowFromVec.emplace_back(CurrentBlock_t.GetIndex());
					}
					if (!RootsRefMap.contains(lpNextInstruction)) {
						if (added == AddBranch(NEW_BRANCH_PREREQ{lpNextInstruction, bAdded + (dwVecSize | CONDITIONAL_BRANCH_MASK | C_JUMP_TAKEN_MASK), 
							CurrentBlock_t.GetIndex(), CurrentBlock_t.dwHeight + 1 },RootsRefMap, EndsRefMap)) {
							RootsRefMap[lpNextInstruction] = *reinterpret_cast<BLOCK**>(&blocksVec[dwVecSize + bAdded]);
							explorationVec.push_back(dwVecSize + 1);
						}
					} else {
						RootsRefMap.at(lpNextInstruction)->flowFromVec.emplace_back(CurrentBlock_t.GetIndex());
					}
				}
				break;
			}
			case no_reached_ret: {
				explorationVec.pop_back();
				vLeafs.push_back(CurrentBlock_t.GetIndex());
				break;
			}
			default: {
				return failed;
			}
		}
 	}
	Print();
 	return success;
}

void BLOCK::LogIndex() const {
	using namespace std;
	if ((dwIndex & ENDS_UNCOND_JUMP))
	{
		cout << "* ";
	}
	if (dwIndex & CONDITIONAL_BRANCH_MASK) {
		if (dwIndex & C_JUMP_TAKEN_MASK) { cout << format("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Conditional Jump Taken)\n\n", dwIndex & MAX_BRANCH_INDEX, dwHeight); }
		else { cout << format("[!] Analysing Branch #{:2d} & Of Height: #{:02d} (Conditional Jump Not Taken)\n\n", dwIndex & MAX_BRANCH_INDEX, dwHeight); }
	} else {
		if (!dwHeight)
		{
			cout << "[!] Analysing Root Branch (Non Conditional)\n\n";
		}
		else { cout << format("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Non Conditional)\n\n", dwIndex & 0x00FFFFFF, dwHeight); }
	}
}

IS_NEW_BRANCH BLOCK::Trace(_Out_ std::vector<BYTE *>& vNewFunctionsVec) {
	using namespace  std;
	LPBYTE	  lpReference = const_cast<BYTE*>(lpLandmarks->lpRoot);
	LDE_STATE state;
	while (state.cb_count_of_instructions < ROOT_BRANCH_INSTRUCTION_COUNT) {
		BYTE ucInstructionLen = LDE::MapInstructionLen(lpReference, state);
		switch (LDE::check_for_new_branch(state, lpReference)) {
			case yes_reached_non_conditional_branch: {
				lpLandmarks->lpEnd = lpReference;
				LDE::prepareForNextStep(state);
				state.contexts_arr.resize(state.cb_count_of_instructions);
				state.prefix_count_arr.resize(state.cb_count_of_instructions);
				ldeState = make_unique<LDE_STATE>(state);
				return yes_reached_non_conditional_branch;
			}
			case yes_reached_conditional_branch: {
				lpLandmarks->lpEnd = lpReference;
				LDE::prepareForNextStep(state);
				state.contexts_arr.resize(state.cb_count_of_instructions);
				state.prefix_count_arr.resize(state.cb_count_of_instructions);
				ldeState = make_unique<LDE_STATE>(state);
				return yes_reached_conditional_branch;
			}
			case yes_is_call: {
				vNewFunctionsVec.push_back(LDE::ResolveJump(lpReference));
				break;
			}
			case no: {
				break;
			}
			case no_reached_ret: {
				lpLandmarks->lpEnd = lpReference;
				LDE::prepareForNextStep(state);
				state.contexts_arr.resize(state.cb_count_of_instructions);
				state.prefix_count_arr.resize(state.cb_count_of_instructions);
				ldeState =  make_unique<LDE_STATE>(state);
				return no_reached_ret;
			}
			default: {
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
	//LogIndex();
	BYTE ucInstructionLen = 0;
	while (state.cb_count_of_instructions < ROOT_BRANCH_INSTRUCTION_COUNT && lpUntilAddress <= lpLandmarks->lpRoot) {
		if (lpReference == lpUntilAddress && ucInstructionLen) {
			lpLandmarks->lpEnd = lpReference - ucInstructionLen;
			ldeState = make_unique<LDE_STATE>(state);
			return no;
		}
		ucInstructionLen = LDE::MapInstructionLen(lpReference, state);
		LDE::logInstructionAndAddress(lpReference, state);

		switch (LDE::check_for_new_branch(state, lpReference)) {
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
			default: { return algorithm_failed; }
		}
		LDE::prepareForNextStep(state);
		lpReference += ucInstructionLen;
	}
	return algorithm_failed;
}

DWORD FUNCTION_TREE::CheckIfAlreadyTraced(BLOCK& CandidateBlock, std::map<BYTE*, BLOCK*>& RootsMap, std::map<BYTE*, BLOCK*>& EndsMap) {
	using namespace std;
	auto prevBlock = RootsMap.upper_bound(const_cast<BYTE*>(CandidateBlock.lpLandmarks->lpRoot));
	if (prevBlock != RootsMap.end()) {
		BLOCK& CloseBlock = *prevBlock->second;
		if (CandidateBlock.isInRange(const_cast<BYTE*>(CloseBlock.lpLandmarks->lpRoot)) && CandidateBlock.dwIndex != CloseBlock.dwIndex) {
			CandidateBlock.FindNewEnd(const_cast<BYTE*>(CloseBlock.lpLandmarks->lpRoot));
			TransferUniqueChildren(CandidateBlock, CloseBlock);
			EndsMap[CandidateBlock.lpLandmarks->lpEnd] = *reinterpret_cast<BLOCK**>(&blocksVec[CandidateBlock.GetIndex()]);
			EndsMap[CloseBlock.lpLandmarks->lpEnd]	   = *reinterpret_cast<BLOCK**>(&blocksVec[CloseBlock.GetIndex()]);
			return TRUE;
		}
	}
	EndsMap[CandidateBlock.lpLandmarks->lpEnd] = *reinterpret_cast<BLOCK**>(&blocksVec[CandidateBlock.GetIndex()]);
	return FALSE;

}

void BLOCK::Print(void) const {
	using namespace std;
	if (!lpLandmarks->lpEnd) { cout << "[!] This Branch Is Not Traced Yet."; }
	DWORD dwAccumulatedLength = 0;
	for (BYTE i = 0; i < ldeState->cb_count_of_instructions; i++) {
		LDE::logInstructionAndAddressCtx(const_cast<LPBYTE>(lpLandmarks->lpRoot) + dwAccumulatedLength, ldeState->contexts_arr[i], i);
		dwAccumulatedLength += LDE::GetInstructionLenCtx(ldeState->contexts_arr[i]);
	}
}

DWORD BLOCK::GetIndex(void) const {
	return dwIndex & MAX_BRANCH_INDEX;
}


void FUNCTION_TREE::TransferUniqueChildren(BLOCK& OldParentBlock, BLOCK& NewParentBlock) const {
	DWORD dwOutNewIndex = NULL;
	if (OldParentBlock.flowToVec.empty()) {
		OldParentBlock.flowToVec.push_back(NewParentBlock.GetIndex());
		NewParentBlock.flowFromVec.push_back(OldParentBlock.GetIndex());
		return;
	}
	BOOLEAN g_State = FALSE;
	for (DWORD dwChildIdx: OldParentBlock.flowToVec) {
		BOOLEAN bState = FALSE;
		BLOCK& ChildBlock = *blocksVec[dwChildIdx];
		BYTE ucParentsIndex = 0;
		for (DWORD dwParentIndex: ChildBlock.flowFromVec) {
			if (dwParentIndex == OldParentBlock.GetIndex()) {
				ChildBlock.flowFromVec[ucParentsIndex] = NewParentBlock.GetIndex();
				break;
			}
			ucParentsIndex++;
		}
		for (DWORD dwInIndex = dwOutNewIndex; dwInIndex < static_cast<DWORD>(NewParentBlock.flowToVec.size()); dwInIndex++) {
			if (dwInIndex == dwChildIdx) {
				bState = TRUE;
				break;
			}
		}
		if (bState) {
			dwOutNewIndex++;
			continue;
		}
		g_State = TRUE;
		NewParentBlock.flowToVec.push_back(dwChildIdx);
		dwOutNewIndex++;
	}
	if (g_State) {
		OldParentBlock.flowToVec.clear();
		OldParentBlock.flowToVec.push_back(NewParentBlock.GetIndex());
	}
}
