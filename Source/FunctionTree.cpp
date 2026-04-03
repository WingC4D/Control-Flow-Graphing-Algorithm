#include "FunctionTree.h"

BOOLEAN Block::isInRange(const LPBYTE candidate_address) const {
	if (!landmarksPtr->end) 
		return false;
	if (landmarksPtr->root > candidate_address)
		return false;
	if (landmarksPtr->end  < candidate_address) 
		return false;
	return true;
}

BOOLEAN Block::isInstructionHead(LPBYTE candidate_address) const {
	if (!landmarksPtr->end) 
		return false;
	for (DWORD dwAccumulatedLength = 0; BYTE Context: ldeState->contextsArray) {
		if (landmarksPtr->root + dwAccumulatedLength == candidate_address) 
			return true;
		dwAccumulatedLength += Lde::getInstructionLengthCtx(Context);
	}
	return false;
}

void Block::resize(BYTE new_size, LPBYTE new_end_address) const {
	if (new_size && new_end_address) {
		landmarksPtr->end		   = new_end_address;
		ldeState->instructionCount = new_size;
		ldeState->contextsArray.resize(new_size);
		ldeState->prefixCountArray.resize(new_size);
	}
}

void Block::findNewEnd(LPBYTE interlacing_root_ptr) const {
	DWORD accumulated_length = 0;
	for (BYTE last_instruction_length = 0, new_instruction_count = 0; BYTE Context : ldeState->contextsArray) {
		if (const_cast<LPBYTE>(landmarksPtr->root) + accumulated_length == interlacing_root_ptr) {
			if (new_instruction_count) 
				resize(new_instruction_count, interlacing_root_ptr - last_instruction_length);
			return;
		}
		last_instruction_length = Lde::getInstructionLengthCtx(Context);
		accumulated_length	   += last_instruction_length;
		new_instruction_count++;
	}
}

BOOLEAN FunctionTree::splitBlock(Block& BlockToSplit, LPBYTE splitting_address, std::map<BYTE*, Block*>& RootsMap) {
#ifdef DEBUG
	if (!BlockToSplit.isInRange(splitting_address)) 
		return false;
#endif
	BYTE  iterated_instructions_count = 0,
	      original_instructions_count = BlockToSplit.ldeState->instructionCount,
		 *split_block_root			  = BlockToSplit.landmarksPtr->root;
	for (DWORD last_instruction_length = 0, accumulated_length = 0, new_index = static_cast<DWORD>(blocksVec.size());
		 BYTE Context : BlockToSplit.ldeState->contextsArray) {
		if (split_block_root + accumulated_length != splitting_address || !iterated_instructions_count) {
			last_instruction_length = Lde::getInstructionLengthCtx(Context);
			accumulated_length	   += last_instruction_length;
			iterated_instructions_count++;
			continue;
		}
		blocksVec.emplace_back(std::make_unique<Block>(splitting_address, BlockToSplit.getIndex(), new_index, BlockToSplit.height + 1));
		Block& NewBlock				  = *blocksVec[new_index];
		BYTE   new_instructions_count = 0;
		for (; iterated_instructions_count + new_instructions_count < original_instructions_count; new_instructions_count++) {
			NewBlock.ldeState->contextsArray[new_instructions_count]	= BlockToSplit.ldeState->contextsArray[new_instructions_count + iterated_instructions_count];
			NewBlock.ldeState->prefixCountArray[new_instructions_count] = BlockToSplit.ldeState->prefixCountArray[new_instructions_count + iterated_instructions_count];
		}
		NewBlock.resize(new_instructions_count, BlockToSplit.landmarksPtr->end);
		transferUniqueChildren(BlockToSplit, NewBlock);
		BlockToSplit.resize(iterated_instructions_count, splitting_address - last_instruction_length);
		RootsMap[splitting_address] = blocksVec[new_index].get();
		break;
	}
	if (iterated_instructions_count == original_instructions_count) 
		return false;

	return true;
}

AddBlock FunctionTree::addBlock(LPBYTE address_to_add, DWORD new_block_index, DWORD parent_index, DWORD height, std::map<BYTE*, Block*>& RootsMap) {
	if (RootsMap.contains(address_to_add)) 
		return  was_traced;
	auto UpperBound = RootsMap.upper_bound(address_to_add);
	if (UpperBound != RootsMap.begin()) {
		Block& PreviousBlock = *(--UpperBound)->second;
		if (PreviousBlock.isInRange(address_to_add)) 
			if (splitBlock(PreviousBlock, address_to_add, RootsMap)) 
				return split;
		
	}
	blocksVec.emplace_back(std::make_unique<Block>(address_to_add, parent_index, new_block_index, height));
	return added;
}

FunctionTree::ErrorCode FunctionTree::Trace() {
	std::vector<DWORD>       ExplorationVec(1);
	std::map<LPBYTE, Block*> RootsMap;
	RootsMap[const_cast<LPBYTE>(root)] = blocksVec[0].get();
	while (!ExplorationVec.empty()) {
		DWORD  current_index =  ExplorationVec[ExplorationVec.size() - 1],
			   vector_size   =  static_cast<DWORD>(blocksVec.size());
		Block& CurrentBlock	 = *blocksVec[current_index];
		if (vector_size == MAX_BRANCH_INDEX) 
			return failed;
		ExplorationVec.pop_back();
		if (CurrentBlock.landmarksPtr->end) 
			continue;
		IsNewBranch trace_result = CurrentBlock.trace(newFunctionsVec);
		if (checkIfTraced(CurrentBlock, RootsMap)) 
			continue;
		FunctionTreeTraceCtx TraceContext = { .rootsMap = RootsMap, .currentBlock = CurrentBlock, .explorationVec = ExplorationVec };
		switch (trace_result) {
			case yes_reached_non_conditional_branch: {
				handleJump(Lde::resolveJump(CurrentBlock.landmarksPtr->end), vector_size, TraceContext);
				break;
			}
			case yes_reached_conditional_branch: {
				LPBYTE			   resolved_jump_ptr	= Lde::resolveJump(CurrentBlock.landmarksPtr->end),
								   next_instruction_ptr = CurrentBlock.landmarksPtr->end + Lde::getInstructionLengthCtx(CurrentBlock.ldeState->contextsArray[CurrentBlock.ldeState->instructionCount - 1]);
				ConditionalJumpCtx ConditionalJumpContext;
				next_instruction_ptr < resolved_jump_ptr ?
					ConditionalJumpContext = { .lpShallowAddress = next_instruction_ptr, .lpDeepAddress = resolved_jump_ptr, .dwShallowIndex = vector_size | COND_BLOCK_MASK, .dwDeepIndex = vector_size + 1 | COND_BLOCK_MASK | C_JUMP_TAKEN_MASK }:
					ConditionalJumpContext = { .lpShallowAddress = resolved_jump_ptr, .lpDeepAddress = next_instruction_ptr, .dwShallowIndex = vector_size | COND_BLOCK_MASK | C_JUMP_TAKEN_MASK, .dwDeepIndex = vector_size + 1 | COND_BLOCK_MASK };

				handleJump(ConditionalJumpContext.lpShallowAddress, ConditionalJumpContext.dwShallowIndex ,TraceContext);
				handleJump(ConditionalJumpContext.lpDeepAddress, ConditionalJumpContext.dwDeepIndex, TraceContext);
				break;
			}
			case no_reached_ret: {
				leavesVec.push_back(CurrentBlock.getIndex());
				break;
			}
			case yes_is_call:
			case algorithm_failed:
			case no: 
				return failed;
		}
 	}
	print();
 	return success;
}

void Block::logIndex() const {
	if (idx & COND_BLOCK_MASK)  idx & C_JUMP_TAKEN_MASK ?
			std::println("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Conditional Jump Taken)\n", idx & MAX_BRANCH_INDEX, height):
			std::println("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Conditional Jump Not Taken)\n", idx & MAX_BRANCH_INDEX, height);
	else  height ?
			std::println("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Non Conditional)\n", idx & 0x00FFFFFF, height):
			std::println("[!] Analysing Root Branch (Non Conditional)\n");
}

void Block::addResolvedCall(std::vector<unsigned char*>& NewFunctionVec, unsigned char* resolved_address) {
	bool was_added = false;
	for (unsigned char* stored_func_address : NewFunctionVec) {
		if (stored_func_address == resolved_address) {
			was_added = true;
			break;
		}
	}
	if (!was_added) NewFunctionVec.emplace_back(resolved_address);
}

void Block::handleEndOfTrace(LPBYTE current_address, LdeState& State) {
	State.contextsArray.resize(State.instructionCount);
	State.prefixCountArray.resize(State.instructionCount);
	ldeState		  = std::make_unique<LdeState>(State);
	landmarksPtr->end = current_address;
}

IsNewBranch Block::trace(_Out_ std::vector<BYTE *>& NewFunctionsVec) {
	LPBYTE	 reference_ptr = landmarksPtr->root;
	LdeState State;
	while (State.instructionCount < ROOT_BRANCH_INSTRUCTION_COUNT && State.status == success) {
		BYTE instruction_length = Lde::mapInstructionLength(reference_ptr, State.currInstructionContext, State.status, State.prefixCountArray[State.instructionCount]);
		if (!instruction_length) 
			return algorithm_failed;
		Lde::prepareForNextStep(State);
		switch (Lde::checkForNewBlock(State, reference_ptr)) {
			case yes_reached_non_conditional_branch: {
				handleEndOfTrace(reference_ptr, State);
				return yes_reached_non_conditional_branch;
			}
			case yes_reached_conditional_branch: {
				handleEndOfTrace(reference_ptr, State);
				return yes_reached_conditional_branch;
			}
			case yes_is_call: {
				addResolvedCall(NewFunctionsVec, Lde::resolveJump(reference_ptr));
				break;
			}
			case no_reached_ret: {
				handleEndOfTrace(reference_ptr, State);
				return no_reached_ret;
			}
			case algorithm_failed: 
				return algorithm_failed;
			case no: 
				break;
		}
		reference_ptr += instruction_length;
	}
	return algorithm_failed;
}

IsNewBranch Block::TraceUntil(_Out_ std::vector<LPBYTE>& NewFunctionsVec, _In_ const LPBYTE until_address) {
	BYTE	*reference_ptr	    = landmarksPtr->root,
			 instruction_length = 0;
	LdeState State;
#ifdef DEBUG
	logIndex();
#endif
	while (State.instructionCount < ROOT_BRANCH_INSTRUCTION_COUNT && until_address > reference_ptr) {
		if (reference_ptr == until_address && instruction_length) {
			handleEndOfTrace(reference_ptr, State);
			return no;
		}
		instruction_length = Lde::mapInstructionLength(reference_ptr, State.currInstructionContext, State.status, State.prefixCountArray[State.instructionCount]);
#ifdef DEBUG
		Lde::logInstructionAndAddress(reference_ptr, State);
#endif
		Lde::prepareForNextStep(State);
		switch (Lde::checkForNewBlock(State, reference_ptr)) {
			case yes_reached_non_conditional_branch: {
				handleEndOfTrace(reference_ptr, State);
				return yes_reached_non_conditional_branch;
			}
			case yes_reached_conditional_branch: {
				handleEndOfTrace(reference_ptr, State);
				return yes_reached_conditional_branch;
			}
			case yes_is_call: {
				addResolvedCall(NewFunctionsVec, Lde::resolveJump(reference_ptr));
				break;
			}
			case no_reached_ret: {
				handleEndOfTrace(reference_ptr, State);
				return no_reached_ret;
			}
			case no:
				break;
			case algorithm_failed: 
				return algorithm_failed;
		}
		reference_ptr += instruction_length;
	}
	return algorithm_failed;
}

BOOLEAN FunctionTree::checkIfTraced(Block& JustTracedBlock, std::map<BYTE*, Block*>& RootsMap) const {
	std::map<BYTE*, Block*>::iterator itNextBlock = RootsMap.upper_bound(JustTracedBlock.landmarksPtr->root);
	if (itNextBlock == RootsMap.end())
		return false;
	if (JustTracedBlock.idx == itNextBlock->second->idx) 
		return false;
	if (!JustTracedBlock.isInRange(itNextBlock->second->landmarksPtr->root))
		return false;
	
	JustTracedBlock.findNewEnd(itNextBlock->second->landmarksPtr->root);
	transferUniqueChildren(JustTracedBlock, *itNextBlock->second);
	return true;
}

void Block::print() const {
	if (!landmarksPtr->end) 
		std::println("[!] This Branch Is Not Traced Yet.");
	for (DWORD accumulated_length = 0, i = 0; BYTE Context: ldeState->contextsArray) {
		Lde::logInstructionAndAddressCtx(landmarksPtr->root + accumulated_length, Context, static_cast<BYTE>(i));
		accumulated_length += Lde::getInstructionLengthCtx(Context);
		if (i == 0xFF) {
			std::println("Hit an error while printing Block #{:03d}", idx);
			return;
		}
		i++;
	}
}

DWORD Block::getIndex() const {
	return idx & MAX_BRANCH_INDEX;
}

void FunctionTree::transferUniqueChildren(Block& OldParentBlock, Block& NewParentBlock) const {
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
	switch (addBlock(resolved_address, new_block_idx, TraceContext.currentBlock.getIndex(), TraceContext.currentBlock.height + 1, TraceContext.rootsMap)) {
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
		case split: 
			break;
	}
}